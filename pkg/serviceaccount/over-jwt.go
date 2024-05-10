/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package serviceaccount

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	v1 "k8s.io/api/core/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	apiserverserviceaccount "k8s.io/apiserver/pkg/authentication/serviceaccount"
)

// ServiceAccountTokenGetter defines functions to retrieve a named service account and secret
type ServiceAccountTokenGetter interface {
	GetServiceAccount(namespace, name string) (*v1.ServiceAccount, error)
	GetPod(namespace, name string) (*v1.Pod, error)
	GetSecret(namespace, name string) (*v1.Secret, error)
}

type TokenGenerator interface {
	// GenerateToken generates a token which will identify the given
	// ServiceAccount. privateClaims is an interface that will be
	// serialized into the JWT payload JSON encoding at the root level of
	// the payload object. Public claims take precedent over private
	// claims i.e. if both claims and privateClaims have an "exp" field,
	// the value in claims will be used.
	GenerateToken(claims *jwt.Claims, privateClaims interface{}) (string, error)
}

// JWTTokenGenerator 返回一个TokenGenerator,使用给定的privateKey生成有签名的JWT令牌.
// privateKey是RSA私钥的pem编码字节数组.
func JWTTokenGenerator(iss string, privateKey interface{}) (TokenGenerator, error) {
	var signer jose.Signer
	var err error
	switch pk := privateKey.(type) {
	case *rsa.PrivateKey:
		signer, err = signerFromRSAPrivateKey(pk)
		if err != nil {
			return nil, fmt.Errorf("could not generate signer for RSA keypair: %v", err)
		}
	case *ecdsa.PrivateKey:
		signer, err = signerFromECDSAPrivateKey(pk)
		if err != nil {
			return nil, fmt.Errorf("could not generate signer for ECDSA keypair: %v", err)
		}
	case jose.OpaqueSigner:
		signer, err = signerFromOpaqueSigner(pk)
		if err != nil {
			return nil, fmt.Errorf("could not generate signer for OpaqueSigner: %v", err)
		}
	default:
		return nil, fmt.Errorf("unknown private key type %T, must be *rsa.PrivateKey, *ecdsa.PrivateKey, or jose.OpaqueSigner", privateKey)
	}

	return &jwtTokenGenerator{
		iss:    iss,
		signer: signer,
	}, nil
}

// keyIDFromPublicKey derives a key ID non-reversibly from a public key.
//
// The Key ID is field on a given on JWTs and JWKs that help relying parties
// pick the correct key for verification when the identity party advertises
// multiple keys.
//
// Making the derivation non-reversible makes it impossible for someone to
// accidentally obtain the real key from the key ID and use it for token
// validation.
func keyIDFromPublicKey(publicKey interface{}) (string, error) {
	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to serialize public key to DER format: %v", err)
	}

	hasher := crypto.SHA256.New()
	hasher.Write(publicKeyDERBytes)
	publicKeyDERHash := hasher.Sum(nil)

	keyID := base64.RawURLEncoding.EncodeToString(publicKeyDERHash)

	return keyID, nil
}

func signerFromRSAPrivateKey(keyPair *rsa.PrivateKey) (jose.Signer, error) {
	keyID, err := keyIDFromPublicKey(&keyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keyID: %v", err)
	}

	// IMPORTANT: If this function is updated to support additional key sizes,
	// algorithmForPublicKey in serviceaccount/openidmetadata.go must also be
	// updated to support the same key sizes. Today we only support RS256.

	// Wrap the RSA keypair in a JOSE JWK with the designated key ID.
	privateJWK := &jose.JSONWebKey{
		Algorithm: string(jose.RS256),
		Key:       keyPair,
		KeyID:     keyID,
		Use:       "sig",
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       privateJWK,
		},
		nil,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %v", err)
	}

	return signer, nil
}

func signerFromECDSAPrivateKey(keyPair *ecdsa.PrivateKey) (jose.Signer, error) {
	var alg jose.SignatureAlgorithm
	switch keyPair.Curve {
	case elliptic.P256():
		alg = jose.ES256
	case elliptic.P384():
		alg = jose.ES384
	case elliptic.P521():
		alg = jose.ES512
	default:
		return nil, fmt.Errorf("unknown private key curve, must be 256, 384, or 521")
	}

	keyID, err := keyIDFromPublicKey(&keyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keyID: %v", err)
	}

	// Wrap the ECDSA keypair in a JOSE JWK with the designated key ID.
	privateJWK := &jose.JSONWebKey{
		Algorithm: string(alg),
		Key:       keyPair,
		KeyID:     keyID,
		Use:       "sig",
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key:       privateJWK,
		},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %v", err)
	}

	return signer, nil
}

func signerFromOpaqueSigner(opaqueSigner jose.OpaqueSigner) (jose.Signer, error) {
	alg := jose.SignatureAlgorithm(opaqueSigner.Public().Algorithm)

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key: &jose.JSONWebKey{
				Algorithm: string(alg),
				Key:       opaqueSigner,
				KeyID:     opaqueSigner.Public().KeyID,
				Use:       "sig",
			},
		},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %v", err)
	}

	return signer, nil
}

type jwtTokenGenerator struct {
	iss    string
	signer jose.Signer
}

func (j *jwtTokenGenerator) GenerateToken(claims *jwt.Claims, privateClaims interface{}) (string, error) {
	// claims are applied in reverse precedence
	return jwt.Signed(j.signer).
		Claims(privateClaims).
		Claims(claims).
		Claims(&jwt.Claims{
			Issuer: j.iss,
		}).
		CompactSerialize()
}

// JWTTokenAuthenticator 将authenticates tokens转换为为JWTTokenGenerator生成的JWT令牌
// 使用每个给定的公钥验证令牌签名,直到其中一个有效(允许密钥旋转)
// 如果查找为真,将检索作为令牌内声明引用的服务帐户和秘密,并使用提供的ServiceAccountTokenGetter进行验证
func JWTTokenAuthenticator(issuers []string, keys []interface{}, implicitAuds authenticator.Audiences, validator Validator) authenticator.Token {
	issuersMap := make(map[string]bool)
	for _, issuer := range issuers {
		issuersMap[issuer] = true
	}
	return &JwtTokenAuthenticator{
		issuers:      issuersMap,
		keys:         keys,
		implicitAuds: implicitAuds,
		validator:    validator,
	}
}

type JwtTokenAuthenticator struct {
	issuers      map[string]bool         // 颁发者
	keys         []interface{}           // 公钥,用于加密
	validator    Validator               //
	implicitAuds authenticator.Audiences // 内置的默认客户端ID,
}

type Validator interface {
	// Validate 验证令牌并返回用户信息或错误.//当调用此函数时,验证器可以假定令牌的颁发者和签名已经得到验证.
	Validate(ctx context.Context, tokenData string, public *jwt.Claims, private interface{}) (*apiserverserviceaccount.ServiceAccountInfo, error)
	// NewPrivateClaims 返回一个结构体,身份验证器应将JWT有效负载反序列化为该结构体.然后,身份验证器可以将此结构体作为“private”参数传递回验证器,
	// 作为Validate()调用的参数.此结构体应包含验证器需要验证JWT的任何私有声明的字段.
	NewPrivateClaims() interface{}
}

func (j *JwtTokenAuthenticator) AuthenticateToken(ctx context.Context, tokenData string) (*authenticator.Response, bool, error) {
	if !j.hasCorrectIssuer(tokenData) {
		return nil, false, nil
	}

	tok, err := jwt.ParseSigned(tokenData)
	if err != nil {
		return nil, false, nil
	}

	public := &jwt.Claims{}
	private := j.validator.NewPrivateClaims()

	// TODO: Pick the key that has the same key ID as `tok`, if one exists.
	var (
		found   bool
		errlist []error
	)
	for _, key := range j.keys { // 公钥
		if err := tok.Claims(key, public, private); err != nil {
			errlist = append(errlist, err)
			continue
		}
		found = true
		break
	}

	if !found {
		return nil, false, utilerrors.NewAggregate(errlist)
	}

	tokenAudiences := authenticator.Audiences(public.Audience) // 客户端ID
	if len(tokenAudiences) == 0 {
		// only apiserver audiences are allowed for legacy tokens
		audit.AddAuditAnnotation(ctx, "authentication.k8s.io/legacy-token", public.Subject)
		legacyTokensTotal.WithContext(ctx).Inc()
		tokenAudiences = j.implicitAuds
	}

	requestedAudiences, ok := authenticator.AudiencesFrom(ctx)
	if !ok {
		// default to apiserver audiences
		requestedAudiences = j.implicitAuds
	}

	auds := authenticator.Audiences(tokenAudiences).Intersect(requestedAudiences)
	if len(auds) == 0 && len(j.implicitAuds) != 0 {
		return nil, false, fmt.Errorf("token audiences %q is invalid for the target audiences %q", tokenAudiences, requestedAudiences)
	}

	// If we get here, we have a token with a recognized signature and
	// issuer string.
	sa, err := j.validator.Validate(ctx, tokenData, public, private)
	if err != nil {
		return nil, false, err
	}

	return &authenticator.Response{
		User:      sa.UserInfo(),
		Audiences: auds,
	}, true, nil
}

// hasCorrectIssuer 如果tokenData是紧凑序列化格式中的有效JWT,并且“iss”声明与此令牌身份验证器的iss字段匹配,则返回true,否则返回false.
// Note: go-jose currently does not allow access to unverified JWS payloads.
// See https://github.com/square/go-jose/issues/169
func (j *JwtTokenAuthenticator) hasCorrectIssuer(tokenData string) bool {
	parts := strings.Split(tokenData, ".")
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	claims := struct {
		// WARNING: this JWT is not verified. Do not trust these claims.
		Issuer string `json:"iss"`
	}{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return false
	}
	return j.issuers[claims.Issuer]
}
