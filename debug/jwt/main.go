package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	apiserverserviceaccount "k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/client-go/util/keyutil"
)

type legacyPrivateClaims struct {
	ServiceAccountName string `json:"kubernetes.io/serviceaccount/service-account.name"`
	ServiceAccountUID  string `json:"kubernetes.io/serviceaccount/service-account.uid"`
	SecretName         string `json:"kubernetes.io/serviceaccount/secret.name"`
	Namespace          string `json:"kubernetes.io/serviceaccount/namespace"`
}

const ecdsaPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEZmTmUhuanLjPA2CLquXivuwBDHTt5XYwgIr/kA1LtRoAoGCCqGSM49
AwEHoUQDQgAEH6cuzP8XuD5wal6wf9M6xDljTOPLX2i8uIp/C/ASqiIGUeeKQtX0
/IR3qCXyThP/dbCiHrF3v1cuhBOHY8CLVg==
-----END EC PRIVATE KEY-----`

func parse(tokenData string) error {
	tok, err := jwt.ParseSigned(tokenData)
	if err != nil {
		return nil
	}

	public := &jwt.Claims{}
	private := &legacyPrivateClaims{}

	if err := tok.Claims(ecdsaPrivateKey, public, private); err != nil {
	}
	fmt.Println(public)
	fmt.Println(private)
	return nil
}

func main() {

	signer, _ := signerFromECDSAPrivateKey(getPrivateKey(ecdsaPrivateKey))
	private := &legacyPrivateClaims{ // jwt看不到信息
		Namespace:          "a",
		ServiceAccountName: "b",
		ServiceAccountUID:  "uid",
		SecretName:         "secret.Name", // 存储在secret中的名字
	}
	serialize, _ := jwt.Signed(signer).
		Claims(private).
		Claims(jwt.Claims{
			Subject: apiserverserviceaccount.MakeUsername("a", "b"),
		}).
		Claims(&jwt.Claims{
			Issuer: "foo",
		}).
		CompactSerialize()
	fmt.Println(string(serialize))
	//	 https://www.box3.cn/tools/jwt.html
	parse(string(serialize))
}

func getPrivateKey(data string) *ecdsa.PrivateKey {
	key, err := keyutil.ParsePrivateKeyPEM([]byte(data))
	if err != nil {
		panic(fmt.Errorf("unexpected error parsing private key: %v", err))
	}
	return key.(*ecdsa.PrivateKey)
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
