package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/golang/glog"
	"k8s.io/klog/v2"
	"strings"
)

var (
	ldapUrl = "ldap://" + "192.168.100.179:389"
)

func authByLdap(username, password string) error {
	groups, err := getLdapGroups(username, password)
	if err != nil {
		return err
	}
	if len(groups) > 0 {
		return nil
	}

	return fmt.Errorf("No matching group or user attribute. Authentication rejected, Username: %s", username)
}

// 获取user的groups
func getLdapGroups(username, password string) ([]string, error) {
	glog.Info("username:password", username, ":", password)
	var groups []string

	config := &tls.Config{InsecureSkipVerify: true}
	ldapConn, err := ldap.DialURL(ldapUrl, ldap.DialWithTLSConfig(config))
	if err != nil {
		glog.V(4).Info("dial ldap failed, err: ", err)
		return groups, err
	}
	defer ldapConn.Close()

	binduser := fmt.Sprintf("CN=%s,ou=People,dc=demo,dc=com", username)

	err = ldapConn.Bind(binduser, password)
	if err != nil {
		klog.V(4).ErrorS(err, "bind user to ldap error")
		return groups, err
	}

	// 查询用户成员
	searchString := fmt.Sprintf("(&(objectClass=person)(cn=%s))", username)
	memberSearchAttribute := "memberOf"
	searchRequest := ldap.NewSearchRequest(
		"dc=demo,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		searchString,
		[]string{memberSearchAttribute},
		nil,
	)
	searchResult, err := ldapConn.Search(searchRequest)
	if err != nil {
		klog.V(4).ErrorS(err, "search user properties error")
		return groups, err
	}
	// 如果没有查到结果，返回失败
	if len(searchResult.Entries[0].Attributes) < 1 {
		return groups, errors.New("no user in ldap")
	}
	entry := searchResult.Entries[0]
	for _, e := range entry.Attributes {
		for _, attr := range e.Values {
			groupList := strings.Split(attr, ",")
			for _, g := range groupList {
				if strings.HasPrefix(g, "cn=") {
					group := strings.Split(g, "=")
					groups = append(groups, group[1])
				}
			}
		}
	}
	return groups, nil
}
