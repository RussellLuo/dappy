package dappy_test

import (
	"testing"

	"github.com/RussellLuo/dappy"
	"github.com/stretchr/testify/assert"
)

var client, _ = dappy.New(dappy.Config{
	Host:    "ldap.forumsys.com:389",
	ROAdmin: dappy.User{Name: "cn=read-only-admin,dc=example,dc=com", Pass: "password"},
	BaseDN:  "dc=example,dc=com",
})

func TestDappyAuth_HappyPath(t *testing.T) {
	assert.Nil(t, client.Auth("tesla", "password"),
		"should authenticate successfully")
}

func TestDappyAuth_InitialBindFail(t *testing.T) {
	_, err := dappy.New(dappy.Config{
		BaseDN: "dc=example,dc=com",
		Filter: "uid",
		ROUser: dappy.User{Name: "cn=read-only-admin,dc=example,dc=com", Pass: "badpassword"},
		Host:   "ldap.forumsys.com:389",
	})
	assert.Equal(t, "LDAP Result Code 49 \"Invalid Credentials\": ", err.Error(),
		"should fail initial bind")
}

func TestDappyAuth_EmptyPassword(t *testing.T) {
	err := client.Auth("tesla", "")
	assert.Equal(t, "LDAP Result Code 206 \"Empty password not allowed by the client\": ldap: empty password not allowed by the client", err.Error(),
		"should fail because of empty password")
}

func TestDappyAuth_FailBadFilter(t *testing.T) {
	client, _ := dappy.New(dappy.Config{
		BaseDN: "dc=example,dc=com",
		Filter: "(",
		ROUser: dappy.User{Name: "cn=read-only-admin,dc=example,dc=com", Pass: "password"},
		Host:   "ldap.forumsys.com:389",
	})
	err := client.Auth("tesla", "password")
	assert.Equal(t, "LDAP Result Code 201 \"Filter Compile Error\": ldap: unexpected end of filter", err.Error(),
		"should fail to perform search")
}

func TestDappyAuth_UserNotFound(t *testing.T) {
	err := client.Auth("daddy", "password")
	assert.Equal(t, "not found", err.Error(),
		"should fail to find user")
}

func TestDappyAuth_FailAuth(t *testing.T) {
	err := client.Auth("tesla", "wrongpassword")
	assert.Equal(t, "LDAP Result Code 49 \"Invalid Credentials\": ", err.Error(),
		"should fail to authenticate user")
}
