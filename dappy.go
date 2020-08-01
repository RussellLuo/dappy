// Package dappy provides an ldap client for simple ldap authentication.
package dappy

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"gopkg.in/ldap.v3"
)

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrInvalidPassword = errors.New("invalid password")
)

// Client interface performs the LDAP auth operation.
type Client interface {
	Auth(username, password string) error
}

// Config to provide a dappy client.
// All fields are required, except for Filter.
type Config struct {
	Host    string // The LDAP host and port, ex. "ldap.example.com:389"
	ROAdmin User   // The read-only admin for initial bind
	BaseDN  string // The base directory, ex. "ou=People,dc=example,dc=com"
	Filter  string // The filter expression, defaults to "uid"
}

// User holds the name and pass required for initial read-only bind.
type User struct {
	Name string
	Pass string
}

// local struct for implementing Client interface
type client struct {
	Config
}

// New creates s client with the provided config.
// If the config is invalid, an error will be returned.
func New(config Config) (Client, error) {
	if config.Host == "" {
		return nil, errors.New("config.Host is empty")
	}
	if config.ROAdmin.Name == "" {
		return nil, errors.New("config.ROAdmin.Name is empty")
	}
	if config.ROAdmin.Pass == "" {
		return nil, errors.New("config.ROAdmin.Pass is empty")
	}
	if config.BaseDN == "" {
		return nil, errors.New("config.BaseDN is empty")
	}
	if config.Filter == "" {
		config.Filter = "uid"
	}

	return client{config}, nil
}

// Auth performs the LDAP auth operation.
func (c client) Auth(username, password string) error {
	// Establish a connection.
	conn, err := connect(c.Host)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Perform the initial read-only bind for admin.
	if err = conn.Bind(c.ROAdmin.Name, c.ROAdmin.Pass); err != nil {
		return err
	}

	// Find the user by name.
	result, err := conn.Search(ldap.NewSearchRequest(
		c.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(%v=%v)", c.Filter, username),
		[]string{"dn"},
		nil,
	))
	if err != nil {
		return err
	}
	if len(result.Entries) < 1 {
		return ErrUserNotFound
	}

	// Attempt to authenticate the user.
	err = conn.Bind(result.Entries[0].DN, password)
	if isErrInvalidCredentials(err) {
		return ErrInvalidPassword
	}
	return err
}

// Helper functions

// connect establishes a connection with an ldap host
// (the caller is expected to Close the connection when finished)
func connect(host string) (*ldap.Conn, error) {
	c, err := net.DialTimeout("tcp", host, time.Second*8)
	if err != nil {
		return nil, err
	}
	conn := ldap.NewConn(c, false)
	conn.Start()
	return conn, nil
}

// isErrInvalidCredentials checks whether err is a Invalid-Credentials error.
func isErrInvalidCredentials(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Invalid Credentials")
}
