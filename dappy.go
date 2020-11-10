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

// Config is the configuration of a dappy client.
type Config struct {
	Host    string // The LDAP host and port, ex. "ldap.example.com:389"
	ROAdmin User   // The read-only admin for initial bind
	BaseDN  string // The base directory, ex. "ou=People,dc=example,dc=com"
}

// User holds the name and pass required for initial read-only bind.
type User struct {
	Name string
	Pass string
}

// local struct for implementing Client interface
type Client struct {
	config Config
}

// New creates s client with the provided config.
// If the config is invalid, an error will be returned.
func New(config Config) (*Client, error) {
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

	return &Client{config: config}, nil
}

// Auth performs the LDAP auth operation.
func (c *Client) Auth(username, password string) error {
	if username == "" {
		return ErrUserNotFound
	}
	if password == "" {
		return ErrInvalidPassword
	}

	conn, err := connect(c.config.Host)
	if err != nil {
		return err
	}
	defer conn.Close()

	filter := fmt.Sprintf("(uid=%v)", username)
	entries, err := c.search(conn, filter, "dn")
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		return ErrUserNotFound
	}
	// Use the first entry.
	userDN := entries[0].DN

	// Attempt to authenticate the user.
	err = conn.Bind(userDN, password)
	if isErrInvalidCredentials(err) {
		return ErrInvalidPassword
	}
	return err
}

// SearchAttrs searches the specified LDAP attributes by the given filter expression.
func (c *Client) SearchAttrs(filter string, attrNames ...string) (attrs []*ldap.EntryAttribute, err error) {
	if filter == "" {
		return nil, errors.New("filter is empty")
	}

	conn, err := connect(c.config.Host)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	entries, err := c.search(conn, filter, attrNames...)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		attrs = append(attrs, entry.Attributes...)
	}
	return attrs, nil
}

// search searches the LDAP entries by the given filter expression.
func (c *Client) search(conn *ldap.Conn, filter string, attrNames ...string) ([]*ldap.Entry, error) {
	// Perform the initial read-only bind for admin.
	if err := conn.Bind(c.config.ROAdmin.Name, c.config.ROAdmin.Pass); err != nil {
		return nil, err
	}

	// Search the LDAP entries.
	result, err := conn.Search(ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, attrNames,
		nil,
	))
	if err != nil {
		return nil, err
	}

	return result.Entries, nil
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
