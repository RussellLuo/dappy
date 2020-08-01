<img src=logo.svg />

# Basic LDAP client for Go

[![GoDoc](https://img.shields.io/badge/godoc-reference-5272B4.svg?style=flat-square)](https://godoc.org/github.com/nerney/dappy)
[![Report Card](https://goreportcard.com/badge/github.com/nerney/dappy)](https://goreportcard.com/report/github.com/nerney/dappy)

LDAP is complicated. Many times, all you really need to do is authenticate users with it.
This package boils down LDAP functionality to User Authentication, that's it.

Thanks to https://github.com/go-ldap/ldap

`go get github.com/RussellLuo/dappy`

Example:

```go
package main

import (
	"log"

	"github.com/RussellLuo/dappy"
)

func main() {
	client, err := dappy.New(dappy.Config{
		Host:   "ldap.example.com:389",
		ROAdmin: dappy.User{Name: "cn=read-only-admin,dc=example,dc=com", Pass: "password"},
		BaseDN: "ou=People,dc=example,dc=com",
	})
	if err != nil {
		panic(err)
	}

	// username and password to authenticate
	username := "tesla"
	password := "password"

	// attempt the authentication
	if err := client.Auth(username, password); err != nil {
		if err == dappy.ErrUserNotFound || err == dappy.ErrInvalidPassword {
		    log.Printf("Failed due to: %v\n", err)
		} else {
			panic(err)
		}
	}
	log.Println("Success!")
}
```
