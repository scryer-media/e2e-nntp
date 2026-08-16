// Package nntp provides a small disk-backed NNTP server for deterministic
// integration tests. It is intentionally not a production Usenet service.
package nntp

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrTestControlDisabled is returned when an embedding caller requests a
	// synthetic control operation without explicitly enabling that surface.
	ErrTestControlDisabled = errors.New("test control is disabled")
)

// Credentials are required for all stateful NNTP operations.
type Credentials struct {
	Username string
	Password string
}

// matches compares both fields in constant time and only then combines the
// results, so a rejected login does not reveal which field was wrong.
func (credentials Credentials) matches(username, password string) bool {
	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(credentials.Username))
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(credentials.Password))
	return usernameMatch&passwordMatch == 1
}

// Config controls one independent server instance.
type Config struct {
	DataDir           string
	ListenAddr        string
	TLS               TLSConfig
	Credentials       Credentials
	Pipelining        bool
	EnableTestControl bool
	Chaos             ChaosConfig
	ChaosSeed         int64
}

func (config Config) normalized() (Config, error) {
	config.DataDir = strings.TrimSpace(config.DataDir)
	if config.DataDir == "" {
		return Config{}, errors.New("data directory is required")
	}
	if strings.TrimSpace(config.ListenAddr) == "" {
		config.ListenAddr = "127.0.0.1:119"
	}
	config.Credentials.Username = strings.TrimSpace(config.Credentials.Username)
	if config.Credentials.Username == "" {
		return Config{}, errors.New("username is required")
	}
	if config.Credentials.Password == "" {
		return Config{}, errors.New("password is required")
	}
	if config.ChaosSeed == 0 {
		config.ChaosSeed = 1
	}
	if err := config.Chaos.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate chaos configuration: %w", err)
	}
	if err := config.TLS.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate TLS configuration: %w", err)
	}
	return config, nil
}
