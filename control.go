package nntp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ChaosConfig describes synthetic, deterministic failures for client tests.
// Each percentage is evaluated independently for the applicable operation.
type ChaosConfig struct {
	Greet201Percent      int
	Greet400Percent      int
	DropConnection       int
	SlowBodyMilliseconds int
	RejectAuthPercent    int
	CorruptBodyPercent   int
	MaxConnections       int
	TimeoutBodyPercent   int
	ReauthBodyPercent    int
	SplitTermPercent     int
	DropMidBodyPercent   int
	BadTermPercent       int
	StatBadCodePercent   int
	StatShortPercent     int
}

// Validate rejects impossible synthetic control settings.
func (config ChaosConfig) Validate() error {
	percentages := map[string]int{
		"greet_201":     config.Greet201Percent,
		"greet_400":     config.Greet400Percent,
		"drop_conn":     config.DropConnection,
		"reject_auth":   config.RejectAuthPercent,
		"corrupt_body":  config.CorruptBodyPercent,
		"timeout_body":  config.TimeoutBodyPercent,
		"reauth_body":   config.ReauthBodyPercent,
		"split_term":    config.SplitTermPercent,
		"drop_mid_body": config.DropMidBodyPercent,
		"bad_term":      config.BadTermPercent,
		"stat_bad_code": config.StatBadCodePercent,
		"stat_short":    config.StatShortPercent,
	}
	for name, value := range percentages {
		if value < 0 || value > 100 {
			return fmt.Errorf("%s must be between 0 and 100", name)
		}
	}
	if config.SlowBodyMilliseconds < 0 {
		return errors.New("slow_body must not be negative")
	}
	if config.MaxConnections < 0 {
		return errors.New("max_conns must not be negative")
	}
	return nil
}

// ParseChaos parses the same compact format accepted by the NNTP test-control
// extension. An empty string and "off" both disable all synthetic faults.
func ParseChaos(value string) (ChaosConfig, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "off") {
		return ChaosConfig{}, nil
	}
	config := ChaosConfig{}
	for _, part := range strings.Split(value, ",") {
		name, rawValue, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found || strings.TrimSpace(name) == "" {
			return ChaosConfig{}, fmt.Errorf("invalid chaos option %q", part)
		}
		parsed, err := strconv.Atoi(strings.TrimSpace(rawValue))
		if err != nil {
			return ChaosConfig{}, fmt.Errorf("parse chaos option %s: %w", name, err)
		}
		switch name {
		case "greet_201":
			config.Greet201Percent = parsed
		case "greet_400":
			config.Greet400Percent = parsed
		case "drop_conn":
			config.DropConnection = parsed
		case "slow_body":
			config.SlowBodyMilliseconds = parsed
		case "reject_auth":
			config.RejectAuthPercent = parsed
		case "corrupt_body":
			config.CorruptBodyPercent = parsed
		case "max_conns":
			config.MaxConnections = parsed
		case "timeout_body":
			config.TimeoutBodyPercent = parsed
		case "reauth_body":
			config.ReauthBodyPercent = parsed
		case "split_term":
			config.SplitTermPercent = parsed
		case "drop_mid_body":
			config.DropMidBodyPercent = parsed
		case "bad_term":
			config.BadTermPercent = parsed
		case "stat_bad_code":
			config.StatBadCodePercent = parsed
		case "stat_short":
			config.StatShortPercent = parsed
		default:
			return ChaosConfig{}, fmt.Errorf("unknown chaos option %q", name)
		}
	}
	if err := config.Validate(); err != nil {
		return ChaosConfig{}, err
	}
	return config, nil
}

// Metrics is a snapshot of synthetic-server network activity.
type Metrics struct {
	BodyCounts         map[string]int `json:"body_counts"`
	StatCounts         map[string]int `json:"stat_counts"`
	BodyBytes          uint64         `json:"body_bytes"`
	BodyTransfers      int64          `json:"body_transfers"`
	BodyFirstUnixNano  int64          `json:"body_first_unix_nano"`
	BodyLastUnixNano   int64          `json:"body_last_unix_nano"`
	StatChaosHits      int            `json:"stat_chaos_hits"`
	ConnectionAttempts int64          `json:"connection_attempts"`
	ConnectionAccepted int64          `json:"connection_accepted"`
	ConnectionRejected int64          `json:"connection_rejected"`
	ActiveConnections  int64          `json:"active_connections"`
	PeakConnections    int64          `json:"peak_connections"`
	ConfiguredLimit    int            `json:"configured_limit"`
}

func (server *Server) requireTestControl() error {
	if !server.config.EnableTestControl {
		return ErrTestControlDisabled
	}
	return nil
}

// SetChaos changes the synthetic fault profile for this instance.
func (server *Server) SetChaos(config ChaosConfig) error {
	if err := server.requireTestControl(); err != nil {
		return err
	}
	if err := config.Validate(); err != nil {
		return err
	}
	server.chaosMu.Lock()
	server.chaos = config
	server.chaosMu.Unlock()
	return nil
}

// ResetMetrics clears per-instance synthetic counters.
func (server *Server) ResetMetrics() error {
	if err := server.requireTestControl(); err != nil {
		return err
	}
	server.metrics.reset(server.activeConnections.Load())
	return nil
}

// Metrics returns a safe copy of the current synthetic counters.
func (server *Server) Metrics() (Metrics, error) {
	if err := server.requireTestControl(); err != nil {
		return Metrics{}, err
	}
	metrics := server.metrics.snapshot(server.activeConnections.Load())
	metrics.ConfiguredLimit = server.currentChaos().MaxConnections
	return metrics, nil
}

// DeleteByPrefix removes a stable percentage of matching message IDs.
func (server *Server) DeleteByPrefix(prefix string, percentage int) (matched, deleted int, err error) {
	if err := server.requireTestControl(); err != nil {
		return 0, 0, err
	}
	return server.store.deleteByPrefix(prefix, percentage)
}

// DeleteID removes one article if it exists.
func (server *Server) DeleteID(messageID string) (bool, error) {
	if err := server.requireTestControl(); err != nil {
		return false, err
	}
	return server.store.deleteByID(stripBrackets(messageID))
}

// Reload rebuilds the in-memory index from the disk-backed article store.
func (server *Server) Reload() (int, error) {
	if err := server.requireTestControl(); err != nil {
		return 0, err
	}
	return server.store.reload()
}
