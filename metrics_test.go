package nntp

import "testing"

func TestMetricsRetainLegacyE2EFields(t *testing.T) {
	var state metricState
	state.reset(0)
	state.recordBody("fixture-body@example.test", 64)
	state.recordStat("fixture-stat@example.test")
	state.recordStatChaos("fixture-stat@example.test")
	metrics := state.snapshot(0)
	if metrics.BodyFirstUnixNano == 0 || metrics.BodyLastUnixNano == 0 {
		t.Fatalf("missing body timing: %#v", metrics)
	}
	if metrics.BodyLastUnixNano < metrics.BodyFirstUnixNano {
		t.Fatalf("body timing order is invalid: %#v", metrics)
	}
	if metrics.StatChaosHits != 1 {
		t.Fatalf("stat chaos hits = %d", metrics.StatChaosHits)
	}
	if got := state.statChaosHits("fixture-stat"); got != 1 {
		t.Fatalf("filtered stat chaos hits = %d", got)
	}
	if got := state.statChaosHits("other"); got != 0 {
		t.Fatalf("unexpected unrelated stat chaos hits = %d", got)
	}
}

func TestMetricsExposeConfiguredConnectionLimit(t *testing.T) {
	server := startFixtureServer(t, Config{
		DataDir:           t.TempDir(),
		ListenAddr:        "127.0.0.1:0",
		Credentials:       Credentials{Username: fixtureUsername, Password: fixturePassword},
		EnableTestControl: true,
	})
	if err := server.SetChaos(ChaosConfig{MaxConnections: 3}); err != nil {
		t.Fatalf("set chaos: %v", err)
	}
	metrics, err := server.Metrics()
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	if metrics.ConfiguredLimit != 3 {
		t.Fatalf("configured limit = %d", metrics.ConfiguredLimit)
	}
}

// A connection whose first command is MODE CONTROL is the harness reading or
// steering the server, so the active and peak counters leave it out; every
// other connection is a session from its first command.
func TestControlChannelIsNotCountedAsASession(t *testing.T) {
	server := startFixtureServer(t, Config{
		DataDir:           t.TempDir(),
		ListenAddr:        "127.0.0.1:0",
		Credentials:       Credentials{Username: fixtureUsername, Password: fixturePassword},
		EnableTestControl: true,
	})
	session := dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, session)

	control := dialFixtureClient(t, server.PlaintextAddr())
	writeClientLine(t, control, "MODE CONTROL")
	expectClientLine(t, control, "200 Control channel, not counted as a session")
	authenticateFixtureClient(t, control)
	writeClientLine(t, control, "METRICS RESET")
	expectClientLine(t, control, "290 Metrics reset")

	// A MODE CONTROL after a session's first command leaves it counted.
	late := dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, late)
	writeClientLine(t, late, "MODE CONTROL")
	expectClientLine(t, late, "200 Reader mode acknowledged")

	metrics, err := server.Metrics()
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	if metrics.ActiveConnections != 2 || metrics.PeakConnections != 2 {
		t.Fatalf("active = %d, peak = %d, want the two sessions only", metrics.ActiveConnections, metrics.PeakConnections)
	}
	closeFixtureClient(t, late)
	closeFixtureClient(t, control)
	closeFixtureClient(t, session)
}
