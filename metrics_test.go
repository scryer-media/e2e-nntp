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
