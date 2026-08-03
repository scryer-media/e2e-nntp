package nntp

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	fixtureUsername = "fixture-user"
	fixturePassword = "fixture-password"
)

func TestServerPostsRetrievesAndReloadsArticles(t *testing.T) {
	directory := t.TempDir()
	server := startFixtureServer(t, Config{DataDir: directory, ListenAddr: "127.0.0.1:0", Credentials: Credentials{Username: fixtureUsername, Password: fixturePassword}})
	client := dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, client)
	writeClientLine(t, client, "POST")
	expectClientLine(t, client, "340 Send article, end with .")
	for _, line := range []string{
		"Message-ID: <fixture-article@example.test>",
		"Subject: fixture",
		"",
		"first line",
		"..dot-prefixed",
		".",
	} {
		writeClientLine(t, client, line)
	}
	expectClientLine(t, client, "240 Article received")

	writeClientLine(t, client, "GROUP alt.binaries.test")
	expectClientLine(t, client, "211 1 1 1 alt.binaries.test")
	writeClientLine(t, client, "STAT <fixture-article@example.test>")
	expectClientLine(t, client, "223 0 <fixture-article@example.test>")
	writeClientLine(t, client, "BODY <fixture-article@example.test>")
	expectClientLine(t, client, "222 0 <fixture-article@example.test>")
	expectClientLine(t, client, "first line")
	expectClientLine(t, client, "..dot-prefixed")
	expectClientLine(t, client, ".")
	closeFixtureClient(t, client)
	if err := server.Close(); err != nil {
		t.Fatalf("close first server: %v", err)
	}

	reloaded := startFixtureServer(t, Config{DataDir: directory, ListenAddr: "127.0.0.1:0", Credentials: Credentials{Username: fixtureUsername, Password: fixturePassword}})
	client = dialFixtureClient(t, reloaded.PlaintextAddr())
	authenticateFixtureClient(t, client)
	writeClientLine(t, client, "STAT <fixture-article@example.test>")
	expectClientLine(t, client, "223 0 <fixture-article@example.test>")
}

func TestTLSGeneratedMaterialIsPersistentAndTrusted(t *testing.T) {
	directory := t.TempDir()
	certificateDirectory := filepath.Join(directory, "generated-tls")
	config := Config{
		DataDir:    filepath.Join(directory, "articles"),
		ListenAddr: "127.0.0.1:0",
		TLS: TLSConfig{
			ListenAddr: "127.0.0.1:0",
			Generated:  &GeneratedTLSConfig{Directory: certificateDirectory, DNSNames: []string{"fixture.test"}},
		},
		Credentials: Credentials{Username: fixtureUsername, Password: fixturePassword},
	}
	server := startFixtureServer(t, config)
	caContents, err := os.ReadFile(server.CACertificatePath())
	if err != nil {
		t.Fatalf("read generated CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caContents) {
		t.Fatal("generated CA did not parse")
	}
	connection, err := tls.Dial("tcp", server.TLSAddr(), &tls.Config{RootCAs: pool, ServerName: "fixture.test", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("dial generated TLS listener: %v", err)
	}
	defer connection.Close()
	reader := bufio.NewReader(connection)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(strings.TrimSpace(line), "200 ") {
		t.Fatalf("unexpected TLS greeting: %q (%v)", line, err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("close TLS server: %v", err)
	}
	for _, name := range []string{"ca.pem", "ca.key", "server.pem", "server.key"} {
		if _, err := os.Stat(filepath.Join(certificateDirectory, name)); err != nil {
			t.Fatalf("persistent generated material missing %s: %v", name, err)
		}
	}
}

func TestTestControlIsOptInAndAuthenticated(t *testing.T) {
	disabled := startFixtureServer(t, Config{DataDir: t.TempDir(), ListenAddr: "127.0.0.1:0", Credentials: Credentials{Username: fixtureUsername, Password: fixturePassword}})
	if err := disabled.SetChaos(ChaosConfig{}); err != ErrTestControlDisabled {
		t.Fatalf("expected disabled direct control, got %v", err)
	}
	client := dialFixtureClient(t, disabled.PlaintextAddr())
	writeClientLine(t, client, "CHAOS off")
	expectClientLine(t, client, "500 Unknown command")
	closeFixtureClient(t, client)

	enabled := startFixtureServer(t, Config{DataDir: t.TempDir(), ListenAddr: "127.0.0.1:0", Credentials: Credentials{Username: fixtureUsername, Password: fixturePassword}, EnableTestControl: true})
	client = dialFixtureClient(t, enabled.PlaintextAddr())
	writeClientLine(t, client, "CHAOS off")
	expectClientLine(t, client, "480 Authentication required")
	authenticateFixtureClient(t, client)
	writeClientLine(t, client, "CHAOS slow_body=1")
	expectClientLine(t, client, "290 Chaos mode updated")
	metrics, err := enabled.Metrics()
	if err != nil {
		t.Fatalf("read direct metrics: %v", err)
	}
	if metrics.ConnectionAccepted == 0 {
		t.Fatal("expected accepted connection metric")
	}
}

func startFixtureServer(t *testing.T, config Config) *Server {
	t.Helper()
	context, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	server, err := Start(context, config)
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close server: %v", err)
		}
	})
	return server
}

func dialFixtureClient(t *testing.T, address string) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	reader := bufio.NewReader(connection)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(strings.TrimSpace(line), "200 ") {
		t.Fatalf("unexpected greeting: %q (%v)", line, err)
	}
	return &fixtureConnection{Conn: connection, reader: reader}
}

type fixtureConnection struct {
	net.Conn
	reader *bufio.Reader
}

func authenticateFixtureClient(t *testing.T, connection net.Conn) {
	t.Helper()
	writeClientLine(t, connection, "AUTHINFO USER "+fixtureUsername)
	expectClientLine(t, connection, "381 Password required")
	writeClientLine(t, connection, "AUTHINFO PASS "+fixturePassword)
	expectClientLine(t, connection, "281 Authentication accepted")
}

func writeClientLine(t *testing.T, connection net.Conn, line string) {
	t.Helper()
	if _, err := fmt.Fprint(connection, line+"\r\n"); err != nil {
		t.Fatalf("write client line: %v", err)
	}
}

func expectClientLine(t *testing.T, connection net.Conn, expected string) {
	t.Helper()
	fixture, ok := connection.(*fixtureConnection)
	if !ok {
		t.Fatal("fixture connection reader is missing")
	}
	line, err := fixture.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read client line: %v", err)
	}
	if actual := strings.TrimRight(line, "\r\n"); actual != expected {
		t.Fatalf("unexpected response: got %q want %q", actual, expected)
	}
}

func closeFixtureClient(t *testing.T, connection net.Conn) {
	t.Helper()
	writeClientLine(t, connection, "QUIT")
	expectClientLine(t, connection, "205 Goodbye")
	if err := connection.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
}
