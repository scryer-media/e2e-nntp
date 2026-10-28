package nntp

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
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
	writeClientLine(t, client, "HEAD <fixture-article@example.test>")
	expectClientLine(t, client, "221 0 <fixture-article@example.test>")
	expectClientLine(t, client, "Message-ID: <fixture-article@example.test>")
	expectClientLine(t, client, "Subject: fixture")
	expectClientLine(t, client, ".")
	writeClientLine(t, client, "HEAD <missing-article@example.test>")
	expectClientLine(t, client, "430 No such article")
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

func TestHeadSynthesizesMessageIDForBodyOnlyArticles(t *testing.T) {
	directory := t.TempDir()
	server := startFixtureServer(t, Config{DataDir: directory, ListenAddr: "127.0.0.1:0", Credentials: Credentials{Username: fixtureUsername, Password: fixturePassword}})
	client := dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, client)
	writeClientLine(t, client, "POST")
	expectClientLine(t, client, "340 Send article, end with .")
	for _, line := range []string{
		"Message-ID: <body-only@example.test>",
		"",
		"=ybegin line=128 size=3 name=file.bin",
		"abc",
		"=yend size=3",
		".",
	} {
		writeClientLine(t, client, line)
	}
	expectClientLine(t, client, "240 Article received")

	writeClientLine(t, client, "HEAD <body-only@example.test>")
	expectClientLine(t, client, "221 0 <body-only@example.test>")
	expectClientLine(t, client, "Message-ID: <body-only@example.test>")
	expectClientLine(t, client, ".")
	closeFixtureClient(t, client)

	if got := string(articleHeaders("bare@example.test", []byte("=ybegin line=128 size=3 name=file.bin\r\nabc\r\n=yend size=3"))); got != "Message-ID: <bare@example.test>" {
		t.Fatalf("articleHeaders on a bare yEnc body = %q", got)
	}
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

func TestOverlongLineClosesSessionBeforeAuthentication(t *testing.T) {
	server := startFixtureServer(t, Config{DataDir: t.TempDir(), ListenAddr: "127.0.0.1:0", Credentials: Credentials{Username: fixtureUsername, Password: fixturePassword}})
	client := dialFixtureClient(t, server.PlaintextAddr())
	// An unauthenticated client streams a command line larger than the
	// session read buffer. The server must answer once and drop the session
	// instead of buffering the line indefinitely.
	oversized := "AUTHINFO USER " + strings.Repeat("x", 2*64*1024)
	if _, err := fmt.Fprint(client, oversized); err != nil {
		t.Fatalf("write oversized line: %v", err)
	}
	expectClientLine(t, client, "501 Line too long")
	fixture := client.(*fixtureConnection)
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if line, err := fixture.reader.ReadString('\n'); err == nil {
		t.Fatalf("session stayed open after an over-long line and answered %q", strings.TrimSpace(line))
	}
	_ = client.Close()

	// A well-formed session on the same server is unaffected.
	client = dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, client)
	closeFixtureClient(t, client)
}

func TestOverlongPostedLineDoesNotDesynchronizeCommands(t *testing.T) {
	server := startFixtureServer(t, Config{DataDir: t.TempDir(), ListenAddr: "127.0.0.1:0", Credentials: Credentials{Username: fixtureUsername, Password: fixturePassword}})
	client := dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, client)
	writeClientLine(t, client, "POST")
	expectClientLine(t, client, "340 Send article, end with .")
	writeClientLine(t, client, "Message-ID: <oversized@example.test>")
	writeClientLine(t, client, "")
	// The tail of the over-long body line spells a command. If the server kept
	// the session and resumed reading mid-line, that tail would execute.
	if _, err := fmt.Fprint(client, strings.Repeat("y", 2*64*1024)+"\r\nQUIT\r\n"); err != nil {
		t.Fatalf("write oversized article line: %v", err)
	}
	expectClientLine(t, client, "441 Posting failed")
	fixture := client.(*fixtureConnection)
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if line, err := fixture.reader.ReadString('\n'); err == nil {
		t.Fatalf("server kept reading after an over-long article line and answered %q", strings.TrimSpace(line))
	}
	_ = client.Close()
	if server.store.count() != 0 {
		t.Fatalf("over-long article was stored: %d articles", server.store.count())
	}
	entries, err := os.ReadDir(server.config.DataDir)
	if err != nil {
		t.Fatalf("read data directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".incoming-") {
			t.Fatalf("temporary article %s was left behind", entry.Name())
		}
	}
}

func TestCredentialsMatchRequiresBothFields(t *testing.T) {
	credentials := Credentials{Username: fixtureUsername, Password: fixturePassword}
	if !credentials.matches(fixtureUsername, fixturePassword) {
		t.Fatal("exact credentials were rejected")
	}
	for _, attempt := range [][2]string{
		{fixtureUsername, "wrong"},
		{"wrong", fixturePassword},
		{"", ""},
		{fixtureUsername + "x", fixturePassword},
		{fixtureUsername, fixturePassword + "x"},
	} {
		if credentials.matches(attempt[0], attempt[1]) {
			t.Fatalf("credentials %q/%q were accepted", attempt[0], attempt[1])
		}
	}
}

func TestHoldBodyBlocksPastItsBudgetUntilTheHoldIsLifted(t *testing.T) {
	if _, err := ParseChaos("hold_body=-1"); err == nil {
		t.Fatal("a negative hold_body was accepted")
	}
	server := startFixtureServer(t, Config{DataDir: t.TempDir(), ListenAddr: "127.0.0.1:0", Credentials: Credentials{Username: fixtureUsername, Password: fixturePassword}, EnableTestControl: true})
	client := dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, client)
	for _, messageID := range []string{"held-first@example.test", "held-second@example.test"} {
		writeClientLine(t, client, "POST")
		expectClientLine(t, client, "340 Send article, end with .")
		for _, line := range []string{"Message-ID: <" + messageID + ">", "", "one", "two", "three", "."} {
			writeClientLine(t, client, line)
		}
		expectClientLine(t, client, "240 Article received")
	}
	control := dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, control)
	writeClientLine(t, control, "CHAOS hold_body=4")
	expectClientLine(t, control, "290 Chaos mode updated")

	// The budget spans bodies: the first article's three lines fit in it and
	// the body completes, the second article gets the fourth line and then
	// blocks before its next one.
	writeClientLine(t, client, "BODY <held-first@example.test>")
	for _, expected := range []string{"222 0 <held-first@example.test>", "one", "two", "three", "."} {
		expectClientLine(t, client, expected)
	}
	writeClientLine(t, client, "BODY <held-second@example.test>")
	expectClientLine(t, client, "222 0 <held-second@example.test>")
	expectClientLine(t, client, "one")
	expectBodyTransfers(t, server, 1)

	// A configuration that keeps a hold does not release the held body.
	writeClientLine(t, control, "CHAOS hold_body=1")
	expectClientLine(t, control, "290 Chaos mode updated")
	expectBodyTransfers(t, server, 1)

	// One without a hold releases it, and the body finishes normally.
	writeClientLine(t, control, "CHAOS off")
	expectClientLine(t, control, "290 Chaos mode updated")
	for _, expected := range []string{"two", "three", "."} {
		expectClientLine(t, client, expected)
	}
	expectBodyTransfers(t, server, 2)
	closeFixtureClient(t, client)
	closeFixtureClient(t, control)
}

func TestHeldBodyServesTheBytesAnUnheldBodyServes(t *testing.T) {
	server := startFixtureServer(t, Config{DataDir: t.TempDir(), ListenAddr: "127.0.0.1:0", Credentials: Credentials{Username: fixtureUsername, Password: fixturePassword}, EnableTestControl: true})
	client := dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, client)
	control := dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, control)
	articles := map[string][]string{
		"stuffed@example.test": {"..leading dot", "plain", "", "=yend size=3"},
		"empty@example.test":   {},
	}
	for messageID, body := range articles {
		writeClientLine(t, client, "POST")
		expectClientLine(t, client, "340 Send article, end with .")
		for _, line := range append([]string{"Message-ID: <" + messageID + ">", ""}, body...) {
			writeClientLine(t, client, line)
		}
		writeClientLine(t, client, ".")
		expectClientLine(t, client, "240 Article received")
	}
	transfers := int64(0)
	for _, messageID := range []string{"stuffed@example.test", "empty@example.test"} {
		writeClientLine(t, client, "BODY <"+messageID+">")
		unheld := readClientBody(t, client)
		transfers++
		expectBodyTransfers(t, server, transfers)

		// A release with no body blocked leaves nothing armed, and the next
		// hold arms afresh: the held fetch below blocks on the new hold.
		writeClientLine(t, control, "CHAOS hold_body=2")
		expectClientLine(t, control, "290 Chaos mode updated")
		writeClientLine(t, control, "CHAOS off")
		expectClientLine(t, control, "290 Chaos mode updated")
		writeClientLine(t, control, "CHAOS hold_body=1")
		expectClientLine(t, control, "290 Chaos mode updated")
		writeClientLine(t, client, "BODY <"+messageID+">")
		var held []string
		if len(unheld) > 2 {
			// The status line and one body line fit the budget; the rest of
			// the body waits for the release.
			held = append(held, readClientLine(t, client), readClientLine(t, client))
			expectBodyTransfers(t, server, transfers)
			writeClientLine(t, control, "CHAOS off")
			expectClientLine(t, control, "290 Chaos mode updated")
		} else {
			// An empty body has no line to hold, so it completes at once.
			writeClientLine(t, control, "CHAOS off")
			expectClientLine(t, control, "290 Chaos mode updated")
		}
		held = append(held, readClientBody(t, client)...)
		transfers++
		expectBodyTransfers(t, server, transfers)
		if strings.Join(held, "\n") != strings.Join(unheld, "\n") {
			t.Fatalf("held body %q differs from unheld body %q", held, unheld)
		}
	}
	closeFixtureClient(t, client)
	closeFixtureClient(t, control)
}

func TestParseHoldIDs(t *testing.T) {
	config, err := ParseChaos("hold_ids=<first@example.test>;second@example.test, slow_body=1")
	if err != nil {
		t.Fatalf("parse hold_ids: %v", err)
	}
	if strings.Join(config.HoldMessageIDs, ";") != "first@example.test;second@example.test" || config.SlowBodyMilliseconds != 1 {
		t.Fatalf("parsed %+v", config)
	}
	for _, messageID := range []string{"<first@example.test>", "first@example.test", "second@example.test"} {
		if !config.holdsMessageID(messageID) {
			t.Fatalf("%s is not held", messageID)
		}
	}
	if config.holdsMessageID("third@example.test") {
		t.Fatal("an unnamed article is held")
	}
	for _, value := range []string{"hold_ids=", "hold_ids=<>", "hold_ids=a@example.test;;b@example.test", "hold_ids=a@example.test;"} {
		if _, err := ParseChaos(value); err == nil {
			t.Fatalf("%q was accepted", value)
		}
	}
	if err := (ChaosConfig{HoldMessageIDs: []string{" "}}).Validate(); err == nil {
		t.Fatal("a blank held ID was accepted")
	}
}

func TestHoldIDsHoldOnlyTheNamedBodyUntilAConfigDropsIt(t *testing.T) {
	server := startFixtureServer(t, Config{DataDir: t.TempDir(), ListenAddr: "127.0.0.1:0", Credentials: Credentials{Username: fixtureUsername, Password: fixturePassword}, EnableTestControl: true})
	held := dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, held)
	postFixtureArticles(t, held, "named@example.test", "other@example.test")
	free := dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, free)
	control := dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, control)
	writeClientLine(t, control, "CHAOS hold_ids=<named@example.test>")
	expectClientLine(t, control, "290 Chaos mode updated")

	writeClientLine(t, held, "BODY <named@example.test>")
	expectClientLine(t, held, "222 0 <named@example.test>")
	// STAT and HEAD for the held article, and another article's BODY, are
	// served meanwhile on another connection.
	writeClientLine(t, free, "STAT <named@example.test>")
	expectClientLine(t, free, "223 0 <named@example.test>")
	writeClientLine(t, free, "HEAD <named@example.test>")
	readClientBody(t, free)
	writeClientLine(t, free, "BODY <other@example.test>")
	for _, expected := range []string{"222 0 <other@example.test>", "one", "two", "."} {
		expectClientLine(t, free, expected)
	}
	expectBodyTransfers(t, server, 1)

	// A configuration that still names the ID keeps the body held.
	writeClientLine(t, control, "CHAOS hold_ids=named@example.test;other@example.test,slow_body=0")
	expectClientLine(t, control, "290 Chaos mode updated")
	expectBodyTransfers(t, server, 1)

	// One that does not name it releases the body, which finishes normally.
	writeClientLine(t, control, "CHAOS hold_ids=other@example.test")
	expectClientLine(t, control, "290 Chaos mode updated")
	for _, expected := range []string{"one", "two", "."} {
		expectClientLine(t, held, expected)
	}
	expectBodyTransfers(t, server, 2)
	closeFixtureClient(t, held)
	closeFixtureClient(t, free)
	closeFixtureClient(t, control)
}

func TestChaosOffReleasesAHeldID(t *testing.T) {
	server := startFixtureServer(t, Config{DataDir: t.TempDir(), ListenAddr: "127.0.0.1:0", Credentials: Credentials{Username: fixtureUsername, Password: fixturePassword}, EnableTestControl: true})
	client := dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, client)
	postFixtureArticles(t, client, "named@example.test")
	control := dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, control)
	writeClientLine(t, control, "CHAOS hold_ids=named@example.test")
	expectClientLine(t, control, "290 Chaos mode updated")
	writeClientLine(t, client, "BODY named@example.test")
	expectClientLine(t, client, "222 0 <named@example.test>")
	expectBodyTransfers(t, server, 0)
	writeClientLine(t, control, "CHAOS off")
	expectClientLine(t, control, "290 Chaos mode updated")
	for _, expected := range []string{"one", "two", "."} {
		expectClientLine(t, client, expected)
	}
	expectBodyTransfers(t, server, 1)
	closeFixtureClient(t, client)
	closeFixtureClient(t, control)
}

// postFixtureArticles posts one two-line article per message ID.
func postFixtureArticles(t *testing.T, connection net.Conn, messageIDs ...string) {
	t.Helper()
	for _, messageID := range messageIDs {
		writeClientLine(t, connection, "POST")
		expectClientLine(t, connection, "340 Send article, end with .")
		for _, line := range []string{"Message-ID: <" + messageID + ">", "", "one", "two", "."} {
			writeClientLine(t, connection, line)
		}
		expectClientLine(t, connection, "240 Article received")
	}
}

func TestCloseReturnsWhileABodyIsHeld(t *testing.T) {
	server := startFixtureServer(t, Config{DataDir: t.TempDir(), ListenAddr: "127.0.0.1:0", Credentials: Credentials{Username: fixtureUsername, Password: fixturePassword}, EnableTestControl: true})
	client := dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, client)
	writeClientLine(t, client, "POST")
	expectClientLine(t, client, "340 Send article, end with .")
	for _, line := range []string{"Message-ID: <closed@example.test>", "", "one", "two", "."} {
		writeClientLine(t, client, line)
	}
	expectClientLine(t, client, "240 Article received")
	writeClientLine(t, client, "CHAOS hold_body=1")
	expectClientLine(t, client, "290 Chaos mode updated")
	writeClientLine(t, client, "BODY <closed@example.test>")
	expectClientLine(t, client, "222 0 <closed@example.test>")
	expectClientLine(t, client, "one")
	// Close waits for every session goroutine, so it returns only if the held
	// body gives up its wait when the server closes.
	if err := server.Close(); err != nil {
		t.Fatalf("close server: %v", err)
	}
	expectBodyTransfers(t, server, 0)
}

func TestDropMidBodyClosesTheConnection(t *testing.T) {
	server := startFixtureServer(t, Config{DataDir: t.TempDir(), ListenAddr: "127.0.0.1:0", Credentials: Credentials{Username: fixtureUsername, Password: fixturePassword}, EnableTestControl: true})
	client := dialFixtureClient(t, server.PlaintextAddr())
	authenticateFixtureClient(t, client)
	writeClientLine(t, client, "POST")
	expectClientLine(t, client, "340 Send article, end with .")
	for _, line := range []string{"Message-ID: <dropped@example.test>", "", "one", "two", "."} {
		writeClientLine(t, client, line)
	}
	expectClientLine(t, client, "240 Article received")
	writeClientLine(t, client, "CHAOS drop_mid_body=100")
	expectClientLine(t, client, "290 Chaos mode updated")
	writeClientLine(t, client, "BODY <dropped@example.test>")
	expectClientLine(t, client, "222 0 <dropped@example.test>")
	expectClientLine(t, client, "one")
	// A real server that drops a body mid-transfer loses the connection: the
	// client reads EOF where the rest of the body and its terminator would be,
	// and the session answers nothing further.
	fixture := client.(*fixtureConnection)
	if line, err := fixture.reader.ReadString('\n'); !errors.Is(err, io.EOF) || line != "" {
		t.Fatalf("after a mid-body drop the client read %q (%v), want EOF", line, err)
	}
	_ = client.Close()
	expectBodyTransfers(t, server, 0)
}

// readClientBody reads response lines up to and including the terminator.
func readClientBody(t *testing.T, connection net.Conn) []string {
	t.Helper()
	var lines []string
	for {
		line := readClientLine(t, connection)
		lines = append(lines, line)
		if line == "." {
			return lines
		}
	}
}

func readClientLine(t *testing.T, connection net.Conn) string {
	t.Helper()
	fixture, ok := connection.(*fixtureConnection)
	if !ok {
		t.Fatal("fixture connection reader is missing")
	}
	line, err := fixture.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read client line: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// expectBodyTransfers reads the completed-body counter the server increments
// only after a body's terminator. A body blocked on the hold cannot move it,
// so the counter proves a body has not completed without waiting on a clock.
func expectBodyTransfers(t *testing.T, server *Server, expected int64) {
	t.Helper()
	metrics, err := server.Metrics()
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	if metrics.BodyTransfers != expected {
		t.Fatalf("completed bodies = %d, want %d", metrics.BodyTransfers, expected)
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
