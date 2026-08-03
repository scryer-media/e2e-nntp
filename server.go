package nntp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Server is an independently configured synthetic NNTP server.
type Server struct {
	config Config
	store  *articleStore

	plaintext net.Listener
	tls       net.Listener
	caPath    string

	closeOnce sync.Once
	closed    chan struct{}
	serveWG   sync.WaitGroup
	clients   sync.Map

	activeConnections atomic.Int64
	chaosMu           sync.RWMutex
	chaos             ChaosConfig
	randomMu          sync.Mutex
	random            *rand.Rand
	metrics           metricState
}

// Start binds configured listeners and serves until Close or context
// cancellation. Empty ListenAddr defaults to a loopback-only listener.
func Start(ctx context.Context, config Config) (*Server, error) {
	config, err := config.normalized()
	if err != nil {
		return nil, err
	}
	store, err := openArticleStore(config.DataDir)
	if err != nil {
		return nil, err
	}
	plaintext, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen for plaintext NNTP: %w", err)
	}
	server := &Server{
		config:    config,
		store:     store,
		plaintext: plaintext,
		closed:    make(chan struct{}),
		chaos:     config.Chaos,
		random:    rand.New(rand.NewSource(config.ChaosSeed)),
	}
	server.metrics.reset(0)
	if config.TLS.ListenAddr != "" {
		tlsConfig, caPath, tlsErr := config.TLS.load()
		if tlsErr != nil {
			_ = plaintext.Close()
			return nil, tlsErr
		}
		listener, listenErr := tls.Listen("tcp", config.TLS.ListenAddr, tlsConfig)
		if listenErr != nil {
			_ = plaintext.Close()
			return nil, fmt.Errorf("listen for TLS NNTP: %w", listenErr)
		}
		server.tls = listener
		server.caPath = caPath
	}
	server.serveWG.Add(1)
	go server.acceptLoop(server.plaintext)
	if server.tls != nil {
		server.serveWG.Add(1)
		go server.acceptLoop(server.tls)
	}
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-server.closed:
		}
	}()
	return server, nil
}

// PlaintextAddr returns the bound plaintext listener address.
func (server *Server) PlaintextAddr() string {
	if server.plaintext == nil {
		return ""
	}
	return server.plaintext.Addr().String()
}

// TLSAddr returns the bound implicit-TLS listener address, if enabled.
func (server *Server) TLSAddr() string {
	if server.tls == nil {
		return ""
	}
	return server.tls.Addr().String()
}

// CACertificatePath reports the generated test CA path. It is empty when
// TLS is disabled or caller-supplied certificate material is used.
func (server *Server) CACertificatePath() string {
	return server.caPath
}

// Close stops listeners and live client sessions. It is safe to call more
// than once and waits for all session goroutines to return.
func (server *Server) Close() error {
	var closeErr error
	server.closeOnce.Do(func() {
		close(server.closed)
		for _, listener := range []net.Listener{server.plaintext, server.tls} {
			if listener != nil {
				closeErr = errors.Join(closeErr, listener.Close())
			}
		}
		server.clients.Range(func(key, _ any) bool {
			if connection, ok := key.(net.Conn); ok {
				closeErr = errors.Join(closeErr, connection.Close())
			}
			return true
		})
		server.serveWG.Wait()
	})
	return closeErr
}

func (server *Server) acceptLoop(listener net.Listener) {
	defer server.serveWG.Done()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-server.closed:
				return
			case <-time.After(25 * time.Millisecond):
				continue
			}
		}
		server.serveWG.Add(1)
		go func() {
			defer server.serveWG.Done()
			server.handleConnection(connection)
		}()
	}
}

func (server *Server) handleConnection(connection net.Conn) {
	server.clients.Store(connection, struct{}{})
	defer server.clients.Delete(connection)
	defer connection.Close()

	server.metrics.attempted.Add(1)
	active := server.activeConnections.Add(1)
	defer server.activeConnections.Add(-1)
	defer func() {
		if recovered := recover(); recovered != nil {
			// A malformed synthetic input must close only this session.
			_ = recovered
		}
	}()

	writer := bufio.NewWriterSize(connection, 64*1024)
	reader := bufio.NewReaderSize(connection, 64*1024)
	chaos := server.currentChaos()
	if chaos.MaxConnections > 0 && int(active) > chaos.MaxConnections {
		server.metrics.rejected.Add(1)
		writeLine(writer, "502 Too many connections")
		return
	}
	server.metrics.accepted.Add(1)
	server.metrics.recordPeak(active)
	if server.roll(chaos.Greet400Percent) {
		writeLine(writer, "400 service temporarily unavailable")
		return
	}
	if server.roll(chaos.Greet201Percent) {
		writeLine(writer, "201 e2e-nntp ready (no posting)")
	} else {
		writeLine(writer, "200 e2e-nntp ready (posting ok)")
	}
	if server.roll(chaos.DropConnection) {
		return
	}

	authenticated := false
	pendingUser := ""
	reauthRequired := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command, argument := splitCommand(line)
		chaos = server.currentChaos()
		switch command {
		case "CAPABILITIES":
			writeLine(writer, "101 Capability list:")
			writeLine(writer, "VERSION 2")
			writeLine(writer, "AUTHINFO USER")
			writeLine(writer, "READER")
			if server.config.Pipelining {
				writeLine(writer, "PIPELINING")
			}
			writeLine(writer, "POST")
			writeLine(writer, ".")
		case "MODE":
			writeLine(writer, "200 Reader mode acknowledged")
		case "AUTHINFO":
			pendingUser, authenticated, reauthRequired = server.handleAuthentication(writer, argument, pendingUser, authenticated, reauthRequired, chaos)
		case "DATE":
			writeLine(writer, "111 "+time.Now().UTC().Format("20060102150405"))
		case "QUIT":
			writeLine(writer, "205 Goodbye")
			return
		case "GROUP":
			if !requireAuthentication(writer, authenticated) {
				continue
			}
			if strings.TrimSpace(argument) != defaultGroup {
				writeLine(writer, "411 No such group")
				continue
			}
			count := server.store.count()
			writeLine(writer, fmt.Sprintf("211 %d 1 %d %s", count, count, defaultGroup))
		case "STAT":
			if !requireAuthentication(writer, authenticated) {
				continue
			}
			messageID := stripBrackets(argument)
			server.metrics.recordStat(messageID)
			if server.roll(chaos.StatShortPercent) {
				writeRaw(writer, []byte("22\r\n"))
				continue
			}
			exists := server.store.exists(messageID)
			if server.roll(chaos.StatBadCodePercent) {
				if exists {
					writeRaw(writer, []byte("2\xff3 0 <"+messageID+">\r\n"))
				} else {
					writeRaw(writer, []byte("4\xff0 No such article\r\n"))
				}
				continue
			}
			if exists {
				writeLine(writer, "223 0 <"+messageID+">")
			} else {
				writeLine(writer, "430 No such article")
			}
		case "BODY":
			if !requireAuthentication(writer, authenticated) {
				continue
			}
			if reauthRequired {
				writeLine(writer, "480 Authentication required")
				continue
			}
			if server.roll(chaos.ReauthBodyPercent) {
				reauthRequired = true
				writeLine(writer, "480 Authentication required")
				continue
			}
			if server.roll(chaos.DropConnection) {
				return
			}
			if server.roll(chaos.TimeoutBodyPercent) {
				time.Sleep(90 * time.Second)
				return
			}
			server.handleBody(writer, stripBrackets(argument), chaos)
		case "ARTICLE":
			if !requireAuthentication(writer, authenticated) {
				continue
			}
			server.handleArticle(writer, stripBrackets(argument))
		case "POST":
			if !requireAuthentication(writer, authenticated) {
				continue
			}
			server.handlePost(reader, writer)
		case "CHAOS", "METRICS", "DELETE", "DELETEID", "RELOAD":
			if !server.config.EnableTestControl {
				writeLine(writer, "500 Unknown command")
				continue
			}
			if !requireAuthentication(writer, authenticated) {
				continue
			}
			server.handleControl(writer, command, argument)
		default:
			writeLine(writer, "500 Unknown command")
		}
	}
}

func (server *Server) handleAuthentication(writer *bufio.Writer, argument, pendingUser string, authenticated, reauthRequired bool, chaos ChaosConfig) (string, bool, bool) {
	fields := strings.Fields(argument)
	if len(fields) < 2 {
		writeLine(writer, "501 Usage: AUTHINFO USER <username> | AUTHINFO PASS <password>")
		return pendingUser, authenticated, reauthRequired
	}
	subcommand := strings.ToUpper(fields[0])
	value := strings.Join(fields[1:], " ")
	switch subcommand {
	case "USER":
		writeLine(writer, "381 Password required")
		return value, authenticated, reauthRequired
	case "PASS":
		if pendingUser == "" {
			writeLine(writer, "482 Authentication commands issued out of sequence")
			return pendingUser, authenticated, reauthRequired
		}
		if server.roll(chaos.RejectAuthPercent) || pendingUser != server.config.Credentials.Username || value != server.config.Credentials.Password {
			writeLine(writer, "481 Authentication failed")
			return "", false, true
		}
		writeLine(writer, "281 Authentication accepted")
		return "", true, false
	default:
		writeLine(writer, "501 Unknown AUTHINFO command")
		return pendingUser, authenticated, reauthRequired
	}
}

func (server *Server) handleBody(writer *bufio.Writer, messageID string, chaos ChaosConfig) {
	article, exists := server.store.load(messageID)
	if !exists {
		writeLine(writer, "430 No such article")
		return
	}
	body := articleBody(article)
	if server.roll(chaos.CorruptBodyPercent) {
		body = corrupt(body, server)
	}
	writeLine(writer, "222 0 <"+messageID+">")
	if chaos.SlowBodyMilliseconds == 0 && chaos.DropMidBodyPercent == 0 && chaos.BadTermPercent == 0 && chaos.SplitTermPercent == 0 {
		writeDotStuffed(writer, body, true)
		server.metrics.recordBody(messageID, len(body))
		return
	}
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	for _, line := range lines {
		if chaos.SlowBodyMilliseconds > 0 {
			time.Sleep(time.Duration(chaos.SlowBodyMilliseconds) * time.Millisecond)
		}
		writeLine(writer, dotStuff(line))
		if server.roll(chaos.DropMidBodyPercent) {
			return
		}
	}
	if server.roll(chaos.BadTermPercent) {
		writeRaw(writer, []byte(".\r"))
		return
	}
	if server.roll(chaos.SplitTermPercent) {
		writeRaw(writer, []byte("."))
		time.Sleep(10 * time.Millisecond)
		writeRaw(writer, []byte("\r\n"))
	} else {
		writeLine(writer, ".")
	}
	server.metrics.recordBody(messageID, len(body))
}

func (server *Server) handleArticle(writer *bufio.Writer, messageID string) {
	article, exists := server.store.load(messageID)
	if !exists {
		writeLine(writer, "430 No such article")
		return
	}
	writeLine(writer, "220 0 <"+messageID+">")
	writeDotStuffed(writer, article, true)
}

func (server *Server) handlePost(reader *bufio.Reader, writer *bufio.Writer) {
	writeLine(writer, "340 Send article, end with .")
	messageID, temporaryPath, _, err := readPostedArticle(reader, server.config.DataDir)
	if err != nil {
		writeLine(writer, "441 Posting failed")
		return
	}
	if err := server.store.commit(messageID, temporaryPath); err != nil {
		_ = os.Remove(temporaryPath)
		if errors.Is(err, os.ErrExist) {
			writeLine(writer, "441 Duplicate article")
			return
		}
		writeLine(writer, "441 Storage error")
		return
	}
	writeLine(writer, "240 Article received")
}

func (server *Server) handleControl(writer *bufio.Writer, command, argument string) {
	switch command {
	case "CHAOS":
		config, err := ParseChaos(argument)
		if err != nil || server.SetChaos(config) != nil {
			writeLine(writer, "501 Invalid chaos configuration")
			return
		}
		writeLine(writer, "290 Chaos mode updated")
	case "METRICS":
		server.handleMetrics(writer, argument)
	case "DELETE":
		fields := strings.Fields(argument)
		if len(fields) == 0 || len(fields) > 2 {
			writeLine(writer, "501 Usage: DELETE <prefix> [percentage]")
			return
		}
		percentage := 100
		if len(fields) == 2 {
			if _, err := fmt.Sscan(fields[1], &percentage); err != nil {
				writeLine(writer, "501 Invalid percentage")
				return
			}
		}
		matched, deleted, err := server.DeleteByPrefix(fields[0], percentage)
		if err != nil {
			writeLine(writer, "501 Invalid percentage")
			return
		}
		writeLine(writer, fmt.Sprintf("290 Deleted %d of %d matching articles", deleted, matched))
	case "DELETEID":
		messageID := stripBrackets(argument)
		if messageID == "" {
			writeLine(writer, "501 Usage: DELETEID <message-id>")
			return
		}
		deleted, err := server.DeleteID(messageID)
		if err != nil {
			writeLine(writer, "500 Delete failed")
			return
		}
		if deleted {
			writeLine(writer, "290 Article deleted")
		} else {
			writeLine(writer, "290 Article already absent")
		}
	case "RELOAD":
		count, err := server.Reload()
		if err != nil {
			writeLine(writer, "500 Reload failed")
			return
		}
		writeLine(writer, fmt.Sprintf("290 Reloaded %d articles", count))
	}
}

func (server *Server) handleMetrics(writer *bufio.Writer, argument string) {
	fields := strings.Fields(argument)
	if len(fields) == 0 || len(fields) > 2 {
		writeLine(writer, "501 Usage: METRICS BODY [prefix] | METRICS STAT [prefix] | METRICS CONNECTIONS | METRICS RESET")
		return
	}
	switch strings.ToUpper(fields[0]) {
	case "RESET":
		if len(fields) != 1 {
			writeLine(writer, "501 Usage: METRICS RESET")
			return
		}
		_ = server.ResetMetrics()
		writeLine(writer, "290 Metrics reset")
	case "BODY", "STAT", "CONNECTIONS":
		metrics, _ := server.Metrics()
		prefix := ""
		if len(fields) == 2 {
			prefix = fields[1]
		}
		var payload any
		switch strings.ToUpper(fields[0]) {
		case "BODY":
			payload = map[string]any{"body_counts": filterCounts(metrics.BodyCounts, prefix), "body_bytes": metrics.BodyBytes, "body_transfers": metrics.BodyTransfers}
		case "STAT":
			payload = map[string]any{"stat_counts": filterCounts(metrics.StatCounts, prefix)}
		case "CONNECTIONS":
			payload = map[string]any{"attempted": metrics.ConnectionAttempts, "accepted": metrics.ConnectionAccepted, "rejected": metrics.ConnectionRejected, "active": metrics.ActiveConnections, "peak_active": metrics.PeakConnections}
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			writeLine(writer, "500 Metrics encoding failed")
			return
		}
		writeLine(writer, "290 "+string(encoded))
	default:
		writeLine(writer, "501 Usage: METRICS BODY [prefix] | METRICS STAT [prefix] | METRICS CONNECTIONS | METRICS RESET")
	}
}

func filterCounts(counts map[string]int, prefix string) map[string]int {
	filtered := make(map[string]int)
	for messageID, count := range counts {
		if prefix == "" || strings.HasPrefix(messageID, prefix) {
			filtered[messageID] = count
		}
	}
	return filtered
}

func (server *Server) currentChaos() ChaosConfig {
	server.chaosMu.RLock()
	defer server.chaosMu.RUnlock()
	return server.chaos
}

func (server *Server) roll(percent int) bool {
	if percent <= 0 {
		return false
	}
	if percent >= 100 {
		return true
	}
	server.randomMu.Lock()
	defer server.randomMu.Unlock()
	return server.random.Intn(100) < percent
}

func splitCommand(line string) (string, string) {
	line = strings.TrimRight(line, "\r\n")
	command, argument, found := strings.Cut(line, " ")
	if !found {
		return strings.ToUpper(command), ""
	}
	return strings.ToUpper(command), strings.TrimSpace(argument)
}

func requireAuthentication(writer *bufio.Writer, authenticated bool) bool {
	if authenticated {
		return true
	}
	writeLine(writer, "480 Authentication required")
	return false
}

func writeLine(writer *bufio.Writer, line string) {
	_, _ = writer.WriteString(line + "\r\n")
	_ = writer.Flush()
}

func writeRaw(writer *bufio.Writer, contents []byte) {
	_, _ = writer.Write(contents)
	_ = writer.Flush()
}

func writeDotStuffed(writer *bufio.Writer, contents []byte, terminator bool) {
	lines := bytes.Split(contents, []byte("\n"))
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	for _, line := range lines {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if bytes.HasPrefix(line, []byte(".")) {
			_ = writer.WriteByte('.')
		}
		_, _ = writer.Write(line)
		_, _ = writer.WriteString("\r\n")
	}
	if terminator {
		_, _ = writer.WriteString(".\r\n")
	}
	_ = writer.Flush()
}

func dotStuff(line string) string {
	if strings.HasPrefix(line, ".") {
		return "." + line
	}
	return line
}

func corrupt(contents []byte, server *Server) []byte {
	if len(contents) < 2 {
		return contents
	}
	copyOfContents := append([]byte(nil), contents...)
	server.randomMu.Lock()
	position := server.random.Intn(len(copyOfContents))
	server.randomMu.Unlock()
	copyOfContents[position] ^= 0xff
	return copyOfContents
}
