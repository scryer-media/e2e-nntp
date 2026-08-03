package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/scryer-media/e2e-nntp"
)

var version = "devel"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(version)
		return
	}
	if len(os.Args) < 2 {
		serve(os.Args[1:])
		return
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "health":
		health(os.Args[2:])
	case "image":
		if len(os.Args) < 3 || os.Args[2] != "build" {
			fatal(errors.New("usage: e2e-nntp image build [flags]"))
		}
		buildImage(os.Args[3:])
	case "--help", "help":
		printUsage()
	default:
		fatal(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}

func printUsage() {
	fmt.Fprint(os.Stdout, `e2e-nntp is a synthetic NNTP server for tests.

Usage:
  e2e-nntp serve [flags]
  e2e-nntp health [flags]
  e2e-nntp image build --version vX.Y.Z [flags]

Use e2e-nntp serve --help, e2e-nntp health --help, or e2e-nntp image build --help for details.
`)
}

func serve(arguments []string) {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	listenAddress := flags.String("listen", stringEnvironment("NNTP_LISTEN_ADDR", "127.0.0.1:119"), "plaintext listen address")
	tlsListenAddress := flags.String("tls-listen", os.Getenv("NNTP_TLS_LISTEN_ADDR"), "implicit TLS listen address")
	dataDirectory := flags.String("data-dir", stringEnvironment("NNTP_DATA_DIR", "./data"), "article data directory")
	username := flags.String("username", os.Getenv("NNTP_USERNAME"), "required NNTP username")
	passwordFile := flags.String("password-file", os.Getenv("NNTP_PASSWORD_FILE"), "required file containing the NNTP password")
	pipelining := flags.Bool("pipelining", boolEnvironment("NNTP_PIPELINING", false), "advertise the PIPELINING capability")
	enableTestControl := flags.Bool("enable-test-control", boolEnvironment("NNTP_ENABLE_TEST_CONTROL", false), "enable authenticated synthetic test-control commands")
	chaosValue := flags.String("chaos", os.Getenv("NNTP_CHAOS"), "initial synthetic chaos configuration")
	chaosSeed := flags.Int64("chaos-seed", int64Environment("NNTP_CHAOS_SEED", 1), "deterministic synthetic chaos seed")
	tlsCertificate := flags.String("tls-cert", os.Getenv("NNTP_TLS_CERT_FILE"), "TLS certificate file")
	tlsKey := flags.String("tls-key", os.Getenv("NNTP_TLS_KEY_FILE"), "TLS private key file")
	generateTestTLS := flags.Bool("generate-test-tls", boolEnvironment("NNTP_GENERATE_TEST_TLS", false), "generate reusable synthetic TLS material")
	tlsDirectory := flags.String("tls-dir", os.Getenv("NNTP_TLS_DIR"), "directory for generated synthetic TLS material")
	var tlsDNSNames stringList
	var tlsIPAddresses stringList
	flags.Var(&tlsDNSNames, "tls-dns-name", "DNS name for generated synthetic TLS certificate (repeatable)")
	flags.Var(&tlsIPAddresses, "tls-ip-address", "IP address for generated synthetic TLS certificate (repeatable)")
	if err := flags.Parse(arguments); err != nil {
		fatal(err)
	}
	if *passwordFile == "" {
		fatal(errors.New("--password-file or NNTP_PASSWORD_FILE is required"))
	}
	password, err := readPasswordFile(*passwordFile)
	if err != nil {
		fatal(err)
	}
	chaos, err := nntp.ParseChaos(*chaosValue)
	if err != nil {
		fatal(err)
	}
	if len(tlsDNSNames) == 0 {
		tlsDNSNames = commaSeparated(os.Getenv("NNTP_TLS_DNS_NAMES"))
	}
	if len(tlsIPAddresses) == 0 {
		tlsIPAddresses = commaSeparated(os.Getenv("NNTP_TLS_IP_ADDRESSES"))
	}
	ipAddresses, err := parseIPAddresses(tlsIPAddresses)
	if err != nil {
		fatal(err)
	}
	tlsConfig := nntp.TLSConfig{ListenAddr: *tlsListenAddress, CertFile: *tlsCertificate, KeyFile: *tlsKey}
	if *generateTestTLS {
		if *tlsDirectory == "" {
			fatal(errors.New("--tls-dir or NNTP_TLS_DIR is required with --generate-test-tls"))
		}
		tlsConfig.Generated = &nntp.GeneratedTLSConfig{Directory: *tlsDirectory, DNSNames: tlsDNSNames, IPAddresses: ipAddresses}
	}
	context, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server, err := nntp.Start(context, nntp.Config{
		DataDir:           *dataDirectory,
		ListenAddr:        *listenAddress,
		TLS:               tlsConfig,
		Credentials:       nntp.Credentials{Username: *username, Password: password},
		Pipelining:        *pipelining,
		EnableTestControl: *enableTestControl,
		Chaos:             chaos,
		ChaosSeed:         *chaosSeed,
	})
	if err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "e2e-nntp plaintext listener: %s\n", server.PlaintextAddr())
	if server.TLSAddr() != "" {
		fmt.Fprintf(os.Stderr, "e2e-nntp TLS listener: %s\n", server.TLSAddr())
	}
	<-context.Done()
	if err := server.Close(); err != nil {
		fatal(err)
	}
}

func health(arguments []string) {
	flags := flag.NewFlagSet("health", flag.ExitOnError)
	address := flags.String("addr", stringEnvironment("NNTP_HEALTH_ADDR", "127.0.0.1:119"), "NNTP listener address")
	timeout := flags.Duration("timeout", time.Second, "connection and response timeout")
	if err := flags.Parse(arguments); err != nil {
		fatal(err)
	}
	if err := checkNNTP(*address, *timeout); err != nil {
		fatal(err)
	}
}

func checkNNTP(address string, timeout time.Duration) error {
	connection, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", address, err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	reader := bufio.NewReader(connection)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(greeting), "200") {
		return fmt.Errorf("unexpected greeting %q", strings.TrimSpace(greeting))
	}
	if _, err := fmt.Fprint(connection, "QUIT\r\n"); err != nil {
		return fmt.Errorf("write QUIT: %w", err)
	}
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read QUIT response: %w", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(response), "205") {
		return fmt.Errorf("unexpected QUIT response %q", strings.TrimSpace(response))
	}
	return nil
}

func readPasswordFile(path string) (string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read password file: %w", err)
	}
	password := strings.TrimRight(string(contents), "\r\n")
	if password == "" {
		return "", errors.New("password file is empty")
	}
	return password, nil
}

func parseIPAddresses(values []string) ([]net.IP, error) {
	addresses := make([]net.IP, 0, len(values))
	for _, value := range values {
		address := net.ParseIP(value)
		if address == nil {
			return nil, fmt.Errorf("invalid TLS IP address %q", value)
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

type stringList []string

func (values *stringList) String() string {
	return strings.Join(*values, ",")
}

func (values *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("value must not be empty")
	}
	*values = append(*values, value)
	return nil
}

func commaSeparated(value string) stringList {
	var values stringList
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			values = append(values, item)
		}
	}
	return values
}

func stringEnvironment(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func boolEnvironment(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		fatal(fmt.Errorf("parse %s: %w", key, err))
	}
	return parsed
}

func int64Environment(key string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		fatal(fmt.Errorf("parse %s: %w", key, err))
	}
	return parsed
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "e2e-nntp:", err)
	os.Exit(1)
}

func absolutePath(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(path), nil
}
