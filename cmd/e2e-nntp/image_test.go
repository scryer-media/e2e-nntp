package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParsePlatform(t *testing.T) {
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		operatingSystem, architecture, err := parsePlatform(platform)
		if err != nil || operatingSystem != "linux" || architecture == "" {
			t.Fatalf("parse %q: operatingSystem=%q architecture=%q err=%v", platform, operatingSystem, architecture, err)
		}
	}
	if _, _, err := parsePlatform("darwin/arm64"); err == nil {
		t.Fatal("non-Linux platform must be rejected")
	}
}

func TestValidModuleVersion(t *testing.T) {
	for _, version := range []string{"v0.1.0", "v12.34.56"} {
		if !validModuleVersion(version) {
			t.Fatalf("expected valid version %q", version)
		}
	}
	for _, version := range []string{"", "latest", "v0.1", "v0.1.0/source", "v0.1.0 next"} {
		if validModuleVersion(version) {
			t.Fatalf("expected invalid version %q", version)
		}
	}
}

func TestImageBuildRejectsAmbiguousOrUnpinnedSourcesBeforeDocker(t *testing.T) {
	if _, err := buildLocalImage(imageBuildOptions{Version: "v0.1.0", SourceDirectory: ".", Tag: "fixture:local", Platform: "linux/amd64"}); err == nil {
		t.Fatal("ambiguous source selection must fail")
	}
	if _, err := buildLocalImage(imageBuildOptions{Tag: "fixture:local", Platform: "linux/amd64"}); err == nil {
		t.Fatal("unpinned module source must fail")
	}
}

func TestImageResultRedactsLocalSourceDirectory(t *testing.T) {
	if got := imageSourceKind("any-local-directory"); got != "source-directory" {
		t.Fatalf("unexpected source kind %q", got)
	}
	if got := imageSourceKind(""); got != "module-version" {
		t.Fatalf("unexpected module source kind %q", got)
	}
}

func TestCheckNNTP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = fmt.Fprint(connection, "200 ready\r\n")
		reader := bufio.NewReader(connection)
		_, _ = reader.ReadString('\n')
		_, _ = fmt.Fprint(connection, "205 goodbye\r\n")
	}()
	if err := checkNNTP(listener.Addr().String(), time.Second); err != nil {
		t.Fatalf("health check: %v", err)
	}
	<-done
}

func TestLocalImageServesNNTP(t *testing.T) {
	if os.Getenv("NNTP_DOCKER_INTEGRATION") != "1" {
		t.Skip("set NNTP_DOCKER_INTEGRATION=1 to exercise Docker")
	}
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate integration-test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	temporary := t.TempDir()
	passwordPath := filepath.Join(temporary, "password")
	if err := os.WriteFile(passwordPath, []byte("fixture-password\n"), 0o600); err != nil {
		t.Fatalf("write password fixture: %v", err)
	}
	tag := fmt.Sprintf("e2e-nntp:integration-%d", time.Now().UnixNano())
	result, err := buildLocalImage(imageBuildOptions{SourceDirectory: root, Tag: tag, Platform: defaultPlatform()})
	if err != nil {
		t.Fatalf("build local image: %v", err)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "image", "rm", result.Tag).Run()
	})
	container := fmt.Sprintf("e2e-nntp-integration-%d", time.Now().UnixNano())
	output, err := exec.Command(
		"docker", "run", "--rm", "-d", "--name", container,
		"-p", "127.0.0.1::119",
		"-v", passwordPath+":/run/nntp-password:ro",
		"-v", filepath.Join(temporary, "data")+":/data",
		result.Tag,
		"serve", "--listen", "0.0.0.0:119", "--data-dir", "/data",
		"--username", "fixture-user", "--password-file", "/run/nntp-password",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("start local image: %v: %s", err, strings.TrimSpace(string(output)))
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", container).Run()
	})
	portOutput, err := exec.Command("docker", "port", container, "119/tcp").Output()
	if err != nil {
		t.Fatalf("resolve published port: %v", err)
	}
	address := strings.TrimSpace(string(portOutput))
	connection := waitForNNTP(t, address)
	defer connection.Close()
	if output, err := exec.Command("docker", "exec", container, "/e2e-nntp", "health", "--addr", "127.0.0.1:119").CombinedOutput(); err != nil {
		t.Fatalf("run image health check: %v: %s", err, strings.TrimSpace(string(output)))
	}
	reader := bufio.NewReader(connection)
	expectNNTP(t, reader, "200 e2e-nntp ready (posting ok)")
	writeNNTP(t, connection, "AUTHINFO USER fixture-user")
	expectNNTP(t, reader, "381 Password required")
	writeNNTP(t, connection, "AUTHINFO PASS fixture-password")
	expectNNTP(t, reader, "281 Authentication accepted")
	writeNNTP(t, connection, "QUIT")
	expectNNTP(t, reader, "205 Goodbye")
}

func waitForNNTP(t *testing.T, address string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
		if err == nil {
			return connection
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("local image did not accept connections at %s", address)
	return nil
}

func writeNNTP(t *testing.T, connection net.Conn, line string) {
	t.Helper()
	if _, err := fmt.Fprint(connection, line+"\r\n"); err != nil {
		t.Fatalf("write NNTP command: %v", err)
	}
}

func expectNNTP(t *testing.T, reader *bufio.Reader, expected string) {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read NNTP response: %v", err)
	}
	if actual := strings.TrimRight(line, "\r\n"); actual != expected {
		t.Fatalf("unexpected NNTP response: got %q want %q", actual, expected)
	}
}
