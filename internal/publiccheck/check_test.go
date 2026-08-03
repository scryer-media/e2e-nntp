package publiccheck

import (
	"strings"
	"testing"
)

func TestScanContentsFlagsSensitiveClassesWithoutEchoingContent(t *testing.T) {
	for _, contents := range [][]byte{
		[]byte("path " + strings.Join([]string{"/", "Users", "example", "project"}, "/")),
		[]byte("host " + strings.Join([]string{"192", "168", "1", "1"}, ".")),
		[]byte(strings.Join([]string{"-----BEGIN ", "PRIVATE", " KEY-----"}, "")),
		[]byte("post" + "gres://user:" + "password@example.invalid/db"),
	} {
		findings := scanContents("fixture.txt", contents)
		if len(findings) == 0 {
			t.Fatalf("expected a finding for sensitive fixture")
		}
		for _, finding := range findings {
			if finding.Path != "fixture.txt" || finding.Rule == "" {
				t.Fatalf("finding must be safe and attributable: %#v", finding)
			}
		}
	}
}

func TestScanContentsAllowsDocumentedPublicEndpoints(t *testing.T) {
	contents := []byte("https://github.com/scryer-media/e2e-nntp https://nntp.bench.test")
	if findings := scanContents("README.md", contents); len(findings) != 0 {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}
