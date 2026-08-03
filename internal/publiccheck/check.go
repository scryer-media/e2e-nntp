// Package publiccheck enforces repository-safe content rules without printing
// the potentially sensitive content that triggered a finding.
package publiccheck

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Options selects a Git working-tree, staged, or all-history scan.
type Options struct {
	Repository string
	Staged     bool
	AllHistory bool
}

// Finding deliberately contains no matched content.
type Finding struct {
	Path string
	Rule string
}

var (
	unixHomePath  = regexp.MustCompile(`/` + `(Users|home)` + `/[A-Za-z0-9._-]+/`)
	windowsPath   = regexp.MustCompile(`(?i)[A-Z]:` + `\\` + `Users` + `\\`)
	privateKey    = regexp.MustCompile(`-----BEGIN [A-Z ]*` + `PRIVATE KEY-----`)
	privateIPv4   = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.` + `168\.\d{1,3}\.\d{1,3})`)
	credentialURL = regexp.MustCompile(`(?i)(?:postgres|mysql|redis|amqp)://[^\s/@]+:[^\s/@]+@`)
	githubToken   = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`)
	awsKey        = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	slackToken    = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)
	httpURL       = regexp.MustCompile(`https?://([A-Za-z0-9.-]+)`)
)

var disallowedSuffixes = map[string]struct{}{
	".pem": {}, ".key": {}, ".p12": {}, ".pfx": {}, ".crt": {}, ".csr": {},
}

var allowedDomains = map[string]struct{}{
	"github.com":           {},
	"www.apache.org":       {},
	"spdx.org":             {},
	"go.dev":               {},
	"pkg.go.dev":           {},
	"golang.org":           {},
	"localhost":            {},
	"example.com":          {},
	"nntp.bench.test":      {},
	"host.docker.internal": {},
}

// Check scans the selected content. It never emits scanned data in errors.
func Check(options Options) ([]Finding, error) {
	if options.Staged && options.AllHistory {
		return nil, errors.New("--staged and --all cannot be combined")
	}
	repository, err := filepath.Abs(options.Repository)
	if err != nil {
		return nil, fmt.Errorf("resolve repository: %w", err)
	}
	if options.AllHistory {
		return checkAllHistory(repository)
	}
	paths, err := trackedPaths(repository, options.Staged)
	if err != nil {
		return nil, err
	}
	findings := make([]Finding, 0)
	for _, path := range paths {
		findings = append(findings, scanPath(path)...)
		info, err := os.Lstat(filepath.Join(repository, path))
		if err != nil {
			return nil, fmt.Errorf("stat tracked path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			findings = append(findings, Finding{Path: path, Rule: "symlink is not permitted"})
			continue
		}
		if info.IsDir() {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(repository, path))
		if err != nil {
			return nil, fmt.Errorf("read tracked path: %w", err)
		}
		findings = append(findings, scanContents(path, contents)...)
	}
	return uniqueFindings(findings), nil
}

func trackedPaths(repository string, staged bool) ([]string, error) {
	arguments := []string{"-C", repository, "ls-files", "-z"}
	if staged {
		arguments = []string{"-C", repository, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"}
	}
	output, err := exec.Command("git", arguments...).Output()
	if err != nil {
		return nil, fmt.Errorf("list tracked paths: %w", err)
	}
	return splitNUL(output), nil
}

func checkAllHistory(repository string) ([]Finding, error) {
	output, err := exec.Command("git", "-C", repository, "rev-list", "--objects", "--all").Output()
	if err != nil {
		return nil, fmt.Errorf("list reachable objects: %w", err)
	}
	findings := make([]Finding, 0)
	seen := map[string]struct{}{}
	for _, entry := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(entry)
		if len(fields) == 0 {
			continue
		}
		objectID := fields[0]
		if _, ok := seen[objectID]; ok {
			continue
		}
		seen[objectID] = struct{}{}
		kind, err := exec.Command("git", "-C", repository, "cat-file", "-t", objectID).Output()
		if err != nil || strings.TrimSpace(string(kind)) != "blob" {
			continue
		}
		contents, err := exec.Command("git", "-C", repository, "cat-file", "blob", objectID).Output()
		if err != nil {
			return nil, fmt.Errorf("read reachable blob: %w", err)
		}
		path := "git-blob/" + objectID
		if len(fields) > 1 {
			path = strings.Join(fields[1:], " ")
		}
		findings = append(findings, scanPath(path)...)
		findings = append(findings, scanContents(path, contents)...)
	}
	return uniqueFindings(findings), nil
}

func splitNUL(output []byte) []string {
	parts := bytes.Split(output, []byte{0})
	paths := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) != 0 {
			paths = append(paths, string(part))
		}
	}
	return paths
}

func scanPath(path string) []Finding {
	base := filepath.Base(path)
	lower := strings.ToLower(base)
	if lower == ".env" || strings.HasPrefix(lower, ".env.") {
		return []Finding{{Path: path, Rule: "environment file is not permitted"}}
	}
	if _, ok := disallowedSuffixes[strings.ToLower(filepath.Ext(base))]; ok {
		return []Finding{{Path: path, Rule: "credential or certificate file is not permitted"}}
	}
	return nil
}

func scanContents(path string, contents []byte) []Finding {
	if len(contents) == 0 || bytes.IndexByte(contents, 0) >= 0 {
		return nil
	}
	text := string(contents)
	rules := []struct {
		name  string
		match *regexp.Regexp
	}{
		{"absolute Unix home path", unixHomePath},
		{"absolute Windows user path", windowsPath},
		{"private network address", privateIPv4},
		{"private key material", privateKey},
		{"credential-bearing connection URL", credentialURL},
		{"GitHub token", githubToken},
		{"cloud access key", awsKey},
		{"chat token", slackToken},
	}
	findings := make([]Finding, 0)
	for _, rule := range rules {
		if rule.match.MatchString(text) {
			findings = append(findings, Finding{Path: path, Rule: rule.name})
		}
	}
	for _, match := range httpURL.FindAllStringSubmatch(text, -1) {
		domain := strings.ToLower(match[1])
		if _, ok := allowedDomains[domain]; !ok {
			findings = append(findings, Finding{Path: path, Rule: "unapproved external domain"})
			break
		}
	}
	return findings
}

func uniqueFindings(findings []Finding) []Finding {
	set := make(map[string]Finding, len(findings))
	for _, finding := range findings {
		set[finding.Path+"\x00"+finding.Rule] = finding
	}
	unique := make([]Finding, 0, len(set))
	for _, finding := range set {
		unique = append(unique, finding)
	}
	sort.Slice(unique, func(left, right int) bool {
		if unique[left].Path == unique[right].Path {
			return unique[left].Rule < unique[right].Rule
		}
		return unique[left].Path < unique[right].Path
	})
	return unique
}
