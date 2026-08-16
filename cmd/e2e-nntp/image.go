package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const modulePath = "github.com/scryer-media/e2e-nntp"

type imageResult struct {
	ModuleVersion string `json:"module_version"`
	Source        string `json:"source"`
	Platform      string `json:"platform"`
	Tag           string `json:"tag"`
	ImageID       string `json:"image_id"`
	BinarySHA256  string `json:"binary_sha256"`
}

func buildImage(arguments []string) {
	flags := flag.NewFlagSet("image build", flag.ExitOnError)
	version := flags.String("version", "", "exact Go module version")
	sourceDirectory := flags.String("source-dir", "", "local module root for a development build")
	tag := flags.String("tag", "e2e-nntp:local", "local Docker image tag")
	platform := flags.String("platform", defaultPlatform(), "target Linux platform")
	if err := flags.Parse(arguments); err != nil {
		fatal(err)
	}
	result, err := buildLocalImage(imageBuildOptions{Version: *version, SourceDirectory: *sourceDirectory, Tag: *tag, Platform: *platform})
	if err != nil {
		fatal(err)
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fatal(err)
	}
	fmt.Println(string(encoded))
}

type imageBuildOptions struct {
	Version         string
	SourceDirectory string
	Tag             string
	Platform        string
}

func buildLocalImage(options imageBuildOptions) (imageResult, error) {
	if options.Tag == "" || strings.ContainsAny(options.Tag, "\r\n") {
		return imageResult{}, errors.New("a valid local image tag is required")
	}
	operatingSystem, architecture, err := parsePlatform(options.Platform)
	if err != nil {
		return imageResult{}, err
	}
	if options.SourceDirectory != "" && options.Version != "" {
		return imageResult{}, errors.New("--source-dir and --version cannot be combined")
	}
	if options.SourceDirectory == "" && !validModuleVersion(options.Version) {
		return imageResult{}, errors.New("--version must be an exact vX.Y.Z module version when --source-dir is absent")
	}

	workspace, err := os.MkdirTemp("", "e2e-nntp-image-*")
	if err != nil {
		return imageResult{}, fmt.Errorf("create image workspace: %w", err)
	}
	defer os.RemoveAll(workspace)

	sourceDirectory, moduleVersion, err := imageSource(workspace, options)
	if err != nil {
		return imageResult{}, err
	}
	binaryPath := filepath.Join(workspace, "e2e-nntp")
	if err := runBuild(sourceDirectory, binaryPath, operatingSystem, architecture, moduleVersion, options.SourceDirectory == ""); err != nil {
		return imageResult{}, err
	}
	binaryContents, err := os.ReadFile(binaryPath)
	if err != nil {
		return imageResult{}, fmt.Errorf("read compiled binary: %w", err)
	}
	binaryDigest := sha256.Sum256(binaryContents)
	dockerfile := "FROM scratch\n" +
		"LABEL org.opencontainers.image.title=e2e-nntp\n" +
		"LABEL org.opencontainers.image.version=" + moduleVersion + "\n" +
		"LABEL org.opencontainers.image.source=" + modulePath + "\n" +
		"COPY e2e-nntp /e2e-nntp\n" +
		"ENTRYPOINT [\"/e2e-nntp\"]\n" +
		"CMD [\"serve\"]\n"
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		return imageResult{}, fmt.Errorf("write generated Dockerfile: %w", err)
	}
	if err := runCommand(workspace, nil, "docker", "build", "--platform", options.Platform, "--tag", options.Tag,
		"--label", "org.opencontainers.image.version="+moduleVersion,
		"--label", "org.opencontainers.image.source="+modulePath,
		"--label", "org.opencontainers.image.revision="+hex.EncodeToString(binaryDigest[:]),
		"."); err != nil {
		return imageResult{}, err
	}
	imageID, err := commandOutput(workspace, nil, "docker", "image", "inspect", "--format", "{{.Id}}", options.Tag)
	if err != nil {
		return imageResult{}, err
	}
	return imageResult{
		ModuleVersion: moduleVersion,
		Source:        imageSourceKind(options.SourceDirectory),
		Platform:      options.Platform,
		Tag:           options.Tag,
		ImageID:       strings.TrimSpace(imageID),
		BinarySHA256:  hex.EncodeToString(binaryDigest[:]),
	}, nil
}

func imageSource(workspace string, options imageBuildOptions) (string, string, error) {
	if options.SourceDirectory != "" {
		directory, err := absolutePath(options.SourceDirectory)
		if err != nil {
			return "", "", fmt.Errorf("resolve source directory: %w", err)
		}
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err != nil {
			return "", "", errors.New("--source-dir must be a Go module root")
		}
		return directory, "devel", nil
	}
	goMod := "module local-e2e-nntp-image-build\n\ngo 1.26.2\n\nrequire " + modulePath + " " + options.Version + "\n"
	if err := os.WriteFile(filepath.Join(workspace, "go.mod"), []byte(goMod), 0o600); err != nil {
		return "", "", fmt.Errorf("write temporary module: %w", err)
	}
	return workspace, options.Version, nil
}

func runBuild(directory, output, operatingSystem, architecture, moduleVersion string, temporaryModule bool) error {
	environment := append(os.Environ(), "CGO_ENABLED=0", "GOOS="+operatingSystem, "GOARCH="+architecture, "GOWORK=off")
	return runCommand(directory, environment, "go", buildArguments(output, moduleVersion, temporaryModule)...)
}

// buildArguments returns the `go` argv for the static binary. The temporary
// module written by imageSource has a require line but no go.sum, and `go
// build` refuses to resolve that on its own; `-mod=mod` lets it download the
// pinned version and record the checksums inside the throwaway workspace.
// A caller-supplied source tree is built read-only so the builder never edits
// a developer's go.mod or go.sum.
func buildArguments(output, moduleVersion string, temporaryModule bool) []string {
	arguments := []string{"build", "-trimpath"}
	if temporaryModule {
		arguments = append(arguments, "-mod=mod")
	}
	return append(arguments, "-ldflags", "-X main.version="+moduleVersion, "-o", output, modulePath+"/cmd/e2e-nntp")
}

func runCommand(directory string, environment []string, program string, arguments ...string) error {
	command := exec.Command(program, arguments...)
	command.Dir = directory
	if environment != nil {
		command.Env = environment
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("run %s: %w: %s", program, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func commandOutput(directory string, environment []string, program string, arguments ...string) (string, error) {
	command := exec.Command(program, arguments...)
	command.Dir = directory
	if environment != nil {
		command.Env = environment
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("run %s: %w: %s", program, err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func parsePlatform(value string) (string, string, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[0] != "linux" || (parts[1] != "amd64" && parts[1] != "arm64") {
		return "", "", errors.New("--platform must be linux/amd64 or linux/arm64")
	}
	return parts[0], parts[1], nil
}

func defaultPlatform() string {
	if runtime.GOARCH == "arm64" {
		return "linux/arm64"
	}
	return "linux/amd64"
}

func validModuleVersion(value string) bool {
	if !strings.HasPrefix(value, "v") || len(value) < 6 || strings.ContainsAny(value, " \t\r\n@/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(value, "v"), ".")
	if len(parts) < 3 {
		return false
	}
	for _, part := range parts[:3] {
		if part == "" {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func imageSourceKind(directory string) string {
	if directory == "" {
		return "module-version"
	}
	return "source-directory"
}
