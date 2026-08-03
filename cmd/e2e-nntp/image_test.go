package main

import "testing"

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
