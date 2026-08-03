package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/scryer-media/e2e-nntp/internal/publiccheck"
)

func main() {
	var options publiccheck.Options
	flag.StringVar(&options.Repository, "repo", ".", "Git repository to scan")
	flag.BoolVar(&options.Staged, "staged", false, "scan staged paths only")
	flag.BoolVar(&options.AllHistory, "all", false, "scan every reachable Git blob")
	flag.Parse()

	findings, err := publiccheck.Check(options)
	if err != nil {
		fmt.Fprintln(os.Stderr, "publiccheck:", err)
		os.Exit(2)
	}
	if len(findings) == 0 {
		fmt.Println("publiccheck: passed")
		return
	}
	for _, finding := range findings {
		fmt.Fprintf(os.Stderr, "%s: %s\n", finding.Path, finding.Rule)
	}
	fmt.Fprintf(os.Stderr, "publiccheck: %d policy violation(s)\n", len(findings))
	os.Exit(1)
}
