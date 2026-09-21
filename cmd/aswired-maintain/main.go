package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/artifact"
)

func main() {
	verify := flag.String("verify", "", "verify an existing local binary")
	source := flag.String("url", "", "explicit release binary HTTPS URL")
	output := flag.String("output", "", "absolute new staging file path")
	checksum := flag.String("sha256", "", "pinned release SHA256")
	version := flag.String("version", "", "exact binary version (not latest)")
	flag.Parse()
	var e error
	if *verify != "" && *source == "" {
		e = artifact.Verify(context.Background(), *verify, *checksum, *version)
	} else if *source != "" && *output != "" && *verify == "" {
		e = artifact.Fetch(context.Background(), *source, *output, *checksum, *version)
	} else {
		fmt.Fprintln(os.Stderr, "Use -verify BINARY or -url URL -output ABSOLUTE_PATH, plus -sha256 HASH -version EXACT_VERSION")
		os.Exit(2)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Println("Release artifact verified; service installation is a separate local operation.")
}
