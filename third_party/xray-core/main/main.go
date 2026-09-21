package main

import (
	"flag"
	"os"

	"github.com/xtls/xray-core/main/commands/base"
	_ "github.com/xtls/xray-core/main/distro/all"
)

func main() {
	os.Args = getArgsV4Compatible()

	base.RootCommand.Long = "Xray is a platform for building proxies."
	base.RootCommand.Commands = append(
		[]*base.Command{
			cmdRun,
			cmdVersion,
		},
		base.RootCommand.Commands...,
	)
	base.Execute()
}

func getArgsV4Compatible() []string {
	if len(os.Args) == 1 {
		return []string{os.Args[0], "run"}
	}
	if os.Args[1][0] != '-' {
		return os.Args
	}
	version := false
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.BoolVar(&version, "version", false, "")

	fs.Usage = func() {}
	fs.SetOutput(&null{})
	err := fs.Parse(os.Args[1:])
	if err == flag.ErrHelp {

		return []string{os.Args[0], "help"}
	}
	if version {

		return []string{os.Args[0], "version"}
	}

	return append([]string{os.Args[0], "run"}, os.Args[1:]...)
}

type null struct{}

func (n *null) Write(p []byte) (int, error) {
	return len(p), nil
}
