package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/control"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/speedtest"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

var version = "0.1.0-dev"

func main() {
	if e := run(); e != nil {
		slog.Error("speedtest client stopped", "error", e)
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("config", "speedtest.json", "home speed-test configuration")
	command := flag.String("command", "", "local JSON speedtest.run command file")
	ver := flag.Bool("version", false, "print version")
	check := flag.Bool("check", false, "validate Home configuration and pinned mihomo binary")
	pairURL := flag.String("pair-url", "", "controller HTTPS origin for a one-use Home pairing")
	pairCode := flag.String("pair-code", "", "one-use Home pairing code from the controller")
	flag.Parse()
	if *ver {
		fmt.Println(version)
		return nil
	}
	b, e := os.ReadFile(*path)
	if e != nil {
		return e
	}
	var sc speedtest.Config
	if e = json.Unmarshal(b, &sc); e != nil {
		return e
	}
	runner, e := speedtest.New(sc)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *pairURL != "" || *pairCode != "" {
		if *pairURL == "" || *pairCode == "" {
			return errors.New("pair-url and pair-code are both required")
		}
		if *command != "" {
			return errors.New("pairing cannot be combined with a local task")
		}
		if e = config.PairHome(ctx, *pairURL, *pairCode, *path); e != nil {
			return e
		}
		b, e = os.ReadFile(*path)
		if e != nil {
			return e
		}
		if e = json.Unmarshal(b, &sc); e != nil {
			return e
		}
		runner, e = speedtest.New(sc)
		if e != nil {
			return e
		}
		fmt.Fprintln(os.Stderr, "Home pairing saved; starting the authenticated connection")
	}
	if *command != "" {
		b, e := os.ReadFile(*command)
		if e != nil {
			return e
		}
		var cmd wire.Command
		if e = json.Unmarshal(b, &cmd); e != nil {
			return e
		}
		result := runner.Handle(ctx, cmd)
		if e = json.NewEncoder(os.Stdout).Encode(result); e != nil {
			return e
		}
		if result.Status != "success" {
			return errors.New(result.Error)
		}
		return nil
	}
	c, e := config.Load(*path)
	if e != nil {
		return e
	}
	c.Role = "speedtest"
	c.ConnectionMode = "websocket"
	if e = c.Validate(false); e != nil {
		return e
	}
	if *check {
		fmt.Println("Home configuration and mihomo artifact valid")
		return nil
	}
	fmt.Fprintln(os.Stderr, "ASWired home speed-test client started identity:", c.ServerID)
	e = control.New(c, runner, version).Run(ctx)
	if ctx.Err() != nil {
		return nil
	}
	return e
}
