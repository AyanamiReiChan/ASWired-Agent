package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/control"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/runtime"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/updater"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
)

var version = "0.1.0-dev"

func main() {
	if e := run(); e != nil {
		slog.Error("agent stopped", "error", e)
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("config", "agent.json", "agent configuration file")
	check := flag.Bool("check", false, "validate local configuration and exit")
	supervise := flag.Bool("supervise", false, "supervise Linux Agent upgrades with rollback")
	standalone := flag.Bool("standalone", false, "run core without a controller")
	once := flag.Bool("observe", false, "print management state and exit")
	ver := flag.Bool("version", false, "print version")
	command := flag.String("command", "", "execute a JSON command from a file locally, then exit")
	flag.Parse()
	if *ver {
		fmt.Println(version)
		return nil
	}
	c, e := config.Load(*path)
	if e != nil {
		return e
	}
	if e = c.Validate(*standalone || *once || *command != ""); e != nil {
		return e
	}
	if *supervise {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return updater.Supervise(ctx, c.ConfigPath, c.DataDir)
	}
	if *check {
		fmt.Println("Agent configuration valid")
		return nil
	}
	if os.Getenv("XRAY_LOCATION_ASSET") == "" && os.Getenv("xray.location.asset") == "" {
		if e = os.Setenv("XRAY_LOCATION_ASSET", filepath.Join(c.DataDir, "geo")); e != nil {
			return e
		}
	}
	r, e := runtime.New(c)
	if e != nil {
		return e
	}
	defer r.Close()
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(io.MultiWriter(os.Stderr, r.LogWriter()), nil)))
	defer slog.SetDefault(previousLogger)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *once {
		return json.NewEncoder(os.Stdout).Encode(r.Snapshot())
	}
	if e = r.Start(ctx); e != nil {
		slog.Error("core startup failed; management remains available", "error", e)
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
		result := r.Handle(ctx, cmd)
		if e = json.NewEncoder(os.Stdout).Encode(result); e != nil {
			return e
		}
		if result.Status != "success" {
			return fmt.Errorf("command failed: %s", result.Error)
		}
		return nil
	}
	slog.Info("ASWired Agent started", "version", version, "mode", c.XrayMode, "controller", c.MasterURL)
	if *standalone {
		<-ctx.Done()
		return nil
	}
	e = control.New(c, r, version).Run(ctx)
	if ctx.Err() != nil {
		return nil
	}
	return e
}
