package control

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/updater"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type Runner interface {
	Handle(context.Context, wire.Command) wire.Result
	Snapshot() map[string]any
	Capabilities() map[string]bool
}
type Client struct {
	cfg        config.Config
	run        Runner
	version    string
	results    []wire.Result
	mu         sync.Mutex
	seen       map[string]wire.Result
	order      []string
	seenSizes  map[string]int
	seenBytes  int
	sentCount  int
	http       *http.Client
	exchangeMu sync.Mutex
	changed    chan struct{}
	lastDirect time.Time
}

func New(c config.Config, r Runner, version string) *Client {
	if c.ConnectionMode == "" {
		c.ConnectionMode = "websocket"
	}
	if c.ListenAddress == "" {
		c.ListenAddress = "0.0.0.0:23889"
	}
	return &Client{cfg: c, run: r, version: version, seen: map[string]wire.Result{}, seenSizes: map[string]int{}, changed: make(chan struct{}, 1), http: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *Client) report() wire.Report {
	c.mu.Lock()
	results := []wire.Result{}
	size := 0
	for i, result := range c.results {
		encoded, e := json.Marshal(result)
		if e != nil || len(encoded) > wire.MaxPacket-(1<<20) {
			result = wire.Result{ID: result.ID, Status: "failed", Error: "command result exceeds the encrypted report limit or cannot be encoded"}
			c.results[i] = result
			encoded, _ = json.Marshal(result)
		}
		if size+len(encoded) > wire.MaxPacket-(1<<20) {
			break
		}
		results = append(results, result)
		size += len(encoded)
	}
	c.sentCount = len(results)
	token := c.cfg.Token
	connectionMode := c.cfg.ConnectionMode
	c.mu.Unlock()
	mode := c.cfg.XrayMode
	observation := c.run.Snapshot()
	observation["agent_update"] = updater.Snapshot(c.cfg.DataDir)
	if core, ok := observation["core"].(map[string]any); ok {
		if current, ok := core["mode"].(string); ok {
			mode = current
		}
	}
	if c.cfg.Role == "speedtest" {
		mode = "speedtest"
	}
	return wire.Report{ConnectionMode: connectionMode, ServerID: c.cfg.ServerID, Token: token, Version: c.version, Mode: mode, Observation: observation, Capabilities: c.capabilities(), Results: results, Timestamp: time.Now().Unix()}
}
func (c *Client) capabilities() map[string]bool {
	caps := c.run.Capabilities()
	if caps == nil {
		caps = map[string]bool{}
	}
	caps["identity_rotation"] = c.cfg.ConfigPath != ""
	caps["agent_update"] = updater.Available()
	caps["connection_modes"] = true
	return caps
}
func (c *Client) execute(ctx context.Context, cmd wire.Command) wire.Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cmd.ID == "" {
		return wire.Result{Status: "failed", Error: "command ID is required"}
	}
	if old, ok := c.seen[cmd.ID]; ok {
		return old
	}
	logExecution := cmd.Action != "agent.report" && !strings.HasPrefix(cmd.Action, "logs.")
	if logExecution {
		slog.Info("任务开始执行", "event", cmd.Action, "taskId", cmd.ID, "status", "running")
	}
	started := time.Now()
	var result wire.Result
	if cmd.Action == "identity.rotate" {
		result = c.rotateIdentity(cmd)
	} else if cmd.Action == "agent.update" {
		url, _ := cmd.Params["url"].(string)
		checksum, _ := cmd.Params["sha256"].(string)
		version, _ := cmd.Params["version"].(string)
		data, err := updater.Stage(ctx, c.cfg.DataDir, cmd.ID, url, checksum, version)
		result = wire.Result{ID: cmd.ID, Status: "success", Data: data}
		if err != nil {
			result.Status = "failed"
			result.Error = err.Error()
		}
	} else if cmd.Action == "agent.report" {
		acknowledgedUpdate, _ := cmd.Params["acknowledged_update"].(string)
		_ = updater.Acknowledge(c.cfg.DataDir, acknowledgedUpdate, c.version)
		oldMode, oldListen := c.cfg.ConnectionMode, c.cfg.ListenAddress
		if mode, _ := cmd.Params["connection_mode"].(string); mode != "" {
			listen, _ := cmd.Params["listen_address"].(string)
			if err := c.setConnectionLocked(mode, listen); err != nil {
				return wire.Result{ID: cmd.ID, Status: "failed", Error: err.Error()}
			}
		}
		observation := c.run.Snapshot()
		observation["agent_update"] = updater.Snapshot(c.cfg.DataDir)
		mode := c.cfg.XrayMode
		if core, ok := observation["core"].(map[string]any); ok {
			if current, ok := core["mode"].(string); ok {
				mode = current
			}
		}
		if c.cfg.Role == "speedtest" {
			mode = "speedtest"
		}
		result = wire.Result{ID: cmd.ID, Status: "success", Data: map[string]any{"observation": observation, "capabilities": c.capabilities(), "version": c.version, "mode": mode, "connection_mode": c.cfg.ConnectionMode, "connection_changed": oldMode != c.cfg.ConnectionMode || oldListen != c.cfg.ListenAddress}}
	} else {
		result = c.run.Handle(ctx, cmd)
	}
	if logExecution {
		level := slog.LevelInfo
		if result.Status != "success" {
			level = slog.LevelError
		}
		slog.Log(ctx, level, "任务执行结束", "event", cmd.Action, "taskId", cmd.ID, "status", result.Status, "durationMs", time.Since(started).Milliseconds(), "error", result.Error)
	}
	c.seen[cmd.ID] = result
	encoded, _ := json.Marshal(result)
	c.seenSizes[cmd.ID] = len(encoded)
	c.seenBytes += len(encoded)
	c.order = append(c.order, cmd.ID)
	for len(c.order) > 2048 || c.seenBytes > 32<<20 {
		c.seenBytes -= c.seenSizes[c.order[0]]
		delete(c.seenSizes, c.order[0])
		delete(c.seen, c.order[0])
		c.order = c.order[1:]
	}
	return result
}
func (c *Client) accept(ctx context.Context, reply wire.Reply) error {
	if reply.Error != "" {
		return errors.New(reply.Error)
	}
	c.mu.Lock()
	if c.sentCount <= len(c.results) {
		for _, result := range c.results[:c.sentCount] {
			if result.Status == "success" {
				_ = updater.Acknowledge(c.cfg.DataDir, result.ID, c.version)
			}
		}
		c.results = append([]wire.Result(nil), c.results[c.sentCount:]...)
	}
	c.sentCount = 0
	if len(c.results) == 0 {
		if err := c.setConnectionLocked(reply.ConnectionMode, reply.ListenAddress); err != nil {
			c.mu.Unlock()
			return err
		}
	}
	c.mu.Unlock()
	_ = updater.Acknowledge(c.cfg.DataDir, "", c.version)
	for _, command := range reply.Commands {
		r := c.execute(ctx, command)
		c.mu.Lock()
		c.results = append(c.results, r)
		c.mu.Unlock()
	}
	return nil
}
func interval(reply wire.Reply) time.Duration {
	seconds := reply.Interval
	if seconds < 1 || seconds > 300 {
		seconds = 5
	}
	return time.Duration(seconds) * time.Second
}
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (c *Client) Run(ctx context.Context) error {
	for ctx.Err() == nil {
		select {
		case <-c.changed:
		default:
		}
		mode, listen := c.connectionSettings()
		var err error
		switch mode {
		case "websocket":
			err = c.webSocket(ctx)
		case "pull":
			c.pullLoop(ctx)
		case "http":
			err = c.direct(ctx)
		case "auto":
			err = c.webSocket(ctx)
			current, address := c.connectionSettings()
			if ctx.Err() == nil && current == "auto" && address == listen {
				fallback, stop := context.WithTimeout(ctx, time.Minute)
				done := make(chan error, 1)
				go func() { done <- c.direct(fallback) }()
				// Give the controller two maintenance ticks to try direct HTTP.
				if sleep(fallback, 10*time.Second) {
					if current, address := c.connectionSettings(); current == mode && address == listen {
						c.pullLoop(fallback)
					}
				}
				stop()
				<-done
			}
		default:
			return errors.New("invalid connection_mode")
		}
		if err != nil && ctx.Err() == nil {
			slog.Warn("agent connection interrupted", "mode", mode, "error", err)
		}
		current, _ := c.connectionSettings()
		if current == mode && !sleep(ctx, 5*time.Second) {
			break
		}
	}
	return ctx.Err()
}
func (c *Client) webSocket(ctx context.Context) error {
	mode, listen := c.connectionSettings()
	u := strings.TrimRight(c.cfg.MasterURL, "/") + "/api/agent/ws"
	u = strings.Replace(u, "https://", "wss://", 1)
	u = strings.Replace(u, "http://", "ws://", 1)
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	conn, _, e := websocket.Dial(dialCtx, u, nil)
	cancel()
	if e != nil {
		return e
	}
	defer conn.CloseNow()
	conn.SetReadLimit(wire.MaxPacket * 2)
	ch, e := wire.NewClient(c.cfg.MasterPublicKey)
	if e != nil {
		return e
	}
	packet, e := ch.Seal(c.report())
	if e != nil {
		return e
	}
	if e = wsjson.Write(ctx, conn, wire.Hello{PublicKey: ch.PublicKey(), Packet: packet}); e != nil {
		return e
	}
	for {
		var packet wire.Packet
		readCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		e = wsjson.Read(readCtx, conn, &packet)
		cancel()
		if e != nil {
			return e
		}
		var reply wire.Reply
		if e = ch.Open(packet, &reply); e != nil {
			return e
		}
		if e = c.accept(ctx, reply); e != nil {
			return e
		}
		if current, address := c.connectionSettings(); current != mode || address != listen {
			return nil
		}
		if !sleep(ctx, interval(reply)) {
			return ctx.Err()
		}
		packet, e = ch.Seal(c.report())
		if e != nil {
			return e
		}
		if e = wsjson.Write(ctx, conn, packet); e != nil {
			return e
		}
	}
}
