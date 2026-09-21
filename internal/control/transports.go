package control

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func (c *Client) pullLoop(ctx context.Context) {
	mode, listen := c.connectionSettings()
	for ctx.Err() == nil {
		if current, address := c.connectionSettings(); current != mode || address != listen {
			return
		}
		c.mu.Lock()
		directActive := mode == "auto" && time.Since(c.lastDirect) < 15*time.Second
		c.mu.Unlock()
		if directActive {
			if !sleep(ctx, time.Second) {
				return
			}
			continue
		}
		delay := 5 * time.Second
		c.exchangeMu.Lock()
		reply, e := c.pull(ctx)
		if e != nil {
			if ctx.Err() == nil {
				slog.Warn("agent pull failed", "error", e)
			}
		} else {
			if e = c.accept(ctx, reply); e != nil {
				slog.Warn("agent report rejected", "error", e)
			}
			delay = interval(reply)
		}
		c.exchangeMu.Unlock()
		if current, address := c.connectionSettings(); current != mode || address != listen {
			return
		}
		if !sleep(ctx, delay) {
			return
		}
	}
}
func (c *Client) pull(ctx context.Context) (wire.Reply, error) {
	ch, e := wire.NewClient(c.cfg.MasterPublicKey)
	if e != nil {
		return wire.Reply{}, e
	}
	packet, e := ch.Seal(c.report())
	if e != nil {
		return wire.Reply{}, e
	}
	body, e := json.Marshal(wire.Hello{PublicKey: ch.PublicKey(), Packet: packet})
	if e != nil {
		return wire.Reply{}, e
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.MasterURL, "/")+"/api/agent/pull", bytes.NewReader(body))
	if e != nil {
		return wire.Reply{}, e
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := c.http.Do(req)
	if e != nil {
		return wire.Reply{}, e
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return wire.Reply{}, fmt.Errorf("controller returned HTTP %d", res.StatusCode)
	}
	var response wire.Packet
	if e = json.NewDecoder(io.LimitReader(res.Body, wire.MaxPacket*2)).Decode(&response); e != nil {
		return wire.Reply{}, e
	}
	var reply wire.Reply
	e = ch.Open(response, &reply)
	return reply, e
}

type directSession struct {
	channel *wire.Channel
	created time.Time
}

func (c *Client) direct(ctx context.Context) error {
	mode, listen := c.connectionSettings()
	c.mu.Lock()
	hasAgentToken := c.cfg.AgentToken != ""
	c.mu.Unlock()
	if !hasAgentToken {
		if mode == "http" {
			return errors.New("agent_token is required for HTTP management")
		}
		<-ctx.Done()
		return nil
	}
	var mu sync.Mutex
	sessions := map[string]directSession{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/hello", func(w http.ResponseWriter, r *http.Request) {
		nonce := r.URL.Query().Get("nonce")
		if !wire.ValidDirectNonce(nonce) || len(r.URL.Query()["nonce"]) != 1 {
			http.Error(w, "a canonical 32-byte nonce is required", http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for k, s := range sessions {
			if time.Since(s.created) > 30*time.Second {
				delete(sessions, k)
			}
		}
		if len(sessions) >= 128 {
			http.Error(w, "too many handshakes", http.StatusTooManyRequests)
			return
		}
		ch, e := wire.NewClient(c.cfg.MasterPublicKey)
		if e != nil {
			http.Error(w, "identity unavailable", 500)
			return
		}
		c.mu.Lock()
		hello, e := wire.SignDirectHello(c.cfg.AgentToken, wire.DirectHello{Protocol: wire.DirectHelloProtocol, Nonce: nonce, PublicKey: ch.PublicKey(), ServerID: c.cfg.ServerID, MasterPublicKey: c.cfg.MasterPublicKey, Timestamp: time.Now().Unix()})
		c.mu.Unlock()
		if e != nil {
			http.Error(w, "identity unavailable", http.StatusInternalServerError)
			return
		}
		sessions[ch.PublicKey()] = directSession{ch, time.Now()}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(hello)
	})
	mux.HandleFunc("POST /v1/rpc", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, wire.MaxPacket*2)
		var hello wire.Hello
		if e := json.NewDecoder(r.Body).Decode(&hello); e != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		mu.Lock()
		s, ok := sessions[hello.PublicKey]
		delete(sessions, hello.PublicKey)
		mu.Unlock()
		if !ok || time.Since(s.created) > 30*time.Second {
			http.Error(w, "expired session", 401)
			return
		}
		var request wire.DirectRequest
		if e := s.channel.Open(hello.Packet, &request); e != nil {
			http.Error(w, "channel authentication failed", 401)
			return
		}
		if !c.validAgentToken(request.Token) || time.Now().Unix()-request.Timestamp > 90 || request.Timestamp-time.Now().Unix() > 90 {
			http.Error(w, "authentication failed", 401)
			return
		}
		c.exchangeMu.Lock()
		defer c.exchangeMu.Unlock()
		result := c.execute(r.Context(), request.Command)
		c.mu.Lock()
		c.lastDirect = time.Now()
		c.mu.Unlock()
		packet, e := s.channel.Seal(result)
		if e != nil {
			http.Error(w, "response failed", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(packet)
	})
	ln, e := net.Listen("tcp", listen)
	if e != nil {
		return e
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	slog.Info("encrypted management listener started", "address", ln.Addr().String())
	select {
	case e = <-done:
		return e
	case <-ctx.Done():
	case <-c.changed:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil {
		_ = srv.Close()
		return err
	}
	return nil
}
func (c *Client) validAgentToken(token string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(c.cfg.AgentToken)) == 1 || (time.Now().Unix() <= c.cfg.PreviousTokenExpires && c.cfg.PreviousAgentToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(c.cfg.PreviousAgentToken)) == 1)
}
