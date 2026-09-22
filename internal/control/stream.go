package control

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/updater"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"github.com/coder/websocket"
)

func (c *Client) acknowledgeResults(ids []string) []string {
	ack := map[string]bool{}
	for _, id := range ids {
		ack[id] = true
	}
	c.mu.Lock()
	remaining := c.results[:0]
	var successful []string
	for _, result := range c.results {
		if !ack[result.ID] {
			remaining = append(remaining, result)
		} else if result.Status == "success" {
			successful = append(successful, result.ID)
		}
	}
	c.results = remaining
	c.mu.Unlock()
	return successful
}

func (c *Client) stream(ctx context.Context, conn *websocket.Conn, channel *wire.Channel, initial wire.Report, first wire.Reply, mode, listen string) error {
	if err := c.acknowledge(first); err != nil {
		return err
	}
	if current, address := c.connectionSettings(); current != mode || address != listen {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() { cancel(); _ = conn.CloseNow(); wg.Wait() }()
	var active atomic.Int32
	commands := make(chan []wire.Command, 1)
	ready := make(chan struct{}, 1)
	telemetry := make(chan wire.Update, 1)
	replies := make(chan wire.Reply, 1)
	errorsCh := make(chan error, 1)
	options := first.Stream
	var ackMu sync.Mutex
	var pendingAcks []string
	ackReady := make(chan struct{}, 1)
	flushAcks := func() {
		ackMu.Lock()
		ids := pendingAcks
		pendingAcks = nil
		ackMu.Unlock()
		for _, id := range ids {
			_ = updater.Acknowledge(c.cfg.DataDir, id, c.version)
		}
	}
	// Sampling and commands can wait on the core's own lock. Neither can hold
	// up the network loop's heartbeat timer.
	wg.Add(4)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				flushAcks()
				return
			case <-ackReady:
				flushAcks()
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case batch := <-commands:
				for _, command := range batch {
					if ctx.Err() != nil {
						return
					}
					result := c.execute(ctx, command)
					c.mu.Lock()
					c.results = append(c.results, result)
					c.mu.Unlock()
					active.Add(-1)
					select {
					case ready <- struct{}{}:
					default:
					}
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Duration(options.TelemetrySeconds) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				update := wire.Update{Kind: "telemetry", Observation: c.snapshot(), Capabilities: c.capabilities()}
				select {
				case telemetry <- update:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			readCtx, stop := context.WithTimeout(ctx, 3*wire.HeartbeatSeconds*time.Second)
			kind, raw, err := conn.Read(readCtx)
			stop()
			var reply wire.Reply
			if err == nil && kind != websocket.MessageBinary {
				err = errors.New("expected negotiated binary reply")
			}
			if err == nil {
				err = channel.OpenBinary(raw, &reply, false)
			}
			if err != nil {
				select {
				case errorsCh <- err:
				case <-ctx.Done():
				}
				return
			}
			select {
			case replies <- reply:
			case <-ctx.Done():
				return
			}
		}
	}()
	queue := func(batch []wire.Command) error {
		if len(batch) == 0 {
			return nil
		}
		if len(batch) > 16 {
			return errors.New("too many stream commands")
		}
		active.Add(int32(len(batch)))
		select {
		case commands <- batch:
			return nil
		default:
			return errors.New("stream command queue overflow")
		}
	}
	if err := queue(first.Commands); err != nil {
		return err
	}
	lastToken, lastCaps := initial.Token, initial.Capabilities
	var telemetryBase, telemetryPending map[string]any
	var telemetryRevision uint64
	var telemetrySentAt time.Time
	send := func(update wire.Update) error {
		c.mu.Lock()
		token, pending := c.cfg.Token, len(c.results) > 0
		c.mu.Unlock()
		update.Timestamp = time.Now().Unix()
		update.Busy = active.Load() > 0 || pending
		if token != lastToken {
			update.Token = token
		}
		compress := options.Compression == "gzip" && update.Kind == "telemetry" && update.Token == ""
		packet, err := channel.SealBinary(update, compress)
		if err != nil {
			return err
		}
		writeCtx, stop := context.WithTimeout(ctx, 30*time.Second)
		err = conn.Write(writeCtx, websocket.MessageBinary, packet)
		stop()
		if err == nil {
			lastToken = token
		}
		return err
	}
	resultsInFlight := false
	sendResults := func() error {
		if resultsInFlight {
			return nil
		}
		c.mu.Lock()
		batch := c.resultBatchLocked()
		c.mu.Unlock()
		if len(batch) == 0 {
			return nil
		}
		if err := send(wire.Update{Kind: "results", Results: batch}); err != nil {
			return err
		}
		resultsInFlight = true
		return nil
	}
	// A reconnect's first report can contain only part of the pending results.
	if err := sendResults(); err != nil {
		return err
	}
	heartbeat := time.NewTicker(time.Duration(options.HeartbeatSeconds) * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errorsCh:
			return err
		case <-heartbeat.C:
			if telemetryPending != nil && time.Since(telemetrySentAt) >= 3*wire.HeartbeatSeconds*time.Second {
				return errors.New("telemetry acknowledgement timed out")
			}
			if err := send(wire.Update{Kind: "heartbeat"}); err != nil {
				return err
			}
		case update := <-telemetry:
			if options.TelemetryDelta {
				// Never compute against an unacknowledged baseline. Subsequent
				// samples are cumulative; a slow ACK can coalesce them safely.
				if telemetryPending != nil {
					continue
				}
				next, err := wire.CloneObservation(update.Observation)
				if err != nil {
					return err
				}
				if telemetryRevision == ^uint64(0) {
					return errors.New("telemetry sequence exhausted")
				}
				delta := wire.MakeObservationDelta(telemetryRevision, telemetryBase, next)
				update.Observation, update.Delta, update.TelemetrySeq = nil, &delta, telemetryRevision+1
				telemetryPending, telemetrySentAt = next, time.Now()
			}
			if reflect.DeepEqual(update.Capabilities, lastCaps) {
				update.Capabilities = nil
			} else {
				lastCaps = update.Capabilities
			}
			if err := send(update); err != nil {
				return err
			}
		case <-ready:
			if err := sendResults(); err != nil {
				return err
			}
		case reply := <-replies:
			if reply.Error != "" {
				return errors.New(reply.Error)
			}
			if options.TelemetryDelta && reply.TelemetryAck > 0 {
				if telemetryPending == nil || reply.TelemetryAck != telemetryRevision+1 {
					return errors.New("invalid telemetry acknowledgement")
				}
				telemetryBase, telemetryPending = telemetryPending, nil
				telemetryRevision = reply.TelemetryAck
			}
			if len(reply.AckResults) > 0 {
				ids := c.acknowledgeResults(reply.AckResults)
				if len(ids) > 0 {
					// The updater lock may be held by an in-progress download.
					// Persist its confirmations without blocking heartbeats.
					ackMu.Lock()
					pendingAcks = append(pendingAcks, ids...)
					ackMu.Unlock()
					select {
					case ackReady <- struct{}{}:
					default:
					}
				}
				resultsInFlight = false
			}
			if err := queue(reply.Commands); err != nil {
				return err
			}
			if err := sendResults(); err != nil {
				return err
			}
			c.mu.Lock()
			var err error
			if active.Load() == 0 && len(c.results) == 0 {
				err = c.setConnectionLocked(reply.ConnectionMode, reply.ListenAddress)
			}
			c.mu.Unlock()
			if err != nil {
				return err
			}
			if current, address := c.connectionSettings(); current != mode || address != listen {
				return nil
			}
		}
	}
}
