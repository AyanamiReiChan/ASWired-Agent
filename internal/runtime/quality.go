package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func networkQuality(ctx context.Context, p map[string]any) (map[string]any, error) {
	method, _ := p["method"].(string)
	if method == "" {
		method = "tcp"
	}
	target, _ := p["target"].(string)
	count := 3
	timeoutMS := 1000
	if n, ok := p["count"].(float64); ok {
		if n != math.Trunc(n) {
			return nil, errors.New("count must be an integer")
		}
		count = int(n)
	}
	if n, ok := p["timeout_ms"].(float64); ok {
		if n != math.Trunc(n) {
			return nil, errors.New("timeout_ms must be an integer")
		}
		timeoutMS = int(n)
	}
	if count < 1 || count > 10 || timeoutMS < 100 || timeoutMS > 5000 {
		return nil, errors.New("count must be 1..10 and timeout_ms 100..5000")
	}
	timeout := time.Duration(timeoutMS) * time.Millisecond
	var probe func(int) (time.Duration, error)
	cleanup := func() {}
	switch method {
	case "tcp":
		if e := validNetworkAddress(target, false); e != nil {
			return nil, e
		}
		probe = func(_ int) (time.Duration, error) {
			start := time.Now()
			c, e := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", target)
			elapsed := time.Since(start)
			if c != nil {
				c.Close()
			}
			return elapsed, e
		}
	case "icmp":
		var e error
		probe, cleanup, e = icmpProbe(ctx, target, timeout)
		if e != nil {
			return nil, e
		}
	default:
		return nil, errors.New("quality method must be tcp or icmp")
	}
	defer cleanup()
	samples := []map[string]any{}
	latencies := []float64{}
	var sum, jitter float64
	for i := 0; i < count; i++ {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		duration, e := probe(i + 1)
		item := map[string]any{"sequence": i + 1, "success": e == nil}
		if e != nil {
			item["error"] = e.Error()
		} else {
			ms := float64(duration.Microseconds()) / 1000
			item["latency_ms"] = ms
			sum += ms
			if len(latencies) > 0 {
				jitter += math.Abs(ms - latencies[len(latencies)-1])
			}
			latencies = append(latencies, ms)
		}
		samples = append(samples, item)
	}
	out := map[string]any{"target": target, "method": method, "samples": samples, "sample_count": count, "successful_samples": len(latencies), "failure_percent": float64(count-len(latencies)) * 100 / float64(count), "timestamp": time.Now().Unix()}
	if method == "icmp" {
		out["packet_loss_percent"] = out["failure_percent"]
	} else {
		out["failure_kind"] = "TCP connection failures; not ICMP packet loss"
	}
	if len(latencies) > 0 {
		sort.Float64s(latencies)
		out["average_ms"] = sum / float64(len(latencies))
		out["minimum_ms"] = latencies[0]
		out["maximum_ms"] = latencies[len(latencies)-1]
		out["median_ms"] = latencies[len(latencies)/2]
		if len(latencies) > 1 {
			out["jitter_ms"] = jitter / float64(len(latencies)-1)
		}
	}
	return out, nil
}
func icmpProbe(ctx context.Context, target string, timeout time.Duration) (func(int) (time.Duration, error), func(), error) {
	return icmpProbeWith(ctx, target, timeout, func(network, address string) (icmpSocket, error) { return icmp.ListenPacket(network, address) })
}

type icmpSocket interface {
	ReadFrom([]byte) (int, net.Addr, error)
	WriteTo([]byte, net.Addr) (int, error)
	SetDeadline(time.Time) error
	Close() error
}

func icmpProbeWith(ctx context.Context, target string, timeout time.Duration, open func(string, string) (icmpSocket, error)) (func(int) (time.Duration, error), func(), error) {
	addresses, e := net.DefaultResolver.LookupIPAddr(ctx, target)
	if e != nil {
		return nil, nil, e
	}
	if len(addresses) == 0 {
		return nil, nil, errors.New("ICMP target did not resolve")
	}
	ip := addresses[0]
	network, datagramNetwork, listen, protocol := "ip4:icmp", "udp4", "0.0.0.0", 1
	var requestType icmp.Type = ipv4.ICMPTypeEcho
	var replyType icmp.Type = ipv4.ICMPTypeEchoReply
	if ip.IP.To4() == nil {
		network, datagramNetwork, listen, protocol = "ip6:ipv6-icmp", "udp6", "::", 58
		requestType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
	}
	conn, e := open(network, listen)
	datagram := false
	if e != nil {
		rawError := e
		// These are ICMP echo (ping) sockets, not UDP probes. Linux can
		// permit them through ping_group_range without CAP_NET_RAW.
		conn, e = open(datagramNetwork, listen)
		if e != nil {
			return nil, nil, fmt.Errorf("%w: raw ICMP socket: %v; ICMP ping socket: %v; on Linux, allow the Agent's group in net.ipv4.ping_group_range or grant CAP_NET_RAW", errNetworkUnsupported, rawError, e)
		}
		datagram = true
	}
	var destination net.Addr = &net.IPAddr{IP: ip.IP, Zone: ip.Zone}
	if datagram {
		destination = &net.UDPAddr{IP: ip.IP, Zone: ip.Zone}
	}
	random := make([]byte, 18)
	if _, e = rand.Read(random); e != nil {
		conn.Close()
		return nil, nil, e
	}
	id := int(binary.BigEndian.Uint16(random[:2]))
	payload := random[2:]
	probe := func(seq int) (time.Duration, error) {
		start := time.Now()
		deadline := start.Add(timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if e := conn.SetDeadline(deadline); e != nil {
			return 0, e
		}
		message := icmp.Message{Type: requestType, Code: 0, Body: &icmp.Echo{ID: id, Seq: seq, Data: payload}}
		packet, e := message.Marshal(nil)
		if e != nil {
			return 0, e
		}
		if _, e = conn.WriteTo(packet, destination); e != nil {
			return 0, e
		}
		buffer := make([]byte, 65535)
		for {
			n, source, e := conn.ReadFrom(buffer)
			if e != nil {
				return time.Since(start), e
			}
			var sourceIP net.IP
			switch address := source.(type) {
			case *net.IPAddr:
				sourceIP = address.IP
			case *net.UDPAddr:
				sourceIP = address.IP
			}
			if !sourceIP.Equal(ip.IP) {
				continue
			}
			reply, e := icmp.ParseMessage(protocol, buffer[:n])
			if e != nil || reply.Type != replyType {
				continue
			}
			echo, ok := reply.Body.(*icmp.Echo)
			// Ping sockets may rewrite the identifier. The kernel demultiplexes
			// those replies; still authenticate the source, sequence and random
			// 128-bit payload. Raw sockets must also match our identifier.
			if !ok || (!datagram && echo.ID != id) || echo.Seq != seq || !bytes.Equal(echo.Data, payload) {
				continue
			}
			return time.Since(start), nil
		}
	}
	return probe, func() { conn.Close() }, nil
}
