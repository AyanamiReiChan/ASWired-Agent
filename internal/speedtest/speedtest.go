package speedtest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/mihomoapi"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Binary               string   `json:"mihomo_binary"`
	SHA256               string   `json:"mihomo_sha256"`
	Version              string   `json:"mihomo_version"`
	DataDir              string   `json:"data_dir"`
	SourceID             string   `json:"server_id"`
	SourceMode           string   `json:"source_mode"`
	SourceAllowedOrigins []string `json:"source_allowed_origins,omitempty"`
	SourceAllowPrivate   bool     `json:"source_allow_private,omitempty"`
}
type Runner struct {
	cfg     Config
	mu      sync.Mutex
	version string
}

func New(cfg Config) (*Runner, error) {
	if cfg.Binary == "" || len(cfg.SHA256) != 64 || cfg.Version == "" {
		return nil, errors.New("mihomo_binary, exact mihomo_version and mihomo_sha256 are required")
	}
	if cfg.DataDir == "" {
		return nil, errors.New("speedtest data_dir is required")
	}
	if cfg.SourceMode == "" {
		cfg.SourceMode = "home"
	}
	if cfg.SourceMode != "home" && cfg.SourceMode != "controller" {
		return nil, errors.New("source_mode must be home or controller")
	}
	if e := os.MkdirAll(cfg.DataDir, 0700); e != nil {
		return nil, e
	}
	r := &Runner{cfg: cfg}
	if e := r.verify(); e != nil {
		return nil, e
	}
	return r, nil
}
func (r *Runner) verify() error {
	f, e := os.Open(r.cfg.Binary)
	if e != nil {
		return e
	}
	hash := sha256.New()
	_, e = io.Copy(hash, f)
	f.Close()
	if e != nil {
		return e
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), r.cfg.SHA256) {
		return errors.New("mihomo binary SHA256 does not match the pinned artifact")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, r.cfg.Binary, "-v").CombinedOutput()
	if e != nil {
		return errors.New("mihomo version command failed")
	}
	version := strings.TrimSpace(string(b))
	matched := false
	for _, part := range strings.Fields(version) {
		if part == r.cfg.Version {
			matched = true
		}
	}
	if !matched {
		return errors.New("mihomo version does not match the configured version")
	}
	r.version = version
	return nil
}
func (r *Runner) Snapshot() map[string]any {
	return map[string]any{"source_mode": r.cfg.SourceMode, "source_id": r.cfg.SourceID, "platform": runtime.GOOS, "arch": runtime.GOARCH, "mihomo_version": r.version, "mihomo_sha256": r.cfg.SHA256, "timestamp": time.Now().UnixMilli()}
}
func (r *Runner) Capabilities() map[string]bool {
	return map[string]bool{"speedtest": true, "speedtest_bounded": true, "source_fetch": true, "core_config": false}
}
func (r *Runner) Handle(ctx context.Context, c wire.Command) wire.Result {
	if c.Action != "speedtest.run" && c.Action != "source.fetch" {
		return wire.Result{ID: c.ID, Status: "unsupported", Error: "this home client only accepts speedtest.run and source.fetch"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var data map[string]any
	var e error
	if c.Action == "source.fetch" {
		data, e = r.fetchSource(ctx, c.Params)
	} else {
		data, e = r.measure(ctx, c.Params)
	}
	result := wire.Result{ID: c.ID, Status: "success", Data: data}
	if e != nil {
		result.Status = "failed"
		result.Error = e.Error()
	}
	return result
}

func (r *Runner) measure(ctx context.Context, p map[string]any) (map[string]any, error) {
	if e := r.verify(); e != nil {
		return nil, e
	}
	node, ok := p["node"].(map[string]any)
	if !ok {
		return nil, errors.New("node must be a Clash proxy object")
	}
	kind, _ := node["type"].(string)
	if kind == "" || kind == "direct" || kind == "reject" || kind == "pass" {
		return nil, errors.New("a real proxy node is required")
	}
	target, _ := p["url"].(string)
	u, e := url.Parse(target)
	if e != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("url must be an HTTP(S) download URL")
	}
	parallel := 1
	if n, ok := p["parallel"].(float64); ok {
		parallel = int(n)
	}
	if parallel != 1 && parallel != 8 && parallel != 16 && parallel != 32 && parallel != 64 {
		return nil, errors.New("parallel must be 1, 8, 16, 32 or 64")
	}
	seconds := 8
	if n, ok := p["duration_seconds"].(float64); ok {
		seconds = int(n)
	}
	if seconds < 1 || seconds > 30 {
		return nil, errors.New("duration_seconds must be 1..30")
	}
	budget := int64(0)
	if n, ok := p["download_bytes"].(float64); ok {
		if n != 1<<20 && n != 4<<20 && n != 8<<20 && n != 16<<20 {
			return nil, errors.New("download_bytes must be 1, 4, 8 or 16 MiB")
		}
		budget = int64(n)
	}
	latencyOnly, _ := p["latency_only"].(bool)
	dir, e := os.MkdirTemp(r.cfg.DataDir, "measurement-")
	if e != nil {
		return nil, e
	}
	defer func() {
		rel, e := filepath.Rel(r.cfg.DataDir, dir)
		if e == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			_ = os.RemoveAll(dir)
		}
	}()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return nil, e
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	apiListener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return nil, e
	}
	apiAddress := apiListener.Addr().String()
	apiListener.Close()
	var secretBytes [32]byte
	if _, e = rand.Read(secretBytes[:]); e != nil {
		return nil, e
	}
	apiSecret := hex.EncodeToString(secretBytes[:])
	copyNode := map[string]any{}
	for k, v := range node {
		copyNode[k] = v
	}
	copyNode["name"] = "ASWired-measurement"
	configuration := map[string]any{"mixed-port": port, "allow-lan": false, "bind-address": "127.0.0.1", "mode": "rule", "log-level": "silent", "ipv6": true, "dns": map[string]any{"enable": false}, "proxies": []any{copyNode}, "rules": []string{"MATCH,ASWired-measurement"}}
	configuration["external-controller"] = apiAddress
	configuration["secret"] = apiSecret
	configuration["external-controller-cors"] = map[string]any{"allow-origins": []string{}}
	b, e := json.Marshal(configuration)
	if e != nil {
		return nil, e
	}
	path := filepath.Join(dir, "config.json")
	if e = os.WriteFile(path, b, 0600); e != nil {
		return nil, e
	}
	lifetime, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	test := exec.CommandContext(lifetime, r.cfg.Binary, "-t", "-d", dir, "-f", path)
	if e = test.Run(); e != nil {
		return nil, errors.New("mihomo rejected the test node configuration")
	}
	process := exec.CommandContext(lifetime, r.cfg.Binary, "-d", dir, "-f", path)
	if e = process.Start(); e != nil {
		return nil, e
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	defer func() { cancel(); <-done }()
	address := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	ready := false
	for i := 0; i < 100; i++ {
		conn, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			conn.Close()
			request, e := http.NewRequestWithContext(ctx, "GET", "http://"+apiAddress+"/proxies/ASWired-measurement", nil)
			if e != nil {
				return nil, e
			}
			request.Header.Set("Authorization", "Bearer "+apiSecret)
			apiClient := http.Client{Timeout: 100 * time.Millisecond, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
			response, e := apiClient.Do(request)
			if e == nil {
				ready = response.StatusCode == 200
				response.Body.Close()
			}
			if ready {
				break
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !ready {
		return nil, errors.New("mihomo proxy listener did not become ready")
	}
	if e = mihomoapi.AwaitConfiguration(ctx, apiAddress, apiSecret); e != nil {
		return nil, e
	}
	proxyURL, _ := url.Parse("http://" + address)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), MaxIdleConnsPerHost: parallel, ResponseHeaderTimeout: 10 * time.Second, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return errors.New("unsupported redirect")
		}
		return nil
	}}
	result := r.Snapshot()
	result["parallel"] = parallel
	result["target_url"] = target
	result["direct_fallback"] = false
	if ipURL, _ := p["ip_check_url"].(string); ipURL != "" {
		result["exit_ip_verified"] = false
		ip, e := proxyExitIP(ctx, client, ipURL)
		if e != nil {
			result["exit_ip_error"] = e.Error()
		} else {
			result["exit_ip"] = ip
			result["ip"] = ip
			result["exit_ip_verified"] = true
		}
	}
	latencies := []float64{}
	for i := 0; i < 3; i++ {
		sampleCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		req, e := http.NewRequestWithContext(sampleCtx, http.MethodHead, target, nil)
		if e != nil {
			stop()
			return result, e
		}
		start := time.Now()
		response, e := client.Do(req)
		if e != nil {
			stop()
			return result, fmt.Errorf("proxy latency request failed: %w", e)
		}
		response.Body.Close()
		stop()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return result, fmt.Errorf("download target returned HTTP %d", response.StatusCode)
		}
		latencies = append(latencies, float64(time.Since(start).Microseconds())/1000)
	}
	result["latency_method"] = "proxied_http_response_headers"
	result["latency_samples_ms"] = latencies
	result["latency_only"] = latencyOnly
	result["download_limit_bytes"] = budget
	if latencyOnly {
		result["completed_at"] = time.Now().UnixMilli()
		return result, nil
	}
	bytes, elapsed, failureCount := downloadMeasurement(ctx, client, target, seconds, parallel, budget)
	result["download_bytes"] = bytes
	result["elapsed_seconds"] = elapsed
	result["download_mbps"] = float64(bytes) * 8 / elapsed / 1e6
	result["request_failures"] = failureCount
	result["completed_at"] = time.Now().UnixMilli()
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if bytes == 0 || failureCount > 0 || (budget > 0 && bytes < budget) {
		return result, errors.New("proxy download did not complete cleanly")
	}
	return result, nil
}

func proxyExitIP(ctx context.Context, client *http.Client, value string) (string, error) {
	u, e := sourceURL(value)
	if e != nil {
		return "", errors.New("ip_check_url must be an HTTP(S) URL")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if e != nil {
		return "", e
	}
	res, e := client.Do(req)
	if e != nil {
		return "", errors.New("proxied exit IP request failed")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", errors.New("exit IP service returned a non-success status")
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, 4097))
	if e != nil || len(b) > 4096 {
		return "", errors.New("exit IP service response is invalid or too large")
	}
	value = strings.TrimSpace(string(b))
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	var object map[string]any
	if json.Unmarshal(b, &object) == nil {
		for _, key := range []string{"ip", "address", "query"} {
			value, _ := object[key].(string)
			if ip := net.ParseIP(strings.TrimSpace(value)); ip != nil {
				return ip.String(), nil
			}
		}
	}
	return "", errors.New("exit IP service did not return an IP address")
}
func downloadMeasurement(ctx context.Context, client *http.Client, target string, seconds, parallel int, budget int64) (int64, float64, int64) {
	measurement, stop := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer stop()
	var count atomic.Int64
	var failures atomic.Int64
	start := time.Now()
	var workers sync.WaitGroup
	for i := 0; i < parallel; i++ {
		workerBudget := int64(0)
		if budget > 0 {
			workerBudget = budget / int64(parallel)
			if int64(i) < budget%int64(parallel) {
				workerBudget++
			}
		}
		workers.Go(func() {
			remaining := workerBudget
			buffer := make([]byte, 32<<10)
			for measurement.Err() == nil && (budget == 0 || remaining > 0) {
				request, e := http.NewRequestWithContext(measurement, http.MethodGet, target, nil)
				if e != nil {
					failures.Add(1)
					return
				}
				response, e := client.Do(request)
				if e != nil {
					if measurement.Err() == nil {
						failures.Add(1)
					}
					return
				}
				if response.StatusCode < 200 || response.StatusCode >= 300 {
					response.Body.Close()
					failures.Add(1)
					return
				}
				var body io.Reader = response.Body
				if budget > 0 {
					body = io.LimitReader(body, remaining)
				}
				responseBytes := int64(0)
				for {
					n, e := body.Read(buffer)
					responseBytes += int64(n)
					remaining -= int64(n)
					count.Add(int64(n))
					if e != nil {
						response.Body.Close()
						if e != io.EOF && measurement.Err() == nil {
							failures.Add(1)
						}
						break
					}
				}
				if responseBytes == 0 {
					failures.Add(1)
					return
				}
			}
		})
	}
	workers.Wait()
	elapsed := time.Since(start).Seconds()
	return count.Load(), elapsed, failures.Load()
}
