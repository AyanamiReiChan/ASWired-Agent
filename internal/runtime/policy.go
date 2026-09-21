package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/time/rate"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type UserPolicy struct {
	UserID          string   `json:"user_id"`
	Emails          []string `json:"emails"`
	BytesPerSecond  int64    `json:"bytes_per_second"`
	ConnectionLimit int      `json:"connection_limit"`
	IPLimit         int      `json:"ip_limit"`
	Disabled        bool     `json:"disabled"`
	Direction       string   `json:"direction,omitempty"`
}
type policyState struct {
	value       UserPolicy
	limiter     *rate.Limiter
	connections int
	ips         map[string]int
}
type policies struct {
	spliceLimitedBytes   atomic.Int64
	spliceUnboundedBytes atomic.Int64
	mu                   sync.Mutex
	byUser               map[string]*policyState
	byEmail              map[string]string
	active               map[uint64]admission
	unbounded            map[uint64]admission
	sequence             uint64
}

func (p *policies) ObserveSplice(direction string, limited bool, bytes int64) {
	if direction != "download" {
		return
	}
	if limited {
		p.spliceLimitedBytes.Add(bytes)
	} else {
		p.spliceUnboundedBytes.Add(bytes)
	}
}

func (p *policies) spliceObservation() map[string]any {
	return map[string]any{"limited_download_bytes": p.spliceLimitedBytes.Load(), "unbounded_download_bytes": p.spliceUnboundedBytes.Load(), "scope": "current_agent_process"}
}

type admission struct {
	email, ip string
	terminate func()
}

func newPolicies() *policies {
	return &policies{byUser: map[string]*policyState{}, byEmail: map[string]string{}, active: map[uint64]admission{}, unbounded: map[uint64]admission{}}
}
func boundedPolicy(v UserPolicy) bool {
	return v.Disabled || v.BytesPerSecond > 0 || v.ConnectionLimit > 0 || v.IPLimit > 0
}
func (p *policies) BeginUnboundedSplice(ctx context.Context, email string, terminate func()) (func(), bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx.Err() != nil || boundedPolicy(p.state(email).value) {
		return nil, false
	}
	p.sequence++
	id := p.sequence
	p.unbounded[id] = admission{email: email, terminate: terminate}
	var once sync.Once
	return func() { once.Do(func() { p.mu.Lock(); delete(p.unbounded, id); p.mu.Unlock() }) }, true
}
func (p *policies) state(email string) *policyState {
	id := p.byEmail[email]
	if id == "" {
		id = email
	}
	s := p.byUser[id]
	if s == nil {
		s = &policyState{value: UserPolicy{UserID: id}, limiter: rate.NewLimiter(rate.Inf, 64<<10), ips: map[string]int{}}
		p.byUser[id] = s
	}
	return s
}
func (p *policies) Acquire(ctx context.Context, email, ip string) (func(), error) {
	return p.AdmitSession(ctx, email, ip, nil)
}
func (p *policies) AdmitSession(ctx context.Context, email, ip string, terminate func()) (func(), error) {
	if addr, e := netip.ParseAddr(ip); e == nil {
		ip = addr.Unmap().String()
	}
	p.mu.Lock()
	s := p.state(email)
	if s.value.Disabled {
		p.mu.Unlock()
		return nil, errors.New("user is disabled")
	}
	if s.value.ConnectionLimit > 0 && s.connections >= s.value.ConnectionLimit {
		p.mu.Unlock()
		return nil, errors.New("user connection limit reached")
	}
	if s.value.IPLimit > 0 && s.ips[ip] == 0 && len(s.ips) >= s.value.IPLimit {
		p.mu.Unlock()
		return nil, errors.New("user simultaneous IP limit reached")
	}
	s.connections++
	s.ips[ip]++
	p.sequence++
	id := p.sequence
	p.active[id] = admission{email, ip, terminate}
	p.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			s := p.state(email)
			delete(p.active, id)
			s.connections--
			s.ips[ip]--
			if s.ips[ip] <= 0 {
				delete(s.ips, ip)
			}
		})
	}, nil
}
func (p *policies) Transfer(ctx context.Context, email string, n int64) error {
	return p.TransferDirection(ctx, email, n, "both")
}
func (p *policies) TransferDirection(ctx context.Context, email string, n int64, direction string) error {
	for n > 0 {
		p.mu.Lock()
		s := p.state(email)
		disabled := s.value.Disabled
		skipRate := s.value.Direction == "download" && direction == "upload"
		limiter := s.limiter
		p.mu.Unlock()
		if disabled {
			return errors.New("user disabled during transfer")
		}
		if skipRate {
			return nil
		}
		chunk := n
		if chunk > 64<<10 {
			chunk = 64 << 10
		}
		if e := limiter.WaitN(ctx, int(chunk)); e != nil {
			return e
		}
		n -= chunk
	}
	return nil
}
func validatePolicies(list []UserPolicy) error {
	emails := map[string]bool{}
	users := map[string]bool{}
	for _, v := range list {
		if v.Direction != "" && v.Direction != "both" && v.Direction != "download" {
			return errors.New("policy direction must be both or download")
		}
		if v.UserID == "" || users[v.UserID] {
			return errors.New("unique user_id required")
		}
		users[v.UserID] = true
		if v.BytesPerSecond < 0 || v.ConnectionLimit < 0 || v.IPLimit < 0 {
			return errors.New("policy limits cannot be negative")
		}
		for _, email := range v.Emails {
			if email == "" || emails[email] {
				return errors.New("email must be nonempty and belong to one user")
			}
			emails[email] = true
		}
	}
	return nil
}
func (p *policies) apply(list []UserPolicy) {
	p.mu.Lock()
	var terminate []func()
	defer func() {
		p.mu.Unlock()
		for _, closeConnection := range terminate {
			closeConnection()
		}
	}()
	desired := map[string]bool{}
	for _, v := range list {
		desired[v.UserID] = true
	}
	for _, s := range p.byUser {
		if !desired[s.value.UserID] {
			s.value = UserPolicy{UserID: s.value.UserID}
			s.limiter.SetLimit(rate.Inf)
		}
		s.connections = 0
		s.ips = map[string]int{}
	}
	p.byEmail = map[string]string{}
	for _, v := range list {
		s := p.byUser[v.UserID]
		if s == nil {
			s = &policyState{limiter: rate.NewLimiter(rate.Inf, 64<<10), ips: map[string]int{}}
			p.byUser[v.UserID] = s
		}
		s.value = v
		limit := rate.Inf
		if v.BytesPerSecond > 0 {
			limit = rate.Limit(v.BytesPerSecond)
		}
		s.limiter.SetLimitAt(time.Now(), limit)
		for _, email := range v.Emails {
			p.byEmail[email] = v.UserID
		}
	}
	for _, a := range p.active {
		s := p.state(a.email)
		s.connections++
		s.ips[a.ip]++
		if s.value.Disabled && a.terminate != nil {
			terminate = append(terminate, a.terminate)
		}
	}
	for _, a := range p.unbounded {
		if boundedPolicy(p.state(a.email).value) && a.terminate != nil {
			terminate = append(terminate, a.terminate)
		}
	}
}
func (p *policies) snapshot() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	items := []map[string]any{}
	for id, s := range p.byUser {
		ips := []string{}
		for ip := range s.ips {
			ips = append(ips, ip)
		}
		items = append(items, map[string]any{"user_id": id, "connections": s.connections, "ips": ips, "policy": s.value})
	}
	return map[string]any{"users": items, "scope": "user_and_physical_node"}
}
func (r *Runtime) applyPolicies(raw any) (map[string]any, error) {
	if raw == nil {
		return nil, errors.New("policies array is required; use [] to clear")
	}
	if r.cfg.XrayMode != "embedded" {
		return nil, errors.New("runtime policies require embedded mode")
	}
	b, e := json.Marshal(raw)
	if e != nil {
		return nil, e
	}
	var list []UserPolicy
	if e = json.Unmarshal(b, &list); e != nil {
		return nil, e
	}
	if e = validatePolicies(list); e != nil {
		return nil, e
	}
	bridged := r.mihomo.BridgeEmails()
	for _, v := range list {
		if v.IPLimit > 0 {
			for _, email := range v.Emails {
				if bridged[email] {
					return nil, errors.New("original-client-IP limits are unsupported for active auxiliary AnyTLS/Snell bridges")
				}
			}
		}
	}
	if e = atomicWrite(filepath.Join(r.cfg.DataDir, "policies.json"), b, 0600); e != nil {
		return nil, e
	}
	r.policies.apply(list)
	return map[string]any{"applied": true, "persisted": true, "users": len(list), "existing_connections": "connection/IP reductions reject new connections; disabled sessions close; activating a policy on an unlimited splice session closes that session so reconnect uses current controls"}, nil
}
func (r *Runtime) loadPolicies() error {
	b, e := os.ReadFile(filepath.Join(r.cfg.DataDir, "policies.json"))
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var list []UserPolicy
	if e = json.Unmarshal(b, &list); e != nil {
		return fmt.Errorf("read policies: %w", e)
	}
	if e = validatePolicies(list); e != nil {
		return e
	}
	r.policies.apply(list)
	return nil
}
