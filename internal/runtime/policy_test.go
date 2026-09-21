package runtime

import (
	"context"
	"testing"
	"time"
)

func TestPoliciesShareConnectionsAndIPsAcrossCredentials(t *testing.T) {
	p := newPolicies()
	p.apply([]UserPolicy{{UserID: "one-user", Emails: []string{"instance-a", "instance-b"}, ConnectionLimit: 2, IPLimit: 1}})
	one, e := p.Acquire(context.Background(), "instance-a", "::ffff:192.0.2.1")
	if e != nil {
		t.Fatal(e)
	}
	two, e := p.Acquire(context.Background(), "instance-b", "192.0.2.1")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Acquire(context.Background(), "instance-a", "192.0.2.1"); e == nil {
		t.Fatal("third connection bypassed shared user cap")
	}
	p.apply([]UserPolicy{{UserID: "one-user", Emails: []string{"instance-a", "instance-b"}, ConnectionLimit: 1, IPLimit: 1}})
	if p.state("instance-a").connections != 2 {
		t.Fatal("lowering limit disconnected or lost established connections")
	}
	one()
	two()
	three, e := p.Acquire(context.Background(), "instance-b", "192.0.2.2")
	if e != nil {
		t.Fatal(e)
	}
	three()
	three()
	if p.state("instance-a").connections != 0 {
		t.Fatal("release is not idempotent")
	}
}
func TestPolicyReassignmentKeepsActiveConnections(t *testing.T) {
	p := newPolicies()
	release, e := p.Acquire(context.Background(), "email", "192.0.2.1")
	if e != nil {
		t.Fatal(e)
	}
	p.apply([]UserPolicy{{UserID: "user", Emails: []string{"email"}, ConnectionLimit: 1}})
	if _, e = p.Acquire(context.Background(), "email", "192.0.2.1"); e == nil {
		t.Fatal("existing unassigned connection was lost during assignment")
	}
	release()
	if p.state("email").connections != 0 {
		t.Fatal("reassigned connection not released")
	}
}
func TestSharedBucketAndDisable(t *testing.T) {
	p := newPolicies()
	p.apply([]UserPolicy{{UserID: "u", Emails: []string{"a", "b"}, BytesPerSecond: 65536}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if e := p.Transfer(ctx, "a", 65536); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	if e := p.Transfer(ctx, "b", 32768); e != nil {
		t.Fatal(e)
	}
	if time.Since(start) < 400*time.Millisecond {
		t.Fatal("two credentials obtained separate rate budgets")
	}
	p.apply([]UserPolicy{{UserID: "u", Emails: []string{"a", "b"}, Disabled: true}})
	if e := p.Transfer(ctx, "a", 1); e == nil {
		t.Fatal("disabled user transferred data")
	}
}
func TestDownloadPolicyDoesNotChargeUploadButStillRejectsDisabled(t *testing.T) {
	p := newPolicies()
	p.apply([]UserPolicy{{UserID: "u", Emails: []string{"a"}, BytesPerSecond: 65536, Direction: "download"}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := p.TransferDirection(ctx, "a", 8<<20, "upload"); e != nil {
		t.Fatal("upload charged download budget", e)
	}
	if e := p.TransferDirection(ctx, "a", 65536, "download"); e != nil {
		t.Fatal("upload consumed initial download burst", e)
	}
	start := time.Now()
	if e := p.TransferDirection(ctx, "a", 16384, "download"); e != nil {
		t.Fatal(e)
	}
	if time.Since(start) < 200*time.Millisecond {
		t.Fatal("download did not consume bucket")
	}
	p.apply([]UserPolicy{{UserID: "u", Emails: []string{"a"}, Direction: "download", Disabled: true}})
	if e := p.TransferDirection(ctx, "a", 1, "upload"); e == nil {
		t.Fatal("download-only policy bypassed disabled state on upload")
	}
}
