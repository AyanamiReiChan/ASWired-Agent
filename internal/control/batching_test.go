package control

import (
	"context"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/config"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
)

func TestLargeResultsAreAcknowledgedInSeparateEncryptedReports(t *testing.T) {
	c := New(config.Config{}, &runner{}, "test")
	payload := strings.Repeat("x", 9<<20)
	c.results = []wire.Result{{ID: "one", Status: "success", Data: map[string]any{"body_base64": payload}}, {ID: "two", Status: "success", Data: map[string]any{"body_base64": payload}}}
	if report := c.report(); len(report.Results) != 1 || report.Results[0].ID != "one" {
		t.Fatal("oversized report was not split")
	}
	if e := c.accept(context.Background(), wire.Reply{}); e != nil {
		t.Fatal(e)
	}
	if report := c.report(); len(report.Results) != 1 || report.Results[0].ID != "two" {
		t.Fatal("acknowledging first result discarded second result")
	}
	if e := c.accept(context.Background(), wire.Reply{}); e != nil {
		t.Fatal(e)
	}
	if len(c.results) != 0 {
		t.Fatal("acknowledged result not removed")
	}
	c.results = []wire.Result{{ID: "oversized", Status: "success", Data: map[string]any{"data": strings.Repeat("x", wire.MaxPacket)}}}
	if report := c.report(); len(report.Results) != 1 || report.Results[0].Status != "failed" {
		t.Fatal("unsendable result caused endless reconnect loop")
	}
}
