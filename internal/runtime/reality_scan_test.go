package runtime

import (
	"context"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	"testing"
	"time"
)

func TestRealityScanRequiresUnexpiredDeadline(t *testing.T) {
	r := newTestRuntime(t)
	for _, expiry := range []string{"", "invalid", time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)} {
		result := r.Handle(context.Background(), wire.Command{ID: "expired-scan-" + expiry, Action: "reality.scan", Params: map[string]any{"targets": "127.0.0.1:443", "expiresAt": expiry}})
		if result.Status != "failed" {
			t.Fatalf("expired scan accepted: %+v", result)
		}
	}
}
