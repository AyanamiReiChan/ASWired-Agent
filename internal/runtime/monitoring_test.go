package runtime

import (
	"context"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
)

func TestManagementSnapshotDoesNotCollectHostMetrics(t *testing.T) {
	r := newTestRuntime(t)
	observation := r.Snapshot()
	for _, key := range []string{"cpu_percent", "memory_used", "disk_used", "interfaces", "hostname", "network_rx_bytes", "network_tx_bytes"} {
		if _, exists := observation[key]; exists {
			t.Fatalf("host metric %q still collected", key)
		}
	}
	if observation["core"] == nil || observation["network_forward"] == nil {
		t.Fatal("management state removed")
	}
	if r.Capabilities()["native_probe"] {
		t.Fatal("Native probe capability still advertised")
	}
	if result := r.Handle(context.Background(), wire.Command{ID: "retired", Action: "probe.sample"}); result.Status != "unsupported" {
		t.Fatal("retired probe still runs")
	}
}
