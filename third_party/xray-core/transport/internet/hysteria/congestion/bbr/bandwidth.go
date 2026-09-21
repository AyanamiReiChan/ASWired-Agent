package bbr

import (
	"math"
	"time"

	"github.com/apernet/quic-go/congestion"
)

const (
	infBandwidth = Bandwidth(math.MaxUint64)
)

type Bandwidth uint64

const (
	BitsPerSecond Bandwidth = 1

	BytesPerSecond = 8 * BitsPerSecond
)

func BandwidthFromDelta(bytes congestion.ByteCount, delta time.Duration) Bandwidth {
	return Bandwidth(bytes) * Bandwidth(time.Second) / Bandwidth(delta) * BytesPerSecond
}
