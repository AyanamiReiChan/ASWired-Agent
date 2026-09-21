package bbr

import "github.com/apernet/quic-go/monotime"

type Clock interface {
	Now() monotime.Time
}

type DefaultClock struct{}

var _ Clock = DefaultClock{}

func (DefaultClock) Now() monotime.Time {
	return monotime.Now()
}
