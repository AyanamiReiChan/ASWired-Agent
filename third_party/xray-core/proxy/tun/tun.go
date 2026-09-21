package tun

type Tun interface {
	Start() error
	Close() error
}

type TunOptions struct {
	Name string
	MTU  uint32
}
