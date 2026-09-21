//go:build !amd64
// +build !amd64

package original

func xorfwd(x []byte) {
	for i := 4; i < len(x); i++ {
		x[i] ^= x[i-4]
	}
}

func xorbkd(x []byte) {
	for i := len(x) - 1; i >= 4; i-- {
		x[i] ^= x[i-4]
	}
}
