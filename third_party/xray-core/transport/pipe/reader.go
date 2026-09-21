package pipe

import (
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type Reader struct {
	pipe *pipe
}

func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.pipe.ReadMultiBuffer()
}

func (r *Reader) ReadMultiBufferTimeout(d time.Duration) (buf.MultiBuffer, error) {
	return r.pipe.ReadMultiBufferTimeout(d)
}

func (r *Reader) Interrupt() {
	r.pipe.Interrupt()
}

func (r *Reader) ReturnAnError(err error) {
	r.pipe.errChan <- err
}

func (r *Reader) Recover() (err error) {
	select {
	case err = <-r.pipe.errChan:
	default:
	}
	return
}
