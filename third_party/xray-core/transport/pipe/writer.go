package pipe

import (
	"github.com/xtls/xray-core/common/buf"
)

type Writer struct {
	pipe *pipe
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.pipe.WriteMultiBuffer(mb)
}

func (w *Writer) Close() error {
	return w.pipe.Close()
}

func (w *Writer) Len() int32 {
	return w.pipe.Len()
}

func (w *Writer) Interrupt() {
	w.pipe.Interrupt()
}
