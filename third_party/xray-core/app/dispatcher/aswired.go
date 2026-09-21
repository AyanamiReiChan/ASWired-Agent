// SPDX-License-Identifier: MPL-2.0

package dispatcher

import (
	"context"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/aswired"
	"github.com/xtls/xray-core/common/buf"
	"time"
)

type aswiredWriter struct {
	ctx       context.Context
	writer    buf.Writer
	direction string
}

type aswiredReader struct {
	ctx    context.Context
	reader buf.TimeoutReader
}

func (r *aswiredReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, e := r.reader.ReadMultiBuffer()
	if !mb.IsEmpty() {
		if x := aswired.TransferDirection(r.ctx, int64(mb.Len()), "upload"); x != nil {
			buf.ReleaseMulti(mb)
			return nil, x
		}
	}
	return mb, e
}
func (r *aswiredReader) ReadMultiBufferTimeout(t time.Duration) (buf.MultiBuffer, error) {
	mb, e := r.reader.ReadMultiBufferTimeout(t)
	if !mb.IsEmpty() {
		if x := aswired.TransferDirection(r.ctx, int64(mb.Len()), "upload"); x != nil {
			buf.ReleaseMulti(mb)
			return nil, x
		}
	}
	return mb, e
}
func (r *aswiredReader) Interrupt() { common.Interrupt(r.reader) }

func (w *aswiredWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if err := aswired.TransferDirection(w.ctx, int64(mb.Len()), w.direction); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	return w.writer.WriteMultiBuffer(mb)
}
func (w *aswiredWriter) Close() error { return common.Close(w.writer) }
func (w *aswiredWriter) Interrupt()   { common.Interrupt(w.writer) }
func limitWriter(ctx context.Context, w buf.Writer, direction string) buf.Writer {
	if !aswired.Managed(ctx) {
		return w
	}
	if stats, ok := w.(*SizeStatWriter); ok {
		stats.Writer = &aswiredWriter{ctx, stats.Writer, direction}
		return stats
	}
	return &aswiredWriter{ctx, w, direction}
}
