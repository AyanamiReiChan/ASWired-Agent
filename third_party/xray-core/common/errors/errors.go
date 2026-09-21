package errors

import (
	"context"
	"runtime"
	"strings"

	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/serial"
)

const trim = len("github.com/xtls/xray-core/")

type hasInnerError interface {
	Unwrap() error
}

type hasSeverity interface {
	Severity() log.Severity
}

type Error struct {
	prefix   []interface{}
	message  []interface{}
	caller   string
	inner    error
	severity log.Severity
}

func (err *Error) Error() string {
	builder := strings.Builder{}
	for _, prefix := range err.prefix {
		builder.WriteByte('[')
		builder.WriteString(serial.ToString(prefix))
		builder.WriteString("] ")
	}

	if len(err.caller) > 0 {
		builder.WriteString(err.caller)
		builder.WriteString(": ")
	}

	msg := serial.Concat(err.message...)
	builder.WriteString(msg)

	if err.inner != nil {
		builder.WriteString(" > ")
		builder.WriteString(err.inner.Error())
	}

	return builder.String()
}

func (err *Error) Unwrap() error {
	if err.inner == nil {
		return nil
	}
	return err.inner
}

func (err *Error) Base(e error) *Error {
	err.inner = e
	return err
}

func (err *Error) atSeverity(s log.Severity) *Error {
	err.severity = s
	return err
}

func (err *Error) Severity() log.Severity {
	if err.inner == nil {
		return err.severity
	}

	if s, ok := err.inner.(hasSeverity); ok {
		as := s.Severity()
		if as < err.severity {
			return as
		}
	}

	return err.severity
}

func (err *Error) AtDebug() *Error {
	return err.atSeverity(log.Severity_Debug)
}

func (err *Error) AtInfo() *Error {
	return err.atSeverity(log.Severity_Info)
}

func (err *Error) AtWarning() *Error {
	return err.atSeverity(log.Severity_Warning)
}

func (err *Error) AtError() *Error {
	return err.atSeverity(log.Severity_Error)
}

func (err *Error) String() string {
	return err.Error()
}

type ExportOptionHolder struct {
	SessionID uint32
}

type ExportOption func(*ExportOptionHolder)

func New(msg ...interface{}) *Error {
	pc, _, _, _ := runtime.Caller(1)
	details := runtime.FuncForPC(pc).Name()
	if len(details) >= trim {
		details = details[trim:]
	}
	i := strings.Index(details, ".")
	if i > 0 {
		details = details[:i]
	}
	return &Error{
		message:  msg,
		severity: log.Severity_Info,
		caller:   details,
	}
}

func LogDebug(ctx context.Context, msg ...interface{}) {
	doLog(ctx, nil, log.Severity_Debug, msg...)
}

func LogDebugInner(ctx context.Context, inner error, msg ...interface{}) {
	doLog(ctx, inner, log.Severity_Debug, msg...)
}

func LogInfo(ctx context.Context, msg ...interface{}) {
	doLog(ctx, nil, log.Severity_Info, msg...)
}

func LogInfoInner(ctx context.Context, inner error, msg ...interface{}) {
	doLog(ctx, inner, log.Severity_Info, msg...)
}

func LogWarning(ctx context.Context, msg ...interface{}) {
	doLog(ctx, nil, log.Severity_Warning, msg...)
}

func LogWarningInner(ctx context.Context, inner error, msg ...interface{}) {
	doLog(ctx, inner, log.Severity_Warning, msg...)
}

func LogError(ctx context.Context, msg ...interface{}) {
	doLog(ctx, nil, log.Severity_Error, msg...)
}

func LogErrorInner(ctx context.Context, inner error, msg ...interface{}) {
	doLog(ctx, inner, log.Severity_Error, msg...)
}

func doLog(ctx context.Context, inner error, severity log.Severity, msg ...interface{}) {
	pc, _, _, _ := runtime.Caller(2)
	details := runtime.FuncForPC(pc).Name()
	if len(details) >= trim {
		details = details[trim:]
	}
	i := strings.Index(details, ".")
	if i > 0 {
		details = details[:i]
	}
	err := &Error{
		message:  msg,
		severity: severity,
		caller:   details,
		inner:    inner,
	}
	if ctx != nil && ctx != context.Background() {
		id := uint32(c.IDFromContext(ctx))
		if id > 0 {
			err.prefix = append(err.prefix, id)
		}
	}
	log.Record(&log.GeneralMessage{
		Severity: GetSeverity(err),
		Content:  err,
	})
}

func Cause(err error) error {
	if err == nil {
		return nil
	}
L:
	for {
		switch inner := err.(type) {
		case hasInnerError:
			if inner.Unwrap() == nil {
				break L
			}
			err = inner.Unwrap()
		default:
			break L
		}
	}
	return err
}

func GetSeverity(err error) log.Severity {
	if s, ok := err.(hasSeverity); ok {
		return s.Severity()
	}
	return log.Severity_Info
}
