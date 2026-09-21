package runtime

import (
	"errors"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/logfiles"
	"github.com/AyanamiReiChan/ASWired-Agent/internal/wire"
	xlog "github.com/xtls/xray-core/app/log"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const managedLogType = xlog.LogType(100)

var managedLogWriters sync.Map

type managedLogHandler struct{ writer *logfiles.Manager }

func (h *managedLogHandler) Handle(message clog.Message) {
	level := "INFO"
	if general, ok := message.(*clog.GeneralMessage); ok {
		level = strings.ToUpper(general.Severity.String())
	}
	_ = h.writer.Append(map[string]any{"time": time.Now().UTC(), "level": level, "msg": message.String()})
}
func init() {
	_ = xlog.RegisterHandlerCreator(managedLogType, func(_ xlog.LogType, options xlog.HandlerCreatorOptions) (clog.Handler, error) {
		value, ok := managedLogWriters.Load(options.Path)
		if !ok {
			return nil, errors.New("managed Xray logger unavailable")
		}
		return &managedLogHandler{value.(*logfiles.Manager)}, nil
	})
}
func (r *Runtime) initLogs() error {
	r.logs = map[string]*logfiles.Manager{}
	for _, name := range []string{"agent", "xray-access", "xray-error"} {
		manager, err := logfiles.OpenNamed(filepath.Join(r.cfg.DataDir, "logs"), name+".log", 50<<20, 5)
		if err != nil {
			r.closeLogs()
			return err
		}
		r.logs[name] = manager
		managedLogWriters.Store(filepath.Join(r.cfg.DataDir, "logs", name+".log"), manager)
	}
	return nil
}
func (r *Runtime) closeLogs() {
	for name, manager := range r.logs {
		managedLogWriters.Delete(filepath.Join(r.cfg.DataDir, "logs", name+".log"))
		manager.Close()
	}
}
func (r *Runtime) LogWriter() io.Writer { return r.logs["agent"] }
func (r *Runtime) managedCoreLogs(config *core.Config) {
	for i, app := range config.App {
		value, err := app.GetInstance()
		if err != nil {
			continue
		}
		logging, ok := value.(*xlog.Config)
		if !ok {
			continue
		}
		logging.AccessLogType = managedLogType
		logging.AccessLogPath = filepath.Join(r.cfg.DataDir, "logs", "xray-access.log")
		logging.ErrorLogType = managedLogType
		logging.ErrorLogPath = filepath.Join(r.cfg.DataDir, "logs", "xray-error.log")
		config.App[i] = serial.ToTypedMessage(logging)
		return
	}
	config.App = append(config.App, serial.ToTypedMessage(&xlog.Config{AccessLogType: managedLogType, AccessLogPath: filepath.Join(r.cfg.DataDir, "logs", "xray-access.log"), ErrorLogType: managedLogType, ErrorLogPath: filepath.Join(r.cfg.DataDir, "logs", "xray-error.log"), ErrorLogLevel: clog.Severity_Warning}))
}
func (r *Runtime) logCommand(c wire.Command) (map[string]any, error) {
	stream, _ := c.Params["stream"].(string)
	if stream == "" {
		stream = "agent"
	}
	manager := r.logs[stream]
	if manager == nil {
		return nil, errors.New("unknown log stream")
	}
	if c.Action == "logs.remove" {
		confirmed, _ := c.Params["confirm"].(bool)
		all, _ := c.Params["all"].(bool)
		name, _ := c.Params["name"].(string)
		if !confirmed || (all && name != "") || (!all && name == "") {
			return nil, errors.New("confirm an explicit log file scope")
		}
		var err error
		if all {
			err = manager.Clear()
		} else {
			err = manager.Delete(name)
		}
		if err != nil {
			return nil, err
		}
	}
	limit := 200
	if n, ok := c.Params["limit"].(float64); ok {
		limit = int(n)
	}
	if n, ok := c.Params["limit"].(int); ok {
		limit = n
	}
	tail, err := manager.Read(limit)
	if err != nil {
		return nil, err
	}
	inventory, err := manager.List()
	if err != nil {
		return nil, err
	}
	return map[string]any{"lines": tail.Lines, "truncated": tail.Truncated, "inventory": inventory}, nil
}
