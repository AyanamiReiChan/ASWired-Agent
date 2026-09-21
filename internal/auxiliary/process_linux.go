//go:build linux

package auxiliary

import (
	"os/exec"
	"syscall"
)

func hideProcess(c *exec.Cmd)              { c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL} }
func ownChild(c *exec.Cmd) (func(), error) { return func() {}, nil }
