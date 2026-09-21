//go:build !windows && !linux

package auxiliary

import "os/exec"

func hideProcess(c *exec.Cmd)              {}
func ownChild(c *exec.Cmd) (func(), error) { return func() {}, nil }
