//go:build windows

package auxiliary

import (
	"golang.org/x/sys/windows"
	"os/exec"
	"syscall"
	"unsafe"
)

func hideProcess(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }

func ownChild(c *exec.Cmd) (func(), error) {
	job, e := windows.CreateJobObject(nil, nil)
	if e != nil {
		return nil, e
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, e = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); e != nil {
		windows.CloseHandle(job)
		return nil, e
	}
	process, e := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(c.Process.Pid))
	if e != nil {
		windows.CloseHandle(job)
		return nil, e
	}
	defer windows.CloseHandle(process)
	if e = windows.AssignProcessToJobObject(job, process); e != nil {
		windows.CloseHandle(job)
		return nil, e
	}
	return func() { windows.CloseHandle(job) }, nil
}
