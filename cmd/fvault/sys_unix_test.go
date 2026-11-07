//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// detach removes the controlling terminal so a test can never block on, or
// read from, /dev/tty.
func detach(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
