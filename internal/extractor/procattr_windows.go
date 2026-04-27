//go:build windows

package extractor

import (
	"os/exec"
	"syscall"
)

// hideCmdWindow sets the CREATE_NO_WINDOW flag so 7z doesn't flash a console.
func hideCmdWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
}
