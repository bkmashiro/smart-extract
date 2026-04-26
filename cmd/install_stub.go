//go:build !windows

package cmd

import "fmt"

// Install is a stub for non-Windows platforms
func Install() error {
	return fmt.Errorf("registry operations are only supported on Windows")
}

// Uninstall is a stub for non-Windows platforms
func Uninstall() error {
	return fmt.Errorf("registry operations are only supported on Windows")
}
