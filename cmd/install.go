//go:build windows

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

const (
	shellKeyPath   = `*\shell\SmartExtract`
	commandSubKey  = "command"
	menuLabel      = "智能解压"
	multiSelectVal = "MultiSelectModel"
	multiSelectKey = "Player"
)

// Install registers the context menu entry in the Windows registry.
func Install() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("getting executable path: %w", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("resolving executable path: %w", err)
	}

	// Open HKCR
	hkcr, err := registry.OpenKey(registry.CLASSES_ROOT, "", registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("opening HKCR: %w", err)
	}
	defer hkcr.Close()

	// Create the shell key: HKCR\*\shell\SmartExtract
	shellKey, _, err := registry.CreateKey(hkcr, shellKeyPath, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("creating shell key: %w", err)
	}
	defer shellKey.Close()

	// Set the display name
	if err := shellKey.SetStringValue("", menuLabel); err != nil {
		return fmt.Errorf("setting menu label: %w", err)
	}

	// Set MultiSelectModel = Player (called once per file for multi-select)
	if err := shellKey.SetStringValue(multiSelectVal, multiSelectKey); err != nil {
		return fmt.Errorf("setting MultiSelectModel: %w", err)
	}

	// Create the command subkey
	cmdKey, _, err := registry.CreateKey(shellKey, commandSubKey, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("creating command key: %w", err)
	}
	defer cmdKey.Close()

	// Set the command: "<exe_path>" "%1"
	command := fmt.Sprintf(`"%s" "%%1"`, exePath)
	if err := cmdKey.SetStringValue("", command); err != nil {
		return fmt.Errorf("setting command: %w", err)
	}

	fmt.Printf("✓ 已安装上下文菜单项\n")
	fmt.Printf("  路径: HKCR\\%s\n", shellKeyPath)
	fmt.Printf("  命令: %s\n", command)
	return nil
}

// Uninstall removes the context menu entry from the Windows registry.
func Uninstall() error {
	hkcr, err := registry.OpenKey(registry.CLASSES_ROOT, "", registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("opening HKCR: %w", err)
	}
	defer hkcr.Close()

	// Delete command subkey first
	cmdPath := shellKeyPath + `\` + commandSubKey
	if err := registry.DeleteKey(hkcr, cmdPath); err != nil && !isNotFoundErr(err) {
		return fmt.Errorf("deleting command key: %w", err)
	}

	// Delete the shell key
	if err := registry.DeleteKey(hkcr, shellKeyPath); err != nil && !isNotFoundErr(err) {
		return fmt.Errorf("deleting shell key: %w", err)
	}

	fmt.Println("✓ 已卸载上下文菜单项")
	return nil
}

func isNotFoundErr(err error) bool {
	return err == registry.ErrNotExist
}
