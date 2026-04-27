package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/bkmashiro/smart-extract/cmd"
	"github.com/bkmashiro/smart-extract/internal/config"
	"github.com/bkmashiro/smart-extract/internal/ui"
)

func main() {
	// Determine base directory (next to the exe)
	exePath, err := os.Executable()
	if err != nil {
		fatal("无法确定程序路径: %v", err)
	}
	baseDir := filepath.Dir(exePath)
	config.Init(baseDir)

	args := os.Args[1:]

	if len(args) == 0 {
		ui.AllocConsole()
		fmt.Println("智能解压 - 使用方法:")
		fmt.Println("  smart-extract.exe --install      安装右键菜单")
		fmt.Println("  smart-extract.exe --uninstall    卸载右键菜单")
		fmt.Println("  smart-extract.exe --reset-prefs  重置偏好设置")
		fmt.Println("  smart-extract.exe <archive>      解压文件")
		fmt.Println()
		ui.WaitForKeypress("按 Enter 键关闭...")
		return
	}

	switch args[0] {
	case "--install":
		ui.AllocConsole()
		if err := cmd.Install(); err != nil {
			fatal("安装失败: %v", err)
		}
		ui.WaitForKeypress("")

	case "--uninstall":
		ui.AllocConsole()
		if err := cmd.Uninstall(); err != nil {
			fatal("卸载失败: %v", err)
		}
		ui.WaitForKeypress("")

	case "--reset-prefs":
		ui.AllocConsole()
		if err := config.ResetPreferences(); err != nil {
			fatal("重置偏好失败: %v", err)
		}
		fmt.Println("✓ 偏好设置已重置，下次解压时将重新询问。")
		ui.WaitForKeypress("")

	case "--help", "-h":
		ui.AllocConsole()
		fmt.Println("智能解压 - 使用方法:")
		fmt.Println("  smart-extract.exe --install      安装右键菜单")
		fmt.Println("  smart-extract.exe --uninstall    卸载右键菜单")
		fmt.Println("  smart-extract.exe --reset-prefs  重置偏好设置")
		fmt.Println("  smart-extract.exe <archive>      解压文件")
		fmt.Println("  smart-extract.exe --help         显示帮助")
		fmt.Println()
		ui.WaitForKeypress("")

	default:
		// Extract all provided files
		hasError := false
		for _, archivePath := range args {
			if err := cmd.Extract(archivePath); err != nil {
				ui.AllocConsole()
				fmt.Printf("\n✗ 解压失败 (%s): %v\n", filepath.Base(archivePath), err)
				hasError = true
			}
		}
		if hasError {
			ui.WaitForKeypress("有文件解压失败，按 Enter 键关闭...")
			os.Exit(1)
		}
	}
}

func fatal(format string, args ...interface{}) {
	ui.AllocConsole()
	fmt.Fprintf(os.Stderr, "错误: "+format+"\n", args...)
	ui.WaitForKeypress("发生错误，按 Enter 键关闭...")
	os.Exit(1)
}
