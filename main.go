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

	// Strip surrounding quotes from arguments — some Windows shell
	// expansions (e.g. drag-and-drop or certain "%1" substitutions) can
	// leave literal quote characters in the argument.
	for i, a := range args {
		if len(a) >= 2 && a[0] == '"' && a[len(a)-1] == '"' {
			args[i] = a[1 : len(a)-1]
		}
	}

	if len(args) == 0 {
		ui.AllocConsole()
		fmt.Println("智能解压 - 使用方法:")
		fmt.Println("  smart-extract.exe --install      安装右键菜单")
		fmt.Println("  smart-extract.exe --uninstall    卸载右键菜单")
		fmt.Println("  smart-extract.exe --reset-prefs  重置偏好设置")
		fmt.Println("  smart-extract.exe --hashdb-public-key <key.json>  输出 HashDB 贡献公钥")
		fmt.Println("  smart-extract.exe --hashdb-add-bundle-source <name> <bundle.json> <key.json>  添加本地 bundle lookup 源")
		fmt.Println("  smart-extract.exe --hashdb-add-sharded-source <name> <base_dir> <key.json>  添加本地 sharded lookup 源")
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

	case "--hashdb-public-key":
		if len(args) < 2 {
			fatal("用法: smart-extract.exe --hashdb-public-key <key.json>")
		}
		publicKey, err := cmd.HashDBPublicKey(args[1])
		if err != nil {
			fatal("读取 HashDB 公钥失败: %v", err)
		}
		fmt.Println(publicKey)

	case "--hashdb-add-bundle-source":
		if len(args) < 4 {
			fatal("用法: smart-extract.exe --hashdb-add-bundle-source <name> <bundle.json> <key.json>")
		}
		publicKey, err := cmd.HashDBAddLocalSource(cmd.HashDBAddLocalSourceOptions{
			Name:    args[1],
			Type:    "bundle",
			Path:    args[2],
			KeyPath: args[3],
		})
		if err != nil {
			fatal("添加 HashDB bundle 源失败: %v", err)
		}
		fmt.Printf("✓ 已添加 HashDB bundle lookup 源，public_key: %s\n", publicKey)

	case "--hashdb-add-sharded-source":
		if len(args) < 4 {
			fatal("用法: smart-extract.exe --hashdb-add-sharded-source <name> <base_dir> <key.json>")
		}
		publicKey, err := cmd.HashDBAddLocalSource(cmd.HashDBAddLocalSourceOptions{
			Name:    args[1],
			Type:    "sharded",
			BaseDir: args[2],
			KeyPath: args[3],
		})
		if err != nil {
			fatal("添加 HashDB sharded 源失败: %v", err)
		}
		fmt.Printf("✓ 已添加 HashDB sharded lookup 源，public_key: %s\n", publicKey)

	case "--help", "-h":
		ui.AllocConsole()
		fmt.Println("智能解压 - 使用方法:")
		fmt.Println("  smart-extract.exe --install      安装右键菜单")
		fmt.Println("  smart-extract.exe --uninstall    卸载右键菜单")
		fmt.Println("  smart-extract.exe --reset-prefs  重置偏好设置")
		fmt.Println("  smart-extract.exe --hashdb-public-key <key.json>  输出 HashDB 贡献公钥")
		fmt.Println("  smart-extract.exe --hashdb-add-bundle-source <name> <bundle.json> <key.json>  添加本地 bundle lookup 源")
		fmt.Println("  smart-extract.exe --hashdb-add-sharded-source <name> <base_dir> <key.json>  添加本地 sharded lookup 源")
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
