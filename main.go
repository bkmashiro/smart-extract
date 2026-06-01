package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/bkmashiro/smart-extract/cmd"
	"github.com/bkmashiro/smart-extract/internal/config"
	"github.com/bkmashiro/smart-extract/internal/ui"
)

// runDeps lets tests substitute the side-effectful bits of dispatch
// (stdout/stderr writers, the Windows console allocation, the Enter-key
// wait) with no-ops so subprocess stdin hacks are not required.
type runDeps struct {
	stdout          io.Writer
	stderr          io.Writer
	allocConsole    func()
	waitForKeypress func(msg string)
	extract         func(path string, opts cmd.ExtractOptions) error
	explain         func(path string, w io.Writer) error
	doctor          func(w io.Writer) error
	explainJSON     func(path string, w io.Writer) error
	doctorJSON      func(w io.Writer) error
}

func main() {
	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 无法确定程序路径: %v\n", err)
		ui.WaitForKeypress("发生错误，按 Enter 键关闭...")
		os.Exit(1)
	}
	baseDir := filepath.Dir(exePath)
	config.Init(baseDir)

	deps := runDeps{
		stdout:          os.Stdout,
		stderr:          os.Stderr,
		allocConsole:    ui.AllocConsole,
		waitForKeypress: ui.WaitForKeypress,
		extract:         cmd.ExtractWithOptions,
	}
	if code := run(os.Args[1:], deps); code != 0 {
		os.Exit(code)
	}
}

func run(args []string, deps runDeps) int {
	if deps.extract == nil {
		deps.extract = cmd.ExtractWithOptions
	}
	if deps.explain == nil {
		deps.explain = cmd.ExplainArchive
	}
	if deps.doctor == nil {
		deps.doctor = cmd.Doctor
	}
	if deps.explainJSON == nil {
		deps.explainJSON = cmd.ExplainArchiveJSON
	}
	if deps.doctorJSON == nil {
		deps.doctorJSON = cmd.DoctorJSON
	}
	// Strip surrounding quotes from arguments — some Windows shell
	// expansions (e.g. drag-and-drop or certain "%1" substitutions) can
	// leave literal quote characters in the argument.
	for i, a := range args {
		if len(a) >= 2 && a[0] == '"' && a[len(a)-1] == '"' {
			args[i] = a[1 : len(a)-1]
		}
	}

	if len(args) == 0 {
		deps.allocConsole()
		printUsage(deps.stdout)
		deps.waitForKeypress("按 Enter 键关闭...")
		return 0
	}

	switch args[0] {
	case "--install":
		deps.allocConsole()
		if err := cmd.Install(); err != nil {
			return reportFatal(deps, "安装失败: %v", err)
		}
		deps.waitForKeypress("")

	case "--uninstall":
		deps.allocConsole()
		if err := cmd.Uninstall(); err != nil {
			return reportFatal(deps, "卸载失败: %v", err)
		}
		deps.waitForKeypress("")

	case "--reset-prefs":
		deps.allocConsole()
		if err := config.ResetPreferences(); err != nil {
			return reportFatal(deps, "重置偏好失败: %v", err)
		}
		fmt.Fprintln(deps.stdout, "✓ 偏好设置已重置，下次解压时将重新询问。")
		deps.waitForKeypress("")

	case "--hashdb-public-key":
		if len(args) < 2 {
			return reportFatal(deps, "用法: smart-extract.exe --hashdb-public-key <key.json>")
		}
		publicKey, err := cmd.HashDBPublicKey(args[1])
		if err != nil {
			return reportFatal(deps, "读取 HashDB 公钥失败: %v", err)
		}
		fmt.Fprintln(deps.stdout, publicKey)

	case "--hashdb-add-bundle-source":
		if len(args) < 4 {
			return reportFatal(deps, "用法: smart-extract.exe --hashdb-add-bundle-source <name> <bundle.json> <key.json>")
		}
		publicKey, err := cmd.HashDBAddLocalSource(cmd.HashDBAddLocalSourceOptions{
			Name:    args[1],
			Type:    "bundle",
			Path:    args[2],
			KeyPath: args[3],
		})
		if err != nil {
			return reportFatal(deps, "添加 HashDB bundle 源失败: %v", err)
		}
		fmt.Fprintf(deps.stdout, "✓ 已添加 HashDB bundle lookup 源，public_key: %s\n", publicKey)

	case "--hashdb-add-sharded-source":
		if len(args) < 4 {
			return reportFatal(deps, "用法: smart-extract.exe --hashdb-add-sharded-source <name> <base_dir> <key.json>")
		}
		publicKey, err := cmd.HashDBAddLocalSource(cmd.HashDBAddLocalSourceOptions{
			Name:    args[1],
			Type:    "sharded",
			BaseDir: args[2],
			KeyPath: args[3],
		})
		if err != nil {
			return reportFatal(deps, "添加 HashDB sharded 源失败: %v", err)
		}
		fmt.Fprintf(deps.stdout, "✓ 已添加 HashDB sharded lookup 源，public_key: %s\n", publicKey)

	case "--hashdb-list-sources":
		deps.allocConsole()
		summaries, err := cmd.HashDBListSources()
		if err != nil {
			return reportFatal(deps, "列出 HashDB 源失败: %v", err)
		}
		if len(summaries) == 0 {
			fmt.Fprintln(deps.stdout, "(no HashDB sources configured)")
		} else {
			for i, s := range summaries {
				if i > 0 {
					fmt.Fprintln(deps.stdout)
				}
				disabled := ""
				if s.Disabled {
					disabled = " [disabled]"
				}
				fmt.Fprintf(deps.stdout, "- %s (%s)%s\n", s.Name, s.Type, disabled)
				if s.Location != "" {
					fmt.Fprintf(deps.stdout, "    location: %s\n", s.Location)
				}
				if s.Compression != "" {
					fmt.Fprintf(deps.stdout, "    compression: %s\n", s.Compression)
				}
				if s.CachePath != "" {
					exists := "missing"
					if s.CacheExists {
						exists = "present"
					}
					fmt.Fprintf(deps.stdout, "    cache: %s (%s)\n", s.CachePath, exists)
				}
			}
		}
		deps.waitForKeypress("")

	case "--hashdb-clear-cache":
		if len(args) < 2 {
			return reportFatal(deps, "用法: smart-extract.exe --hashdb-clear-cache <name> | --all")
		}
		deps.allocConsole()
		if args[1] == "--all" {
			removals, err := cmd.HashDBClearAllSourceCaches()
			if err != nil {
				return reportFatal(deps, "清理 HashDB 缓存失败: %v", err)
			}
			if len(removals) == 0 {
				fmt.Fprintln(deps.stdout, "(no HashDB HTTP sources to clear)")
			} else {
				for _, r := range removals {
					state := "已不存在"
					if r.Existed {
						state = "已删除"
					}
					fmt.Fprintf(deps.stdout, "✓ %s: %s (%s)\n", r.Name, r.Path, state)
				}
			}
		} else {
			path, existed, err := cmd.HashDBClearSourceCache(args[1])
			if err != nil {
				return reportFatal(deps, "清理 HashDB 缓存失败: %v", err)
			}
			if existed {
				fmt.Fprintf(deps.stdout, "✓ 已删除 %s 的缓存: %s\n", args[1], path)
			} else {
				fmt.Fprintf(deps.stdout, "✓ %s 的缓存目录不存在: %s\n", args[1], path)
			}
		}
		deps.waitForKeypress("")

	case "--hashdb-disable-source":
		if len(args) < 2 {
			return reportFatal(deps, "用法: smart-extract.exe --hashdb-disable-source <name>")
		}
		deps.allocConsole()
		src, err := cmd.HashDBSetSourceDisabled(args[1], true)
		if err != nil {
			return reportFatal(deps, "禁用 HashDB 源失败: %v", err)
		}
		fmt.Fprintf(deps.stdout, "✓ 已禁用 HashDB 源: %s\n", src.Name)
		deps.waitForKeypress("")

	case "--hashdb-enable-source":
		if len(args) < 2 {
			return reportFatal(deps, "用法: smart-extract.exe --hashdb-enable-source <name>")
		}
		deps.allocConsole()
		src, err := cmd.HashDBSetSourceDisabled(args[1], false)
		if err != nil {
			return reportFatal(deps, "启用 HashDB 源失败: %v", err)
		}
		fmt.Fprintf(deps.stdout, "✓ 已启用 HashDB 源: %s\n", src.Name)
		deps.waitForKeypress("")

	case "--help", "-h":
		deps.allocConsole()
		printUsage(deps.stdout)
		fmt.Fprintln(deps.stdout, "  smart-extract.exe --help         显示帮助")
		deps.waitForKeypress("")

	case "--doctor":
		if err := deps.doctor(deps.stdout); err != nil {
			return reportFatal(deps, "诊断失败: %v", err)
		}

	case "--debug-log":
		if len(args) < 3 {
			return reportFatal(deps, "用法: smart-extract.exe --debug-log <log.txt> <archive> [archive...]")
		}
		if code := extractArchives(args[2:], deps, args[1]); code != 0 {
			return code
		}

	case "--explain":
		if len(args) < 2 {
			return reportFatal(deps, "用法: smart-extract.exe --explain <archive>")
		}
		if err := deps.explain(args[1], deps.stdout); err != nil {
			return reportFatal(deps, "生成诊断信息失败: %v", err)
		}

	case "--explain-json":
		if len(args) < 2 {
			return reportFatal(deps, "用法: smart-extract.exe --explain-json <archive>")
		}
		if err := deps.explainJSON(args[1], deps.stdout); err != nil {
			return reportFatal(deps, "生成诊断信息失败: %v", err)
		}

	case "--doctor-json":
		if err := deps.doctorJSON(deps.stdout); err != nil {
			return reportFatal(deps, "诊断失败: %v", err)
		}

	default:
		if code := extractArchives(args, deps, ""); code != 0 {
			return code
		}
	}
	return 0
}

func extractArchives(archivePaths []string, deps runDeps, debugLogPath string) int {
	var debugLog io.Writer
	var debugFile *os.File
	if debugLogPath != "" {
		if err := os.MkdirAll(filepath.Dir(debugLogPath), 0o755); err != nil && filepath.Dir(debugLogPath) != "." {
			return reportFatal(deps, "创建调试日志目录失败: %v", err)
		}
		f, err := os.Create(debugLogPath)
		if err != nil {
			return reportFatal(deps, "创建调试日志失败: %v", err)
		}
		debugFile = f
		debugLog = f
		fmt.Fprintf(deps.stdout, "调试日志: %s\n", debugLogPath)
	}
	if debugFile != nil {
		defer debugFile.Close()
	}

	hasError := false
	for _, archivePath := range archivePaths {
		if err := deps.extract(archivePath, cmd.ExtractOptions{DebugLog: debugLog}); err != nil {
			deps.allocConsole()
			fmt.Fprintf(deps.stdout, "\n✗ 解压失败 (%s): %v\n", filepath.Base(archivePath), err)
			hasError = true
		}
	}
	if hasError {
		deps.waitForKeypress("有文件解压失败，按 Enter 键关闭...")
		return 1
	}
	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "智能解压 - 使用方法:")
	fmt.Fprintln(w, "  smart-extract.exe --install      安装右键菜单")
	fmt.Fprintln(w, "  smart-extract.exe --uninstall    卸载右键菜单")
	fmt.Fprintln(w, "  smart-extract.exe --reset-prefs  重置偏好设置")
	fmt.Fprintln(w, "  smart-extract.exe --hashdb-public-key <key.json>  输出 HashDB 贡献公钥")
	fmt.Fprintln(w, "  smart-extract.exe --hashdb-add-bundle-source <name> <bundle.json> <key.json>  添加本地 bundle lookup 源")
	fmt.Fprintln(w, "  smart-extract.exe --hashdb-add-sharded-source <name> <base_dir> <key.json>  添加本地 sharded lookup 源")
	fmt.Fprintln(w, "  smart-extract.exe --hashdb-list-sources                       列出已配置的 HashDB 源")
	fmt.Fprintln(w, "  smart-extract.exe --hashdb-disable-source <name>              临时禁用指定 HashDB 源")
	fmt.Fprintln(w, "  smart-extract.exe --hashdb-enable-source <name>               启用指定 HashDB 源")
	fmt.Fprintln(w, "  smart-extract.exe --hashdb-clear-cache <name>                 清理指定 HashDB 源的本地缓存")
	fmt.Fprintln(w, "  smart-extract.exe --hashdb-clear-cache --all                  清理所有 HashDB 源的本地缓存")
	fmt.Fprintln(w, "  smart-extract.exe --doctor                                   检查配置、7-Zip、学习库与 HashDB 源")
	fmt.Fprintln(w, "  smart-extract.exe --doctor-json                              以 JSON 输出 doctor 诊断结果（适合 bug report）")
	fmt.Fprintln(w, "  smart-extract.exe --debug-log <log.txt> <archive> [archive...] 输出调试日志（不记录明文密码）")
	fmt.Fprintln(w, "  smart-extract.exe --explain <archive>                         仅诊断候选来源/HashDB，不解压")
	fmt.Fprintln(w, "  smart-extract.exe --explain-json <archive>                    以 JSON 输出 explain 诊断结果")
	fmt.Fprintln(w, "  smart-extract.exe <archive>      解压文件")
	fmt.Fprintln(w)
}

func reportFatal(deps runDeps, format string, args ...interface{}) int {
	deps.allocConsole()
	fmt.Fprintf(deps.stderr, "错误: "+format+"\n", args...)
	deps.waitForKeypress("发生错误，按 Enter 键关闭...")
	return 1
}
