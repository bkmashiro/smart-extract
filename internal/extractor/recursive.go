package extractor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bkmashiro/smart-extract/internal/budget"
	"github.com/bkmashiro/smart-extract/internal/throttle"
)

// RecursiveExtractOptions controls recursive extraction behavior
type RecursiveExtractOptions struct {
	SevenZipPath string
	BandizipPath string
	MaxDepth     int
	// MaxParallelProbes caps the number of parallel password workers.
	// 0 means use runtime.NumCPU(). Default is 4.
	MaxParallelProbes int
	// ThrottleDir enables a cross-process throttle for heavy probe workers when
	// non-empty. This is used to keep Explorer multi-select launches from each
	// consuming the full local parallel probe budget.
	ThrottleDir string
	// ThrottleSlots is the global cross-process probe slot cap. Values <=0 are
	// treated as the local budgeted max parallelism.
	ThrottleSlots int
	// ThrottleStaleAfter controls stale lock-file reclamation. Zero disables
	// reclamation.
	ThrottleStaleAfter time.Duration
	// BudgetProfile controls cost-aware candidate and probe budgets.
	// The zero value is budget.ProfileNormal for backwards compatibility.
	BudgetProfile budget.Profile
	// ParentPassword is the password that successfully opened the enclosing
	// archive, if this archive was discovered during recursive extraction.
	ParentPassword string
	// TryPassword is called when an archive needs a password attempt.
	// It should return a list of passwords to try, in order. parentPassword is
	// empty for top-level archives and set for nested archives.
	TryPassword func(archivePath, parentPassword string) ([]string, error)
	// OnArchiveSuccess is called after each archive is successfully extracted,
	// including nested archives. The password is empty for archives that did not
	// require one.
	OnArchiveSuccess func(archivePath, password string)
	// OnProgress is called with progress messages
	OnProgress func(msg string)
}

// RecursiveExtract extracts an archive and then recursively extracts any nested archives.
// passwordsToTry is the ordered list of passwords for the top-level archive.
// Returns the output directory and the successful password (or "" if no password needed).
func RecursiveExtract(archivePath string, opts RecursiveExtractOptions, depth int) (outDir string, successPwd string, err error) {
	maxDepth := opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 10
	}
	if depth > maxDepth {
		return "", "", fmt.Errorf("max recursion depth (%d) reached", maxDepth)
	}

	outputDir := OutputDirForArchive(archivePath)

	if opts.OnProgress != nil {
		opts.OnProgress(fmt.Sprintf("📦 解压 %s → %s", filepath.Base(archivePath), outputDir))
	}

	// Detect archive format and choose probe strategy.
	af := DetectFormat(archivePath, opts.SevenZipPath)
	if opts.OnProgress != nil {
		opts.OnProgress(fmt.Sprintf("🔍 格式: %s", DetectFormatString(af)))
	}

	// Get passwords to try after format detection so per-archive budgets can
	// be applied consistently, including nested archives.
	passwords, err := opts.TryPassword(archivePath, opts.ParentPassword)
	if err != nil {
		return "", "", err
	}

	maxPar, releaseProbeBudget := acquireProbeBudget(opts, af, archiveSize(archivePath))
	defer releaseProbeBudget()

	// Use the appropriate probing strategy — both extract directly (no double-extraction)
	switch af.Strategy {
	case ProbeParallel:
		successPwd, err = ParallelProbe(
			context.Background(),
			opts.SevenZipPath, archivePath, outputDir,
			passwords, maxPar, opts.OnProgress,
		)
	case ProbeSerial:
		successPwd, err = SerialProbe(
			opts.SevenZipPath, archivePath, outputDir,
			passwords, opts.OnProgress,
		)
	}

	if err != nil {
		// Check if the failure is a "not archive" error — try steganographic format forcing
		if IsProbeNotArchive(err) {
			if opts.OnProgress != nil {
				opts.OnProgress("🔍 检测到非标准存档格式，尝试隐写存档检测...")
			}
			successPwd, err = trySteganographicExtract(
				opts.SevenZipPath, opts.BandizipPath, archivePath, outputDir,
				passwords, maxPar, af.Strategy, opts.OnProgress,
			)
			if err != nil {
				return "", "", err
			}
		} else {
			return "", "", err
		}
	}
	notifyArchiveSuccess(opts, archivePath, successPwd)

	// Flatten single-folder nesting
	if err := FlattenSingleFolder(outputDir); err != nil {
		if opts.OnProgress != nil {
			opts.OnProgress(fmt.Sprintf("警告：展平目录失败: %v", err))
		}
	}

	// Recursively extract nested archives. Nested archives should try the
	// enclosing archive's successful password first.
	childOpts := childOptionsWithParentPassword(opts, successPwd)
	if err := walkAndExtract(outputDir, childOpts, depth+1); err != nil {
		if opts.OnProgress != nil {
			opts.OnProgress(fmt.Sprintf("警告：递归解压失败: %v", err))
		}
	}

	return outputDir, successPwd, nil
}

func childOptionsWithParentPassword(opts RecursiveExtractOptions, parentPassword string) RecursiveExtractOptions {
	opts.ParentPassword = parentPassword
	return opts
}

func notifyArchiveSuccess(opts RecursiveExtractOptions, archivePath, password string) {
	if opts.OnArchiveSuccess != nil {
		opts.OnArchiveSuccess(archivePath, password)
	}
}

func budgetedMaxParallel(opts RecursiveExtractOptions, af ArchiveFormat, archiveSizeBytes int64) int {
	rec := budget.Recommend(budget.Inputs{
		Format:            af.Format,
		ArchiveSizeBytes:  archiveSizeBytes,
		Profile:           opts.BudgetProfile,
		MaxParallelProbes: opts.MaxParallelProbes,
	})
	if rec.MaxParallelProbes < 1 {
		return 1
	}
	return rec.MaxParallelProbes
}

func acquireProbeBudget(opts RecursiveExtractOptions, af ArchiveFormat, archiveSizeBytes int64) (int, func()) {
	budgeted := budgetedMaxParallel(opts, af, archiveSizeBytes)
	if opts.ThrottleDir == "" {
		return budgeted, func() {}
	}

	slots := opts.ThrottleSlots
	if slots <= 0 {
		slots = budgeted
	}
	maxParallel, leases, err := throttle.EffectiveParallel(context.Background(), budgeted, throttle.Options{
		Dir:        opts.ThrottleDir,
		Slots:      slots,
		StaleAfter: opts.ThrottleStaleAfter,
	})
	if err != nil {
		if opts.OnProgress != nil {
			opts.OnProgress(fmt.Sprintf("警告：跨进程探测节流不可用，降级为串行探测: %v", err))
		}
		return 1, func() {}
	}
	return maxParallel, func() { throttle.ReleaseAll(leases) }
}

func archiveSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

// trySteganographicExtract retries extraction with forced format types (-tzip, -t7z, -trar).
// For each format, it tries all passwords. If all formats fail, it tries Bandizip as a last resort.
func trySteganographicExtract(
	sevenZipPath, bandizipConfigPath, archivePath, outputDir string,
	passwords []string, maxWorkers int,
	strategy ProbeStrategy,
	onProgress func(string),
) (string, error) {
	for _, formatFlag := range SteganographicFormats {
		formatName := formatFlag[2:] // strip "-t" prefix
		if onProgress != nil {
			onProgress(fmt.Sprintf("🔄 尝试强制格式: %s", formatName))
		}

		for _, pwd := range passwords {
			tempDir := outputDir + "_stego_probe"
			result := TryExtractWithFormat(sevenZipPath, archivePath, tempDir, pwd, formatFlag)

			if result.Success {
				// Move temp dir to final output
				if err := os.Rename(tempDir, outputDir); err != nil {
					if err2 := moveContents(tempDir, outputDir); err2 != nil {
						os.RemoveAll(tempDir)
						return "", fmt.Errorf("failed to move extraction result: %v (rename: %v)", err2, err)
					}
				}
				os.RemoveAll(tempDir)

				if onProgress != nil {
					onProgress(fmt.Sprintf("⚠ 检测到隐写存档 (format: %s)，已成功解压", formatName))
				}
				return pwd, nil
			}

			os.RemoveAll(tempDir)

			// If "not archive" with this format too, skip remaining passwords for this format
			if result.NotArchive {
				break
			}

			// If wrong password, try next password
			if result.WrongPassword {
				if onProgress != nil {
					onProgress(fmt.Sprintf("✗ %s 密码错误: %s", formatName, MaskPassword(pwd)))
				}
				continue
			}

			// Other error — skip this format
			break
		}
	}

	// All forced formats failed — try Bandizip as last resort
	bandizipPath := FindBandizip(bandizipConfigPath)
	if bandizipPath != "" {
		if onProgress != nil {
			onProgress("🔄 尝试 Bandizip 解压...")
		}
		for _, pwd := range passwords {
			tempDir := outputDir + "_bz_probe"
			result := TryBandizipExtract(bandizipPath, archivePath, tempDir, pwd)
			if result.Success {
				if err := os.Rename(tempDir, outputDir); err != nil {
					if err2 := moveContents(tempDir, outputDir); err2 != nil {
						os.RemoveAll(tempDir)
						return "", fmt.Errorf("failed to move extraction result: %v (rename: %v)", err2, err)
					}
				}
				os.RemoveAll(tempDir)
				if onProgress != nil {
					onProgress("⚠ 检测到隐写存档 (Bandizip)，已成功解压")
				}
				return pwd, nil
			}
			os.RemoveAll(tempDir)
		}
	}

	return "", fmt.Errorf("steganographic extraction failed for %s: no format/password combination worked", filepath.Base(archivePath))
}

// walkAndExtract walks a directory and extracts any archives found
func walkAndExtract(dir string, opts RecursiveExtractOptions, depth int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if e.IsDir() {
			if err := walkAndExtract(path, opts, depth); err != nil {
				return err
			}
			continue
		}
		if IsArchive(path) {
			_, _, err := RecursiveExtract(path, opts, depth)
			if err != nil {
				if opts.OnProgress != nil {
					opts.OnProgress(fmt.Sprintf("警告：无法解压嵌套档案 %s: %v", e.Name(), err))
				}
			} else {
				// Remove the nested archive after successful extraction
				os.Remove(path)
			}
		}
	}
	return nil
}
