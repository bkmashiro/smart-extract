package extractor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// RecursiveExtractOptions controls recursive extraction behavior
type RecursiveExtractOptions struct {
	SevenZipPath string
	MaxDepth     int
	// MaxParallelProbes caps the number of parallel password workers.
	// 0 means use runtime.NumCPU(). Default is 4.
	MaxParallelProbes int
	// TryPassword is called when an archive needs a password attempt.
	// It should return a list of passwords to try, in order.
	TryPassword func(archivePath string) ([]string, error)
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

	// Get passwords to try
	passwords, err := opts.TryPassword(archivePath)
	if err != nil {
		return "", "", err
	}

	if opts.OnProgress != nil {
		opts.OnProgress(fmt.Sprintf("📦 解压 %s → %s", filepath.Base(archivePath), outputDir))
	}

	// Detect archive format and choose probe strategy
	af := DetectFormat(archivePath, opts.SevenZipPath)
	if opts.OnProgress != nil {
		opts.OnProgress(fmt.Sprintf("🔍 格式: %s", DetectFormatString(af)))
	}

	maxPar := opts.MaxParallelProbes
	if maxPar == 0 {
		maxPar = DefaultMaxParallelProbes
	}

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
				opts.SevenZipPath, archivePath, outputDir,
				passwords, maxPar, af.Strategy, opts.OnProgress,
			)
			if err != nil {
				return "", "", err
			}
		} else {
			return "", "", err
		}
	}

	// Flatten single-folder nesting
	if err := FlattenSingleFolder(outputDir); err != nil {
		if opts.OnProgress != nil {
			opts.OnProgress(fmt.Sprintf("警告：展平目录失败: %v", err))
		}
	}

	// Recursively extract nested archives
	if err := walkAndExtract(outputDir, opts, depth+1); err != nil {
		if opts.OnProgress != nil {
			opts.OnProgress(fmt.Sprintf("警告：递归解压失败: %v", err))
		}
	}

	return outputDir, successPwd, nil
}

// trySteganographicExtract retries extraction with forced format types (-tzip, -t7z, -trar).
// For each format, it tries all passwords. If all formats fail, it tries Bandizip as a last resort.
func trySteganographicExtract(
	sevenZipPath, archivePath, outputDir string,
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
	bandizipPath := FindBandizip()
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
