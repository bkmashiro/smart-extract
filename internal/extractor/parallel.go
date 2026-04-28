package extractor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// DefaultMaxParallelProbes is the default cap on parallel workers.
const DefaultMaxParallelProbes = 4

// ParallelProbeResult holds the result of a parallel password probe.
type ParallelProbeResult struct {
	Success    bool
	Password   string
	TempDir    string // temp directory where extraction landed
	Output     string
	Error      error
	NotArchive bool // true if 7z said "not archive" (not a password issue)
}

// ParallelProbe tries passwords in parallel using a worker pool.
// Each worker extracts directly to a temp directory. On success, the winning
// temp dir is renamed to finalOutputDir and all losers' temp dirs are cleaned up.
// Returns the successful password (or error if all fail).
func ParallelProbe(ctx context.Context, sevenZipPath, archivePath, finalOutputDir string, passwords []string, maxWorkers int, onProgress func(string)) (string, error) {
	if len(passwords) == 0 {
		return "", fmt.Errorf("no passwords to try")
	}

	numWorkers := pickWorkerCount(len(passwords), maxWorkers)

	if onProgress != nil {
		onProgress(fmt.Sprintf("⚡ 并行尝试 %d 个密码（%d 工作线程）", len(passwords), numWorkers))
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Channel for passwords to try
	pwCh := make(chan indexedPassword, len(passwords))
	for i, pw := range passwords {
		pwCh <- indexedPassword{index: i, password: pw}
	}
	close(pwCh)

	// Channel for results
	resultCh := make(chan ParallelProbeResult, numWorkers)

	// Track all temp dirs for cleanup
	var tempDirsMu sync.Mutex
	var allTempDirs []string

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		workerID := w
		go func() {
			defer wg.Done()
			for ipw := range pwCh {
				// Check if cancelled
				select {
				case <-ctx.Done():
					return
				default:
				}

				tempDir := fmt.Sprintf("%s_probe_%d", finalOutputDir, workerID)
				tempDirsMu.Lock()
				allTempDirs = append(allTempDirs, tempDir)
				tempDirsMu.Unlock()

				result := tryExtractWithCancel(ctx, sevenZipPath, archivePath, tempDir, ipw.password)

				if result.Success {
					resultCh <- ParallelProbeResult{
						Success:  true,
						Password: ipw.password,
						TempDir:  tempDir,
					}
					cancel() // cancel all other workers
					return
				}

				// Failed — clean up temp dir
				os.RemoveAll(tempDir)

				// "Not archive" error — won't be fixed by other passwords
				if result.NotArchive {
					resultCh <- ParallelProbeResult{
						Success:    false,
						NotArchive: true,
						Output:     result.Output,
					}
					cancel()
					return
				}

				if onProgress != nil {
					onProgress(fmt.Sprintf("✗ 密码错误: %s", MaskPassword(ipw.password)))
				}

				if !result.WrongPassword {
					// Non-password error — report but continue trying others
					// (could be a partial extraction that got cancelled)
					if ctx.Err() != nil {
						return
					}
				}
			}
		}()
	}

	// Close result channel when all workers done
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect result
	var winner *ParallelProbeResult
	var notArchiveResult *ParallelProbeResult
	for r := range resultCh {
		if r.Success {
			rCopy := r
			winner = &rCopy
			break
		}
		if r.NotArchive {
			rCopy := r
			notArchiveResult = &rCopy
			break
		}
	}

	// Wait for all workers to finish
	cancel()
	wg.Wait()

	if notArchiveResult != nil {
		return "", &ProbeError{
			Message:    fmt.Sprintf("not recognized as archive: %s", filepath.Base(archivePath)),
			NotArchive: true,
		}
	}

	if winner == nil {
		return "", &ProbeError{
			Message:    fmt.Sprintf("all passwords failed for %s", filepath.Base(archivePath)),
			NotArchive: false,
		}
	}

	// Rename winner's temp dir to final output dir
	if err := os.Rename(winner.TempDir, finalOutputDir); err != nil {
		// Rename might fail cross-device; try move contents
		if err2 := moveContents(winner.TempDir, finalOutputDir); err2 != nil {
			return "", fmt.Errorf("failed to move extraction result: %v (rename: %v)", err2, err)
		}
	}

	// Clean up any remaining temp dirs (losers)
	tempDirsMu.Lock()
	dirs := allTempDirs
	tempDirsMu.Unlock()
	for _, d := range dirs {
		if d != winner.TempDir {
			os.RemoveAll(d)
		}
	}
	// Also clean up the winner's temp dir if rename moved it
	os.RemoveAll(winner.TempDir)

	if onProgress != nil {
		if winner.Password == "" {
			onProgress("✓ 成功（无密码）")
		} else {
			onProgress(fmt.Sprintf("✓ 成功（密码: %s）", MaskPassword(winner.Password)))
		}
	}

	return winner.Password, nil
}

// SerialProbe tries passwords one at a time, extracting directly to temp dirs.
// This eliminates the double-extraction (probe with `7z t`, then `7z x`).
func SerialProbe(sevenZipPath, archivePath, finalOutputDir string, passwords []string, onProgress func(string)) (string, error) {
	if len(passwords) == 0 {
		return "", fmt.Errorf("no passwords to try")
	}

	sawNotArchive := false

	for _, pwd := range passwords {
		tempDir := finalOutputDir + "_probe"
		result := TryExtract(sevenZipPath, archivePath, tempDir, pwd)

		if result.Success {
			// Rename temp dir to final
			if err := os.Rename(tempDir, finalOutputDir); err != nil {
				if err2 := moveContents(tempDir, finalOutputDir); err2 != nil {
					return "", fmt.Errorf("failed to move extraction result: %v (rename: %v)", err2, err)
				}
			}
			os.RemoveAll(tempDir)

			if onProgress != nil {
				if pwd == "" {
					onProgress("✓ 成功（无密码）")
				} else {
					onProgress(fmt.Sprintf("✓ 成功（密码: %s）", MaskPassword(pwd)))
				}
			}
			return pwd, nil
		}

		// Clean up failed temp dir
		os.RemoveAll(tempDir)

		if result.NotArchive {
			sawNotArchive = true
			// "Not archive" errors won't be fixed by a different password; stop early
			return "", &ProbeError{
				Message:    fmt.Sprintf("not recognized as archive: %s", filepath.Base(archivePath)),
				NotArchive: true,
			}
		}

		if !result.WrongPassword {
			return "", fmt.Errorf("extraction failed: %s", result.Output)
		}

		if onProgress != nil {
			onProgress(fmt.Sprintf("✗ 密码错误: %s", MaskPassword(pwd)))
		}
	}

	_ = sawNotArchive
	return "", &ProbeError{
		Message:    fmt.Sprintf("all passwords failed for %s", filepath.Base(archivePath)),
		NotArchive: false,
	}
}

// ProbeError is returned by SerialProbe/ParallelProbe with extra context
// about why extraction failed (wrong passwords vs not an archive).
type ProbeError struct {
	Message    string
	NotArchive bool // true if 7z said "not archive"
}

func (e *ProbeError) Error() string {
	return e.Message
}

// IsProbeNotArchive checks if an error from probing indicates "not archive".
func IsProbeNotArchive(err error) bool {
	if pe, ok := err.(*ProbeError); ok {
		return pe.NotArchive
	}
	return false
}

type indexedPassword struct {
	index    int
	password string
}

// tryExtractWithCancel runs 7z x with context cancellation support.
// If the context is cancelled, the 7z subprocess is killed.
func tryExtractWithCancel(ctx context.Context, sevenZipPath, archivePath, outputDir, password string) ExtractionResult {
	args := []string{"x"}
	if password != "" {
		args = append(args, "-p"+password)
	} else {
		args = append(args, "-p")
	}
	args = append(args,
		"-o"+outputDir,
		archivePath,
		"-y",
		"-aoa",
		"-sccUTF-8",
	)

	cmd := exec.CommandContext(ctx, sevenZipPath, args...)
	hideCmdWindow(cmd)
	out, err := cmd.CombinedOutput()
	outStr := string(out)

	if err == nil {
		return ExtractionResult{Success: true, Output: outStr}
	}

	// Check if context was cancelled (process killed)
	if ctx.Err() != nil {
		return ExtractionResult{Success: false, WrongPassword: false, Output: "cancelled", Error: ctx.Err()}
	}

	// Check for wrong password indicators
	outLower := strings.ToLower(outStr)
	if strings.Contains(outLower, "wrong password") ||
		strings.Contains(outLower, "cannot open encrypted archive") ||
		strings.Contains(outLower, "data error") ||
		strings.Contains(outLower, "crc failed") ||
		strings.Contains(outLower, "headers error") {
		return ExtractionResult{Success: false, WrongPassword: true, Output: outStr}
	}

	// Check for "not archive" indicators
	if IsNotArchiveError(outStr) {
		return ExtractionResult{Success: false, NotArchive: true, Output: outStr, Error: err}
	}

	return ExtractionResult{Success: false, WrongPassword: false, Output: outStr, Error: err}
}

// pickWorkerCount determines the number of parallel workers.
func pickWorkerCount(numPasswords, maxParallel int) int {
	if maxParallel <= 0 {
		maxParallel = runtime.NumCPU()
	}
	n := numPasswords
	if n > maxParallel {
		n = maxParallel
	}
	if n > 8 {
		n = 8
	}
	if n < 1 {
		n = 1
	}
	return n
}

// moveContents moves all files from src to dst (fallback when os.Rename fails cross-device).
func moveContents(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, e := range entries {
		srcPath := filepath.Join(src, e.Name())
		dstPath := filepath.Join(dst, e.Name())
		if err := os.Rename(srcPath, dstPath); err != nil {
			// If rename fails, we need a deep copy — but for simplicity
			// just report the error. Cross-device moves are rare.
			return fmt.Errorf("moving %s to %s: %w", srcPath, dstPath, err)
		}
	}

	return os.RemoveAll(src)
}
