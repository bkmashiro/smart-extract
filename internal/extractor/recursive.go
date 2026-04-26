package extractor

import (
	"fmt"
	"os"
	"path/filepath"
)

// RecursiveExtractOptions controls recursive extraction behavior
type RecursiveExtractOptions struct {
	SevenZipPath string
	MaxDepth     int
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
	if depth > 10 {
		return "", "", fmt.Errorf("max recursion depth reached")
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

	// Try each password
	var lastResult ExtractionResult
	tried := false
	for _, pwd := range passwords {
		result := TryExtract(opts.SevenZipPath, archivePath, outputDir, pwd)
		lastResult = result
		tried = true

		if result.Success {
			successPwd = pwd
			if opts.OnProgress != nil {
				if pwd == "" {
					opts.OnProgress(fmt.Sprintf("✓ 成功（无密码）"))
				} else {
					opts.OnProgress(fmt.Sprintf("✓ 成功（密码: %s）", pwd))
				}
			}
			break
		}
		if !result.WrongPassword {
			// Non-password error — don't keep trying
			return "", "", fmt.Errorf("extraction failed: %s", result.Output)
		}
		if opts.OnProgress != nil {
			opts.OnProgress(fmt.Sprintf("✗ 密码错误: %q", pwd))
		}
	}

	if !tried || !lastResult.Success {
		return "", "", fmt.Errorf("all passwords failed for %s", filepath.Base(archivePath))
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
