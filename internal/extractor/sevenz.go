package extractor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// FindSevenZip locates 7z.exe using multiple strategies
func FindSevenZip(configPath string) (string, error) {
	// 1. Use configured path
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			return configPath, nil
		}
	}

	// 2. Common install locations
	candidates := []string{
		`C:\Program Files\7-Zip\7z.exe`,
		`C:\Program Files (x86)\7-Zip\7z.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}

	// 3. PATH
	if p, err := exec.LookPath("7z.exe"); err == nil {
		return p, nil
	}
	if p, err := exec.LookPath("7z"); err == nil {
		return p, nil
	}

	return "", fmt.Errorf("7z.exe not found; install 7-Zip or set sevenzip_path in config.yaml")
}

// ExtractionResult holds the outcome of a single extraction attempt
type ExtractionResult struct {
	Success      bool
	WrongPassword bool
	Output       string
	Error        error
}

// TryExtract attempts to extract an archive with a given password.
// outputDir is the directory to extract into.
// password may be empty (try without password).
func TryExtract(sevenZipPath, archivePath, outputDir, password string) ExtractionResult {
	args := []string{"x"}
	if password != "" {
		args = append(args, "-p"+password)
	} else {
		// Use -p"" to suppress password prompt
		args = append(args, "-p")
	}
	args = append(args,
		"-o"+outputDir,
		archivePath,
		"-y",       // yes to all
		"-aoa",     // overwrite all
	)

	cmd := exec.Command(sevenZipPath, args...)
	out, err := cmd.CombinedOutput()
	outStr := string(out)

	if err == nil {
		return ExtractionResult{Success: true, Output: outStr}
	}

	// Check for wrong password indicators
	outLower := strings.ToLower(outStr)
	if strings.Contains(outLower, "wrong password") ||
		strings.Contains(outLower, "cannot open encrypted archive") ||
		strings.Contains(outLower, "data error") ||
		strings.Contains(outLower, "crc failed") {
		return ExtractionResult{Success: false, WrongPassword: true, Output: outStr}
	}

	return ExtractionResult{Success: false, WrongPassword: false, Output: outStr, Error: err}
}

// IsArchive returns true if the file extension is a supported archive format
func IsArchive(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".zip", ".rar", ".7z", ".gz", ".bz2", ".tar", ".xz", ".lzma", ".cab", ".arj", ".z", ".tgz", ".tbz2":
		return true
	}
	// Handle .tar.gz, .tar.bz2 etc.
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tar.bz2") ||
		strings.HasSuffix(lower, ".tar.xz") || strings.HasSuffix(lower, ".tar.lzma") {
		return true
	}
	return false
}

// OutputDirForArchive returns the output directory path for an archive.
// It strips the extension(s) and creates a sibling folder.
func OutputDirForArchive(archivePath string) string {
	dir := filepath.Dir(archivePath)
	base := filepath.Base(archivePath)

	// Handle double extensions like .tar.gz
	lower := strings.ToLower(base)
	var name string
	for _, doubleExt := range []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lzma"} {
		if strings.HasSuffix(lower, doubleExt) {
			name = base[:len(base)-len(doubleExt)]
			return filepath.Join(dir, name)
		}
	}

	// Single extension
	ext := filepath.Ext(base)
	if ext != "" {
		name = base[:len(base)-len(ext)]
	} else {
		name = base
	}
	return filepath.Join(dir, name)
}
