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

	// 2. Next to our own executable (portable installs)
	if selfExe, err := os.Executable(); err == nil {
		selfDir := filepath.Dir(selfExe)
		local7z := filepath.Join(selfDir, "7z.exe")
		if _, err := os.Stat(local7z); err == nil {
			return local7z, nil
		}
	}

	// 3. Common Windows install locations
	candidates := []string{
		`C:\Program Files\7-Zip\7z.exe`,
		`C:\Program Files (x86)\7-Zip\7z.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}

	// 4. PATH
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
	Success       bool
	WrongPassword bool
	NotArchive    bool // true when 7z says "not archive" / "Cannot open the file as archive"
	Output        string
	Error         error
}

// TryExtract attempts to extract an archive with a given password.
// outputDir is the directory to extract into.
// password may be empty (try without password).
func TryExtract(sevenZipPath, archivePath, outputDir, password string) ExtractionResult {
	args := []string{"x"}
	if password != "" {
		args = append(args, "-p"+password)
	} else {
		// Use -p to suppress password prompt (sends empty password)
		args = append(args, "-p")
	}
	args = append(args,
		"-o"+outputDir,
		archivePath,
		"-y",   // yes to all
		"-aoa", // overwrite all
		"-sccUTF-8", // output in UTF-8
	)

	cmd := exec.Command(sevenZipPath, args...)
	// Prevent 7z from inheriting and showing a console window
	hideCmdWindow(cmd)
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
		strings.Contains(outLower, "crc failed") ||
		strings.Contains(outLower, "headers error") {
		// Clean up the failed output directory if it was freshly created and is empty
		cleanupEmptyDir(outputDir)
		return ExtractionResult{Success: false, WrongPassword: true, Output: outStr}
	}

	// Check for "not archive" indicators (steganographic archives, wrong format)
	if IsNotArchiveError(outStr) {
		cleanupEmptyDir(outputDir)
		return ExtractionResult{Success: false, NotArchive: true, Output: outStr, Error: err}
	}

	return ExtractionResult{Success: false, WrongPassword: false, Output: outStr, Error: err}
}

// TryExtractWithFormat attempts to extract an archive with a forced format type flag (e.g. "-tzip").
func TryExtractWithFormat(sevenZipPath, archivePath, outputDir, password, formatFlag string) ExtractionResult {
	args := []string{"x"}
	if password != "" {
		args = append(args, "-p"+password)
	} else {
		args = append(args, "-p")
	}
	args = append(args,
		formatFlag,
		"-o"+outputDir,
		archivePath,
		"-y",
		"-aoa",
		"-sccUTF-8",
	)

	cmd := exec.Command(sevenZipPath, args...)
	hideCmdWindow(cmd)
	out, err := cmd.CombinedOutput()
	outStr := string(out)

	if err == nil {
		return ExtractionResult{Success: true, Output: outStr}
	}

	outLower := strings.ToLower(outStr)
	if strings.Contains(outLower, "wrong password") ||
		strings.Contains(outLower, "cannot open encrypted archive") ||
		strings.Contains(outLower, "data error") ||
		strings.Contains(outLower, "crc failed") ||
		strings.Contains(outLower, "headers error") {
		cleanupEmptyDir(outputDir)
		return ExtractionResult{Success: false, WrongPassword: true, Output: outStr}
	}

	if IsNotArchiveError(outStr) {
		cleanupEmptyDir(outputDir)
		return ExtractionResult{Success: false, NotArchive: true, Output: outStr, Error: err}
	}

	return ExtractionResult{Success: false, WrongPassword: false, Output: outStr, Error: err}
}

// IsNotArchiveError returns true when 7z output indicates the file is not recognized as an archive.
func IsNotArchiveError(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "cannot open the file as archive") ||
		strings.Contains(lower, "is not archive") ||
		strings.Contains(lower, "can not open output file") ||
		strings.Contains(lower, "no files to process")
}

// FindBandizip locates Bandizip CLI (bz.exe).
func FindBandizip(configPath string) string {
	// 1. Use configured path
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			return configPath
		}
	}

	// 2. Check PATH
	if p, err := exec.LookPath("bz.exe"); err == nil {
		return p
	}
	if p, err := exec.LookPath("bz"); err == nil {
		return p
	}

	// 3. Common install locations
	candidates := []string{
		`C:\Program Files\Bandizip\bz.exe`,
		`C:\Program Files (x86)\Bandizip\bz.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	return ""
}

// TryBandizipExtract attempts extraction using Bandizip CLI (bz.exe).
func TryBandizipExtract(bandizipPath, archivePath, outputDir, password string) ExtractionResult {
	args := []string{"x"}
	args = append(args, "-o:"+outputDir)
	args = append(args, "-y")
	if password != "" {
		args = append(args, "-p:"+password)
	}
	args = append(args, archivePath)

	cmd := exec.Command(bandizipPath, args...)
	hideCmdWindow(cmd)
	out, err := cmd.CombinedOutput()
	outStr := string(out)

	if err == nil {
		return ExtractionResult{Success: true, Output: outStr}
	}
	return ExtractionResult{Success: false, Output: outStr, Error: err}
}

// SteganographicFormats is the ordered list of format flags to try for steganographic archives.
var SteganographicFormats = []string{"-tzip", "-t7z", "-trar"}

// MaskPassword returns a masked version of a password for display.
func MaskPassword(pwd string) string {
	if pwd == "" {
		return "(空)"
	}
	r := []rune(pwd)
	if len(r) <= 2 {
		return strings.Repeat("*", len(r))
	}
	return string(r[0]) + strings.Repeat("*", len(r)-2) + string(r[len(r)-1])
}

// cleanupEmptyDir removes a directory only if it exists and is empty.
func cleanupEmptyDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	if len(entries) == 0 {
		os.Remove(dir)
	}
}

// IsArchive returns true if the file extension is a supported archive format.
// Also recognizes multi-part archives like .zip.001, .7z.001, .part1.rar.
func IsArchive(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".zip", ".rar", ".7z", ".gz", ".bz2", ".tar", ".xz", ".lzma",
		".cab", ".arj", ".z", ".tgz", ".tbz2", ".iso", ".wim", ".lz4", ".zst":
		return true
	}

	lower := strings.ToLower(path)

	// Handle .tar.gz, .tar.bz2 etc.
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tar.bz2") ||
		strings.HasSuffix(lower, ".tar.xz") || strings.HasSuffix(lower, ".tar.lzma") {
		return true
	}

	// Handle multi-part archives: .zip.001, .7z.001, .7z.002 etc.
	// Only treat .001 as the archive (other parts are consumed automatically by 7z)
	if strings.HasSuffix(lower, ".001") {
		withoutPart := lower[:len(lower)-4]
		partExt := strings.ToLower(filepath.Ext(withoutPart))
		switch partExt {
		case ".zip", ".7z", ".rar":
			return true
		}
	}

	return false
}

// OutputDirForArchive returns the output directory path for an archive.
// It strips the extension(s) and creates a sibling folder.
// If the directory already exists and contains files, it appends a numeric suffix.
func OutputDirForArchive(archivePath string) string {
	dir := filepath.Dir(archivePath)
	base := filepath.Base(archivePath)

	lower := strings.ToLower(base)
	var name string

	// Handle multi-part: .zip.001, .7z.001 etc. → strip both parts
	if strings.HasSuffix(lower, ".001") {
		withoutPart := base[:len(base)-4]
		withoutPartLower := strings.ToLower(withoutPart)
		partExt := filepath.Ext(withoutPartLower)
		switch partExt {
		case ".zip", ".7z", ".rar":
			name = withoutPart[:len(withoutPart)-len(partExt)]
			return resolveOutputDir(dir, name)
		}
	}

	// Handle double extensions like .tar.gz
	for _, doubleExt := range []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lzma"} {
		if strings.HasSuffix(lower, doubleExt) {
			name = base[:len(base)-len(doubleExt)]
			return resolveOutputDir(dir, name)
		}
	}

	// Single extension
	ext := filepath.Ext(base)
	if ext != "" {
		name = base[:len(base)-len(ext)]
	} else {
		name = base + "_extracted"
	}
	return resolveOutputDir(dir, name)
}

// resolveOutputDir returns dir/name, appending a numeric suffix if the path
// already exists and is not an empty directory.
func resolveOutputDir(dir, name string) string {
	candidate := filepath.Join(dir, name)
	if !dirExistsAndNonEmpty(candidate) {
		return candidate
	}
	for i := 2; i < 1000; i++ {
		candidate = filepath.Join(dir, fmt.Sprintf("%s_%d", name, i))
		if !dirExistsAndNonEmpty(candidate) {
			return candidate
		}
	}
	return filepath.Join(dir, name)
}

// dirExistsAndNonEmpty returns true if path is an existing non-empty directory.
func dirExistsAndNonEmpty(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	return len(entries) > 0
}
