package extractor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ProbeStrategy determines whether password probing can be parallelized.
type ProbeStrategy int

const (
	// ProbeParallel means password verification is cheap (reads only a small header),
	// so multiple passwords can be tested concurrently.
	ProbeParallel ProbeStrategy = iota
	// ProbeSerial means password verification requires significant decompression,
	// so passwords must be tested one at a time.
	ProbeSerial
)

func (s ProbeStrategy) String() string {
	switch s {
	case ProbeParallel:
		return "parallel"
	case ProbeSerial:
		return "serial"
	default:
		return "unknown"
	}
}

// ArchiveFormat describes the detected format and probe strategy for an archive.
type ArchiveFormat struct {
	Strategy ProbeStrategy
	Format   string // "zip", "rar", "7z", "7z-solid", "tar-compressed", "unknown"
}

// DetectFormat inspects the archive file and determines the optimal probe strategy.
// sevenZipPath is needed to run `7z l -slt` for 7z solid detection.
func DetectFormat(archivePath, sevenZipPath string) ArchiveFormat {
	ext := strings.ToLower(filepath.Ext(archivePath))
	lower := strings.ToLower(archivePath)

	// Handle double extensions
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tar.bz2") ||
		strings.HasSuffix(lower, ".tar.xz") || strings.HasSuffix(lower, ".tar.lzma") {
		return ArchiveFormat{Strategy: ProbeSerial, Format: "tar-compressed"}
	}

	// Handle multi-part: check the real extension before .001
	if ext == ".001" {
		withoutPart := lower[:len(lower)-4]
		ext = strings.ToLower(filepath.Ext(withoutPart))
	}

	// Try magic bytes first, fall back to extension
	magic := readMagic(archivePath)

	switch {
	case isZipMagic(magic) || ext == ".zip":
		return ArchiveFormat{Strategy: ProbeParallel, Format: "zip"}

	case isRarMagic(magic) || ext == ".rar":
		return ArchiveFormat{Strategy: ProbeParallel, Format: "rar"}

	case is7zMagic(magic) || ext == ".7z":
		if is7zSolid(archivePath, sevenZipPath) {
			return ArchiveFormat{Strategy: ProbeSerial, Format: "7z-solid"}
		}
		return ArchiveFormat{Strategy: ProbeParallel, Format: "7z"}

	case ext == ".gz" || ext == ".bz2" || ext == ".xz" || ext == ".lzma" ||
		ext == ".tgz" || ext == ".tbz2":
		return ArchiveFormat{Strategy: ProbeSerial, Format: "tar-compressed"}

	default:
		// Unknown format; be safe and use serial
		return ArchiveFormat{Strategy: ProbeSerial, Format: "unknown"}
	}
}

// readMagic reads the first 8 bytes of a file for magic number detection.
func readMagic(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	buf := make([]byte, 8)
	n, err := f.Read(buf)
	if err != nil || n < 4 {
		return nil
	}
	return buf[:n]
}

// isZipMagic checks for ZIP magic bytes: PK\x03\x04
func isZipMagic(magic []byte) bool {
	if len(magic) < 4 {
		return false
	}
	return magic[0] == 'P' && magic[1] == 'K' && magic[2] == 0x03 && magic[3] == 0x04
}

// isRarMagic checks for RAR magic bytes: Rar!\x1a\x07
func isRarMagic(magic []byte) bool {
	if len(magic) < 6 {
		return false
	}
	return magic[0] == 'R' && magic[1] == 'a' && magic[2] == 'r' &&
		magic[3] == '!' && magic[4] == 0x1a && magic[5] == 0x07
}

// is7zMagic checks for 7z magic bytes: 7z\xbc\xaf\x27\x1c
func is7zMagic(magic []byte) bool {
	if len(magic) < 6 {
		return false
	}
	return magic[0] == '7' && magic[1] == 'z' &&
		magic[2] == 0xbc && magic[3] == 0xaf &&
		magic[4] == 0x27 && magic[5] == 0x1c
}

// is7zSolid runs `7z l -slt archive.7z` and checks for "Solid = +"
func is7zSolid(archivePath, sevenZipPath string) bool {
	if sevenZipPath == "" {
		return false // can't detect, assume not solid
	}

	cmd := exec.Command(sevenZipPath, "l", "-slt", archivePath)
	hideCmdWindow(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// If we can't list (e.g. encrypted headers), assume not solid
		return false
	}

	return strings.Contains(string(out), "Solid = +")
}

// DetectFormatString returns a human-readable description of the detected format.
func DetectFormatString(af ArchiveFormat) string {
	return fmt.Sprintf("%s (%s)", af.Format, af.Strategy)
}
