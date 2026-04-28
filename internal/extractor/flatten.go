package extractor

import (
	"io"
	"os"
	"path/filepath"
)

// FlattenSingleFolder checks if outputDir contains exactly one subdirectory
// (and no files at top level), and if so, moves its contents up to outputDir.
// Repeats until the top level has more than one entry or contains files.
// e.g., output/inner/deep/files → output/files
func FlattenSingleFolder(outputDir string) error {
	for {
		entries, err := os.ReadDir(outputDir)
		if err != nil {
			return err
		}

		// Check: exactly one entry, which is a directory
		if len(entries) != 1 || !entries[0].IsDir() {
			return nil // nothing to flatten
		}

		innerDir := filepath.Join(outputDir, entries[0].Name())
		if err := flattenInto(innerDir, outputDir); err != nil {
			return err
		}
		// Loop again — there may be another single-folder layer
	}
}

// flattenInto moves all contents of src into dst, then removes src.
func flattenInto(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, e := range entries {
		srcPath := filepath.Join(src, e.Name())
		dstPath := filepath.Join(dst, e.Name())

		// If destination exists, rename with conflict suffix
		if _, err := os.Stat(dstPath); err == nil {
			dstPath = dstPath + "_conflict"
		}

		if err := moveFileOrDir(srcPath, dstPath); err != nil {
			return err
		}
	}

	// Remove the now-empty src directory
	return os.Remove(src)
}

// moveFileOrDir moves a file or directory from src to dst.
func moveFileOrDir(src, dst string) error {
	// Try atomic rename first
	if err := os.Rename(src, dst); err == nil {
		return nil
	}

	// Fallback: copy then delete
	info, err := os.Stat(src)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return copyDir(src, dst)
	}
	return copyFile(src, dst)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}

	info, err := in.Stat()
	if err != nil {
		in.Close()
		return err
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		in.Close()
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		in.Close()
		return err
	}

	// Close both files BEFORE removing the source. On Windows, os.Remove
	// fails if the file is still open (mandatory file locking).
	out.Close()
	in.Close()

	return os.Remove(src)
}

func copyDir(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, info.Mode()); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		if e.IsDir() {
			if err := copyDir(s, d); err != nil {
				return err
			}
		} else {
			if err := copyFile(s, d); err != nil {
				return err
			}
		}
	}
	return os.RemoveAll(src)
}
