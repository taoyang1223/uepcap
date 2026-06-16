package pcap

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	pcapExtensionPattern      = regexp.MustCompile(`^\.pcap\d*$`)
	downloadCopySuffixPattern = regexp.MustCompile(`\s*\(\d+\)$`)
)

// IsPcapFile checks if a file has a pcap extension
func IsPcapFile(filename string) bool {
	return isPcapCaptureName(normalizeCaptureFilename(filename))
}

// IsGzipPcapFile checks if a file is a gzip-compressed pcap capture.
func IsGzipPcapFile(filename string) bool {
	if !strings.EqualFold(filepath.Ext(filename), ".gz") {
		return false
	}
	return isPcapCaptureName(normalizeCaptureFilename(filename))
}

// UncompressedFilename strips upload/download suffixes that should not affect capture parsing.
func UncompressedFilename(filename string) string {
	return normalizeCaptureFilename(filename)
}

func isPcapCaptureName(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return pcapExtensionPattern.MatchString(ext) || ext == ".pcapng" || ext == ".cap"
}

func uncompressedFilename(filename string) string {
	ext := filepath.Ext(filename)
	if strings.EqualFold(ext, ".gz") {
		return strings.TrimSuffix(filename, ext)
	}
	return filename
}

func normalizeCaptureFilename(filename string) string {
	return downloadCopySuffixPattern.ReplaceAllString(uncompressedFilename(filename), "")
}

// FileSize returns the size of a file in bytes
func FileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// EnsureDir ensures a directory exists
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// CleanDir removes all files in a directory but keeps the directory
func CleanDir(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		err := os.RemoveAll(filepath.Join(path, entry.Name()))
		if err != nil {
			return err
		}
	}
	return nil
}
