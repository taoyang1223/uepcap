package pcap

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var pcapExtensionPattern = regexp.MustCompile(`^\.pcap\d*$`)

// IsPcapFile checks if a file has a pcap extension
func IsPcapFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return pcapExtensionPattern.MatchString(ext) || ext == ".pcapng" || ext == ".cap"
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
