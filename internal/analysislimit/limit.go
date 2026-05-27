package analysislimit

import (
	"os"
	"strconv"
	"strings"
)

const DefaultMaxRows = 200000
const DefaultMaxJSONBytes int64 = 128 << 20

func MaxRows(envName string) int {
	value := strings.TrimSpace(os.Getenv(envName))
	if value == "" {
		return DefaultMaxRows
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return DefaultMaxRows
	}
	return parsed
}

func MaxBytes(envName string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(envName))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
