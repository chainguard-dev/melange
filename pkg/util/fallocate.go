//go:build !linux && !darwin

package util

import (
	"fmt"
	"os"
)

func Fallocate(file *os.File, offset int64, length int64) error {
	return fmt.Errorf("not implemented for this platform")
}
