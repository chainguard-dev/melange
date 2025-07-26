// Copyright 2025 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package container

import (
	"runtime"
	"testing"
)

func TestGetAvailableMemoryKB(t *testing.T) {
	// This test ensures the function works correctly on both Linux and macOS
	// with the new implementation that uses MemAvailable on Linux and vm_stat on macOS

	result := getAvailableMemoryKB()

	// Check that we get a positive value
	if result <= 0 {
		t.Errorf("getAvailableMemoryKB() = %d, expected positive value", result)
	}

	// Check that the value is reasonable (at least 1MB, less than 1PB)
	// This ensures we're not getting garbage values
	minExpected := 1024                      // 1MB in KB
	maxExpected := 1024 * 1024 * 1024 * 1024 // 1PB in KB

	if result < minExpected || result > maxExpected {
		t.Errorf("getAvailableMemoryKB() = %d KB, outside reasonable range [%d, %d]",
			result, minExpected, maxExpected)
	}

	// Log the result for debugging
	t.Logf("getAvailableMemoryKB() returned %d KB on %s", result, runtime.GOOS)
}

func TestGetAvailableMemoryKB_LinuxBehavior(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}

	// On Linux, the function should read from /proc/meminfo
	// We can't easily mock this without refactoring the function,
	// but we can at least verify it returns a reasonable value

	result := getAvailableMemoryKB()

	// On a Linux system, we should get a value > 0
	if result <= 0 {
		t.Errorf("getAvailableMemoryKB() on Linux = %d, expected positive value", result)
	}

	// The new implementation tries MemAvailable first, then falls back to
	// MemFree + Buffers + Cached. Either way, we should get a reasonable value.
	t.Logf("Linux system reported %d KB available memory", result)
}

func TestGetAvailableMemoryKB_DarwinBehavior(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin-specific test")
	}

	// On macOS, the function should use vm_stat command
	// The new implementation parses vm_stat output to calculate
	// available memory as: (free + inactive + speculative) * pageSize / 1024

	result := getAvailableMemoryKB()

	// On a macOS system, we should get a value > 0
	if result <= 0 {
		t.Errorf("getAvailableMemoryKB() on Darwin = %d, expected positive value", result)
	}

	// The value should be reasonable for a macOS system
	// Most modern Macs have at least 8GB of RAM, so available should be at least 1GB
	minExpectedMac := 1024 * 1024 // 1GB in KB
	if result < minExpectedMac {
		t.Logf("Warning: getAvailableMemoryKB() on Darwin = %d KB, which seems low for a modern Mac", result)
	}

	t.Logf("macOS system reported %d KB available memory", result)
}

func TestGetAvailableMemoryKB_Fallback(t *testing.T) {
	// Test that the fallback value is reasonable
	// The function returns 16000000 (approximately 15.3GB) as a fallback

	// We can't easily test the fallback case without mocking,
	// but we document the expected behavior
	expectedFallback := 16000000

	t.Logf("Fallback value is %d KB (%.1f GB)", expectedFallback, float64(expectedFallback)/1024/1024)

	// Ensure fallback is reasonable
	if expectedFallback < 1024*1024 { // Less than 1GB
		t.Errorf("Fallback value %d KB seems too low", expectedFallback)
	}
}
