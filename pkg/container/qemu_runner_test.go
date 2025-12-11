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
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/clog/slogtest"
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

func TestGetAdditionalPackages(t *testing.T) {
	ctx := clog.WithLogger(context.Background(), slogtest.TestLogger(t))

	tests := []struct {
		name     string
		envValue string
		expected []string
	}{
		{
			name:     "empty environment variable",
			envValue: "",
			expected: nil,
		},
		{
			name:     "single package",
			envValue: "hello-wolfi",
			expected: []string{"hello-wolfi"},
		},
		{
			name:     "multiple packages",
			envValue: "hello-wolfi,nginx-stable,strace",
			expected: []string{"hello-wolfi", "nginx-stable", "strace"},
		},
		{
			name:     "packages with spaces around commas rejected",
			envValue: "hello-wolfi, nginx-stable , strace",
			expected: nil,
		},
		{
			name:     "packages with dots and underscores",
			envValue: "python-3.11,gcc_musl,nginx-1.25.0",
			expected: []string{"python-3.11", "gcc_musl", "nginx-1.25.0"},
		},
		{
			name:     "empty entries filtered out",
			envValue: "hello-wolfi,,nginx-stable",
			expected: []string{"hello-wolfi", "nginx-stable"},
		},
		{
			name:     "invalid characters rejected",
			envValue: "hello-wolfi;rm -rf /",
			expected: nil,
		},
		{
			name:     "shell injection attempt",
			envValue: "package$(evil_command)",
			expected: nil,
		},
		{
			name:     "quotes rejected",
			envValue: "\"hello-wolfi\"",
			expected: nil,
		},
		{
			name:     "spaces in package name rejected",
			envValue: "hello wolfi",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			if tt.envValue == "" {
				os.Unsetenv("QEMU_ADDITIONAL_PACKAGES")
			} else {
				os.Setenv("QEMU_ADDITIONAL_PACKAGES", tt.envValue)
			}
			defer os.Unsetenv("QEMU_ADDITIONAL_PACKAGES")

			result := getAdditionalPackages(ctx)

			// Compare results
			if len(result) != len(tt.expected) {
				t.Errorf("getAdditionalPackages() returned %d packages, expected %d: got %v, want %v",
					len(result), len(tt.expected), result, tt.expected)
				return
			}

			for i, pkg := range result {
				if pkg != tt.expected[i] {
					t.Errorf("getAdditionalPackages()[%d] = %q, expected %q", i, pkg, tt.expected[i])
				}
			}
		})
	}
}

func TestGetPackageCacheSuffix(t *testing.T) {
	tests := []struct {
		name     string
		packages []string
		expected string
	}{
		{
			name:     "empty package list",
			packages: []string{},
			expected: "",
		},
		{
			name:     "nil package list",
			packages: nil,
			expected: "",
		},
		{
			name:     "single package",
			packages: []string{"hello-wolfi"},
			expected: "-f5c4369d6487",
		},
		{
			name:     "multiple packages deterministic",
			packages: []string{"hello-wolfi", "nginx-stable", "strace"},
			expected: "-8315f3ef029a",
		},
		{
			name:     "same packages different order produces different hash",
			packages: []string{"strace", "hello-wolfi", "nginx-stable"},
			expected: "-5236a484f919",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getPackageCacheSuffix(tt.packages)

			if result != tt.expected {
				t.Errorf("getPackageCacheSuffix(%v) = %q, expected %q", tt.packages, result, tt.expected)
			}

			// Additional validation: check format
			if len(tt.packages) > 0 {
				// Should start with dash and have 12 hex characters
				if len(result) != 13 { // "-" + 12 hex chars
					t.Errorf("getPackageCacheSuffix(%v) = %q, expected 13 characters (dash + 12 hex)", tt.packages, result)
				}
				if result[0] != '-' {
					t.Errorf("getPackageCacheSuffix(%v) = %q, expected to start with '-'", tt.packages, result)
				}
			}
		})
	}
}

func TestGetPackageCacheSuffix_Deterministic(t *testing.T) {
	// Test that the same packages always produce the same hash
	packages := []string{"hello-wolfi", "nginx-stable", "strace"}

	result1 := getPackageCacheSuffix(packages)
	result2 := getPackageCacheSuffix(packages)

	if result1 != result2 {
		t.Errorf("getPackageCacheSuffix is not deterministic: first call returned %q, second call returned %q", result1, result2)
	}
}

func TestGetPackageCacheSuffix_NoCollisions(t *testing.T) {
	// Test that different package lists produce different hashes
	testCases := [][]string{
		{"package-a", "package-b", "package-c", "package-d", "package-e"},
		{"package-a", "package-b", "package-c", "package-d", "package-f"},
		{"hello-wolfi"},
		{"hello-wolfi", "nginx-stable"},
		{"nginx-stable", "hello-wolfi"}, // Order matters
	}

	hashes := make(map[string][]string)
	for _, packages := range testCases {
		hash := getPackageCacheSuffix(packages)
		hashes[hash] = packages
	}

	// Should have unique hashes for each unique package list
	if len(hashes) != len(testCases) {
		t.Errorf("getPackageCacheSuffix produced collisions: %d unique hashes for %d test cases", len(hashes), len(testCases))
		for hash, packages := range hashes {
			t.Logf("Hash %q: %v", hash, packages)
		}
	}
}
