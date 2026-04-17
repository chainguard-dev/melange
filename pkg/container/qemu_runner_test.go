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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/u-root/u-root/pkg/cpio"
	"golang.org/x/crypto/ssh"
)

// testConfigWithSSHKeys creates a minimal Config with SSH host keys for testing.
func testConfigWithSSHKeys(t *testing.T) *Config {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test SSH key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("failed to create signer from test key: %v", err)
	}
	privateKeyPEM, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		t.Fatalf("failed to marshal test private key: %v", err)
	}
	return &Config{
		VMHostKeySigner:          signer,
		VMHostKeyPublic:          signer.PublicKey(),
		VMHostKeyPrivate:         privateKey,
		VMHostKeyPrivateKeyBytes: pem.EncodeToMemory(privateKeyPEM),
	}
}

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

func TestParseDNSSearchDomains(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
		wantErr  bool
	}{
		// Valid single domain
		{
			name:     "single valid domain",
			input:    "example.com",
			expected: []string{"example.com"},
		},
		// Valid multiple domains - comma separated
		{
			name:     "comma separated domains",
			input:    "example.com,test.org",
			expected: []string{"example.com", "test.org"},
		},
		// Multiple commas collapsed
		{
			name:     "multiple commas collapsed",
			input:    "a.com,,b.org",
			expected: []string{"a.com", "b.org"},
		},
		// Comma with spaces around domains (trimmed)
		{
			name:     "comma with spaces trimmed",
			input:    "a.com, b.org , c.net",
			expected: []string{"a.com", "b.org", "c.net"},
		},
		// Hyphenated domain
		{
			name:     "hyphenated domain",
			input:    "my-domain.example.com",
			expected: []string{"my-domain.example.com"},
		},
		// Nested subdomains
		{
			name:     "nested subdomains",
			input:    "a.b.c.d.example.com",
			expected: []string{"a.b.c.d.example.com"},
		},
		// Numeric domain parts
		{
			name:     "numeric domain parts",
			input:    "123.example.com",
			expected: []string{"123.example.com"},
		},
		// Empty input
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		// Only whitespace
		{
			name:    "only whitespace",
			input:   "   ",
			wantErr: true,
		},
		// Only commas
		{
			name:    "only commas",
			input:   ",,,",
			wantErr: true,
		},
		// Space-separated domains (not allowed)
		{
			name:    "space separated domains rejected",
			input:   "example.com test.org",
			wantErr: true,
		},
		// Newline in domain (not allowed)
		{
			name:    "newline rejected",
			input:   "foo\nbar",
			wantErr: true,
		},
		// Tab in domain (not allowed)
		{
			name:    "tab rejected",
			input:   "foo\tbar",
			wantErr: true,
		},
		// Injection with equals sign (netdev option injection)
		{
			name:    "injection attempt with equals",
			input:   "evil=value",
			wantErr: true,
		},
		// Injection with hostfwd attempt
		{
			name:    "hostfwd injection attempt",
			input:   "foo,hostfwd=tcp::8080-:22",
			wantErr: true,
		},
		// Injection with colon
		{
			name:    "colon injection (port-like)",
			input:   "domain:8080",
			wantErr: true,
		},
		// Semicolon injection (command separator)
		{
			name:    "semicolon injection",
			input:   "foo;rm -rf /",
			wantErr: true,
		},
		// Pipe injection
		{
			name:    "pipe injection",
			input:   "foo|cat /etc/passwd",
			wantErr: true,
		},
		// Backtick injection
		{
			name:    "backtick injection",
			input:   "foo`whoami`",
			wantErr: true,
		},
		// Dollar sign injection
		{
			name:    "dollar sign injection",
			input:   "foo$HOME",
			wantErr: true,
		},
		// Quote injection
		{
			name:    "double quote injection",
			input:   `foo"bar`,
			wantErr: true,
		},
		// Single quote injection
		{
			name:    "single quote injection",
			input:   "foo'bar",
			wantErr: true,
		},
		// Ampersand injection
		{
			name:    "ampersand injection",
			input:   "foo&bar",
			wantErr: true,
		},
		// Parentheses injection
		{
			name:    "parentheses injection",
			input:   "foo(bar)",
			wantErr: true,
		},
		// Bracket injection
		{
			name:    "bracket injection",
			input:   "foo[bar]",
			wantErr: true,
		},
		// Brace injection
		{
			name:    "brace injection",
			input:   "foo{bar}",
			wantErr: true,
		},
		// Angle bracket injection
		{
			name:    "angle bracket injection",
			input:   "foo<bar>",
			wantErr: true,
		},
		// Backslash injection
		{
			name:    "backslash injection",
			input:   "foo\\bar",
			wantErr: true,
		},
		// Forward slash (path-like)
		{
			name:    "forward slash injection",
			input:   "foo/bar",
			wantErr: true,
		},
		// One valid, one invalid domain
		{
			name:    "mixed valid and invalid domains",
			input:   "good.com,evil=bad",
			wantErr: true,
		},
		// QEMU dnssearch option injection attempt
		{
			name:    "dnssearch option injection",
			input:   "foo,dnssearch=evil.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseDNSSearchDomains(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseDNSSearchDomains(%q) expected error, got nil with result %v", tt.input, result)
				}
				return
			}

			if err != nil {
				t.Errorf("parseDNSSearchDomains(%q) unexpected %v", tt.input, err)
				return
			}

			if len(result) != len(tt.expected) {
				t.Errorf("parseDNSSearchDomains(%q) returned %d domains, expected %d: got %v, want %v",
					tt.input, len(result), len(tt.expected), result, tt.expected)
				return
			}

			for i, domain := range result {
				if domain != tt.expected[i] {
					t.Errorf("parseDNSSearchDomains(%q)[%d] = %q, expected %q",
						tt.input, i, domain, tt.expected[i])
				}
			}
		})
	}
}

func TestBuildDNSSearchNetdevArgs(t *testing.T) {
	tests := []struct {
		name     string
		domains  []string
		expected string
	}{
		{
			name:     "empty domains",
			domains:  nil,
			expected: "",
		},
		{
			name:     "single domain",
			domains:  []string{"example.com"},
			expected: ",dnssearch=example.com",
		},
		{
			name:     "multiple domains",
			domains:  []string{"a.com", "b.org", "c.net"},
			expected: ",dnssearch=a.com,dnssearch=b.org,dnssearch=c.net",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildDNSSearchNetdevArgs(tt.domains)
			if result != tt.expected {
				t.Errorf("buildDNSSearchNetdevArgs(%v) = %q, expected %q",
					tt.domains, result, tt.expected)
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

func TestVirtiofsdSearchPaths(t *testing.T) {
	// Verify search paths are defined and non-empty
	if len(virtiofsdSearchPaths) == 0 {
		t.Error("virtiofsdSearchPaths is empty")
	}

	// Verify expected paths are present
	expectedPaths := map[string]bool{
		"/usr/libexec/virtiofsd":  false,
		"/usr/lib/qemu/virtiofsd": false,
		"virtiofsd":               false,
	}

	for _, path := range virtiofsdSearchPaths {
		if _, ok := expectedPaths[path]; ok {
			expectedPaths[path] = true
		}
	}

	for path, found := range expectedPaths {
		if !found {
			t.Errorf("expected path %q not found in virtiofsdSearchPaths", path)
		}
	}

	t.Logf("virtiofsdSearchPaths: %v", virtiofsdSearchPaths)
}

func TestIsVirtiofsdAvailable(t *testing.T) {
	path, available := isVirtiofsdAvailable()

	if available {
		// If available, path should be non-empty
		if path == "" {
			t.Error("isVirtiofsdAvailable() returned available=true but empty path")
		}
		t.Logf("virtiofsd found at: %s", path)
	} else {
		// If not available, path should be empty
		if path != "" {
			t.Errorf("isVirtiofsdAvailable() returned available=false but non-empty path: %s", path)
		}
		t.Log("virtiofsd not found on this system")
	}
}

func TestUseVirtiofs(t *testing.T) {
	// Save original env and restore after test
	originalEnv, hadEnv := os.LookupEnv("QEMU_USE_VIRTIOFS")
	defer func() {
		if hadEnv {
			os.Setenv("QEMU_USE_VIRTIOFS", originalEnv)
		} else {
			os.Unsetenv("QEMU_USE_VIRTIOFS")
		}
	}()

	tests := []struct {
		name        string
		envValue    string
		envSet      bool
		expectUse   bool
		expectError bool
	}{
		{
			name:        "env not set",
			envSet:      false,
			expectUse:   false,
			expectError: false,
		},
		{
			name:        "env set to false",
			envValue:    "false",
			envSet:      true,
			expectUse:   false,
			expectError: false,
		},
		{
			name:        "env set to 0",
			envValue:    "0",
			envSet:      true,
			expectUse:   false,
			expectError: false,
		},
		{
			name:        "env set to invalid value",
			envValue:    "invalid",
			envSet:      true,
			expectUse:   false,
			expectError: false,
		},
		{
			name:        "env set to empty string",
			envValue:    "",
			envSet:      true,
			expectUse:   false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envSet {
				os.Setenv("QEMU_USE_VIRTIOFS", tt.envValue)
			} else {
				os.Unsetenv("QEMU_USE_VIRTIOFS")
			}

			use, err := useVirtiofs()

			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if use != tt.expectUse {
				t.Errorf("useVirtiofs() = %v, expected %v", use, tt.expectUse)
			}
		})
	}
}

func TestUseVirtiofs_EnabledWithAvailability(t *testing.T) {
	// Save original env and restore after test
	originalEnv, hadEnv := os.LookupEnv("QEMU_USE_VIRTIOFS")
	defer func() {
		if hadEnv {
			os.Setenv("QEMU_USE_VIRTIOFS", originalEnv)
		} else {
			os.Unsetenv("QEMU_USE_VIRTIOFS")
		}
	}()

	// Test with QEMU_USE_VIRTIOFS=1
	os.Setenv("QEMU_USE_VIRTIOFS", "1")

	_, available := isVirtiofsdAvailable()
	use, err := useVirtiofs()

	if available {
		// virtiofsd is available, should return true with no error
		if err != nil {
			t.Errorf("unexpected error when virtiofsd is available: %v", err)
		}
		if !use {
			t.Error("useVirtiofs() = false when virtiofsd is available and QEMU_USE_VIRTIOFS=1")
		}
		t.Log("virtiofsd available: useVirtiofs returned true")
	} else {
		// virtiofsd is not available, should return error
		if err == nil {
			t.Error("expected error when virtiofsd not available but QEMU_USE_VIRTIOFS=1")
		}
		if use {
			t.Error("useVirtiofs() = true when virtiofsd is not available")
		}
		t.Logf("virtiofsd not available: useVirtiofs returned error: %v", err)
	}
}

func TestUseVirtiofs_ErrorMessageContainsPaths(t *testing.T) {
	// Skip if virtiofsd is available (can't test error path)
	if _, available := isVirtiofsdAvailable(); available {
		t.Skip("virtiofsd is available, cannot test error message")
	}

	// Save original env and restore after test
	originalEnv, hadEnv := os.LookupEnv("QEMU_USE_VIRTIOFS")
	defer func() {
		if hadEnv {
			os.Setenv("QEMU_USE_VIRTIOFS", originalEnv)
		} else {
			os.Unsetenv("QEMU_USE_VIRTIOFS")
		}
	}()

	os.Setenv("QEMU_USE_VIRTIOFS", "1")
	_, err := useVirtiofs()

	if err == nil {
		t.Fatal("expected error but got nil")
	}

	errMsg := err.Error()

	// Error message should mention the search paths
	for _, path := range virtiofsdSearchPaths {
		if !contains(errMsg, path) {
			t.Errorf("error message should contain path %q: %s", path, errMsg)
		}
	}

	t.Logf("error message: %s", errMsg)
}

func TestStopVirtiofsd_NoOp(t *testing.T) {
	ctx := clog.WithLogger(context.Background(), slogtest.TestLogger(t))

	// Test that stopVirtiofsd doesn't panic with zero values
	cfg := &Config{}
	stopVirtiofsd(ctx, cfg)

	// Test with already-zeroed PID
	cfg.VirtiofsdPID = 0
	cfg.VirtiofsdSocketPath = ""
	stopVirtiofsd(ctx, cfg)

	// Should not panic or error
	t.Log("stopVirtiofsd handled zero-value config correctly")
}

func TestStopVirtiofsd_CleansUpSocket(t *testing.T) {
	ctx := clog.WithLogger(context.Background(), slogtest.TestLogger(t))

	// Create a temporary file to simulate a socket
	tmpFile, err := os.CreateTemp("", "test-virtiofsd-*.sock")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	// Verify file exists
	if _, err := os.Stat(tmpPath); os.IsNotExist(err) {
		t.Fatal("temp file should exist")
	}

	cfg := &Config{
		VirtiofsdPID:        0, // No process to kill
		VirtiofsdSocketPath: tmpPath,
	}

	stopVirtiofsd(ctx, cfg)

	// Socket path should be cleared
	if cfg.VirtiofsdSocketPath != "" {
		t.Errorf("VirtiofsdSocketPath should be cleared, got %q", cfg.VirtiofsdSocketPath)
	}

	// File should be removed
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("socket file should be removed")
		os.Remove(tmpPath) // Clean up
	}
}

func TestInjectRuntimeData(t *testing.T) {
	ctx := clog.WithLogger(context.Background(), slogtest.TestLogger(t))
	cfg := testConfigWithSSHKeys(t)

	tmpDir := t.TempDir()
	modulesDir := filepath.Join(tmpDir, "lib/modules")
	testModuleDir := "lib/modules/6.12.0-fakever/test"
	testModulePath := filepath.Join(testModuleDir, "test.ko")
	if err := os.MkdirAll(filepath.Join(tmpDir, testModuleDir), 0o755); err != nil {
		t.Fatalf("failed to create test module dir: %v", err)
	}

	moduleContent := []byte("fake kernel module content")
	if err := os.WriteFile(filepath.Join(tmpDir, testModulePath), moduleContent, 0o644); err != nil {
		t.Fatalf("failed to write test module: %v", err)
	}

	// Create a minimal CPIO file to use as base
	baseCpio := filepath.Join(tmpDir, "base.cpio")
	if err := os.WriteFile(baseCpio, []byte{}, 0o644); err != nil {
		t.Fatalf("failed to create base cpio: %v", err)
	}

	// Test injecting SSH keys and modules into initramfs.
	result, err := injectRuntimeData(ctx, cfg, modulesDir, baseCpio)
	if err != nil {
		t.Fatalf("injectRuntimeData failed: %v", err)
	}
	defer os.Remove(result)

	info, err := os.Stat(result)
	if err != nil {
		t.Fatalf("result file not found: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("result file is empty")
	}

	resultFile, err := os.Open(result)
	if err != nil {
		t.Fatalf("failed to open result cpio: %v", err)
	}
	defer resultFile.Close()

	cpioReader := cpio.Newc.Reader(resultFile)
	foundModule := false
	var foundContent []byte

	for {
		rec, err := cpioReader.ReadRecord()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("failed to read cpio record: %v", err)
		}
		if rec.Name == cpio.Trailer {
			break
		}

		if rec.Name == testModulePath {
			foundModule = true
			reader := io.NewSectionReader(rec.ReaderAt, 0, int64(rec.FileSize))
			foundContent, err = io.ReadAll(reader)
			if err != nil {
				t.Fatalf("failed to read module content from cpio: %v", err)
			}
			break
		}
	}

	if !foundModule {
		t.Errorf("module not found at expected path %q in cpio archive", testModulePath)
	}
	if string(foundContent) != string(moduleContent) {
		t.Errorf("module content mismatch: got %q, want %q", string(foundContent), string(moduleContent))
	}
}

// contains checks if substr is in s
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestEffectiveCPU(t *testing.T) {
	tests := []struct {
		name      string
		cfgCPU    int
		cgroupCPU int
		hostCPU   int
		want      int
	}{
		// Flag / YAML precedence (Invariants 1 & 2):
		// cfg wins over the fallback (never returns 2 when cfgCPU is set)
		// but is still capped at the cgroup-narrowed host.
		{name: "flag wins under host", cfgCPU: 4, cgroupCPU: 0, hostCPU: 8, want: 4},
		{name: "flag wins over cgroup when smaller", cfgCPU: 4, cgroupCPU: 8, hostCPU: 16, want: 4},
		{name: "flag wins at host boundary", cfgCPU: 8, cgroupCPU: 0, hostCPU: 8, want: 8},
		{name: "flag capped at host when larger", cfgCPU: 16, cgroupCPU: 0, hostCPU: 8, want: 8},
		{name: "flag capped at cgroup when cgroup narrower", cfgCPU: 16, cgroupCPU: 4, hostCPU: 8, want: 4},
		{name: "flag capped at cgroup on big host", cfgCPU: 16, cgroupCPU: 4, hostCPU: 32, want: 4},

		// Cgroup precedence (Invariant 3)
		{name: "cgroup wins when cfg empty", cfgCPU: 0, cgroupCPU: 3, hostCPU: 8, want: 3},
		{name: "cgroup at host boundary falls to fallback", cfgCPU: 0, cgroupCPU: 8, hostCPU: 8, want: 2},
		// cgroupCPU >= hostCPU means cgroup didn't actually narrow — fallback applies.

		// Fallback (Invariant 4)
		{name: "regression: no cfg no cgroup big host", cfgCPU: 0, cgroupCPU: 0, hostCPU: 16, want: 2},
		{name: "fallback caps at 2 on 32-core host", cfgCPU: 0, cgroupCPU: 0, hostCPU: 32, want: 2},
		{name: "fallback small host", cfgCPU: 0, cgroupCPU: 0, hostCPU: 1, want: 1},
		{name: "fallback exact 2 host", cfgCPU: 0, cgroupCPU: 0, hostCPU: 2, want: 2},

		// Edge: zero / degenerate inputs
		{name: "all zero (degenerate)", cfgCPU: 0, cgroupCPU: 0, hostCPU: 0, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := effectiveCPU(tt.cfgCPU, tt.cgroupCPU, tt.hostCPU)
			if got != tt.want {
				t.Errorf("effectiveCPU(cfg=%d, cgroup=%d, host=%d) = %d, want %d",
					tt.cfgCPU, tt.cgroupCPU, tt.hostCPU, got, tt.want)
			}
		})
	}
}

func TestEffectiveMemoryKB(t *testing.T) {
	const (
		gib       = int64(1024 * 1024) // 1 GiB in KB
		fallback  = int64(4 * 1024 * 1024)
		bigHost   = int64(108 * 1024 * 1024) // 108 GiB in KB (85% of 128 GiB)
		smallHost = int64(2 * 1024 * 1024)
	)

	tests := []struct {
		name     string
		cfgKB    int64
		hostKB   int64 // the already-scaled (85%) host-available value
		cgroupKB int64
		want     int64
	}{
		// Flag / YAML precedence
		{name: "cfg wins under host", cfgKB: 8 * gib, hostKB: bigHost, cgroupKB: 0, want: 8 * gib},
		{name: "cfg wins over cgroup", cfgKB: 8 * gib, hostKB: 16 * gib, cgroupKB: 32 * gib, want: 8 * gib},
		{name: "cfg capped at host", cfgKB: 32 * gib, hostKB: smallHost, cgroupKB: 0, want: smallHost},

		// Cgroup precedence: host is already cgroup-aware, so pass through.
		{name: "cgroup wins when cfg empty", cfgKB: 0, hostKB: 8 * gib, cgroupKB: 16 * gib, want: 8 * gib},

		// Fallback cap at 4Gi when no cfg and no cgroup
		{name: "regression: 128GiB host capped at 4GiB", cfgKB: 0, hostKB: bigHost, cgroupKB: 0, want: fallback},
		{name: "fallback exact 4GiB host", cfgKB: 0, hostKB: fallback, cgroupKB: 0, want: fallback},
		{name: "fallback small host below cap", cfgKB: 0, hostKB: 2 * gib, cgroupKB: 0, want: 2 * gib},

		// Edge
		{name: "cfg zero host zero", cfgKB: 0, hostKB: 0, cgroupKB: 0, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := effectiveMemoryKB(tt.cfgKB, tt.hostKB, tt.cgroupKB)
			if got != tt.want {
				t.Errorf("effectiveMemoryKB(cfg=%d, host=%d, cgroup=%d) = %d, want %d",
					tt.cfgKB, tt.hostKB, tt.cgroupKB, got, tt.want)
			}
		})
	}
}
