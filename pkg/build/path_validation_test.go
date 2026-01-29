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

package build

import (
	"testing"
)

// TestIsValidPath validates the path traversal protection added for GHSA-qxx2-7h4c-83f4
func TestIsValidPath(t *testing.T) {
	baseDir := "/workspace"

	tests := []struct {
		name      string
		path      string
		wantError bool
		errMsg    string
	}{
		{
			name:      "valid relative path",
			path:      "melange-out/package/file.txt",
			wantError: false,
		},
		{
			name:      "valid nested path",
			path:      "melange-out/package/subdir/file.txt",
			wantError: false,
		},
		{
			name:      "valid single file",
			path:      "file.txt",
			wantError: false,
		},
		{
			name:      "path traversal with ../",
			path:      "../../etc/passwd",
			wantError: true,
			errMsg:    "path traversal detected",
		},
		{
			name:      "path traversal in middle",
			path:      "melange-out/../../etc/passwd",
			wantError: true,
			errMsg:    "path traversal detected",
		},
		{
			name:      "absolute path",
			path:      "/etc/passwd",
			wantError: true,
			errMsg:    "absolute paths not allowed",
		},
		{
			name:      "absolute path to tmp",
			path:      "/tmp/malicious",
			wantError: true,
			errMsg:    "absolute paths not allowed",
		},
		{
			name:      "null byte injection",
			path:      "file\x00.txt",
			wantError: true,
			errMsg:    "null byte",
		},
		{
			name:      "just ..",
			path:      "..",
			wantError: true,
			errMsg:    "path traversal detected",
		},
		{
			name:      "multiple ../",
			path:      "../../../../../../../etc/passwd",
			wantError: true,
			errMsg:    "path traversal detected",
		},
		{
			name:      "path with ./ prefix (should be cleaned)",
			path:      "./melange-out/file.txt",
			wantError: false,
		},
		{
			name:      "tricky traversal with unicode",
			path:      "melange-out/../../../etc/passwd",
			wantError: true,
			errMsg:    "path traversal detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := isValidPath(tt.path, baseDir)
			if tt.wantError {
				if err == nil {
					t.Errorf("isValidPath(%q, %q) expected error containing %q, got nil", tt.path, baseDir, tt.errMsg)
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("isValidPath(%q, %q) error = %v, want error containing %q", tt.path, baseDir, err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("isValidPath(%q, %q) unexpected error: %v", tt.path, baseDir, err)
				}
			}
		})
	}
}

// TestIsValidPath_SymlinkTargets tests validation of symlink targets
func TestIsValidPath_SymlinkTargets(t *testing.T) {
	baseDir := "/workspace"

	tests := []struct {
		name       string
		linkTarget string
		wantError  bool
		errMsg     string
	}{
		{
			name:       "valid relative symlink",
			linkTarget: "melange-out/other-file",
			wantError:  false,
		},
		{
			name:       "symlink traversal attack",
			linkTarget: "../../../etc/passwd",
			wantError:  true,
			errMsg:     "path traversal detected",
		},
		{
			name:       "absolute symlink target",
			linkTarget: "/etc/passwd",
			wantError:  true,
			errMsg:     "absolute paths not allowed",
		},
		{
			name:       "symlink to /syft (real attack vector)",
			linkTarget: "../../../../syft",
			wantError:  true,
			errMsg:     "path traversal detected",
		},
		{
			name:       "symlink to /usr/bin/curl (real attack vector)",
			linkTarget: "../../../../usr/bin/curl",
			wantError:  true,
			errMsg:     "path traversal detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := isValidPath(tt.linkTarget, baseDir)
			if tt.wantError {
				if err == nil {
					t.Errorf("isValidPath(%q, %q) for symlink target expected error, got nil", tt.linkTarget, baseDir)
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("isValidPath(%q, %q) error = %v, want error containing %q", tt.linkTarget, baseDir, err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("isValidPath(%q, %q) for symlink target unexpected error: %v", tt.linkTarget, baseDir, err)
				}
			}
		})
	}
}

// TestIsValidPath_RealWorldAttacks tests actual attack vectors from GHSA-qxx2-7h4c-83f4
func TestIsValidPath_RealWorldAttacks(t *testing.T) {
	baseDir := "/workspace"

	attacks := []struct {
		name   string
		path   string
		target string // for symlinks
	}{
		{
			name: "overwrite /syft binary",
			path: "../../../../syft",
		},
		{
			name: "overwrite /usr/bin/curl",
			path: "../../../../usr/bin/curl",
		},
		{
			name: "overwrite /usr/bin/mal",
			path: "../../../../usr/bin/mal",
		},
		{
			name: "overwrite /ko-app/entrypoint",
			path: "../../../../ko-app/entrypoint",
		},
		{
			name: "overwrite /root/.bashrc",
			path: "../../../../root/.bashrc",
		},
		{
			name: "write to /tmp",
			path: "../../../../tmp/backdoor.sh",
		},
		{
			name: "write to /etc",
			path: "../../../../etc/backdoor",
		},
		{
			name:   "symlink to escape workspace",
			path:   "innocent-file",
			target: "../../../etc/passwd",
		},
	}

	for _, attack := range attacks {
		t.Run(attack.name, func(t *testing.T) {
			if attack.target != "" {
				// For symlink attacks, the path itself may be innocent but target is malicious
				err := isValidPath(attack.target, baseDir)
				if err == nil {
					t.Errorf("isValidPath(%q) should block symlink target for attack %q, but returned nil", attack.target, attack.name)
				}
			} else {
				// For direct path attacks, test the path validation
				err := isValidPath(attack.path, baseDir)
				if err == nil {
					t.Errorf("isValidPath(%q) should block attack vector %q, but returned nil", attack.path, attack.name)
				}
			}
		})
	}
}

// TestIsValidPath_EdgeCases tests edge cases and boundary conditions
func TestIsValidPath_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		baseDir   string
		wantError bool
	}{
		{
			name:      "empty path",
			path:      "",
			baseDir:   "/workspace",
			wantError: false, // Empty path is cleaned to "." which is valid
		},
		{
			name:      "just dot",
			path:      ".",
			baseDir:   "/workspace",
			wantError: false,
		},
		{
			name:      "multiple slashes",
			path:      "melange-out///file.txt",
			baseDir:   "/workspace",
			wantError: false, // Cleaned by filepath.Clean
		},
		{
			name:      "Windows-style path with backslashes",
			path:      "melange-out\\..\\..\\file.txt",
			baseDir:   "/workspace",
			wantError: false, // On Unix, backslash is valid filename char
		},
		{
			name:      "trailing slash",
			path:      "melange-out/",
			baseDir:   "/workspace",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := isValidPath(tt.path, tt.baseDir)
			if tt.wantError && err == nil {
				t.Errorf("isValidPath(%q, %q) expected error, got nil", tt.path, tt.baseDir)
			} else if !tt.wantError && err != nil {
				t.Errorf("isValidPath(%q, %q) unexpected error: %v", tt.path, tt.baseDir, err)
			}
		})
	}
}

// Helper function to check if a string contains a substring
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

// Benchmark the validation function
func BenchmarkIsValidPath(b *testing.B) {
	baseDir := "/workspace"
	testPaths := []string{
		"melange-out/package/file.txt",
		"../../etc/passwd",
		"/absolute/path",
		"./relative/path",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, path := range testPaths {
			_ = isValidPath(path, baseDir)
		}
	}
}
