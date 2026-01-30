// Copyright 2026 Chainguard, Inc.
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
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"chainguard.dev/melange/pkg/config"
)

// compilePatchPipeline is a helper that compiles the actual patch pipeline
// from pipelines/patch.yaml with the given inputs and returns the compiled script.
// This ensures all tests use the real pipeline definition, not hardcoded patterns.
func compilePatchPipeline(t *testing.T, with map[string]string) string {
	t.Helper()
	ctx := context.Background()

	pipeline := config.Pipeline{
		Uses: "patch",
		With: with,
	}

	sm := &SubstitutionMap{
		Substitutions: map[string]string{},
	}

	c := &Compiled{}
	if err := c.compilePipeline(ctx, sm, &pipeline, nil); err != nil {
		t.Fatalf("Failed to compile pipeline: %v", err)
	}

	// The patch.yaml has a pipeline section with runs inside
	// After compilation, the runs are in pipeline.Pipeline[0].Runs
	var script string
	if len(pipeline.Pipeline) > 0 {
		script = pipeline.Pipeline[0].Runs
	} else {
		script = pipeline.Runs
	}

	if script == "" {
		t.Fatalf("Compiled pipeline has no script")
	}

	return script
}

// TestPatchPipelineCompilation tests that the patch pipeline compiles correctly
// with various inputs. This uses compilePipeline() which loads the actual
// pipelines/patch.yaml file.
func TestPatchPipelineCompilation(t *testing.T) {
	tests := []struct {
		name string
		with map[string]string
	}{
		{
			name: "with patches input",
			with: map[string]string{
				"patches":          "fix.patch security.patch",
				"strip-components": "1",
				"fuzz":             "2",
			},
		},
		{
			name: "with series file input",
			with: map[string]string{
				"series":           "patches/series",
				"strip-components": "2",
				"fuzz":             "0",
			},
		},
		{
			name: "with default values",
			with: map[string]string{
				"patches": "my.patch",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := compilePatchPipeline(t, tt.with)
			// Just verify it compiled and produced a non-empty script
			if script == "" {
				t.Errorf("Expected non-empty compiled script")
			}
		})
	}
}

// TestPatchPipelineMaliciousInputsBlocked tests that malicious inputs
// are blocked by the validation logic in the actual compiled pipeline script.
// This test compiles the real patch.yaml with malicious inputs and verifies
// the validation rejects them.
func TestPatchPipelineMaliciousInputsBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping shell execution tests in short mode")
	}

	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	tests := []struct {
		name        string
		with        map[string]string
		shouldError bool
		errorMsg    string
	}{
		{
			name: "valid series path",
			with: map[string]string{
				"series":           "/tmp/patches/series",
				"strip-components": "1",
				"fuzz":             "2",
			},
			// Will fail because file doesn't exist, but NOT due to validation
			shouldError: true,
			errorMsg:    "does not exist",
		},
		{
			name: "series with single quote",
			with: map[string]string{
				"series":           "path'with'quote",
				"strip-components": "1",
				"fuzz":             "2",
			},
			shouldError: true,
			errorMsg:    "invalid characters",
		},
		{
			name: "series with command substitution",
			with: map[string]string{
				"series":           "$(malicious)",
				"strip-components": "1",
				"fuzz":             "2",
			},
			shouldError: true,
			errorMsg:    "invalid characters",
		},
		{
			name: "series with backticks",
			with: map[string]string{
				"series":           "`malicious`",
				"strip-components": "1",
				"fuzz":             "2",
			},
			shouldError: true,
			errorMsg:    "invalid characters",
		},
		{
			name: "series with semicolon",
			with: map[string]string{
				"series":           "/tmp/patches;evil",
				"strip-components": "1",
				"fuzz":             "2",
			},
			shouldError: true,
			errorMsg:    "invalid characters",
		},
		{
			name: "series with pipe",
			with: map[string]string{
				"series":           "/tmp/patches|evil",
				"strip-components": "1",
				"fuzz":             "2",
			},
			shouldError: true,
			errorMsg:    "invalid characters",
		},
		{
			name: "series with variable expansion",
			with: map[string]string{
				"series":           "${PATH}",
				"strip-components": "1",
				"fuzz":             "2",
			},
			shouldError: true,
			errorMsg:    "invalid characters",
		},
		{
			name: "fuzz with semicolon",
			with: map[string]string{
				"patches":          "test.patch",
				"strip-components": "1",
				"fuzz":             "2;evil",
			},
			shouldError: true,
			errorMsg:    "non-negative integer",
		},
		{
			name: "fuzz with letters",
			with: map[string]string{
				"patches":          "test.patch",
				"strip-components": "1",
				"fuzz":             "abc",
			},
			shouldError: true,
			errorMsg:    "non-negative integer",
		},
		{
			name: "strip-components with letters",
			with: map[string]string{
				"patches":          "test.patch",
				"strip-components": "abc",
				"fuzz":             "2",
			},
			shouldError: true,
			errorMsg:    "non-negative integer",
		},
		{
			name: "strip-components negative",
			with: map[string]string{
				"patches":          "test.patch",
				"strip-components": "-1",
				"fuzz":             "2",
			},
			shouldError: true,
			errorMsg:    "non-negative integer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := compilePatchPipeline(t, tt.with)

			// Execute the compiled script
			tmpDir := t.TempDir()
			cmd := exec.Command("sh", "-c", script)
			cmd.Dir = tmpDir
			output, err := cmd.CombinedOutput()

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected script to fail for %q, but it passed.\nOutput: %s", tt.name, output)
				} else if tt.errorMsg != "" && !strings.Contains(string(output), tt.errorMsg) {
					t.Errorf("Expected error message containing %q, got: %s\nScript:\n%s", tt.errorMsg, output, script)
				}
			} else {
				if err != nil {
					t.Errorf("Expected script to pass for %q, but it failed.\nOutput: %s\nError: %v", tt.name, output, err)
				}
			}
		})
	}
}

// TestPatchPipelineEndToEnd tests that the patch pipeline works correctly
// with actual patch files in a real environment. This uses the actual
// compiled pipeline from pipelines/patch.yaml.
func TestPatchPipelineEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping end-to-end tests in short mode")
	}

	// Check if required tools are available
	for _, tool := range []string{"sh", "patch", "grep", "mktemp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}

	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Create a source file to patch
	sourceFile := filepath.Join(tmpDir, "source.txt")
	if err := os.WriteFile(sourceFile, []byte("line1\nline2\nline3\n"), 0o644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	// Create a valid patch file (unified diff format)
	patchContent := `--- source.txt.orig
+++ source.txt
@@ -1,3 +1,3 @@
 line1
-line2
+line2_patched
 line3
`
	patchFile := filepath.Join(tmpDir, "test.patch")
	if err := os.WriteFile(patchFile, []byte(patchContent), 0o644); err != nil {
		t.Fatalf("Failed to create patch file: %v", err)
	}

	// Create a series file with the patch filename
	seriesFile := filepath.Join(tmpDir, "series")
	if err := os.WriteFile(seriesFile, []byte(patchFile+"\n"), 0o644); err != nil {
		t.Fatalf("Failed to create series file: %v", err)
	}

	// Compile and run the actual patch pipeline
	script := compilePatchPipeline(t, map[string]string{
		"series":           seriesFile,
		"strip-components": "0",
		"fuzz":             "0",
	})

	cmd := exec.Command("sh", "-c", script)
	cmd.Dir = tmpDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Patch pipeline failed: %v\nOutput: %s\nScript:\n%s", err, output, script)
	}

	// Verify the patch was applied
	patched, err := os.ReadFile(sourceFile)
	if err != nil {
		t.Fatalf("Failed to read patched file: %v", err)
	}

	if !strings.Contains(string(patched), "line2_patched") {
		t.Errorf("Patch was not applied correctly.\nExpected 'line2_patched' in:\n%s\nScript output:\n%s\nScript:\n%s", patched, output, script)
	}
}

// TestPatchPipelinePatchfileValidation tests that malicious patch filenames
// read from a series file are blocked by the actual compiled pipeline.
func TestPatchPipelinePatchfileValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping shell execution tests in short mode")
	}

	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	tests := []struct {
		name            string
		patchfileName   string
		shouldBeBlocked bool
	}{
		{
			name:            "patch with single quote",
			patchfileName:   "fix'quote.patch",
			shouldBeBlocked: true,
		},
		{
			name:            "patch with backtick",
			patchfileName:   "fix`id`.patch",
			shouldBeBlocked: true,
		},
		{
			name:            "patch with command substitution",
			patchfileName:   "fix$(whoami).patch",
			shouldBeBlocked: true,
		},
		{
			name:            "patch with semicolon",
			patchfileName:   "fix.patch;evil",
			shouldBeBlocked: true,
		},
		{
			name:            "patch with pipe",
			patchfileName:   "fix.patch|evil",
			shouldBeBlocked: true,
		},
		{
			name:            "patch with ampersand",
			patchfileName:   "fix.patch&evil",
			shouldBeBlocked: true,
		},
		{
			name:            "patch with redirect",
			patchfileName:   "fix.patch>evil",
			shouldBeBlocked: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Create a series file with the potentially malicious patch filename
			seriesFile := filepath.Join(tmpDir, "series")
			if err := os.WriteFile(seriesFile, []byte(tt.patchfileName+"\n"), 0o644); err != nil {
				t.Fatalf("Failed to create series file: %v", err)
			}

			// Compile the actual patch pipeline
			script := compilePatchPipeline(t, map[string]string{
				"series":           seriesFile,
				"strip-components": "1",
				"fuzz":             "2",
			})

			// Execute the compiled script
			cmd := exec.Command("sh", "-c", script)
			cmd.Dir = tmpDir
			output, err := cmd.CombinedOutput()

			if tt.shouldBeBlocked {
				if err == nil {
					t.Errorf("Expected malicious patchfile %q to be blocked, but validation passed.\nOutput: %s\nScript:\n%s",
						tt.patchfileName, output, script)
				} else if !strings.Contains(string(output), "invalid characters") {
					t.Errorf("Expected 'invalid characters' error for %q, got: %s", tt.patchfileName, output)
				}
			} else {
				// For valid filenames, it should fail because the file doesn't exist,
				// NOT because of validation
				if err != nil && strings.Contains(string(output), "invalid characters") {
					t.Errorf("Valid patchfile %q was incorrectly blocked.\nOutput: %s\nError: %v",
						tt.patchfileName, output, err)
				}
			}
		})
	}
}

// TestPatchPipelinePOSIXCompatibility verifies the compiled pipeline script
// is POSIX-compliant by testing with different shells.
func TestPatchPipelinePOSIXCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping POSIX compatibility tests in short mode")
	}

	// Compile the actual patch pipeline with valid inputs
	// We use patches input (not series) so we can test the validation logic
	// without needing actual files
	script := compilePatchPipeline(t, map[string]string{
		"patches":          "test.patch",
		"strip-components": "1",
		"fuzz":             "2",
	})

	// Check for common bashisms in the compiled script
	bashisms := []struct {
		pattern     string
		description string
	}{
		{
			pattern:     "$'\\n'",
			description: "ANSI-C quoting for newline",
		},
		{
			pattern:     "$'\\r'",
			description: "ANSI-C quoting for carriage return",
		},
		{
			pattern:     "$'\\t'",
			description: "ANSI-C quoting for tab",
		},
		// Note: We don't check for [[ and ]] because [[:space:]] is a valid
		// POSIX character class. Actual bash extended test would be caught
		// by running with dash/sh below.
		{
			pattern:     "function ",
			description: "bash function keyword",
		},
		{
			pattern:     "declare ",
			description: "bash declare builtin",
		},
	}

	for _, bashism := range bashisms {
		if strings.Contains(script, bashism.pattern) {
			t.Errorf("Compiled script contains bashism: %s (%s)", bashism.pattern, bashism.description)
		}
	}

	// Test syntax with different POSIX shells
	shells := []string{"sh"}
	for _, shell := range []string{"dash", "ash"} {
		if _, err := exec.LookPath(shell); err == nil {
			shells = append(shells, shell)
		}
	}

	for _, shell := range shells {
		t.Run(shell+" syntax check", func(t *testing.T) {
			// Use -n flag to check syntax without executing
			cmd := exec.Command(shell, "-n", "-c", script)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("%s failed syntax check: %v\nOutput: %s\nScript:\n%s", shell, err, output, script)
			}
		})
	}
}

// TestPatchPipelineValidInputsAccepted tests that valid inputs are accepted
// and the script only fails when files don't exist (not due to validation).
func TestPatchPipelineValidInputsAccepted(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping shell execution tests in short mode")
	}

	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	tests := []struct {
		name       string
		with       map[string]string
		notInError string // Error message that should NOT appear (indicates validation failure)
	}{
		{
			name: "normal path",
			with: map[string]string{
				"series":           "/tmp/valid/path/series",
				"strip-components": "1",
				"fuzz":             "2",
			},
			notInError: "invalid characters",
		},
		{
			name: "path with dots",
			with: map[string]string{
				"series":           "./relative/path/series",
				"strip-components": "0",
				"fuzz":             "0",
			},
			notInError: "invalid characters",
		},
		{
			name: "path with dashes and underscores",
			with: map[string]string{
				"series":           "/path/to-my_series-file",
				"strip-components": "3",
				"fuzz":             "1",
			},
			notInError: "invalid characters",
		},
		{
			name: "large strip-components",
			with: map[string]string{
				"patches":          "test.patch",
				"strip-components": "99",
				"fuzz":             "2",
			},
			notInError: "non-negative integer",
		},
		{
			name: "zero fuzz",
			with: map[string]string{
				"patches":          "test.patch",
				"strip-components": "1",
				"fuzz":             "0",
			},
			notInError: "non-negative integer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := compilePatchPipeline(t, tt.with)

			tmpDir := t.TempDir()
			cmd := exec.Command("sh", "-c", script)
			cmd.Dir = tmpDir
			output, err := cmd.CombinedOutput()

			// We expect the script to fail (files don't exist), but NOT due to validation
			if err != nil && strings.Contains(string(output), tt.notInError) {
				t.Errorf("Valid input %q was incorrectly rejected with validation error.\nOutput: %s", tt.name, output)
			}
		})
	}
}
