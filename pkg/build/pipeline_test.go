// Copyright 2022 Chainguard, Inc.
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
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/util"

	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/require"
)

func Test_mutateStringFromMap(t *testing.T) {
	keys := map[string]string{
		"${{inputs.foo}}": "foo",
		"${{inputs.bar}}": "bar",
	}

	input1 := "${{inputs.foo}} ${{inputs.baz-bah-boom}}"
	_, err := util.MutateStringFromMap(keys, input1)

	require.Error(t, err)
}

func Test_substitutionMap(t *testing.T) {
	tests := []struct {
		initialVersion string
		match          string
		replace        string
		expected       string
	}{
		{initialVersion: "1.2.3.9", match: `\.(\d+)$`, replace: "+$1", expected: "1.2.3+9"},
	}
	for _, tt := range tests {
		pkg := config.Package{
			Name:    "foo",
			Version: tt.initialVersion,
		}

		t.Run("sub", func(t *testing.T) {
			cfg := config.Configuration{
				Package: pkg,
				VarTransforms: []config.VarTransforms{
					{
						From:    "${{package.version}}",
						Match:   tt.match,
						Replace: tt.replace,
						To:      "mangled-package-version",
					},
				},
			}
			m, err := NewSubstitutionMap(&cfg, "", "", nil)
			require.NoError(t, err)
			require.Equal(t, tt.expected, m.Substitutions["${{vars.mangled-package-version}}"])
		})
	}
}

func Test_MutateWith(t *testing.T) {
	for _, tc := range []struct {
		version string
		epoch   uint64
		want    string
	}{{
		version: "1.2.3",
		epoch:   0,
		want:    "1.2.3-r0",
	}, {
		version: "1.2.3",
		epoch:   3,
		want:    "1.2.3-r3",
	}} {
		cfg := config.Configuration{
			Package: config.Package{
				Version: tc.version,
				Epoch:   tc.epoch,
			},
		}
		sm, err := NewSubstitutionMap(&cfg, "", "", nil)
		require.NoError(t, err)
		got, err := sm.MutateWith(map[string]string{})
		if err != nil {
			t.Fatalf("MutateWith failed with: %v", err)
		}
		gotFullVer := got[config.SubstitutionPackageFullVersion]
		if gotFullVer != tc.want {
			t.Errorf("got %s, want %s", gotFullVer, tc.want)
		}
	}
}

func Test_substitutionNeedPackages(t *testing.T) {
	ctx := slogtest.Context(t)
	pkg := config.Package{
		Name:    "foo",
		Version: "1.2.3",
	}

	cfg := config.Configuration{
		Package: pkg,
		Pipeline: []config.Pipeline{
			{
				Uses: "go/build",
				With: map[string]string{
					"go-package": "go-5.4.3",
					"output":     "foo",
					"packages":   "./bar",
				},
			},
		},
	}
	pipelineDirs := []string{"pipelines"}

	c := &Compiled{PipelineDirs: pipelineDirs}
	sm, err := NewSubstitutionMap(&cfg, "", "", nil)
	require.NoError(t, err)

	err = c.CompilePipelines(ctx, sm, cfg.Pipeline)
	require.NoError(t, err)
	require.Equal(t, "go-5.4.3", c.Needs[0])
}

func Test_buildEvalRunCommand(t *testing.T) {
	p := &config.Pipeline{
		Environment: map[string]string{"FOO": "bar"},
	}

	debugOption := 'x'
	workdir := "/bar"
	fragment := "baz"
	command := buildEvalRunCommand(p, debugOption, workdir, fragment)
	// Note: shellquote.Join() only adds quotes when necessary
	// Simple paths like /bar don't need quotes, so they're returned unquoted
	expected := []string{"/bin/sh", "-c", `set -ex
[ -d /bar ] || mkdir -p /bar
cd /bar
baz
exit 0`}
	require.Equal(t, expected, command)
}

func TestAllPipelines(t *testing.T) {
	// Get all the yamls in pipelines/*/*.yaml and test that they unmarshal
	pipelines, err := filepath.Glob("pipelines/*/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pipeline := &config.Pipeline{}
	for _, p := range pipelines {
		t.Run(p, func(t *testing.T) {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := yaml.Unmarshal(b, pipeline); err != nil {
				t.Errorf("unexpected error unmarshalling pipeline: %v", err)
			}
		})
	}
}

func Test_validateWith(t *testing.T) {
	tests := []struct {
		name        string
		data        map[string]string
		inputs      map[string]config.Input
		expected    map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid SHA256 checksum",
			data: map[string]string{
				"expected-sha256": "a3c2567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			},
			inputs: map[string]config.Input{
				"expected-sha256": {Default: "", Required: true},
			},
			expected: map[string]string{
				"expected-sha256": "a3c2567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			},
			expectError: false,
		},
		{
			name: "Invalid SHA256 length",
			data: map[string]string{
				"expected-sha256": "abcdef",
			},
			inputs: map[string]config.Input{
				"expected-sha256": {Default: "", Required: true},
			},
			expectError: true,
			errorMsg:    "checksum input \"expected-sha256\" for pipeline, invalid length",
		},
		{
			name: "Missing required input",
			data: map[string]string{},
			inputs: map[string]config.Input{
				"expected-commit": {Default: "", Required: true},
			},
			expectError: true,
			errorMsg:    "required input \"expected-commit\" for pipeline is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateWith(tt.data, tt.inputs)

			if tt.expectError {
				require.Error(t, err)
				require.EqualError(t, err, tt.errorMsg)
				return // Skip further checks if error is expected
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected, result)
		})
	}
}

func Test_parseDuration(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		defaultDuration time.Duration
		expected        time.Duration
		expectError     bool
	}{
		{
			name:            "empty string returns default",
			input:           "",
			defaultDuration: 5 * time.Second,
			expected:        5 * time.Second,
			expectError:     false,
		},
		{
			name:            "valid duration string",
			input:           "10s",
			defaultDuration: 1 * time.Second,
			expected:        10 * time.Second,
			expectError:     false,
		},
		{
			name:            "valid duration with milliseconds",
			input:           "500ms",
			defaultDuration: 1 * time.Second,
			expected:        500 * time.Millisecond,
			expectError:     false,
		},
		{
			name:            "valid duration with minutes",
			input:           "2m",
			defaultDuration: 1 * time.Second,
			expected:        2 * time.Minute,
			expectError:     false,
		},
		{
			name:            "invalid duration string",
			input:           "invalid",
			defaultDuration: 1 * time.Second,
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseDuration(tt.input, tt.defaultDuration)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected, result)
		})
	}
}

func Test_calculateBackoff(t *testing.T) {
	tests := []struct {
		name         string
		strategy     string
		attemptNum   int
		initialDelay time.Duration
		maxDelay     time.Duration
		expected     time.Duration
	}{
		{
			name:         "constant backoff",
			strategy:     "constant",
			attemptNum:   0,
			initialDelay: 1 * time.Second,
			maxDelay:     60 * time.Second,
			expected:     1 * time.Second,
		},
		{
			name:         "constant backoff attempt 5",
			strategy:     "constant",
			attemptNum:   5,
			initialDelay: 2 * time.Second,
			maxDelay:     60 * time.Second,
			expected:     2 * time.Second,
		},
		{
			name:         "linear backoff attempt 0",
			strategy:     "linear",
			attemptNum:   0,
			initialDelay: 1 * time.Second,
			maxDelay:     60 * time.Second,
			expected:     1 * time.Second,
		},
		{
			name:         "linear backoff attempt 2",
			strategy:     "linear",
			attemptNum:   2,
			initialDelay: 1 * time.Second,
			maxDelay:     60 * time.Second,
			expected:     3 * time.Second,
		},
		{
			name:         "exponential backoff attempt 0",
			strategy:     "exponential",
			attemptNum:   0,
			initialDelay: 1 * time.Second,
			maxDelay:     60 * time.Second,
			expected:     1 * time.Second,
		},
		{
			name:         "exponential backoff attempt 3",
			strategy:     "exponential",
			attemptNum:   3,
			initialDelay: 1 * time.Second,
			maxDelay:     60 * time.Second,
			expected:     8 * time.Second,
		},
		{
			name:         "exponential backoff attempt 10 capped by maxDelay",
			strategy:     "exponential",
			attemptNum:   10,
			initialDelay: 1 * time.Second,
			maxDelay:     30 * time.Second,
			expected:     30 * time.Second,
		},
		{
			name:         "default to exponential for unknown strategy",
			strategy:     "unknown",
			attemptNum:   2,
			initialDelay: 1 * time.Second,
			maxDelay:     60 * time.Second,
			expected:     4 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateBackoff(tt.strategy, tt.attemptNum, tt.initialDelay, tt.maxDelay)
			require.Equal(t, tt.expected, result)
		})
	}
}

func Test_validateRetryConfig(t *testing.T) {
	tests := []struct {
		name        string
		retry       *config.RetryConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil retry config is valid",
			retry:       nil,
			expectError: false,
		},
		{
			name: "valid retry config with defaults",
			retry: &config.RetryConfig{
				Attempts: 3,
			},
			expectError: false,
		},
		{
			name: "valid retry config with all fields",
			retry: &config.RetryConfig{
				Attempts:     5,
				Backoff:      "exponential",
				InitialDelay: "2s",
				MaxDelay:     "30s",
			},
			expectError: false,
		},
		{
			name: "invalid attempts (less than 1)",
			retry: &config.RetryConfig{
				Attempts: 0,
			},
			expectError: true,
			errorMsg:    "attempts must be at least 1, got 0",
		},
		{
			name: "invalid backoff strategy",
			retry: &config.RetryConfig{
				Attempts: 3,
				Backoff:  "invalid",
			},
			expectError: true,
			errorMsg:    "backoff must be one of [constant linear exponential], got \"invalid\"",
		},
		{
			name: "invalid initial delay",
			retry: &config.RetryConfig{
				Attempts:     3,
				InitialDelay: "invalid",
			},
			expectError: true,
		},
		{
			name: "invalid max delay",
			retry: &config.RetryConfig{
				Attempts: 3,
				MaxDelay: "invalid",
			},
			expectError: true,
		},
		{
			name: "valid constant backoff",
			retry: &config.RetryConfig{
				Attempts: 3,
				Backoff:  "constant",
			},
			expectError: false,
		},
		{
			name: "valid linear backoff",
			retry: &config.RetryConfig{
				Attempts: 3,
				Backoff:  "linear",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRetryConfig(tt.retry)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					require.Contains(t, err.Error(), tt.errorMsg)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}

func Test_retryConfigUnmarshal(t *testing.T) {
	// Test that retry configuration can be properly unmarshaled from YAML
	yamlData := `
name: test-pipeline
retry:
  attempts: 3
  backoff: exponential
  initial-delay: 2s
  max-delay: 30s
runs: echo "test"
`
	var pipeline config.Pipeline
	err := yaml.Unmarshal([]byte(yamlData), &pipeline)
	require.NoError(t, err)
	require.NotNil(t, pipeline.Retry)
	require.Equal(t, 3, pipeline.Retry.Attempts)
	require.Equal(t, "exponential", pipeline.Retry.Backoff)
	require.Equal(t, "2s", pipeline.Retry.InitialDelay)
	require.Equal(t, "30s", pipeline.Retry.MaxDelay)
}
