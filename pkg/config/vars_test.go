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

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/require"
)

func Test_VarTransformValidation(t *testing.T) {
	ctx := slogtest.Context(t)

	tests := []struct {
		name          string
		config        string
		errorContains []string
	}{
		{
			name: "regex doesn't match input (grafana case)",
			config: `
package:
  name: test-no-match
  version: 12.0.3
  epoch: 0

var-transforms:
  - from: ${{package.version}}
    match: '^(\d+\.\d+\.\d+)\.(\d+)$'
    replace: '$1'
    to: mangled-package-version

pipeline:
  - runs: echo "version is ${{vars.mangled-package-version}}"
`,
			errorContains: []string{
				"var-transform \"mangled-package-version\" failed: regex",
				"does not match input \"12.0.3\"",
				"(no substitution will be performed)",
			},
		},
		{
			name: "var-transform results in empty value",
			config: `
package:
  name: test-empty-result
  version: 1.2.3
  epoch: 0

var-transforms:
  - from: ${{package.version}}
    match: '^(\d+)\.(\d+)\.(\d+)$'
    replace: ''
    to: empty-version

pipeline:
  - runs: echo "This should not be reached"
`,
			errorContains: []string{
				"var-transform \"empty-version\" resulted in empty value",
				"transformed variables cannot be empty",
			},
		},
		{
			name: "empty input with regex that matches empty string",
			config: `
package:
  name: test-empty-input
  version: 1.0.0
  epoch: 0

vars:
  empty: ""

var-transforms:
  - from: ${{vars.empty}}
    match: '^$'
    replace: ''
    to: still-empty

pipeline:
  - runs: echo "empty var"
`,
			errorContains: []string{
				"var-transform \"still-empty\" resulted in empty value",
				"transformed variables cannot be empty",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := filepath.Join(os.TempDir(), "melange-test-var-transform-"+tt.name)
			if err := os.WriteFile(fp, []byte(tt.config), 0o644); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(fp)

			_, err := ParseConfiguration(ctx, fp)
			require.Error(t, err)
			for _, expected := range tt.errorContains {
				require.Contains(t, err.Error(), expected)
			}
		})
	}
}

func Test_VarTransformSuccess(t *testing.T) {
	ctx := slogtest.Context(t)

	// Test case where var-transform works correctly
	fp := filepath.Join(os.TempDir(), "melange-test-var-transform-success")
	if err := os.WriteFile(fp, []byte(`
package:
  name: test-success
  version: 12.0.3.01
  epoch: 0

var-transforms:
  - from: ${{package.version}}
    match: '^(\d+\.\d+\.\d+)\.(\d+)$'
    replace: '$1'
    to: mangled-package-version

pipeline:
  - runs: echo "version is ${{vars.mangled-package-version}}"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(fp)

	cfg, err := ParseConfiguration(ctx, fp)
	require.NoError(t, err)

	// Verify the transformed variable is set correctly
	expectedVar := "${{vars.mangled-package-version}}"
	nw := buildConfigMap(cfg)
	err = cfg.PerformVarSubstitutions(nw)
	require.NoError(t, err)
	require.Equal(t, "12.0.3", nw[expectedVar])
}
