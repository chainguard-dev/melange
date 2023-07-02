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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
)

var requireErrInvalidConfiguration require.ErrorAssertionFunc = func(t require.TestingT, err error, _ ...interface{}) {
	require.ErrorAs(t, err, &ErrInvalidConfiguration{})
}

// TestConfiguration_Load is the main set of tests for loading a configuration
// file. When in doubt, add your test here.
func TestConfiguration_Load(t *testing.T) {
	tests := []struct {
		name       string
		requireErr require.ErrorAssertionFunc
		expected   Configuration
	}{
		{
			name:       "range-subpackages",
			requireErr: require.NoError,
			expected: Configuration{
				Package: Package{
					Name:    "hello",
					Version: "world",
				},
				Pipeline: []Pipeline{
					{
						Name: "hello",
						Runs: "world",
					},
				},
				Subpackages: []Subpackage{{
					Name: "cats",
					Pipeline: []Pipeline{{
						Runs: "cats are angry",
					}},
				}, {
					Name: "dogs",
					Pipeline: []Pipeline{{
						Runs: "dogs are loyal",
					}},
				}, {
					Name: "turtles",
					Pipeline: []Pipeline{{
						Runs: "turtles are slow",
					}},
				}, {
					Name: "donatello",
					Pipeline: []Pipeline{
						{
							Runs: "donatello's color is purple",
						},
						{
							Uses: "go/build",
							With: map[string]string{"packages": "purple"},
						},
					},
				}, {
					Name: "leonardo",
					Pipeline: []Pipeline{
						{
							Runs: "leonardo's color is blue",
						},
						{
							Uses: "go/build",
							With: map[string]string{"packages": "blue"},
						},
					},
				}, {
					Name: "michelangelo",
					Pipeline: []Pipeline{
						{
							Runs: "michelangelo's color is orange",
						},
						{
							Uses: "go/build",
							With: map[string]string{"packages": "orange"},
						},
					},
				}, {
					Name: "raphael",
					Pipeline: []Pipeline{
						{
							Runs: "raphael's color is red",
						},
						{
							Uses: "go/build",
							With: map[string]string{"packages": "red"},
						},
					},
				}},
			},
		},
		{
			name:       "github",
			requireErr: require.NoError,
			expected: Configuration{
				Package: Package{
					Name:    "cosign",
					Version: "2.0.0",
				},
				Update: Update{
					Enabled: true,
					Shared:  false,
					GitHubMonitor: &GitHubMonitor{
						Identifier:  "sigstore/cosign",
						StripPrefix: "v",
						UseTags:     true,
					},
				},
			},
		},
		{
			name:       "release-monitor",
			requireErr: require.NoError,
			expected: Configuration{
				Package: Package{Name: "bison", Version: "3.8.2"},
				Update: Update{
					Enabled: true,
					Shared:  false,
					ReleaseMonitor: &ReleaseMonitor{
						Identifier: 193,
					},
				},
			},
		},
		{
			name:       "unknown-fields",
			requireErr: require.Error,
			expected:   Configuration{},
		},
		{
			name:       "missing-package-name",
			requireErr: requireErrInvalidConfiguration,
			expected:   Configuration{},
		},
		{
			name:       "invalid-package-name",
			requireErr: requireErrInvalidConfiguration,
			expected:   Configuration{},
		},
		{
			name:       "invalid-range-subpackage-name",
			requireErr: requireErrInvalidConfiguration,
			expected:   Configuration{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := nopLogger{}
			ctx := Build{
				ConfigFile: filepath.Join("testdata", "configuration_load", fmt.Sprintf("%s.melange.yaml", tt.name)),
				Logger:     log,
			}

			cfg := &Configuration{}
			err := cfg.Load(ctx)
			tt.requireErr(t, err)

			cleanTestConfig(cfg)

			if d := cmp.Diff(tt.expected, *cfg, cmpopts.IgnoreUnexported(Pipeline{})); d != "" {
				t.Fatalf("actual didn't match expected (-want, +got): %s", d)
			}
		})
	}
}

func cleanTestConfig(cfg *Configuration) {
	if cfg == nil {
		return
	}

	cfg.Environment.Accounts.Users = nil
	cfg.Environment.Accounts.Groups = nil
	cfg.Environment.Environment = nil

	if len(cfg.Subpackages) == 0 {
		cfg.Subpackages = nil
	}
}

// TestConfiguration_Load_Raw tests loading a configuration file with raw
// resolved values for fields not specified by the input YAML file.
func TestConfiguration_Load_Raw(t *testing.T) {
	contents := `
package:
  name: nginx
  version: 100
`
	expected := &Configuration{
		Package: Package{
			Name:    "nginx",
			Version: "100",
		},
		Subpackages: []Subpackage{},
	}
	expected.Environment.Accounts.Users = []apko_types.User{{
		UserName: "build",
		UID:      1000,
		GID:      1000,
	}}
	expected.Environment.Accounts.Groups = []apko_types.Group{{
		GroupName: "build",
		GID:       1000,
		Members:   []string{"build"},
	}}
	expected.Environment.Environment = map[string]string{
		"HOME":   "/home/build",
		"GOPATH": "/home/build/.cache/go",
	}

	f := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(f, []byte(contents), 0755); err != nil {
		t.Fatal(err)
	}

	log := nopLogger{}
	ctx := Build{
		ConfigFile: f,
		Logger:     log,
	}
	cfg := &Configuration{}
	if err := cfg.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if d := cmp.Diff(expected, cfg); d != "" {
		t.Fatalf("actual didn't match expected: %s", d)
	}
}
