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
	"time"

	"chainguard.dev/melange/pkg/config"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
)

var requireErrInvalidConfiguration require.ErrorAssertionFunc = func(t require.TestingT, err error, _ ...any) {
	require.ErrorAs(t, err, &config.ErrInvalidConfiguration{})
}

// TestConfiguration_Load is the main set of tests for loading a configuration
// file. When in doubt, add your test here.
func TestConfiguration_Load(t *testing.T) {
	tests := []struct {
		name                string
		skipConfigCleanStep bool
		requireErr          require.ErrorAssertionFunc
		expected            *config.Configuration
	}{
		{
			name:       "range-subpackages",
			requireErr: require.NoError,
			expected: &config.Configuration{
				Package: config.Package{
					Name:      "hello",
					Version:   "world",
					Resources: &config.Resources{},
				},
				Pipeline: []config.Pipeline{
					{
						Name: "hello",
						Runs: "world",
					},
				},
				Subpackages: []config.Subpackage{{
					Name: "cats",
					Pipeline: []config.Pipeline{{
						Runs: "cats are angry",
					}},
				}, {
					Name: "dogs",
					Pipeline: []config.Pipeline{{
						Runs: "dogs are loyal",
					}},
				}, {
					Name: "turtles",
					Pipeline: []config.Pipeline{{
						Runs: "turtles are slow",
					}},
				}, {
					Name: "donatello",
					Pipeline: []config.Pipeline{
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
					Pipeline: []config.Pipeline{
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
					Pipeline: []config.Pipeline{
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
					Pipeline: []config.Pipeline{
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
			expected: &config.Configuration{
				Package: config.Package{
					Name:      "cosign",
					Version:   "2.0.0",
					Resources: &config.Resources{},
				},
				Update: config.Update{
					Enabled: true,
					Shared:  false,
					GitHubMonitor: &config.GitHubMonitor{
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
			expected: &config.Configuration{
				Package: config.Package{Name: "bison", Version: "3.8.2", Resources: &config.Resources{}},
				Update: config.Update{
					Enabled: true,
					Shared:  false,
					ReleaseMonitor: &config.ReleaseMonitor{
						Identifier: 193,
					},
				},
			},
		},
		{
			name:                "unknown-fields",
			skipConfigCleanStep: true,
			requireErr:          require.Error,
			expected:            nil,
		},
		{
			name:                "missing-package-name",
			skipConfigCleanStep: true,
			requireErr:          requireErrInvalidConfiguration,
			expected:            nil,
		},
		{
			name:                "uses-and-runs",
			skipConfigCleanStep: true,
			requireErr:          requireErrInvalidConfiguration,
			expected:            nil,
		},
		{
			name:                "invalid-package-name",
			skipConfigCleanStep: true,
			requireErr:          requireErrInvalidConfiguration,
			expected:            nil,
		},
		{
			name:                "invalid-range-subpackage-name",
			skipConfigCleanStep: true,
			requireErr:          requireErrInvalidConfiguration,
			expected:            nil,
		},
		{
			name:                "invalid-duplicate-package-name",
			skipConfigCleanStep: true,
			requireErr:          requireErrInvalidConfiguration,
			expected:            nil,
		},
		{
			name:                "env-vars-set-that-have-default-values",
			skipConfigCleanStep: true,
			requireErr:          require.NoError,
			expected: &config.Configuration{
				Package: config.Package{
					Name:      "cosign",
					Version:   "2.0.0",
					Epoch:     0,
					Resources: &config.Resources{},
				},
				Environment: apko_types.ImageConfiguration{
					Environment: map[string]string{
						"GOMODCACHE": "/var/cache/melange/gomodcache",
						"HOME":       "/home/build/special-case",
						"GOPATH":     "/var/cache/melange/go",
					},
					Accounts: apko_types.ImageAccounts{
						Users:  []apko_types.User{{UserName: buildUser, UID: 1000, GID: apko_types.GID(&gid1000)}},
						Groups: []apko_types.Group{{GroupName: buildUser, GID: 1000, Members: []string{buildUser}}},
					},
				},
				Subpackages: []config.Subpackage{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := slogtest.Context(t)
			bctx := Build{
				ConfigFile: filepath.Join("testdata", "configuration_load", fmt.Sprintf("%s.melange.yaml", tt.name)),
			}

			cfg, err := config.ParseConfiguration(ctx,
				bctx.ConfigFile,
				config.WithEnvFileForParsing(bctx.EnvFile),
				config.WithVarsFileForParsing(bctx.VarsFile))
			tt.requireErr(t, err)

			if !tt.skipConfigCleanStep {
				cleanTestConfig(cfg)
			}

			if tt.expected == nil {
				if cfg != nil {
					t.Fatalf("actual didn't match expected (want nil, got config)")
				}
			} else {
				if d := cmp.Diff(
					*tt.expected,
					*cfg,
					cmpopts.IgnoreUnexported(config.Pipeline{}, config.Configuration{}),
				); d != "" {
					t.Fatalf("actual didn't match expected (-want, +got): %s", d)
				}
			}
		})
	}
}

func cleanTestConfig(cfg *config.Configuration) {
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
	ctx := slogtest.Context(t)
	contents := `
package:
  name: nginx
  version: 100
`
	expected := &config.Configuration{
		Package: config.Package{
			Name:      "nginx",
			Version:   "100",
			Resources: &config.Resources{},
		},
		Subpackages: []config.Subpackage{},
	}
	gid1000 := uint32(1000)
	expected.Environment.Accounts.Users = []apko_types.User{{
		UserName: buildUser,
		UID:      1000,
		GID:      apko_types.GID(&gid1000),
	}}
	expected.Environment.Accounts.Groups = []apko_types.Group{{
		GroupName: buildUser,
		GID:       1000,
		Members:   []string{buildUser},
	}}
	expected.Environment.Environment = map[string]string{
		"HOME":       "/home/build",
		"GOPATH":     "/home/build/.cache/go",
		"GOMODCACHE": "/var/cache/melange/gomodcache",
	}

	f := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(f, []byte(contents), 0o755); err != nil {
		t.Fatal(err)
	}

	bctx := Build{
		ConfigFile: f,
	}
	cfg, err := config.ParseConfiguration(ctx,
		bctx.ConfigFile,
		config.WithEnvFileForParsing(bctx.EnvFile),
		config.WithVarsFileForParsing(bctx.VarsFile))
	if err != nil {
		t.Fatal(err)
	}
	if d := cmp.Diff(expected, cfg, cmpopts.IgnoreUnexported(config.Configuration{})); d != "" {
		t.Fatalf("actual didn't match expected: %s", d)
	}
}

func TestSourceDateEpoch(t *testing.T) {
	tests := []struct {
		name            string
		sourceDateEpoch string
		defaultTime     time.Time
		want            time.Time
		wantErr         bool
	}{
		{
			name:        "empty",
			defaultTime: time.Time{},
			want:        time.Time{},
		},
		{
			name:            "strings",
			sourceDateEpoch: "    ",
			defaultTime:     time.Time{},
			want:            time.Time{},
		},
		{
			name:        "defaultTime",
			defaultTime: time.Unix(1234567890, 0),
			want:        time.Unix(1234567890, 0),
		},
		{
			name:            "0",
			sourceDateEpoch: "0",
			defaultTime:     time.Unix(1234567890, 0),
			want:            time.Unix(0, 0),
		},
		{
			name:            "1234567890",
			sourceDateEpoch: "1234567890",
			defaultTime:     time.Unix(0, 0),
			want:            time.Unix(1234567890, 0),
		},
		{
			name:            "invalid date",
			sourceDateEpoch: "tacocat",
			defaultTime:     time.Unix(0, 0),
			wantErr:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.sourceDateEpoch != "" {
				t.Setenv("SOURCE_DATE_EPOCH", tt.sourceDateEpoch)
			}
			got, err := sourceDateEpoch(tt.defaultTime)
			if err != nil {
				if !tt.wantErr {
					t.Fatalf("SourceDateEpoch() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if !got.Equal(tt.want) {
				t.Errorf("SourceDateEpoch() = %v, want %v", got, tt.want)
			}
		})
	}
}
