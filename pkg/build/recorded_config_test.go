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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"

	"chainguard.dev/melange/pkg/config"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/require"
)

func TestRecordedConfiguration(t *testing.T) {
	buildEnv := map[string]string{
		"CONFIG_PATH": "/run/injected/config",
		"CFLAGS":      "-O2",
	}

	tests := []struct {
		name     string
		excluded []string
		want     map[string]string
	}{
		{
			name:     "no exclusions records all environment variables",
			excluded: nil,
			want: map[string]string{
				"CONFIG_PATH": "/run/injected/config",
				"CFLAGS":      "-O2",
			},
		},
		{
			name:     "excluded key is omitted from the recorded config",
			excluded: []string{"CONFIG_PATH"},
			want: map[string]string{
				"CFLAGS": "-O2",
			},
		},
		{
			name:     "excluding an unset key changes nothing",
			excluded: []string{"NOT_SET"},
			want: map[string]string{
				"CONFIG_PATH": "/run/injected/config",
				"CFLAGS":      "-O2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Build{
				Configuration: &config.Configuration{
					Environment: apko_types.ImageConfiguration{
						Environment: map[string]string{
							"CONFIG_PATH": "/run/injected/config",
							"CFLAGS":      "-O2",
						},
					},
				},
				ExcludedEnvFromRecordedConfig: tt.excluded,
			}

			got := b.recordedConfiguration()
			require.Equal(t, tt.want, got.Environment.Environment)

			// The configuration driving the build environment keeps
			// every variable regardless of exclusions.
			require.Equal(t, buildEnv, b.Configuration.Environment.Environment)
		})
	}
}

// TestGenerateControlSection_ExcludedEnv proves the full path from an
// --env-file through config parsing to the .melange.yaml embedded in the
// control section: an excluded variable reaches the configuration used for
// the build environment, but never the recorded configuration.
func TestGenerateControlSection_ExcludedEnv(t *testing.T) {
	ctx := slogtest.Context(t)
	dir := t.TempDir()

	cfgPath := filepath.Join(dir, "test.melange.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
package:
  name: hello
  version: "1.0.0"
  epoch: 0
`), 0o644))

	envPath := filepath.Join(dir, "build.env")
	require.NoError(t, os.WriteFile(envPath, []byte("CONFIG_PATH=/run/injected/config\nCFLAGS=-O2\n"), 0o644))

	cfg, err := config.ParseConfiguration(ctx, cfgPath, config.WithEnvFilesForParsing([]string{envPath}))
	require.NoError(t, err)

	// Both env-file variables reach the configuration that is used to set
	// up the build environment.
	require.Equal(t, "/run/injected/config", cfg.Environment.Environment["CONFIG_PATH"])
	require.Equal(t, "-O2", cfg.Environment.Environment["CFLAGS"])

	pc := &PackageBuild{
		Build: &Build{
			Configuration:                 cfg,
			ExcludedEnvFromRecordedConfig: []string{"CONFIG_PATH"},
		},
		Origin:      &cfg.Package,
		PackageName: cfg.Package.Name,
	}

	controlSection, err := pc.generateControlSection(ctx)
	require.NoError(t, err)

	embedded := readControlFile(t, controlSection, ".melange.yaml")
	require.NotContains(t, embedded, "CONFIG_PATH")
	require.NotContains(t, embedded, "/run/injected/config")
	require.Contains(t, embedded, "CFLAGS: -O2")

	// The configuration used for the build environment is untouched.
	require.Equal(t, "/run/injected/config", cfg.Environment.Environment["CONFIG_PATH"])
}

func TestGenerateSLSA_ExcludedEnv(t *testing.T) {
	pc := &PackageBuild{
		Build: &Build{
			Configuration: &config.Configuration{
				Package: config.Package{
					Name:    "hello",
					Version: "1.0.0",
				},
				Environment: apko_types.ImageConfiguration{
					Environment: map[string]string{
						"CONFIG_PATH": "/run/injected/config",
						"CFLAGS":      "-O2",
					},
				},
			},
			ExcludedEnvFromRecordedConfig: []string{"CONFIG_PATH"},
		},
		PackageName: "hello",
		Origin: &config.Package{
			Name:    "hello",
			Version: "1.0.0",
		},
		DataHash: "abcdef1234567890",
	}

	result, err := pc.generateSLSA()
	require.NoError(t, err)

	provenance := string(result)
	require.NotContains(t, provenance, "CONFIG_PATH")
	require.NotContains(t, provenance, "/run/injected/config")
	require.Contains(t, provenance, "CFLAGS")
}

// readControlFile extracts a single file from a gzipped control section
// tarball.
func readControlFile(t *testing.T, controlSection []byte, name string) string {
	t.Helper()

	zr, err := gzip.NewReader(bytes.NewReader(controlSection))
	require.NoError(t, err)
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if hdr.Name == name {
			contents, err := io.ReadAll(tr)
			require.NoError(t, err)
			return string(contents)
		}
	}
	t.Fatalf("%s not found in control section", name)
	return ""
}
