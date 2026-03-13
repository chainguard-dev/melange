// Copyright 2025-2026 Chainguard, Inc.
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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apko_types "chainguard.dev/apko/pkg/build/types"

	"chainguard.dev/melange/pkg/config"
)

func TestCreateGccSpecFile(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "creates spec file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			b := &Build{
				WorkspaceDir: tmpDir,
				Arch:         apko_types.ParseArchitecture("x86_64"),
				Namespace:    "test",
				Configuration: &config.Configuration{
					Package: config.Package{
						Name:    "test-package",
						Version: "1.0.0",
						Epoch:   0,
					},
				},
			}

			err := b.createGccSpecFile()
			require.NoError(t, err)

			// Verify file was created
			specPath := filepath.Join(tmpDir, ".melange.gcc.spec")
			assert.FileExists(t, specPath)

			// Read and verify basic structure
			content, err := os.ReadFile(specPath)
			require.NoError(t, err)

			// Should start with *link:
			assert.True(t, strings.HasPrefix(string(content), "*link:\n"))

			// Should contain the package-metadata flag
			assert.Contains(t, string(content), "+ --package-metadata=")
		})
	}
}

func TestCreateGccSpecFileError(t *testing.T) {
	t.Run("invalid workspace directory", func(t *testing.T) {
		b := &Build{
			WorkspaceDir: "/nonexistent/directory",
		}

		err := b.createGccSpecFile()
		assert.Error(t, err)
	})

	t.Run("read-only workspace directory", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("Skipping test when running as root")
		}

		tmpDir := t.TempDir()
		readOnlyDir := filepath.Join(tmpDir, "readonly")
		require.NoError(t, os.Mkdir(readOnlyDir, 0o555))

		b := &Build{
			WorkspaceDir: readOnlyDir,
		}

		err := b.createGccSpecFile()
		assert.Error(t, err)
	})
}

func TestCreateClangConfigFile(t *testing.T) {
	tests := []struct {
		name         string
		includePaths []string
		wantContent  string
	}{
		{
			name:         "single include path",
			includePaths: []string{"/etc/clang-19/x86_64-unknown-linux-gnu-clang.cfg"},
			wantContent:  "@/etc/clang-19/x86_64-unknown-linux-gnu-clang.cfg\n",
		},
		{
			name: "multiple include paths",
			includePaths: []string{
				"../../.melange.clang.cfg",
				"/etc/clang-19/x86_64-unknown-linux-gnu-clang.cfg",
			},
			wantContent: "@../../.melange.clang.cfg\n@/etc/clang-19/x86_64-unknown-linux-gnu-clang.cfg\n",
		},
		{
			name:         "no include paths",
			includePaths: []string{},
			wantContent:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			outputPath := filepath.Join(tmpDir, "test.cfg")

			err := createClangConfigFile(outputPath, tt.includePaths...)
			require.NoError(t, err)

			// Verify file was created
			assert.FileExists(t, outputPath)

			// Verify content
			content, err := os.ReadFile(outputPath)
			require.NoError(t, err)
			assert.Equal(t, tt.wantContent, string(content))

			// Verify file permissions (should be world-readable)
			info, err := os.Stat(outputPath)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
		})
	}
}

func TestCreateClangConfigFileError(t *testing.T) {
	t.Run("invalid output path", func(t *testing.T) {
		err := createClangConfigFile("/nonexistent/directory/test.cfg", "/etc/clang.cfg")
		assert.Error(t, err)
	})

	t.Run("read-only directory", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("Skipping test when running as root")
		}

		tmpDir := t.TempDir()
		readOnlyDir := filepath.Join(tmpDir, "readonly")
		require.NoError(t, os.Mkdir(readOnlyDir, 0o555))

		err := createClangConfigFile(filepath.Join(readOnlyDir, "test.cfg"), "/etc/clang.cfg")
		assert.Error(t, err)
	})
}

func TestCreateClangConfigFiles(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "creates all clang config files",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			ctx := clog.WithLogger(context.Background(), slogtest.TestLogger(t))

			b := &Build{
				WorkspaceDir: tmpDir,
				Arch:         apko_types.ParseArchitecture("x86_64"),
				Namespace:    "test",
				Configuration: &config.Configuration{
					Package: config.Package{
						Name:    "test-package",
						Version: "1.0.0",
						Epoch:   0,
					},
				},
			}

			err := b.createClangConfigFiles(ctx)
			require.NoError(t, err)

			// Verify the main melange clang config file was created
			melangeClangCfg := filepath.Join(tmpDir, ".melange.clang.cfg")
			assert.FileExists(t, melangeClangCfg)

			// Read and verify basic structure of the main config
			content, err := os.ReadFile(melangeClangCfg)
			require.NoError(t, err)
			assert.Contains(t, string(content), "-Xlinker --package-metadata=")
			assert.Contains(t, string(content), "test-package")
			assert.Contains(t, string(content), "1.0.0")

			// Verify config directories were created
			configBaseDir := filepath.Join(tmpDir, ".config")
			assert.DirExists(t, configBaseDir)

			// Verify a few specific files we know should exist
			// For clang min version, x86_64, clang driver
			clangMinDir := filepath.Join(configBaseDir, fmt.Sprintf("clang-%d", minClangVer))
			assert.DirExists(t, clangMinDir)

			clangMinX86ClangCfg := filepath.Join(clangMinDir, "x86_64-unknown-linux-gnu-clang.cfg")
			assert.FileExists(t, clangMinX86ClangCfg)

			// Verify the content includes both the melange config and system config
			cfgContent, err := os.ReadFile(clangMinX86ClangCfg)
			require.NoError(t, err)
			assert.Contains(t, string(cfgContent), "@../../.melange.clang.cfg")
			assert.Contains(t, string(cfgContent), fmt.Sprintf("@/etc/clang-%d/x86_64-unknown-linux-gnu-clang.cfg", minClangVer))

			// For clang min version, aarch64, clang++ driver
			clangMinAarch64ClangxxCfg := filepath.Join(clangMinDir, "aarch64-unknown-linux-gnu-clang++.cfg")
			assert.FileExists(t, clangMinAarch64ClangxxCfg)

			// For clang max version, x86_64, clang driver
			clangMaxDir := filepath.Join(configBaseDir, fmt.Sprintf("clang-%d", maxClangVer))
			assert.DirExists(t, clangMaxDir)

			clangMaxX86ClangCfg := filepath.Join(clangMaxDir, "x86_64-unknown-linux-gnu-clang.cfg")
			assert.FileExists(t, clangMaxX86ClangCfg)
		})
	}
}

func TestCreateClangConfigFilesError(t *testing.T) {
	t.Run("invalid workspace directory", func(t *testing.T) {
		ctx := context.Background()
		b := &Build{
			WorkspaceDir: "/nonexistent/directory",
			Arch:         apko_types.ParseArchitecture("x86_64"),
			Namespace:    "test",
			Configuration: &config.Configuration{
				Package: config.Package{
					Name:    "test-package",
					Version: "1.0.0",
				},
			},
		}

		err := b.createClangConfigFiles(ctx)
		assert.Error(t, err)
	})
}

func TestCreateCompilerConfigFiles(t *testing.T) {
	t.Run("creates both gcc and clang config files", func(t *testing.T) {
		tmpDir := t.TempDir()
		ctx := clog.WithLogger(context.Background(), slogtest.TestLogger(t))

		b := &Build{
			WorkspaceDir: tmpDir,
			Arch:         apko_types.ParseArchitecture("x86_64"),
			Namespace:    "test",
			Configuration: &config.Configuration{
				Package: config.Package{
					Name:    "test-package",
					Version: "1.0.0",
					Epoch:   0,
				},
			},
		}

		err := b.createCompilerConfigFiles(ctx)
		require.NoError(t, err)

		// Verify GCC spec file exists
		gccSpecPath := filepath.Join(tmpDir, ".melange.gcc.spec")
		assert.FileExists(t, gccSpecPath)

		// Verify clang config file exists
		clangCfgPath := filepath.Join(tmpDir, ".melange.clang.cfg")
		assert.FileExists(t, clangCfgPath)

		// Verify at least one clang driver config exists
		clangMinX86ClangCfg := filepath.Join(tmpDir, ".config", fmt.Sprintf("clang-%d", minClangVer), "x86_64-unknown-linux-gnu-clang.cfg")
		assert.FileExists(t, clangMinX86ClangCfg)
	})
}
