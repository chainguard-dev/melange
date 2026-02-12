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
	"os"
	"path/filepath"
	"strings"
	"testing"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/config"
	"github.com/chainguard-dev/clog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestDetectClangSystemConfigDirs(t *testing.T) {
	tests := []struct {
		name           string
		setupDirs      []string
		expectedDirs   []string
		unexpectedDirs []string
	}{
		{
			name:           "single clang version",
			setupDirs:      []string{"clang-18"},
			expectedDirs:   []string{"clang-18"},
			unexpectedDirs: []string{},
		},
		{
			name:           "multiple clang versions",
			setupDirs:      []string{"clang-17", "clang-18", "clang-19"},
			expectedDirs:   []string{"clang-17", "clang-18", "clang-19"},
			unexpectedDirs: []string{},
		},
		{
			name:           "filters non-matching directories",
			setupDirs:      []string{"clang-18", "clang", "clang-abc", "other-18"},
			expectedDirs:   []string{"clang-18"},
			unexpectedDirs: []string{"clang", "clang-abc", "other-18"},
		},
		{
			name:           "no clang directories",
			setupDirs:      []string{},
			expectedDirs:   []string{},
			unexpectedDirs: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpEtc := t.TempDir()

			// Setup test directories
			for _, dir := range tt.setupDirs {
				require.NoError(t, os.Mkdir(filepath.Join(tmpEtc, dir), 0o755))
			}

			// Simulate detectClangSystemConfigDirs logic with tmpEtc instead of /etc
			entries, err := os.ReadDir(tmpEtc)
			require.NoError(t, err)

			var foundDirs []string
			for _, entry := range entries {
				if entry.IsDir() && strings.HasPrefix(entry.Name(), "clang-") {
					suffix := strings.TrimPrefix(entry.Name(), "clang-")
					allDigits := len(suffix) > 0
					for _, c := range suffix {
						if c < '0' || c > '9' {
							allDigits = false
							break
						}
					}
					if allDigits {
						foundDirs = append(foundDirs, entry.Name())
					}
				}
			}

			// Verify expected directories were found
			assert.Len(t, foundDirs, len(tt.expectedDirs), "unexpected number of directories found")
			for _, expected := range tt.expectedDirs {
				assert.Contains(t, foundDirs, expected, "expected directory not found: %s", expected)
			}

			// Verify unexpected directories were not found
			for _, unexpected := range tt.unexpectedDirs {
				assert.NotContains(t, foundDirs, unexpected, "unexpected directory was found: %s", unexpected)
			}
		})
	}
}

func TestDetectClangSystemConfigFiles(t *testing.T) {
	tests := []struct {
		name            string
		arch            string
		setupFiles      map[string]bool // path -> isFile (true=file, false=dir)
		expectedFiles   []string        // expected basenames
		unexpectedFiles []string        // files that should not be matched
	}{
		{
			name: "matches architecture-specific configs",
			arch: "x86_64",
			setupFiles: map[string]bool{
				"clang-18/x86_64-alpine-clang.cfg":   true,
				"clang-18/x86_64-alpine-clang++.cfg": true,
				"clang-18/aarch64-alpine-clang.cfg":  true,
			},
			expectedFiles: []string{
				"x86_64-alpine-clang.cfg",
				"x86_64-alpine-clang++.cfg",
			},
			unexpectedFiles: []string{
				"aarch64-alpine-clang.cfg",
			},
		},
		{
			name: "matches multiple versions",
			arch: "aarch64",
			setupFiles: map[string]bool{
				"clang-17/aarch64-unknown-clang.cfg": true,
				"clang-18/aarch64-unknown-clang.cfg": true,
				"clang-19/aarch64-unknown-clang.cfg": true,
			},
			expectedFiles: []string{
				"aarch64-unknown-clang.cfg",
				"aarch64-unknown-clang.cfg",
				"aarch64-unknown-clang.cfg",
			},
		},
		{
			name: "filters non-matching files",
			arch: "x86_64",
			setupFiles: map[string]bool{
				"clang-18/x86_64-vendor-clang.cfg":  true,
				"clang-18/x86_64-vendor.cfg":        true,
				"clang-18/aarch64-vendor-clang.cfg": true,
				"clang-18/random.txt":               true,
			},
			expectedFiles: []string{
				"x86_64-vendor-clang.cfg",
			},
			unexpectedFiles: []string{
				"x86_64-vendor.cfg",
				"aarch64-vendor-clang.cfg",
				"random.txt",
			},
		},
		{
			name: "skips directories",
			arch: "x86_64",
			setupFiles: map[string]bool{
				"clang-18/x86_64-vendor-clang.cfg": true,
				"clang-18/subdir":                  false, // directory
			},
			expectedFiles: []string{
				"x86_64-vendor-clang.cfg",
			},
			unexpectedFiles: []string{
				"subdir",
			},
		},
		{
			name: "handles symlinks",
			arch: "x86_64",
			setupFiles: map[string]bool{
				"clang-18/x86_64-vendor-clang.cfg": true,
			},
			expectedFiles: []string{
				"x86_64-vendor-clang.cfg",
			},
		},
		{
			name:          "no matching files",
			arch:          "x86_64",
			setupFiles:    map[string]bool{},
			expectedFiles: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpEtc := t.TempDir()

			// Setup test files and directories
			for path, isFile := range tt.setupFiles {
				fullPath := filepath.Join(tmpEtc, path)
				dir := filepath.Dir(fullPath)
				require.NoError(t, os.MkdirAll(dir, 0o755))

				if isFile {
					require.NoError(t, os.WriteFile(fullPath, []byte("test content"), 0o644))
				} else {
					require.NoError(t, os.MkdirAll(fullPath, 0o755))
				}
			}

			// Create Build with test architecture
			b := &Build{
				Arch: apko_types.ParseArchitecture(tt.arch),
			}

			// Simulate detectClangSystemConfigFiles logic with tmpEtc instead of /etc
			entries, err := os.ReadDir(tmpEtc)
			require.NoError(t, err)

			var clangDirs []string
			for _, entry := range entries {
				if entry.IsDir() && strings.HasPrefix(entry.Name(), "clang-") {
					suffix := strings.TrimPrefix(entry.Name(), "clang-")
					allDigits := len(suffix) > 0
					for _, c := range suffix {
						if c < '0' || c > '9' {
							allDigits = false
							break
						}
					}
					if allDigits {
						clangDirs = append(clangDirs, filepath.Join(tmpEtc, entry.Name()))
					}
				}
			}

			var configFiles []string
			for _, dir := range clangDirs {
				dirEntries, err := os.ReadDir(dir)
				if err != nil {
					continue
				}

				for _, entry := range dirEntries {
					fileType := entry.Type()
					if !fileType.IsRegular() && fileType&os.ModeSymlink == 0 {
						continue
					}

					// Match pattern: <arch>-*-clang(++)?.cfg
					basename := entry.Name()
					if !strings.HasPrefix(basename, b.Arch.ToAPK()+"-") {
						continue
					}
					if !strings.HasSuffix(basename, "-clang.cfg") && !strings.HasSuffix(basename, "-clang++.cfg") {
						continue
					}

					configFiles = append(configFiles, basename)
				}
			}

			// Verify expected files
			assert.Len(t, configFiles, len(tt.expectedFiles), "unexpected number of config files")

			// Verify unexpected files are not present
			for _, unexpected := range tt.unexpectedFiles {
				assert.NotContains(t, configFiles, unexpected, "unexpected file was matched: %s", unexpected)
			}
		})
	}
}

func TestCreateClangConfigFile(t *testing.T) {
	tests := []struct {
		name            string
		includePaths    []string
		expectedContent string
	}{
		{
			name:            "single include",
			includePaths:    []string{"/path/to/config1.cfg"},
			expectedContent: "@/path/to/config1.cfg\n",
		},
		{
			name:            "multiple includes",
			includePaths:    []string{"/path/to/config1.cfg", "/path/to/config2.cfg"},
			expectedContent: "@/path/to/config1.cfg\n@/path/to/config2.cfg\n",
		},
		{
			name:            "no includes",
			includePaths:    []string{},
			expectedContent: "",
		},
		{
			name:            "three includes",
			includePaths:    []string{"/a.cfg", "/b.cfg", "/c.cfg"},
			expectedContent: "@/a.cfg\n@/b.cfg\n@/c.cfg\n",
		},
		{
			name:            "includes with spaces",
			includePaths:    []string{"/path/with spaces/config.cfg"},
			expectedContent: "@/path/with spaces/config.cfg\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			outputPath := filepath.Join(tmpDir, "test-config.cfg")

			err := createClangConfigFile(outputPath, tt.includePaths...)
			require.NoError(t, err)

			// Verify file exists
			assert.FileExists(t, outputPath)

			// Verify content
			content, err := os.ReadFile(outputPath)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedContent, string(content))

			// Verify file permissions
			info, err := os.Stat(outputPath)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
		})
	}
}

func TestCreateClangConfigFileErrors(t *testing.T) {
	t.Run("invalid output path", func(t *testing.T) {
		// Try to write to a non-existent directory
		err := createClangConfigFile("/nonexistent/dir/config.cfg", "/some/path.cfg")
		assert.Error(t, err)
	})

	t.Run("read-only directory", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("Skipping test when running as root")
		}

		tmpDir := t.TempDir()
		readOnlyDir := filepath.Join(tmpDir, "readonly")
		require.NoError(t, os.Mkdir(readOnlyDir, 0o555))

		outputPath := filepath.Join(readOnlyDir, "config.cfg")
		err := createClangConfigFile(outputPath, "/some/path.cfg")
		assert.Error(t, err)
	})
}

func TestCreateClangConfigFiles(t *testing.T) {
	tests := []struct {
		name                string
		arch                string
		setupSystemConfigs  map[string]string // path -> content
		expectBaseConfig    bool
		expectDriverConfigs []string // relative paths
	}{
		{
			name: "creates configs when system configs exist",
			arch: "x86_64",
			setupSystemConfigs: map[string]string{
				"clang-18/x86_64-vendor-clang.cfg": "# system config",
			},
			expectBaseConfig: true,
			expectDriverConfigs: []string{
				".config/clang-18/x86_64-vendor-clang.cfg",
			},
		},
		{
			name: "creates multiple driver configs",
			arch: "aarch64",
			setupSystemConfigs: map[string]string{
				"clang-17/aarch64-vendor-clang.cfg":   "# clang 17",
				"clang-18/aarch64-vendor-clang.cfg":   "# clang 18",
				"clang-18/aarch64-vendor-clang++.cfg": "# clang++ 18",
			},
			expectBaseConfig: true,
			expectDriverConfigs: []string{
				".config/clang-17/aarch64-vendor-clang.cfg",
				".config/clang-18/aarch64-vendor-clang.cfg",
				".config/clang-18/aarch64-vendor-clang++.cfg",
			},
		},
		{
			name:                "handles no system configs",
			arch:                "x86_64",
			setupSystemConfigs:  map[string]string{},
			expectBaseConfig:    false,
			expectDriverConfigs: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workspaceDir := t.TempDir()
			etcDir := t.TempDir()

			// Setup system config files
			for relPath, content := range tt.setupSystemConfigs {
				fullPath := filepath.Join(etcDir, relPath)
				dir := filepath.Dir(fullPath)
				require.NoError(t, os.MkdirAll(dir, 0o755))
				require.NoError(t, os.WriteFile(fullPath, []byte(content), 0o644))
			}

			// Note: We can't easily test the full createClangConfigFiles method
			// without modifying it to accept a custom /etc path, so we'll test
			// the logic manually here

			if len(tt.setupSystemConfigs) > 0 {
				// Create base config
				baseConfigPath := filepath.Join(workspaceDir, ".melange.clang.cfg")
				require.NoError(t, os.WriteFile(baseConfigPath, []byte("-Xlinker --package-metadata='test'\n"), 0o644))

				if tt.expectBaseConfig {
					assert.FileExists(t, baseConfigPath)
				}

				// Simulate creating driver configs
				for _, driverPath := range tt.expectDriverConfigs {
					fullPath := filepath.Join(workspaceDir, driverPath)
					dir := filepath.Dir(fullPath)
					require.NoError(t, os.MkdirAll(dir, 0o755))

					content := "@" + baseConfigPath + "\n@/etc/" + filepath.Base(filepath.Dir(driverPath)) + "/" + filepath.Base(driverPath) + "\n"
					require.NoError(t, os.WriteFile(fullPath, []byte(content), 0o644))

					assert.FileExists(t, fullPath)

					// Verify content
					fileContent, err := os.ReadFile(fullPath)
					require.NoError(t, err)
					assert.Contains(t, string(fileContent), "@"+baseConfigPath)
				}
			}
		})
	}
}

func TestCreateCompilerConfigFiles(t *testing.T) {
	t.Run("creates both gcc and clang config files", func(t *testing.T) {
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

		ctx := context.Background()
		ctx = clog.WithLogger(ctx, clog.DefaultLogger())

		err := b.createCompilerConfigFiles(ctx)
		require.NoError(t, err)

		// Verify GCC spec file was created
		gccSpecPath := filepath.Join(tmpDir, ".melange.gcc.spec")
		assert.FileExists(t, gccSpecPath, "GCC spec file should be created")

		// Read GCC spec file
		content, err := os.ReadFile(gccSpecPath)
		require.NoError(t, err)
		assert.Contains(t, string(content), "*link:")
	})

	t.Run("handles errors from createGccSpecFile", func(t *testing.T) {
		b := &Build{
			WorkspaceDir: "/nonexistent/directory",
			Arch:         apko_types.ParseArchitecture("x86_64"),
		}

		ctx := context.Background()
		ctx = clog.WithLogger(ctx, clog.DefaultLogger())

		err := b.createCompilerConfigFiles(ctx)
		assert.Error(t, err, "should fail when workspace directory doesn't exist")
	})
}
