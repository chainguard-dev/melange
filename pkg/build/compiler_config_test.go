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
	"os"
	"path/filepath"
	"strings"
	"testing"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/config"
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
