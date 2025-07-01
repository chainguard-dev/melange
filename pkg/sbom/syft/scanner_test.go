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

package syft

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/require"
)

func TestNewScanner(t *testing.T) {
	scanner := NewScanner("/test/path")
	require.NotNil(t, scanner)
	require.Equal(t, "/test/path", scanner.path)
}

func TestScan_EmptyDirectory(t *testing.T) {
	ctx := slogtest.Context(t)
	
	// Create a temporary empty directory
	tmpDir := t.TempDir()
	
	scanner := NewScanner(tmpDir)
	packages, err := scanner.Scan(ctx)
	
	require.NoError(t, err)
	require.Empty(t, packages)
}

func TestScan_WithGoModule(t *testing.T) {
	ctx := slogtest.Context(t)
	
	// Create a temporary directory with a Go binary
	tmpDir := t.TempDir()
	
	// TODO: Once we add Syft dependency, we can create a real Go binary
	// For now, just test that scanning doesn't error
	scanner := NewScanner(tmpDir)
	packages, err := scanner.Scan(ctx)
	
	require.NoError(t, err)
	require.Empty(t, packages) // Will be non-empty once Syft is integrated
}

func TestScan_NonExistentPath(t *testing.T) {
	ctx := slogtest.Context(t)
	
	scanner := NewScanner("/non/existent/path")
	packages, err := scanner.Scan(ctx)
	
	// For now, this should not error since we're returning empty slice
	require.NoError(t, err)
	require.Empty(t, packages)
}

func TestScan_WithTestFiles(t *testing.T) {
	ctx := slogtest.Context(t)
	
	// Create a temporary directory with some test files
	tmpDir := t.TempDir()
	
	// Create a fake Go module file
	goModContent := `module example.com/test

go 1.24

require (
	github.com/stretchr/testify v1.8.0
	github.com/chainguard-dev/clog v1.0.0
)
`
	err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goModContent), 0644)
	require.NoError(t, err)
	
	// Create a fake Python requirements file
	requirementsContent := `numpy==1.24.0
pandas==2.0.0
requests==2.28.1
`
	err = os.WriteFile(filepath.Join(tmpDir, "requirements.txt"), []byte(requirementsContent), 0644)
	require.NoError(t, err)
	
	// Create a fake package.json file
	packageJSONContent := `{
  "name": "test-package",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "react": "^18.2.0"
  }
}
`
	err = os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSONContent), 0644)
	require.NoError(t, err)
	
	scanner := NewScanner(tmpDir)
	packages, err := scanner.Scan(ctx)
	
	require.NoError(t, err)
	// Once Syft is integrated, we should find packages from these files
	require.Empty(t, packages) // Will be non-empty once Syft is integrated
}