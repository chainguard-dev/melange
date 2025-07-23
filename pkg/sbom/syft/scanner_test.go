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

	// Create a temporary directory
	tmpDir := t.TempDir()

	// Create a go.mod file in the temporary directory
	goModContent := `module example.com/test

go 1.21

require github.com/sirupsen/logrus v1.9.3

require golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
`
	err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goModContent), 0644)
	require.NoError(t, err)

	// Create a go.sum file for better detection
	goSumContent := `github.com/davecgh/go-spew v1.1.0/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/davecgh/go-spew v1.1.1 h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=
github.com/davecgh/go-spew v1.1.1/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/pmezard/go-difflib v1.0.0 h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=
github.com/pmezard/go-difflib v1.0.0/go.mod h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4=
github.com/sirupsen/logrus v1.9.3 h1:dueUQJ1C2q9oE3F7wvmSGAaVtTmUizReu6fjN8uqzbQ=
github.com/sirupsen/logrus v1.9.3/go.mod h1:naHLuLoDiP4jHNo9R0sCBMtWGeIprob74mVsIT4qYEQ=
github.com/stretchr/objx v0.1.0/go.mod h1:HFkY916IF+rwdDfMAkV7OtwuqBVzrE8GR6GFx+wExME=
github.com/stretchr/testify v1.7.0 h1:nwc3DEeHmmLAfoZucVR881uASk0Mfjw8xYJ99tb5CcY=
github.com/stretchr/testify v1.7.0/go.mod h1:6Fq8oRcR53rry900zMqJjRRixrwX3KX962/h/Wwjteg=
golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 h1:0A+M6Uqn+Eje4kHMK80dtF3JCXC4ykBgQG4Fe06QRhQ=
golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c h1:dUUwHk2QECo/6vqA44rthZ8ie2QXMNeKRTHCNY2nXvo=
gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
`
	err = os.WriteFile(filepath.Join(tmpDir, "go.sum"), []byte(goSumContent), 0644)
	require.NoError(t, err)

	// Create a simple Go source file to ensure detection
	goSourceContent := `package main

import "github.com/sirupsen/logrus"

func main() {
	logrus.Info("Hello, World!")
}
`
	err = os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(goSourceContent), 0644)
	require.NoError(t, err)

	// Scan the directory
	scanner := NewScanner(tmpDir)
	packages, err := scanner.Scan(ctx)

	// Verify that the scanner runs without error
	require.NoError(t, err)

	// With DirectoryTag catalogers, go.mod files ARE scanned
	require.Len(t, packages, 2) // Should find logrus and sys dependencies
}

func TestScan_NonExistentPath(t *testing.T) {
	ctx := slogtest.Context(t)

	scanner := NewScanner("/non/existent/path")
	packages, err := scanner.Scan(ctx)

	// Syft should error on non-existent paths
	require.Error(t, err)
	require.Contains(t, err.Error(), "no such file or directory")
	require.Nil(t, packages)
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

	// With ImageTag/FileTag catalogers, manifest files are not scanned
	// With DirectoryTag catalogers, we should find packages from all manifest files
	// We have: go.mod (2 packages), requirements.txt (3 packages), package.json (2 packages),
	// Gemfile (2 packages), pom.xml (2 packages) = 11 total
	require.GreaterOrEqual(t, len(packages), 5, "should find packages from manifest files")
}
