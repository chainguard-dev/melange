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

// Some of this code is based on the bom tool scan code originally
// found at https://github.com/kubernetes-sigs/bom/blob/main/pkg/spdx/implementation.go

package sbom

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetDirectoryTree(t *testing.T) {
	d := t.TempDir()
	original := []string{
		"/README.go",
		"/http/agent.go",
		"/http/httpfakes/fake_agent_implementation.go",
		"/http.go",
		"/http_test.go",
	}
	for _, tf := range original {
		dir := filepath.Dir(tf)
		require.NoError(t, os.MkdirAll(filepath.Join(d, dir), os.FileMode(0o755)))
		require.NoError(t, os.WriteFile(filepath.Join(d, tf), []byte("dummy"), os.FileMode(0o644)))
	}
	readList, err := getDirectoryTree(d)
	require.NoError(t, err)
	require.Equal(t, original, readList)
}
