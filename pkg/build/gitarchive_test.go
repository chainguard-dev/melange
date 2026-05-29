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
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/require"
)

// newTestRepo creates a git repository under t.TempDir() containing:
//
//	sub/chart/Chart.yaml
//	sub/chart/values.yaml
//	top.txt
//
// It returns the repository root and the HEAD commit hash.
func newTestRepo(t *testing.T) (repoDir, commit string) {
	t.Helper()
	repoDir = t.TempDir()

	write := func(rel, content string) {
		p := filepath.Join(repoDir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	}
	write("sub/chart/Chart.yaml", "name: common\nversion: 1.0.0\n")
	write("sub/chart/values.yaml", "replicas: 1\n")
	write("top.txt", "top-level\n")

	// Run git with a self-contained identity so the test does not depend on the
	// host's global git config.
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		)
		out, err := cmd.CombinedOutput()
		require.NoErrorf(t, err, "git %v: %s", args, out)
	}
	git("init", "-q", "-b", "main")
	git("add", ".")
	git("commit", "-q", "-m", "initial")

	out, err := exec.Command("git", "-C", repoDir, "rev-parse", "HEAD").Output()
	require.NoError(t, err)
	commit = string(out[:len(out)-1]) // strip trailing newline
	return repoDir, commit
}

func TestGitArchive(t *testing.T) {
	ctx := slogtest.Context(t)
	repoDir, commit := newTestRepo(t)

	t.Run("extracts subtree at HEAD with path prefix", func(t *testing.T) {
		dest := t.TempDir()
		resolved, err := gitArchive(ctx, &gitArchiveOptions{
			RepositoryDir:  repoDir,
			Ref:            "HEAD",
			Path:           "sub/chart",
			ExpectedCommit: commit,
			Destination:    dest,
		})
		require.NoError(t, err)
		require.Equal(t, commit, resolved)

		// The path prefix is preserved beneath the destination.
		require.FileExists(t, filepath.Join(dest, "sub/chart/Chart.yaml"))
		require.FileExists(t, filepath.Join(dest, "sub/chart/values.yaml"))
		// Only the requested subtree is extracted.
		require.NoFileExists(t, filepath.Join(dest, "top.txt"))
	})

	t.Run("anchors at repository toplevel from a subdirectory", func(t *testing.T) {
		dest := t.TempDir()
		// RepositoryDir points inside the repo, not at its root. git archive
		// must still resolve Path relative to the repository root.
		resolved, err := gitArchive(ctx, &gitArchiveOptions{
			RepositoryDir:  filepath.Join(repoDir, "sub", "chart"),
			Ref:            "HEAD",
			Path:           "sub/chart",
			ExpectedCommit: commit,
			Destination:    dest,
		})
		require.NoError(t, err)
		require.Equal(t, commit, resolved)
		require.FileExists(t, filepath.Join(dest, "sub/chart/Chart.yaml"))
	})

	t.Run("defaults RepositoryDir to current directory", func(t *testing.T) {
		dest := t.TempDir()
		// Empty RepositoryDir means ".", so run with the working directory set
		// inside the repo.
		t.Chdir(repoDir)
		resolved, err := gitArchive(ctx, &gitArchiveOptions{
			Ref:         "HEAD",
			Path:        "sub/chart",
			Destination: dest,
		})
		require.NoError(t, err)
		require.Equal(t, commit, resolved)
		require.FileExists(t, filepath.Join(dest, "sub/chart/Chart.yaml"))
	})

	t.Run("expected-commit mismatch fails", func(t *testing.T) {
		dest := t.TempDir()
		_, err := gitArchive(ctx, &gitArchiveOptions{
			RepositoryDir:  repoDir,
			Ref:            "HEAD",
			Path:           "sub/chart",
			ExpectedCommit: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			Destination:    dest,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected")
	})

	t.Run("nonexistent path fails", func(t *testing.T) {
		dest := t.TempDir()
		_, err := gitArchive(ctx, &gitArchiveOptions{
			RepositoryDir: repoDir,
			Ref:           "HEAD",
			Path:          "does/not/exist",
			Destination:   dest,
		})
		require.Error(t, err)
	})

	t.Run("missing required inputs fail", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			opts *gitArchiveOptions
		}{
			{"no ref", &gitArchiveOptions{RepositoryDir: repoDir, Path: "sub/chart", Destination: t.TempDir()}},
			{"no path", &gitArchiveOptions{RepositoryDir: repoDir, Ref: "HEAD", Destination: t.TempDir()}},
			{"no destination", &gitArchiveOptions{RepositoryDir: repoDir, Ref: "HEAD", Path: "sub/chart"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := gitArchive(ctx, tc.opts)
				require.Error(t, err)
			})
		}
	})
}

func TestGitRevParse(t *testing.T) {
	ctx := slogtest.Context(t)
	repoDir, commit := newTestRepo(t)

	t.Run("resolves HEAD to full commit", func(t *testing.T) {
		got, err := gitRevParse(ctx, repoDir, "HEAD")
		require.NoError(t, err)
		require.Equal(t, commit, got)
	})

	t.Run("resolves from a subdirectory", func(t *testing.T) {
		got, err := gitRevParse(ctx, filepath.Join(repoDir, "sub", "chart"), "HEAD")
		require.NoError(t, err)
		require.Equal(t, commit, got)
	})

	t.Run("unknown ref fails", func(t *testing.T) {
		_, err := gitRevParse(ctx, repoDir, "no-such-ref")
		require.Error(t, err)
	})
}
