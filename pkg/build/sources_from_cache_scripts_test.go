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
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/melange/pkg/config"
)

// These tests compile the real git-checkout pipeline and run its
// script under busybox sh, the shell a build guest has. The only change to the
// script is pointing /var/cache/melange at a directory of the test's own.

const sourcesFromCacheCloneAttempt = "Attempting git clone"

// sourcesFromCacheRequireTools skips the test when a tool it needs is missing,
// or fails it when MELANGE_REQUIRE_SCRIPT_TOOLS is set.
func sourcesFromCacheRequireTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"git", "busybox"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("MELANGE_REQUIRE_SCRIPT_TOOLS") != "" {
				t.Fatalf("%s is required by MELANGE_REQUIRE_SCRIPT_TOOLS", tool)
			}
			t.Skipf("%s not available", tool)
		}
	}
}

// sourcesFromCacheEnv isolates git from the developer's configuration, which
// could name a signing helper that hangs the test. The scripts write a global
// configuration, so it is a file of the test's own.
func sourcesFromCacheEnv(home string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + home, "TMPDIR=" + home,
		"GIT_CONFIG_GLOBAL=" + filepath.Join(home, "gitconfig"), "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=commit.gpgsign", "GIT_CONFIG_VALUE_0=false",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
	}
}

func sourcesFromCacheGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir, cmd.Env = dir, sourcesFromCacheEnv(t.TempDir())
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return strings.TrimSpace(string(out))
}

// sourcesFromCacheRun compiles the pipeline named by uses with the given
// inputs and runs its script.
func sourcesFromCacheRun(t *testing.T, uses, cache string, with, environ map[string]string) (string, error) {
	t.Helper()
	p := config.Pipeline{Uses: uses, With: with}
	sm := &SubstitutionMap{Substitutions: map[string]string{
		config.SubstitutionPackageName: "hello", config.SubstitutionPackageVersion: "1.0",
	}}
	require.NoError(t, (&Compiled{}).compilePipeline(t.Context(), sm, &p, nil))
	script := strings.ReplaceAll(p.Pipeline[0].Runs, "/var/cache/melange", cache)

	work := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(work, "script.sh"), []byte(script), 0o755))

	cmd := exec.CommandContext(t.Context(), "busybox", "sh", "-e", "-o", "pipefail", filepath.Join(work, "script.sh"))
	cmd.Dir = work
	cmd.Env = sourcesFromCacheEnv(work)
	for k, v := range environ {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// sourcesFromCacheUpstream is a one-commit repository, cached the way a build
// emitting a -source package stashes it. It returns the repository, its commit
// and the cache.
func sourcesFromCacheUpstream(t *testing.T) (string, string, string) {
	t.Helper()
	repo := t.TempDir()
	sourcesFromCacheGit(t, repo, "init", "-q", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644))
	sourcesFromCacheGit(t, repo, "add", "-A")
	sourcesFromCacheGit(t, repo, "commit", "-q", "-m", "one")
	commit := sourcesFromCacheGit(t, repo, "rev-parse", "HEAD")

	stash := t.TempDir()
	out, err := sourcesFromCacheRun(t, "git-checkout", t.TempDir(), map[string]string{
		"repository": repo, "destination": filepath.Join(t.TempDir(), "out"), "branch": "main",
		"expected-commit": commit, "max-retries": "0",
	}, map[string]string{"MELANGE_SOURCE_STASH": stash})
	require.NoError(t, err, out)
	require.FileExists(t, filepath.Join(stash, "git:"+commit+".tar.gz"))
	return repo, commit, stash
}

func TestGitCheckoutStrictSourcesFromCache(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	repo, commit, cache := sourcesFromCacheUpstream(t)
	gone := filepath.Join(t.TempDir(), "no-such-repository")

	tests := []struct {
		name    string
		mode    string
		cache   string // empty means an empty cache
		with    map[string]string
		wantErr bool
		cloned  bool
	}{
		{
			name: "strict restores from the cache without the repository", mode: "strict", cache: cache,
			with: map[string]string{"repository": gone, "expected-commit": commit},
		},
		{
			name: "strict with no archive", mode: "strict", wantErr: true,
			with: map[string]string{"repository": repo, "branch": "main", "expected-commit": commit},
		},
		{
			name: "strict without expected-commit", mode: "strict", cache: cache, wantErr: true,
			with: map[string]string{"repository": repo, "branch": "main"},
		},
		{
			name: "strict with sparse-paths", mode: "strict", cache: cache, wantErr: true,
			with: map[string]string{"repository": repo, "expected-commit": commit, "sparse-paths": "a.txt"},
		},
		{
			name: "strict without restore refuses to clone", mode: "strict-only", cache: cache, wantErr: true,
			with: map[string]string{"repository": repo, "branch": "main", "expected-commit": commit},
		},
		{
			name: "1 with no archive clones", mode: "1", cloned: true,
			with: map[string]string{"repository": repo, "branch": "main", "expected-commit": commit},
		},
		{
			name: "unset with an archive still clones", cache: cache, cloned: true,
			with: map[string]string{"repository": repo, "branch": "main", "expected-commit": commit},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.cache == "" {
				tt.cache = t.TempDir()
			}
			dest := filepath.Join(t.TempDir(), "out")
			with := maps.Clone(tt.with)
			with["destination"], with["max-retries"] = dest, "0"
			environ := map[string]string{}
			switch tt.mode {
			case "strict":
				environ["MELANGE_SOURCE_RESTORE"], environ["MELANGE_SOURCE_STRICT"] = "1", "1"
			case "strict-only":
				environ["MELANGE_SOURCE_STRICT"] = "1"
			case "":
			default:
				environ["MELANGE_SOURCE_RESTORE"] = tt.mode
			}
			out, err := sourcesFromCacheRun(t, "git-checkout", tt.cache, with, environ)

			if tt.wantErr {
				require.Error(t, err, out)
				require.Contains(t, out, "--strict-sources-from-cache")
				require.Contains(t, out, "refusing to clone")
				require.Contains(t, out, "git:<expected-commit>.tar.gz")
				require.NotContains(t, out, "git:.tar.gz")
				require.NotContains(t, out, sourcesFromCacheCloneAttempt)
				require.NoDirExists(t, dest)
				return
			}
			require.NoError(t, err, out)
			require.Equal(t, tt.cloned, strings.Contains(out, sourcesFromCacheCloneAttempt), out)
			require.Equal(t, commit, sourcesFromCacheGit(t, dest, "rev-parse", "HEAD"))
		})
	}
}
