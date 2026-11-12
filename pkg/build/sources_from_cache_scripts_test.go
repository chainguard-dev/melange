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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

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
//
//nolint:unparam // uses: the credential tests (#2738) run fetch through it too
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

// sourcesFromCacheMonorepo is a two-commit repository, the first commit
// tagged, laid out so that a cone of a/b holds the root's files, a's own
// files and all of a/b, and leaves out d and e. It serves partial clones, as
// a forge does. It returns the repository, its file:// URL and its commit.
func sourcesFromCacheMonorepo(t *testing.T) (string, string, string) {
	t.Helper()
	repo := t.TempDir()
	sourcesFromCacheGit(t, repo, "init", "-q", "-b", "main")
	sourcesFromCacheGit(t, repo, "config", "uploadpack.allowFilter", "true")
	for name, body := range map[string]string{
		"root.txt": "root\n", "a/x": "x\n", "a/b/y": "y\n", "a/b/c/z": "z\n", "d/w": "w\n", "e/v": "v\n",
	} {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(repo, name)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(repo, name), []byte(body), 0o644))
	}
	sourcesFromCacheGit(t, repo, "add", "-A")
	sourcesFromCacheGit(t, repo, "commit", "-q", "-m", "one")
	sourcesFromCacheGit(t, repo, "tag", "-a", "-m", "v1", "v1")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "d", "w2"), []byte("w2\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "a", "b", "y2"), []byte("y2\n"), 0o644))
	sourcesFromCacheGit(t, repo, "add", "-A")
	// committed in the past, so an archive dated now is told apart
	cmd := exec.CommandContext(t.Context(), "git", "commit", "-q", "-m", "two")
	cmd.Dir, cmd.Env = repo, append(sourcesFromCacheEnv(t.TempDir()), "GIT_COMMITTER_DATE=@1669683910 +0000")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return repo, "file://" + repo, sourcesFromCacheGit(t, repo, "rev-parse", "HEAD")
}

// sourcesFromCacheArchive lists the regular files of a stashed archive, with
// their contents, the leading directory stripped.
func sourcesFromCacheArchive(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	zr, err := gzip.NewReader(f)
	require.NoError(t, err)
	files := map[string]string{}
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		body, err := io.ReadAll(tr)
		require.NoError(t, err)
		_, name, _ := strings.Cut(hdr.Name, "/")
		files[name] = string(body)
	}
	return files
}

// sourcesFromCacheArchiveTimes is the modification time of every entry of a
// stashed archive.
func sourcesFromCacheArchiveTimes(t *testing.T, path string) map[string]time.Time {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	zr, err := gzip.NewReader(f)
	require.NoError(t, err)
	times := map[string]time.Time{}
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		times[hdr.Name] = hdr.ModTime
	}
	require.NotEmpty(t, times)
	return times
}

// sourcesFromCacheRewrite rewrites a stashed archive, keeping the regular
// files keep accepts and appending the files add names under the same
// leading directory.
func sourcesFromCacheRewrite(t *testing.T, path string, keep func(name string) bool, add map[string]string) {
	t.Helper()
	in, err := os.ReadFile(path)
	require.NoError(t, err)
	zr, err := gzip.NewReader(bytes.NewReader(in))
	require.NoError(t, err)
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	tr := tar.NewReader(zr)
	prefix := ""
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		dir, name, _ := strings.Cut(hdr.Name, "/")
		prefix = dir + "/"
		if hdr.Typeflag == tar.TypeReg && !keep(name) {
			continue
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err = io.Copy(tw, tr)
		require.NoError(t, err)
	}
	for name, body := range add {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: prefix + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}))
		_, err = tw.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, zw.Close())
	require.NoError(t, os.WriteFile(path, out.Bytes(), 0o644))
}

// sourcesFromCacheCopy copies a stash, so a case can tamper with its own.
func sourcesFromCacheCopy(t *testing.T, stash string) string {
	t.Helper()
	dst := t.TempDir()
	entries, err := os.ReadDir(stash)
	require.NoError(t, err)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(stash, e.Name()))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dst, e.Name()), b, 0o644))
	}
	return dst
}

// sourcesFromCacheSparseKey is the name a sparse checkout of commit is
// stashed under, cone being `git sparse-checkout list` of it.
func sourcesFromCacheSparseKey(commit string, cone ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(cone, "\n") + "\n"))
	return "git:" + commit + "-sparse-" + hex.EncodeToString(sum[:])[:16]
}

// sourcesFromCacheView is what a build can see of a checkout: HEAD and its
// shape, the index, the sparse cone, version and status as builds derive
// them, and every file in the work tree with its contents.
func sourcesFromCacheView(t *testing.T, dir string) map[string]string {
	t.Helper()
	view := map[string]string{
		"rev-parse":            sourcesFromCacheGit(t, dir, "rev-parse", "HEAD"),
		"HEAD":                 sourcesFromCacheGit(t, dir, "rev-parse", "--symbolic-full-name", "HEAD"),
		"describe":             sourcesFromCacheGit(t, dir, "describe", "--tags", "--long", "--dirty"),
		"ls-files -s -t":       sourcesFromCacheGit(t, dir, "ls-files", "-s", "-t"),
		"status":               sourcesFromCacheGit(t, dir, "status", "--porcelain"),
		"sparse-checkout":      sourcesFromCacheGit(t, dir, "config", "--get", "core.sparseCheckout"),
		"sparse-cone":          sourcesFromCacheGit(t, dir, "config", "--get", "core.sparseCheckoutCone"),
		"sparse-checkout list": sourcesFromCacheGit(t, dir, "sparse-checkout", "list"),
		// out-of-cone blobs are absent; git must still take them as
		// promised, or write-tree (and commit, stash, am) fails
		"promisor":   sourcesFromCacheGit(t, dir, "config", "--get", "remote.origin.promisor"),
		"write-tree": sourcesFromCacheGit(t, dir, "write-tree"),
	}
	var files []string
	require.NoError(t, filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		require.NoError(t, err)
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			rel, err := filepath.Rel(dir, path)
			require.NoError(t, err)
			body, err := os.ReadFile(path)
			require.NoError(t, err)
			files = append(files, rel+"="+string(body))
		}
		return nil
	}))
	slices.Sort(files)
	view["files"] = strings.Join(files, "\n")
	return view
}

// A sparse checkout is stashed as the paths it checked out, with its cone,
// and restored from the stash alone, without the repository, as the same
// checkout: the same files, index, skip-worktree bits, cone, HEAD and
// describe. A tampered or mismatched stash is refused.
func TestGitCheckoutSparseSourcePackage(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	repo, url, commit := sourcesFromCacheMonorepo(t)
	with := func(dest, sparse string) map[string]string {
		w := map[string]string{
			"repository": url, "destination": dest, "branch": "main",
			"expected-commit": commit, "max-retries": "0",
		}
		if sparse != "" {
			w["sparse-paths"] = sparse
		}
		return w
	}
	capture := func(sparse string) (string, string) {
		dest, stash := filepath.Join(t.TempDir(), "out"), t.TempDir()
		out, err := sourcesFromCacheRun(t, "git-checkout", t.TempDir(), with(dest, sparse), map[string]string{"MELANGE_SOURCE_STASH": stash})
		require.NoError(t, err, out)
		return dest, stash
	}
	key := sourcesFromCacheSparseKey(commit, "a/b")

	built, stash := capture("a/b\n")
	require.Equal(t, map[string]string{
		"root.txt": "root\n", "a/x": "x\n", "a/b/y": "y\n", "a/b/y2": "y2\n", "a/b/c/z": "z\n",
	}, sourcesFromCacheArchive(t, filepath.Join(stash, key+".tar.gz")), "the archive holds the cone and nothing else")
	sparse, err := os.ReadFile(filepath.Join(stash, key+".sparse"))
	require.NoError(t, err)
	require.Equal(t, "a/b\n", string(sparse))
	for _, sidecar := range []string{".uri", ".commit", ".trees", ".tags"} {
		require.FileExists(t, filepath.Join(stash, key+sidecar))
	}
	// the clone fetched no blob outside the cone, then or while stashing
	missing := sourcesFromCacheGit(t, built, "rev-list", "--objects", "--missing=print", "HEAD")
	for _, path := range []string{"d/w", "d/w2", "e/v"} {
		require.Contains(t, missing, "?"+sourcesFromCacheGit(t, built, "rev-parse", "HEAD:"+path), path)
	}
	// the tree archived was written beside the clone's repository, not in it
	require.Contains(t, sourcesFromCacheGit(t, built, "count-objects", "-v"), "count: 0\n")
	// dated as git archive dates a commit
	when, err := strconv.ParseInt(sourcesFromCacheGit(t, built, "log", "-1", "--format=%ct"), 10, 64)
	require.NoError(t, err)
	for name, mtime := range sourcesFromCacheArchiveTimes(t, filepath.Join(stash, key+".tar.gz")) {
		require.Equal(t, when, mtime.Unix(), name)
	}
	_, again := capture("a/b\n")
	b1, err := os.ReadFile(filepath.Join(stash, key+".tar.gz"))
	require.NoError(t, err)
	b2, err := os.ReadFile(filepath.Join(again, key+".tar.gz"))
	require.NoError(t, err)
	require.Equal(t, b1, b2, "the archive bytes are reproducible")
	want := sourcesFromCacheView(t, built)
	require.Contains(t, want["ls-files -s -t"], "S 100644", "the clone left paths outside the cone skip-worktree")

	gone := filepath.Join(t.TempDir(), "no-such-repository")
	strict := map[string]string{"MELANGE_SOURCE_RESTORE": "1", "MELANGE_SOURCE_STRICT": "1"}
	restore := func(cache, sparse string, environ map[string]string) (string, string, error) {
		dest := filepath.Join(t.TempDir(), "out")
		w := with(dest, sparse)
		w["repository"] = "file://" + gone
		out, err := sourcesFromCacheRun(t, "git-checkout", cache, w, environ)
		return dest, out, err
	}

	t.Run("restored as the build saw it", func(t *testing.T) {
		t.Parallel()
		restash := t.TempDir()
		environ := maps.Clone(strict)
		environ["MELANGE_SOURCE_STASH"] = restash
		dest, out, err := restore(stash, "a/b\n", environ)
		require.NoError(t, err, out)
		require.Contains(t, out, "restoring instead of cloning")
		require.Equal(t, want, sourcesFromCacheView(t, dest))
		// and a rebuild's companion carries the same stash
		for _, sidecar := range []string{".tar.gz", ".sparse", ".commit", ".trees", ".uri"} {
			a, err := os.ReadFile(filepath.Join(stash, key+sidecar))
			require.NoError(t, err)
			b, err := os.ReadFile(filepath.Join(restash, key+sidecar))
			require.NoError(t, err)
			require.Equal(t, a, b, sidecar)
		}
	})

	tests := []struct {
		name    string
		sparse  string
		tamper  func(t *testing.T, cache string)
		wantMsg string
	}{{
		name: "a path outside the cone added", sparse: "a/b",
		tamper: func(t *testing.T, cache string) {
			sourcesFromCacheRewrite(t, filepath.Join(cache, key+".tar.gz"), func(string) bool { return true }, map[string]string{"d/w": "w\n"})
		},
		wantMsg: "archive holds paths outside the sparse checkout: d/w",
	}, {
		name: "an untracked path added", sparse: "a/b",
		tamper: func(t *testing.T, cache string) {
			sourcesFromCacheRewrite(t, filepath.Join(cache, key+".tar.gz"), func(string) bool { return true }, map[string]string{"a/b/new": "new\n"})
		},
		wantMsg: "archive holds files the tree does not name",
	}, {
		name: "a path inside the cone dropped", sparse: "a/b",
		tamper: func(t *testing.T, cache string) {
			sourcesFromCacheRewrite(t, filepath.Join(cache, key+".tar.gz"), func(name string) bool { return name != "a/b/y" }, nil)
		},
		wantMsg: "archive lacks paths the sparse checkout holds: a/b/y",
	}, {
		name: "a file inside the cone changed", sparse: "a/b",
		tamper: func(t *testing.T, cache string) {
			sourcesFromCacheRewrite(t, filepath.Join(cache, key+".tar.gz"), func(name string) bool { return name != "a/b/y" }, map[string]string{"a/b/y": "tampered\n"})
		},
		wantMsg: "restored files do not match the tree the commit names: a/b/y",
	}, {
		name: "no tree objects", sparse: "a/b",
		tamper: func(t *testing.T, cache string) {
			require.NoError(t, os.Remove(filepath.Join(cache, key+".trees")))
		},
		wantMsg: "a sparse checkout cannot be restored without it",
	}, {
		name: "another cone", sparse: "a",
		wantMsg: "--strict-sources-from-cache: refusing to clone; restoring needs MELANGE_SOURCE_RESTORE, expected-commit, and git:<expected-commit>.tar.gz in the cache (--cache-dir), or git:<expected-commit>-sparse-<cone>.tar.gz for a step with sparse-paths (here " + sourcesFromCacheSparseKey(commit, "a") + ".tar.gz)",
	}, {
		name: "another cone's stash under this cone's name", sparse: "a",
		tamper: func(t *testing.T, cache string) {
			files, err := filepath.Glob(filepath.Join(cache, key+".*"))
			require.NoError(t, err)
			for _, f := range files {
				require.NoError(t, os.Rename(f, filepath.Join(cache, sourcesFromCacheSparseKey(commit, "a")+strings.TrimPrefix(filepath.Base(f), key))))
			}
		},
		wantMsg: "the stash was made with another sparse-paths (a/b )",
	}, {
		name: "the cone's own stash is checked against its cone, not its name", sparse: "a/b",
		tamper: func(t *testing.T, cache string) {
			require.NoError(t, os.WriteFile(filepath.Join(cache, key+".sparse"), []byte("a\n"), 0o644))
		},
		wantMsg: "FAIL " + filepath.Join("CACHE", key) + ".tar.gz cannot be restored as this sparse checkout",
	}, {
		name:    "the configuration has no sparse-paths",
		wantMsg: "--strict-sources-from-cache: refusing to clone",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cache := sourcesFromCacheCopy(t, stash)
			if tt.tamper != nil {
				tt.tamper(t, cache)
			}
			dest, out, err := restore(cache, tt.sparse, strict)
			require.Error(t, err, out)
			require.Contains(t, out, strings.ReplaceAll(tt.wantMsg, "CACHE", cache))
			require.NotContains(t, out, sourcesFromCacheCloneAttempt)
			require.NoDirExists(t, dest)
		})
	}

	t.Run("a tag checkout restores detached", func(t *testing.T) {
		t.Parallel()
		w := with(filepath.Join(t.TempDir(), "out"), "a/b")
		delete(w, "branch")
		w["tag"], w["expected-commit"] = "v1", sourcesFromCacheGit(t, repo, "rev-parse", "v1^{commit}")
		stash := t.TempDir()
		out, err := sourcesFromCacheRun(t, "git-checkout", t.TempDir(), w, map[string]string{"MELANGE_SOURCE_STASH": stash})
		require.NoError(t, err, out)
		want := sourcesFromCacheView(t, w["destination"])
		require.Equal(t, "HEAD", want["HEAD"], "a tag checkout is detached")
		require.Equal(t, "v1-0-g"+w["expected-commit"][:7], want["describe"])

		w["destination"], w["repository"] = filepath.Join(t.TempDir(), "out"), "file://"+gone
		out, err = sourcesFromCacheRun(t, "git-checkout", stash, w, strict)
		require.NoError(t, err, out)
		require.NotContains(t, out, "invalid object", "detaching HEAD writes a tree over the paths outside the cone")
		require.Equal(t, want, sourcesFromCacheView(t, w["destination"]))
	})

	t.Run("a sparse step does not restore a full stash", func(t *testing.T) {
		t.Parallel()
		_, full := capture("")
		_, out, err := restore(full, "a/b", strict)
		require.Error(t, err, out)
		require.Contains(t, out, "--strict-sources-from-cache: refusing to clone")
	})
}

// A checkout without sparse-paths is stashed as before: the archive is git
// archive of HEAD, there is no .sparse sidecar, and it restores as a full
// checkout with no sparse configuration.
func TestGitCheckoutFullSourcePackageUnchanged(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	repo, url, commit := sourcesFromCacheMonorepo(t)
	key := "git:" + commit
	built, stash := filepath.Join(t.TempDir(), "out"), t.TempDir()
	with := map[string]string{"repository": url, "destination": built, "branch": "main", "expected-commit": commit, "max-retries": "0"}
	out, err := sourcesFromCacheRun(t, "git-checkout", t.TempDir(), with, map[string]string{"MELANGE_SOURCE_STASH": stash})
	require.NoError(t, err, out)
	require.NoFileExists(t, filepath.Join(stash, key+".sparse"))

	cmd := exec.CommandContext(t.Context(), "sh", "-c", "git -c tar.umask=022 archive --format=tar --prefix=\"$1\" HEAD | gzip -n", "sh", filepath.Base(repo)+"-"+commit+"/")
	cmd.Dir, cmd.Env = repo, sourcesFromCacheEnv(t.TempDir())
	archive, err := cmd.Output()
	require.NoError(t, err)
	got, err := os.ReadFile(filepath.Join(stash, key+".tar.gz"))
	require.NoError(t, err)
	require.Equal(t, archive, got, "the archive is git archive of HEAD, byte for byte")

	dest := filepath.Join(t.TempDir(), "out")
	with["destination"], with["repository"] = dest, "file://"+filepath.Join(t.TempDir(), "no-such-repository")
	out, err = sourcesFromCacheRun(t, "git-checkout", stash, with, map[string]string{"MELANGE_SOURCE_RESTORE": "1", "MELANGE_SOURCE_STRICT": "1"})
	require.NoError(t, err, out)
	require.Equal(t, sourcesFromCacheGit(t, built, "ls-files", "-s", "-t"), sourcesFromCacheGit(t, dest, "ls-files", "-s", "-t"))
	require.NotContains(t, sourcesFromCacheGit(t, dest, "ls-files", "-t"), "S ")
	require.Equal(t, commit, sourcesFromCacheGit(t, dest, "rev-parse", "HEAD"))
	require.Equal(t, sourcesFromCacheGit(t, built, "describe", "--tags", "--long", "--dirty"), sourcesFromCacheGit(t, dest, "describe", "--tags", "--long", "--dirty"))
	cmd = exec.CommandContext(t.Context(), "git", "config", "--get", "core.sparseCheckout")
	cmd.Dir, cmd.Env = dest, sourcesFromCacheEnv(t.TempDir())
	require.Error(t, cmd.Run(), "a full checkout restores with no sparse configuration")
}

// sourcesFromCacheFailingGit is a PATH whose git fails every command that
// names the given subcommand and, if within is set, an argument ending in
// it, and runs the real git for the rest.
func sourcesFromCacheFailingGit(t *testing.T, subcommand, within string) string {
	t.Helper()
	git, err := exec.LookPath("git")
	require.NoError(t, err)
	dir := t.TempDir()
	script := "#!/bin/sh\nsubcommand='" + subcommand + "' within='" + within + "' git='" + git + "'\n" + `sub= in=
[ -z "$within" ] && in=1
for a in "$@"; do
	[ "$a" = "$subcommand" ] && sub=1
	case "$a" in *"$within") [ -n "$within" ] && in=1 ;; esac
done
[ -n "$sub" ] && [ -n "$in" ] && exit 1
exec "$git" "$@"
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o755))
	return dir + ":" + os.Getenv("PATH")
}

// A checkout whose archive or, for a sparse checkout, whose tree objects
// cannot be written fails the step, leaving nothing of itself in the stash:
// a -source package without its upstream is incomplete source.
func TestGitCheckoutSourceStashFailure(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	_, url, commit := sourcesFromCacheMonorepo(t)
	for _, tt := range []struct {
		name, sparse, fail, wantMsg string
	}{
		{name: "archive", fail: "archive", wantMsg: "archiving the checkout for the -source package failed"},
		{name: "sparse archive", sparse: "a/b", fail: "archive", wantMsg: "archiving the checkout for the -source package failed"},
		{name: "sparse tree objects", sparse: "a/b", fail: "pack-objects", wantMsg: "recording the sparse checkout for the -source package failed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stash := t.TempDir()
			with := map[string]string{
				"repository": url, "destination": filepath.Join(t.TempDir(), "out"), "branch": "main",
				"expected-commit": commit, "max-retries": "0",
			}
			if tt.sparse != "" {
				with["sparse-paths"] = tt.sparse
			}
			out, err := sourcesFromCacheRun(t, "git-checkout", t.TempDir(), with, map[string]string{
				"MELANGE_SOURCE_STASH": stash, "PATH": sourcesFromCacheFailingGit(t, tt.fail, ""),
			})
			require.Error(t, err, out)
			require.Contains(t, out, "FAIL "+tt.wantMsg)
			left, err := filepath.Glob(filepath.Join(stash, "git:"+commit+"*"))
			require.NoError(t, err)
			require.Empty(t, left, "nothing of the checkout is left in the stash")
		})
	}
}

// A submodule whose archive cannot be written fails the step too.
func TestGitCheckoutSourceStashSubmoduleFailure(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	_, sub, _ := sourcesFromCacheMonorepo(t)
	repo := t.TempDir()
	sourcesFromCacheGit(t, repo, "init", "-q", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "top.txt"), []byte("top\n"), 0o644))
	sourcesFromCacheGit(t, repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", sub, "vendor/sub")
	sourcesFromCacheGit(t, repo, "add", "-A")
	sourcesFromCacheGit(t, repo, "commit", "-q", "-m", "with a submodule")
	commit := sourcesFromCacheGit(t, repo, "rev-parse", "HEAD")
	with := map[string]string{
		"repository": "file://" + repo, "destination": filepath.Join(t.TempDir(), "out"), "branch": "main",
		"expected-commit": commit, "max-retries": "0", "recurse-submodules": "true",
	}
	environ := map[string]string{
		"MELANGE_SOURCE_STASH": t.TempDir(),
		"GIT_CONFIG_COUNT":     "2", "GIT_CONFIG_KEY_1": "protocol.file.allow", "GIT_CONFIG_VALUE_1": "always",
	}
	out, err := sourcesFromCacheRun(t, "git-checkout", t.TempDir(), with, environ)
	require.NoError(t, err, out)
	require.FileExists(t, filepath.Join(environ["MELANGE_SOURCE_STASH"], "git:"+commit+".submodules"))

	environ["MELANGE_SOURCE_STASH"], environ["PATH"] = t.TempDir(), sourcesFromCacheFailingGit(t, "archive", "/vendor/sub")
	with["destination"] = filepath.Join(t.TempDir(), "out")
	out, err = sourcesFromCacheRun(t, "git-checkout", t.TempDir(), with, environ)
	require.Error(t, err, out)
	require.Contains(t, out, "FAIL archiving submodule vendor/sub for the -source package failed")
}

// Steps of one build that check out the same commit with different cones,
// or one sparse and one full, are each stashed under a name of their own, and
// a rebuild restores each from its own archive. A step repeating a cone
// reuses the archive an earlier one stashed.
func TestGitCheckoutSourceStashSameCommit(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	repo, url, commit := sourcesFromCacheMonorepo(t)
	gone := "file://" + filepath.Join(t.TempDir(), "no-such-repository")
	steps := []string{"a/b", "", "d", "a/b"}
	run := func(cache, repository, sparse string, environ map[string]string) (string, string) {
		dest := filepath.Join(t.TempDir(), "out")
		w := map[string]string{
			"repository": repository, "destination": dest, "branch": "main",
			"expected-commit": commit, "max-retries": "0",
		}
		if sparse != "" {
			w["sparse-paths"] = sparse
		}
		out, err := sourcesFromCacheRun(t, "git-checkout", cache, w, environ)
		require.NoError(t, err, out)
		return dest, out
	}

	stash := t.TempDir()
	built := make([]string, len(steps))
	for i, sparse := range steps {
		built[i], _ = run(t.TempDir(), url, sparse, map[string]string{"MELANGE_SOURCE_STASH": stash})
	}
	cone := func(dir string) map[string]string {
		return sourcesFromCacheArchive(t, filepath.Join(stash, dir+".tar.gz"))
	}
	require.Equal(t, map[string]string{
		"root.txt": "root\n", "a/x": "x\n", "a/b/y": "y\n", "a/b/y2": "y2\n", "a/b/c/z": "z\n",
	}, cone(sourcesFromCacheSparseKey(commit, "a/b")))
	require.Equal(t, map[string]string{
		"root.txt": "root\n", "d/w": "w\n", "d/w2": "w2\n",
	}, cone(sourcesFromCacheSparseKey(commit, "d")))
	require.Equal(t, map[string]string{
		"root.txt": "root\n", "a/x": "x\n", "a/b/y": "y\n", "a/b/y2": "y2\n", "a/b/c/z": "z\n",
		"d/w": "w\n", "d/w2": "w2\n", "e/v": "v\n",
	}, cone("git:"+commit), "the full checkout is stashed whole, beside the sparse ones")
	require.NoFileExists(t, filepath.Join(stash, "git:"+commit+".sparse"))

	// the rebuild restores every step from the companion, without the
	// repository, and its own companion carries the same files
	restash := t.TempDir()
	strict := map[string]string{"MELANGE_SOURCE_RESTORE": "1", "MELANGE_SOURCE_STRICT": "1", "MELANGE_SOURCE_STASH": restash}
	for i, sparse := range steps {
		dest, out := run(stash, gone, sparse, strict)
		require.Contains(t, out, "restoring instead of cloning", sparse)
		if sparse != "" {
			require.Equal(t, sourcesFromCacheView(t, built[i]), sourcesFromCacheView(t, dest), sparse)
		} else {
			require.Equal(t, sourcesFromCacheGit(t, built[i], "ls-files", "-s", "-t"), sourcesFromCacheGit(t, dest, "ls-files", "-s", "-t"))
			require.Equal(t, sourcesFromCacheGit(t, repo, "rev-parse", "HEAD^{tree}"), sourcesFromCacheGit(t, dest, "write-tree"))
		}
	}
	entries, err := os.ReadDir(stash)
	require.NoError(t, err)
	reentries, err := os.ReadDir(restash)
	require.NoError(t, err)
	require.Len(t, reentries, len(entries))
	for _, e := range entries {
		a, err := os.ReadFile(filepath.Join(stash, e.Name()))
		require.NoError(t, err)
		b, err := os.ReadFile(filepath.Join(restash, e.Name()))
		require.NoError(t, err)
		require.Equal(t, a, b, e.Name())
	}
}

// Two steps of one build that would stash different checkouts under one
// name fail the build: the companion could restore only one of them.
func TestGitCheckoutSourceStashConflict(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	repo, url, commit := sourcesFromCacheMonorepo(t)
	sourcesFromCacheGit(t, repo, "checkout", "-q", "-b", "side")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "a", "b", "fix"), []byte("fix\n"), 0o644))
	sourcesFromCacheGit(t, repo, "add", "-A")
	sourcesFromCacheGit(t, repo, "commit", "-q", "-m", "fix")
	fix := sourcesFromCacheGit(t, repo, "rev-parse", "HEAD")
	sourcesFromCacheGit(t, repo, "checkout", "-q", "main")
	step := func(extra map[string]string) map[string]string {
		w := map[string]string{
			"repository": url, "destination": filepath.Join(t.TempDir(), "out"), "branch": "main",
			"expected-commit": commit, "max-retries": "0",
		}
		maps.Copy(w, extra)
		return w
	}
	for _, tt := range []struct {
		name          string
		first, second map[string]string
		wantMsg       string
	}{{
		name:    "different cherry-picks",
		first:   step(nil),
		second:  step(map[string]string{"cherry-picks": "side/" + fix + ": a fix\n"}),
		wantMsg: "is already stashed from HEAD " + commit + ", not ",
	}, {
		name:    "different cherry-picks, sparse",
		first:   step(map[string]string{"sparse-paths": "a/b"}),
		second:  step(map[string]string{"sparse-paths": "a/b", "cherry-picks": "side/" + fix + ": a fix\n"}),
		wantMsg: "is already stashed from HEAD " + commit + ", not ",
	}, {
		name:    "different recurse-submodules",
		first:   step(map[string]string{"recurse-submodules": "true"}),
		second:  step(nil),
		wantMsg: "is already stashed by a step with recurse-submodules: true, and this one has false",
	}} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			environ := map[string]string{"MELANGE_SOURCE_STASH": t.TempDir()}
			out, err := sourcesFromCacheRun(t, "git-checkout", t.TempDir(), tt.first, environ)
			require.NoError(t, err, out)
			out, err = sourcesFromCacheRun(t, "git-checkout", t.TempDir(), tt.second, environ)
			require.Error(t, err, out)
			require.Contains(t, out, "FAIL ")
			require.Contains(t, out, tt.wantMsg)
		})
	}
}

// `git clone --sparse --recurse-submodules` checks out every submodule,
// inside the cone or not. Both are stashed, and the restore accepts the one
// outside the cone, authenticated against the gitlink the tree pins.
func TestGitCheckoutSparseSourcePackageSubmodules(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	_, sub, _ := sourcesFromCacheMonorepo(t)
	repo := t.TempDir()
	sourcesFromCacheGit(t, repo, "init", "-q", "-b", "main")
	sourcesFromCacheGit(t, repo, "config", "uploadpack.allowFilter", "true")
	for name, body := range map[string]string{"top.txt": "top\n", "a/b/y": "y\n", "d/w": "w\n"} {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(repo, name)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(repo, name), []byte(body), 0o644))
	}
	for _, path := range []string{"a/b/sub", "d/sub"} {
		sourcesFromCacheGit(t, repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", sub, path)
	}
	sourcesFromCacheGit(t, repo, "add", "-A")
	sourcesFromCacheGit(t, repo, "commit", "-q", "-m", "with submodules")
	commit := sourcesFromCacheGit(t, repo, "rev-parse", "HEAD")
	key := sourcesFromCacheSparseKey(commit, "a/b")
	with := map[string]string{
		"repository": "file://" + repo, "destination": filepath.Join(t.TempDir(), "out"), "branch": "main",
		"expected-commit": commit, "max-retries": "0", "recurse-submodules": "true", "sparse-paths": "a/b",
	}
	stash := t.TempDir()
	environ := map[string]string{
		"MELANGE_SOURCE_STASH": stash,
		"GIT_CONFIG_COUNT":     "2", "GIT_CONFIG_KEY_1": "protocol.file.allow", "GIT_CONFIG_VALUE_1": "always",
	}
	out, err := sourcesFromCacheRun(t, "git-checkout", t.TempDir(), with, environ)
	require.NoError(t, err, out)
	built := with["destination"]
	index := sourcesFromCacheGit(t, built, "ls-files", "-s", "-t")
	require.Contains(t, index, "H 160000", "the clone checked out the submodules")
	require.NotContains(t, index, "S 160000", "the clone checked out the submodule outside the cone")
	submodules, err := os.ReadFile(filepath.Join(stash, key+".submodules"))
	require.NoError(t, err)
	require.Contains(t, string(submodules), "d/sub ")
	require.Contains(t, string(submodules), "a/b/sub ")

	// what a build sees, less the submodules' .git, which a clone makes a
	// file and a restore a directory
	view := func(dir string) map[string]string {
		v := map[string]string{
			"rev-parse":       sourcesFromCacheGit(t, dir, "rev-parse", "HEAD"),
			"ls-files -s -t":  sourcesFromCacheGit(t, dir, "ls-files", "-s", "-t"),
			"status":          sourcesFromCacheGit(t, dir, "status", "--porcelain"),
			"write-tree":      sourcesFromCacheGit(t, dir, "write-tree"),
			"a/b/sub HEAD":    sourcesFromCacheGit(t, filepath.Join(dir, "a/b/sub"), "rev-parse", "HEAD"),
			"d/sub HEAD":      sourcesFromCacheGit(t, filepath.Join(dir, "d/sub"), "rev-parse", "HEAD"),
			"d/sub ls-files":  sourcesFromCacheGit(t, filepath.Join(dir, "d/sub"), "ls-files", "-s"),
			"sparse-checkout": sourcesFromCacheGit(t, dir, "sparse-checkout", "list"),
		}
		var files []string
		require.NoError(t, filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			require.NoError(t, err)
			if d.Name() == ".git" {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.IsDir() {
				rel, err := filepath.Rel(dir, path)
				require.NoError(t, err)
				files = append(files, rel)
			}
			return nil
		}))
		slices.Sort(files)
		v["files"] = strings.Join(files, "\n")
		return v
	}

	environ["MELANGE_SOURCE_STASH"], environ["MELANGE_SOURCE_RESTORE"], environ["MELANGE_SOURCE_STRICT"] = t.TempDir(), "1", "1"
	with["destination"], with["repository"] = filepath.Join(t.TempDir(), "out"), "file://"+filepath.Join(t.TempDir(), "no-such-repository")
	out, err = sourcesFromCacheRun(t, "git-checkout", stash, with, environ)
	require.NoError(t, err, out)
	require.Equal(t, view(built), view(with["destination"]))
}
