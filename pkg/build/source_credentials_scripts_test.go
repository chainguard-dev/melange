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
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests run the real fetch and git-checkout scripts, as
// sources_from_cache_scripts_test.go does, and check the <key>.credentials
// record each leaves in the stash when what it stashed was obtained with
// credentials.

const credentialsTestSecret = "s3cret-pw-do-not-leak"

// credentialsGitServer serves a bare copy of repo over smart http through
// git http-backend. With auth set, every request must carry the test's basic
// credentials.
func credentialsGitServer(t *testing.T, repo string, auth bool) *url.URL {
	t.Helper()
	backend := filepath.Join(sourcesFromCacheGit(t, repo, "--exec-path"), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skipf("git-http-backend not available: %v", err)
	}
	root := t.TempDir()
	sourcesFromCacheGit(t, root, "clone", "-q", "--bare", repo, filepath.Join(root, "r.git"))
	h := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth {
			if u, p, ok := r.BasicAuth(); !ok || u != "u" || p != credentialsTestSecret {
				w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL + "/r.git")
	require.NoError(t, err)
	return u
}

// credentialsHome is a HOME, and a global git configuration in it, for the
// script: the configuration is the given lines plus what the scripts expect.
func credentialsHome(t *testing.T, gitconfig string) map[string]string {
	t.Helper()
	home := t.TempDir()
	cfg := filepath.Join(home, "gitconfig")
	require.NoError(t, os.WriteFile(cfg, []byte("[commit]\n\tgpgsign = false\n"+gitconfig), 0o644))
	return map[string]string{"HOME": home, "GIT_CONFIG_GLOBAL": cfg}
}

// requireNoSecret fails if any file under dir, or the record's warning in
// out, holds the secret. (git-checkout's log already echoes a repository URL
// as given, userinfo and all; that is not the record's to fix.)
func requireNoSecret(t *testing.T, dir, out string) {
	t.Helper()
	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, "obtained with credentials") {
			require.NotContains(t, line, credentialsTestSecret)
		}
	}
	require.NoError(t, filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		require.NotContains(t, string(b), credentialsTestSecret, p)
		return nil
	}))
}

func TestGitCheckoutRecordsCredentials(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	repo := t.TempDir()
	sourcesFromCacheGit(t, repo, "init", "-q", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644))
	sourcesFromCacheGit(t, repo, "add", "-A")
	sourcesFromCacheGit(t, repo, "commit", "-q", "-m", "one")
	commit := sourcesFromCacheGit(t, repo, "rev-parse", "HEAD")

	private := credentialsGitServer(t, repo, true)
	public := credentialsGitServer(t, repo, false)
	host := private.Hostname()
	withUser := *private
	withUser.User = url.UserPassword("u", credentialsTestSecret)
	helper := "[credential]\n\thelper = \"!f() { test \\\"$1\\\" = get && echo username=u && echo password=" + credentialsTestSecret + "; }; f\"\n"

	tests := []struct {
		name      string
		repo      string
		gitconfig string
		want      []string // the record's lines; none means no record
	}{
		{name: "a local path", repo: repo},
		{name: "public over http", repo: public.String()},
		{
			name: "a helper the public clone never needed", repo: public.String(), gitconfig: helper,
		},
		{
			name: "a credential helper", repo: private.String(), gitconfig: helper,
			want: []string{"authorization " + host},
		},
		{
			name: "userinfo in the URL", repo: withUser.String(),
			want: []string{"authorization " + host, "userinfo " + host},
		},
		{
			name: "userinfo through insteadOf", repo: "https://example.invalid/r.git",
			gitconfig: fmt.Sprintf("[url %q]\n\tinsteadOf = https://example.invalid/\n", strings.TrimSuffix(withUser.String(), "r.git")),
			want:      []string{"authorization " + host, "userinfo " + host},
		},
		{
			name: "an extra header", repo: public.String(),
			gitconfig: "[http]\n\textraHeader = \"Authorization: Bearer " + credentialsTestSecret + "\"\n",
			want:      []string{"authorization " + host, "extraheader " + host},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stash := t.TempDir()
			environ := credentialsHome(t, tt.gitconfig)
			environ["MELANGE_SOURCE_STASH"] = stash
			out, err := sourcesFromCacheRun(t, "git-checkout", t.TempDir(), map[string]string{
				"repository": tt.repo, "destination": filepath.Join(t.TempDir(), "out"), "branch": "main",
				"expected-commit": commit, "max-retries": "0",
			}, environ)
			require.NoError(t, err, out)
			require.FileExists(t, filepath.Join(stash, "git:"+commit+".tar.gz"), out)
			requireRecord(t, filepath.Join(stash, "git:"+commit+sourceCredentialsSuffix), tt.want, out)
			requireNoSecret(t, stash, out)
		})
	}
}

// A checkout restored from a companion sends no request; its record comes
// with the archive and is kept, and the URL is still checked.
func TestGitCheckoutRestoreKeepsTheRecord(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	_, commit, cache := sourcesFromCacheUpstream(t)
	record := filepath.Join(cache, "git:"+commit+sourceCredentialsSuffix)

	for _, tt := range []struct {
		name, repo, prior string
		want              []string
	}{
		{name: "nothing to record", repo: "https://example.invalid/r.git"},
		{
			name: "the restored record", repo: "https://example.invalid/r.git", prior: "authorization example.invalid\n",
			want: []string{"authorization example.invalid"},
		},
		{name: "an ssh URL", repo: "git@example.invalid:o/r.git", want: []string{"ssh example.invalid"}},
		{name: "an ssh:// URL", repo: "ssh://git@example.invalid/o/r.git", want: []string{"ssh example.invalid", "userinfo example.invalid"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := t.TempDir()
			for _, f := range mustGlob(t, filepath.Join(cache, "git:"+commit+".*")) {
				if f == record {
					continue
				}
				b, err := os.ReadFile(f)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(c, filepath.Base(f)), b, 0o644))
			}
			if tt.prior != "" {
				require.NoError(t, os.WriteFile(filepath.Join(c, filepath.Base(record)), []byte(tt.prior), 0o644))
			}
			stash := t.TempDir()
			environ := credentialsHome(t, "")
			environ["MELANGE_SOURCE_STASH"], environ["MELANGE_SOURCE_RESTORE"], environ["MELANGE_SOURCE_STRICT"] = stash, "1", "1"
			out, err := sourcesFromCacheRun(t, "git-checkout", c, map[string]string{
				"repository": tt.repo, "destination": filepath.Join(t.TempDir(), "out"),
				"expected-commit": commit, "max-retries": "0",
			}, environ)
			require.NoError(t, err, out)
			require.NotContains(t, out, sourcesFromCacheCloneAttempt)
			requireRecord(t, filepath.Join(stash, filepath.Base(record)), tt.want, out)
		})
	}
}

func TestFetchRecordsCredentials(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"busybox", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	body := []byte("tarball bytes\n")
	sum := fmt.Sprintf("%x", sha256.Sum256(body))
	key := "sha256:" + sum

	for _, tt := range []struct {
		name, uri, netrc, wgetrc, prior string
		want                            []string
	}{
		{name: "a public URL", uri: "https://example.com/foo-1.tar.gz"},
		{name: "a netrc for another host", uri: "https://example.com/foo-1.tar.gz", netrc: "machine other.example login u password " + credentialsTestSecret + "\n"},
		{name: "a commented wgetrc", uri: "https://example.com/foo-1.tar.gz", wgetrc: "#header = Authorization: x\n"},
		{name: "a query that is no credential", uri: "https://example.com/foo-1.tar.gz?viasf=1"},
		{name: "userinfo", uri: "https://u:" + credentialsTestSecret + "@example.com/foo-1.tar.gz", want: []string{"userinfo example.com"}},
		{name: "a token in the query", uri: "https://example.com/foo-1.tar.gz?private_token=" + credentialsTestSecret, want: []string{"query example.com"}},
		{name: "a netrc for the host", uri: "https://example.com/foo-1.tar.gz", netrc: "machine example.com\n  login u\n  password " + credentialsTestSecret + "\n", want: []string{"netrc example.com"}},
		{name: "a netrc default", uri: "https://example.com/foo-1.tar.gz", netrc: "default login u password " + credentialsTestSecret + "\n", want: []string{"netrc example.com"}},
		{name: "a header in a wgetrc", uri: "https://example.com/foo-1.tar.gz", wgetrc: "header = PRIVATE-TOKEN: " + credentialsTestSecret + "\n", want: []string{"wgetrc example.com"}},
		{name: "a record from the cache", uri: "https://example.com/foo-1.tar.gz", prior: "netrc example.com\n", want: []string{"netrc example.com"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cache, home, stash := t.TempDir(), t.TempDir(), t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(cache, key), body, 0o644))
			if tt.prior != "" {
				require.NoError(t, os.WriteFile(filepath.Join(cache, key+sourceCredentialsSuffix), []byte(tt.prior), 0o644))
			}
			if tt.netrc != "" {
				require.NoError(t, os.WriteFile(filepath.Join(home, ".netrc"), []byte(tt.netrc), 0o600))
			}
			wgetrc := filepath.Join(home, "wgetrc")
			if tt.wgetrc != "" {
				require.NoError(t, os.WriteFile(wgetrc, []byte(tt.wgetrc), 0o600))
			}
			out, err := sourcesFromCacheRun(t, "fetch", cache, map[string]string{
				"uri": tt.uri, "expected-sha256": sum, "extract": "false",
			}, map[string]string{
				"HOME": home, "MELANGE_SOURCE_STASH": stash,
				"SYSTEM_WGETRC": filepath.Join(home, "no-system-wgetrc"), "WGETRC": wgetrc,
			})
			require.NoError(t, err, out)
			require.Contains(t, out, "found "+filepath.Join(cache, key)+" in cache", "the test must not reach the network")
			require.FileExists(t, filepath.Join(stash, key))
			requireRecord(t, filepath.Join(stash, key+sourceCredentialsSuffix), tt.want, out)
			requireNoSecret(t, stash, out)
		})
	}
}

// requireRecord checks the record at path holds exactly want, one per line,
// or is absent when want is empty.
func requireRecord(t *testing.T, path string, want []string, out string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if len(want) == 0 {
		require.ErrorIs(t, err, os.ErrNotExist, "no record expected, found %q\n%s", b, out)
		return
	}
	require.NoError(t, err, out)
	require.Equal(t, strings.Join(want, "\n")+"\n", string(b), out)
	require.Contains(t, out, "obtained with credentials")
}

func mustGlob(t *testing.T, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(pattern)
	require.NoError(t, err)
	require.NotEmpty(t, m, pattern)
	return m
}

// A submodule cloned with credentials marks the superproject's record: the
// submodule's tree ships in the same companion. Its URL is checked as well as
// its requests: userinfo a public server never challenged sends nothing.
func TestGitCheckoutRecordsSubmoduleCredentials(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	sub := t.TempDir()
	sourcesFromCacheGit(t, sub, "init", "-q", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(sub, "s.txt"), []byte("s\n"), 0o644))
	sourcesFromCacheGit(t, sub, "add", "-A")
	sourcesFromCacheGit(t, sub, "commit", "-q", "-m", "sub")
	private := credentialsGitServer(t, sub, true)
	public := credentialsGitServer(t, sub, false)
	publicUser := *public
	publicUser.User = url.UserPassword("u", "not-a-secret")
	host := private.Hostname()

	for _, tt := range []struct {
		name, url string
		want      []string
	}{
		{name: "a credential helper", url: private.String(), want: []string{"authorization " + host}},
		{name: "userinfo never sent", url: publicUser.String(), want: []string{"userinfo " + host}},
		{name: "public", url: public.String()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			super := t.TempDir()
			sourcesFromCacheGit(t, super, "init", "-q", "-b", "main")
			require.NoError(t, os.WriteFile(filepath.Join(super, "a.txt"), []byte("a\n"), 0o644))
			sourcesFromCacheGit(t, super, "-c", "protocol.file.allow=always", "submodule", "add", "-q", sub, "vendor/s")
			require.NoError(t, os.WriteFile(filepath.Join(super, ".gitmodules"),
				[]byte("[submodule \"vendor/s\"]\n\tpath = vendor/s\n\turl = "+tt.url+"\n"), 0o644))
			sourcesFromCacheGit(t, super, "add", "-A")
			sourcesFromCacheGit(t, super, "commit", "-q", "-m", "super")
			commit := sourcesFromCacheGit(t, super, "rev-parse", "HEAD")

			stash := t.TempDir()
			environ := credentialsHome(t, "[credential]\n\thelper = \"!f() { test \\\"$1\\\" = get && echo username=u && echo password="+credentialsTestSecret+"; }; f\"\n")
			environ["MELANGE_SOURCE_STASH"] = stash
			out, err := sourcesFromCacheRun(t, "git-checkout", t.TempDir(), map[string]string{
				"repository": super, "destination": filepath.Join(t.TempDir(), "out"), "branch": "main",
				"expected-commit": commit, "max-retries": "0", "recurse-submodules": "true",
			}, environ)
			require.NoError(t, err, out)
			require.FileExists(t, filepath.Join(stash, "git:"+commit+".tar.gz"), out)
			require.FileExists(t, filepath.Join(stash, "git:"+commit+".submodules"), out)
			requireRecord(t, filepath.Join(stash, "git:"+commit+sourceCredentialsSuffix), tt.want, out)
			requireNoSecret(t, stash, out)
		})
	}
}

// The trace is redacted and removed, so a checkout that fails after sending
// credentials leaves no secret behind in the temporary directory either.
func TestGitCheckoutTraceLeavesNoSecret(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	repo := t.TempDir()
	sourcesFromCacheGit(t, repo, "init", "-q", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644))
	sourcesFromCacheGit(t, repo, "add", "-A")
	sourcesFromCacheGit(t, repo, "commit", "-q", "-m", "one")
	private := credentialsGitServer(t, repo, true)

	tmp := t.TempDir()
	header := base64.StdEncoding.EncodeToString([]byte("u:" + credentialsTestSecret))
	environ := credentialsHome(t, "[http]\n\textraHeader = \"Authorization: Basic "+header+"\"\n")
	environ["MELANGE_SOURCE_STASH"], environ["TMPDIR"] = t.TempDir(), tmp
	out, err := sourcesFromCacheRun(t, "git-checkout", t.TempDir(), map[string]string{
		"repository": private.String(), "destination": filepath.Join(t.TempDir(), "out"), "branch": "main",
		"expected-commit": strings.Repeat("0", 40), "max-retries": "0",
	}, environ)
	require.Error(t, err, out)
	require.Contains(t, out, "cloned from", "the clone must have succeeded, with the header")
	traces := 0
	require.NoError(t, filepath.WalkDir(tmp, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			b, rerr := os.ReadFile(p)
			require.NoError(t, rerr)
			require.NotContains(t, string(b), header, p)
			if strings.Contains(string(b), "Send header") {
				traces++
			}
		}
		return err
	}))
	require.Zero(t, traces, "the curl trace must be removed")
}
