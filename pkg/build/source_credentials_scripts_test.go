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
	"cmp"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"chainguard.dev/melange/pkg/config"
)

// These tests run the real fetch and git-checkout scripts, as
// sources_from_cache_scripts_test.go does, and check the <key>.credentials
// record each leaves in the stash when what it stashed was obtained with
// credentials.

const credentialsTestSecret = "s3cret-pw-do-not-leak"

// credentialsRequire skips the test when a tool it needs is missing, or fails
// it under MELANGE_REQUIRE_SCRIPT_TOOLS, as sourcesFromCacheRequireTools does,
// so CI cannot pass by skipping.
func credentialsRequire(t *testing.T, err error, tool string) {
	t.Helper()
	if err == nil {
		return
	}
	if os.Getenv("MELANGE_REQUIRE_SCRIPT_TOOLS") != "" {
		t.Fatalf("%s is required by MELANGE_REQUIRE_SCRIPT_TOOLS: %v", tool, err)
	}
	t.Skipf("%s not available: %v", tool, err)
}

// credentialsRun compiles the pipeline named by uses with the given inputs
// and runs its script, as sourcesFromCacheRun does for git-checkout. It is
// separate so these tests do not depend on that helper's signature.
func credentialsRun(t *testing.T, uses, cache string, with, environ map[string]string) (string, error) {
	t.Helper()
	out, err := credentialsCommand(t, uses, cache, with, environ).CombinedOutput()
	return string(out), err
}

// credentialsCommand is the command credentialsRun runs, not yet started.
func credentialsCommand(t *testing.T, uses, cache string, with, environ map[string]string) *exec.Cmd {
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
	return cmd
}

// credentialsGitServer serves a bare copy of repo over smart http through
// git http-backend. With auth set, every request must carry the test's basic
// credentials.
func credentialsGitServer(t *testing.T, repo string, auth bool) *url.URL {
	t.Helper()
	srv := httptest.NewServer(credentialsGitHandler(t, repo, auth))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL + "/r.git")
	require.NoError(t, err)
	return u
}

// credentialsGitHandler serves a bare copy of repo, as r.git, through git
// http-backend.
func credentialsGitHandler(t *testing.T, repo string, auth bool) http.Handler {
	t.Helper()
	backend := filepath.Join(sourcesFromCacheGit(t, repo, "--exec-path"), "git-http-backend")
	_, err := os.Stat(backend)
	credentialsRequire(t, err, "git-http-backend (Wolfi's git-daemon)")
	root := t.TempDir()
	sourcesFromCacheGit(t, root, "clone", "-q", "--bare", repo, filepath.Join(root, "r.git"))
	h := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth {
			if u, p, ok := r.BasicAuth(); !ok || u != "u" || p != credentialsTestSecret {
				w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
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
	cookies := filepath.Join(t.TempDir(), "cookies.txt")
	require.NoError(t, os.WriteFile(cookies, []byte(host+"\tFALSE\t/\tFALSE\t0\tsession\t"+credentialsTestSecret+"\n"), 0o600))

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
			name: "a cookie file", repo: public.String(),
			gitconfig: fmt.Sprintf("[http]\n\tcookieFile = %s\n", cookies),
			want:      []string{"cookie " + host},
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
			out, err := credentialsRun(t, "git-checkout", t.TempDir(), map[string]string{
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
			out, err := credentialsRun(t, "git-checkout", c, map[string]string{
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
		_, err := exec.LookPath(tool)
		credentialsRequire(t, err, tool)
	}
	body := []byte("tarball bytes\n")
	sum := fmt.Sprintf("%x", sha256.Sum256(body))
	key := "sha256:" + sum

	for _, tt := range []struct {
		name, uri, netrc, netrcEnv, wgetrc, prior string
		environ                                   map[string]string
		want                                      []string
	}{
		{name: "a public URL", uri: "https://example.com/foo-1.tar.gz"},
		{name: "an empty netrc", uri: "https://example.com/foo-1.tar.gz", netrc: "# nothing\n"},
		{name: "a commented wgetrc command", uri: "https://example.com/foo-1.tar.gz", wgetrc: "  # http-user = u\ntimeout = 5\n"},
		{name: "a NETRC file, checked to fail closed", uri: "https://example.com/foo-1.tar.gz", netrcEnv: "default login u password " + credentialsTestSecret + "\n", want: []string{"netrc example.com"}},
		// wget follows redirects to hosts the URL does not name
		{name: "a netrc for another host", uri: "https://example.com/foo-1.tar.gz", netrc: "machine other.example login u password " + credentialsTestSecret + "\n", want: []string{"netrc -"}},
		{name: "a netrc for the host in another case", uri: "https://EXAMPLE.com/foo-1.tar.gz", netrc: "machine example.COM login u password " + credentialsTestSecret + "\n", want: []string{"netrc example.com"}},
		{name: "a commented wgetrc", uri: "https://example.com/foo-1.tar.gz", wgetrc: "#header = Authorization: x\n"},
		{name: "an empty query", uri: "https://example.com/foo-1.tar.gz?#frag"},
		// any query is recorded: signed URLs and tokens use too many names
		{name: "a query with no credential-like name", uri: "https://example.com/foo-1.tar.gz?viasf=1", want: []string{"query example.com"}},
		{name: "a pwd in the query", uri: "https://example.com/foo-1.tar.gz?pwd=" + credentialsTestSecret, want: []string{"query example.com"}},
		{name: "an hmac in the query", uri: "https://example.com/foo-1.tar.gz?hmac=" + credentialsTestSecret, want: []string{"query example.com"}},
		{name: "a session in the query", uri: "https://example.com/foo-1.tar.gz?session=" + credentialsTestSecret, want: []string{"query example.com"}},
		{name: "a ticket in the query", uri: "https://example.com/foo-1.tar.gz?ticket=" + credentialsTestSecret, want: []string{"query example.com"}},
		{name: "a bare value as the query", uri: "https://example.com/foo-1.tar.gz?deadbeef" + credentialsTestSecret, want: []string{"query example.com"}},
		{name: "userinfo", uri: "https://u:" + credentialsTestSecret + "@example.com/foo-1.tar.gz", want: []string{"userinfo example.com"}},
		{name: "a token in the query", uri: "https://example.com/foo-1.tar.gz?private_token=" + credentialsTestSecret, want: []string{"query example.com"}},
		{name: "an auth_token in the query", uri: "https://example.com/foo-1.tar.gz?v=1&auth_token=" + credentialsTestSecret, want: []string{"query example.com"}},
		{name: "a jwt in the query", uri: "https://example.com/foo-1.tar.gz?jwt=" + credentialsTestSecret + "#frag", want: []string{"query example.com"}},
		{name: "an oauth_token in the query", uri: "https://example.com/foo-1.tar.gz?OAuth_Token=" + credentialsTestSecret, want: []string{"query example.com"}},
		{name: "a netrc for the host", uri: "https://example.com/foo-1.tar.gz", netrc: "machine example.com\n  login u\n  password " + credentialsTestSecret + "\n", want: []string{"netrc example.com"}},
		{name: "a netrc default", uri: "https://example.com/foo-1.tar.gz", netrc: "default login u password " + credentialsTestSecret + "\n", want: []string{"netrc example.com"}},
		{name: "a header in a wgetrc", uri: "https://example.com/foo-1.tar.gz", wgetrc: "header = PRIVATE-TOKEN: " + credentialsTestSecret + "\n", want: []string{"wgetrc example.com"}},
		{name: "http-user in a wgetrc", uri: "https://example.com/foo-1.tar.gz", wgetrc: "http-user = u\nhttp-password = " + credentialsTestSecret + "\n", want: []string{"wgetrc example.com"}},
		{name: "httppassword in a wgetrc", uri: "https://example.com/foo-1.tar.gz", wgetrc: "HttpPassword=" + credentialsTestSecret + "\n", want: []string{"wgetrc example.com"}},
		{name: "load_cookies in a wgetrc", uri: "https://example.com/foo-1.tar.gz", wgetrc: "load_cookies = /tmp/cookies.txt\n", want: []string{"wgetrc example.com"}},
		{name: "a client certificate in a wgetrc", uri: "https://example.com/foo-1.tar.gz", wgetrc: "certificate = /c.pem\nprivate-key = /k.pem\n", want: []string{"wgetrc example.com"}},
		{name: "ftp_user in a wgetrc", uri: "https://example.com/foo-1.tar.gz", wgetrc: "ftp_user = u\n", want: []string{"wgetrc example.com"}},
		{name: "a record from the cache", uri: "https://example.com/foo-1.tar.gz", prior: "netrc example.com\n", want: []string{"netrc example.com"}},
		{name: "https_proxy with userinfo", uri: "https://example.com/foo-1.tar.gz", environ: map[string]string{"https_proxy": "http://u:" + credentialsTestSecret + "@proxy.example:3128/"}, want: []string{"proxy proxy.example"}},
		{name: "HTTP_PROXY with userinfo and no scheme", uri: "https://example.com/foo-1.tar.gz", environ: map[string]string{"HTTP_PROXY": "u:" + credentialsTestSecret + "@proxy.example:3128"}, want: []string{"proxy proxy.example"}},
		{name: "ftp_proxy with userinfo", uri: "https://example.com/foo-1.tar.gz", environ: map[string]string{"ftp_proxy": "http://u:" + credentialsTestSecret + "@proxy.example"}, want: []string{"proxy proxy.example"}},
		{name: "a proxy without credentials", uri: "https://example.com/foo-1.tar.gz", environ: map[string]string{"https_proxy": "http://proxy.example:3128", "no_proxy": "example.com"}},
		{name: "proxy_user in a wgetrc", uri: "https://example.com/foo-1.tar.gz", wgetrc: "use_proxy = on\nhttps_proxy = http://proxy.example:3128/\nproxy_user = u\nproxy_password = " + credentialsTestSecret + "\n", want: []string{"proxy -"}},
		{name: "a proxy URL with userinfo in a wgetrc", uri: "https://example.com/foo-1.tar.gz", wgetrc: "https-proxy = http://u:" + credentialsTestSecret + "@proxy.example:3128/\n", want: []string{"proxy proxy.example"}},
		{name: "a proxy without credentials in a wgetrc", uri: "https://example.com/foo-1.tar.gz", wgetrc: "use_proxy = on\nhttps_proxy = http://proxy.example:3128/\n"},
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
			environ := maps.Clone(tt.environ)
			if environ == nil {
				environ = map[string]string{}
			}
			if tt.netrcEnv != "" {
				environ["NETRC"] = filepath.Join(home, "netrc-env")
				require.NoError(t, os.WriteFile(environ["NETRC"], []byte(tt.netrcEnv), 0o600))
			}
			wgetrc := filepath.Join(home, "wgetrc")
			if tt.wgetrc != "" {
				require.NoError(t, os.WriteFile(wgetrc, []byte(tt.wgetrc), 0o600))
			}
			environ["HOME"], environ["MELANGE_SOURCE_STASH"] = home, stash
			environ["SYSTEM_WGETRC"], environ["WGETRC"] = filepath.Join(home, "no-system-wgetrc"), wgetrc
			out, err := credentialsRun(t, "fetch", cache, map[string]string{
				"uri": tt.uri, "expected-sha256": sum, "extract": "false",
			}, environ)
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
		name, url, jobs string
		want            []string
	}{
		{name: "a credential helper", url: private.String(), want: []string{"authorization " + host}},
		// parallel submodule clones interleave their trace lines, so the
		// host is not known, and no exemption matches "-"
		{name: "a credential helper, in parallel", url: private.String(), jobs: "4", want: []string{"authorization -"}},
		{name: "userinfo never sent", url: publicUser.String(), want: []string{"userinfo " + host}},
		{name: "public", url: public.String()},
		{name: "public, in parallel", url: public.String(), jobs: "4"},
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
			out, err := credentialsRun(t, "git-checkout", t.TempDir(), map[string]string{
				"repository": super, "destination": filepath.Join(t.TempDir(), "out"), "branch": "main",
				"expected-commit": commit, "max-retries": "0", "recurse-submodules": "true",
				"submodule-jobs": cmp.Or(tt.jobs, "1"),
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
	out, err := credentialsRun(t, "git-checkout", t.TempDir(), map[string]string{
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

// A checkout authenticated by a TLS client certificate sends no header, so the
// trace shows nothing: the certificate configured for the URL is the signal,
// through git's configuration or its environment.
func TestGitCheckoutRecordsClientCertificate(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	repo := t.TempDir()
	sourcesFromCacheGit(t, repo, "init", "-q", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644))
	sourcesFromCacheGit(t, repo, "add", "-A")
	sourcesFromCacheGit(t, repo, "commit", "-q", "-m", "one")
	commit := sourcesFromCacheGit(t, repo, "rev-parse", "HEAD")

	certs := t.TempDir()
	clientCert, clientKey, pool := credentialsClientCertificate(t, certs)
	// serve starts a TLS server, requiring a client certificate when
	// needCert is set, and returns its URL and a CA file that trusts it.
	serve := func(needCert bool) (string, string) {
		srv := httptest.NewUnstartedServer(credentialsGitHandler(t, repo, false))
		if needCert {
			srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
		}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		ca := filepath.Join(certs, strings.TrimPrefix(srv.URL, "https://127.0.0.1:")+".pem")
		require.NoError(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644))
		return srv.URL + "/r.git", ca
	}
	private, privateCA := serve(true)
	public, publicCA := serve(false)
	host := "127.0.0.1"
	// A PEM holding both the certificate and its key, so GIT_SSL_CERT can be
	// set on its own: curl reads the key from the certificate file.
	combined := filepath.Join(certs, "client-combined.pem")
	certPEM, err := os.ReadFile(clientCert)
	require.NoError(t, err)
	keyPEM, err := os.ReadFile(clientKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(combined, append(certPEM, keyPEM...), 0o600))

	for _, tt := range []struct {
		name, repo, ca                            string
		config, configCertOnly, environ, certOnly bool
		want                                      []string
	}{
		{name: "no client certificate", repo: public, ca: publicCA},
		{name: "http.sslCert and http.sslKey", repo: private, ca: privateCA, config: true, want: []string{"sslcert " + host}},
		{name: "GIT_SSL_CERT and GIT_SSL_KEY", repo: private, ca: privateCA, environ: true, want: []string{"sslcert " + host}},
		{name: "GIT_SSL_CERT alone", repo: private, ca: privateCA, certOnly: true, want: []string{"sslcert " + host}},
		{name: "http.sslCert alone", repo: private, ca: privateCA, configCertOnly: true, want: []string{"sslcert " + host}},
		// The documented fail-closed exception: a configured certificate is
		// recorded even when the server never requests one.
		{name: "a certificate a public server never requests", repo: public, ca: publicCA, config: true, want: []string{"sslcert " + host}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gitconfig := fmt.Sprintf("[http]\n\tsslCAInfo = %s\n", tt.ca)
			if tt.config {
				gitconfig += fmt.Sprintf("[http %q]\n\tsslCert = %s\n\tsslKey = %s\n", tt.repo, clientCert, clientKey)
			}
			if tt.configCertOnly {
				gitconfig += fmt.Sprintf("[http %q]\n\tsslCert = %s\n", tt.repo, combined)
			}
			stash := t.TempDir()
			environ := credentialsHome(t, gitconfig)
			environ["MELANGE_SOURCE_STASH"] = stash
			if tt.environ {
				environ["GIT_SSL_CERT"], environ["GIT_SSL_KEY"] = clientCert, clientKey
			}
			if tt.certOnly {
				environ["GIT_SSL_CERT"] = combined
			}
			out, err := credentialsRun(t, "git-checkout", t.TempDir(), map[string]string{
				"repository": tt.repo, "destination": filepath.Join(t.TempDir(), "out"), "branch": "main",
				"expected-commit": commit, "max-retries": "0",
			}, environ)
			require.NoError(t, err, out)
			require.FileExists(t, filepath.Join(stash, "git:"+commit+".tar.gz"), out)
			requireRecord(t, filepath.Join(stash, "git:"+commit+sourceCredentialsSuffix), tt.want, out)
		})
	}
}

// Production remotes (github.com, the GitLab mirror) speak HTTP/2 with git's
// curl, and curl traces an h2 request through a different path than an
// HTTP/1.1 one. The authorization match must hold there too, or a private
// clone over h2 would ship with no record.
func TestGitCheckoutRecordsCredentialsOverHTTP2(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	repo := t.TempDir()
	sourcesFromCacheGit(t, repo, "init", "-q", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644))
	sourcesFromCacheGit(t, repo, "add", "-A")
	sourcesFromCacheGit(t, repo, "commit", "-q", "-m", "one")
	commit := sourcesFromCacheGit(t, repo, "rev-parse", "HEAD")

	certs := t.TempDir()
	// serve starts an HTTP/2 TLS server and returns its URL, a CA file that
	// trusts it, and whether any request it served used HTTP/2.
	serve := func(auth bool) (string, string, *atomic.Bool) {
		var h2 atomic.Bool
		inner := credentialsGitHandler(t, repo, auth)
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor == 2 {
				h2.Store(true)
			}
			inner.ServeHTTP(w, r)
		}))
		srv.EnableHTTP2 = true
		srv.StartTLS()
		t.Cleanup(srv.Close)
		ca := filepath.Join(certs, strings.TrimPrefix(srv.URL, "https://127.0.0.1:")+".pem")
		require.NoError(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644))
		return srv.URL + "/r.git", ca, &h2
	}
	private, privateCA, privateH2 := serve(true)
	public, publicCA, publicH2 := serve(false)
	helper := "[credential]\n\thelper = \"!f() { test \\\"$1\\\" = get && echo username=u && echo password=" + credentialsTestSecret + "; }; f\"\n"

	for _, tt := range []struct {
		name, repo, ca, gitconfig string
		h2                        *atomic.Bool
		want                      []string
	}{
		{name: "public over h2", repo: public, ca: publicCA, h2: publicH2},
		{name: "a credential helper over h2", repo: private, ca: privateCA, gitconfig: helper, h2: privateH2, want: []string{"authorization 127.0.0.1"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stash := t.TempDir()
			environ := credentialsHome(t, fmt.Sprintf("[http]\n\tsslCAInfo = %s\n", tt.ca)+tt.gitconfig)
			environ["MELANGE_SOURCE_STASH"] = stash
			out, err := credentialsRun(t, "git-checkout", t.TempDir(), map[string]string{
				"repository": tt.repo, "destination": filepath.Join(t.TempDir(), "out"), "branch": "main",
				"expected-commit": commit, "max-retries": "0",
			}, environ)
			require.NoError(t, err, out)
			require.True(t, tt.h2.Load(), "the clone did not use HTTP/2; this test would prove nothing")
			requireRecord(t, filepath.Join(stash, "git:"+commit+sourceCredentialsSuffix), tt.want, out)
			requireNoSecret(t, stash, out)
		})
	}
}

// credentialsClientCertificate writes a self-signed client certificate and
// its key under dir, and returns their paths and a pool that trusts it.
func credentialsClientCertificate(t *testing.T, dir string) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "melange-test-client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certPath, keyPath := filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600))
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return certPath, keyPath, pool
}

// EBS supplies its GitLab mirror's deploy token through a GIT_CONFIG_GLOBAL
// holding url.*.insteadOf rewrites of public upstreams to the mirror, with no
// userinfo, and credential.helper=store --file=<a .git-credentials>. The record
// must then be exactly "authorization <mirror host>", which
// --source-credential-exempt-host drops, leaving no record in the companion.
func TestGitCheckoutMirrorCredentialIsExempt(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	repo := t.TempDir()
	sourcesFromCacheGit(t, repo, "init", "-q", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644))
	sourcesFromCacheGit(t, repo, "add", "-A")
	sourcesFromCacheGit(t, repo, "commit", "-q", "-m", "one")
	commit := sourcesFromCacheGit(t, repo, "rev-parse", "HEAD")

	mirror := credentialsGitServer(t, repo, true)
	mirrorDir := t.TempDir()
	store := filepath.Join(mirrorDir, ".git-credentials")
	withUser := url.URL{Scheme: mirror.Scheme, Host: mirror.Host, User: url.UserPassword("u", credentialsTestSecret)}
	require.NoError(t, os.WriteFile(store, []byte(withUser.String()+"\n"), 0o600))
	gitconfig := fmt.Sprintf("[credential]\n\thelper = store --file=%s\n\n[url %q]\n\tinsteadOf = https://github.com/example/\n",
		store, strings.TrimSuffix(mirror.String(), "r.git"))

	stash := t.TempDir()
	environ := credentialsHome(t, gitconfig)
	environ["MELANGE_SOURCE_STASH"] = stash
	out, err := credentialsRun(t, "git-checkout", t.TempDir(), map[string]string{
		"repository": "https://github.com/example/r.git", "destination": filepath.Join(t.TempDir(), "out"), "branch": "main",
		"expected-commit": commit, "max-retries": "0",
	}, environ)
	require.NoError(t, err, out)
	record := filepath.Join(stash, "git:"+commit+sourceCredentialsSuffix)
	requireRecord(t, record, []string{"authorization " + mirror.Hostname()}, out)
	requireNoSecret(t, stash, out)

	data, err := os.ReadFile(record)
	require.NoError(t, err)
	require.Empty(t, (&Build{SourceCredentialExemptHosts: []string{mirror.Hostname()}}).withoutExemptCredentials(data))
	require.Equal(t, string(data), string((&Build{SourceCredentialExemptHosts: []string{"other.example"}}).withoutExemptCredentials(data)))
}

// A second step that checks out a commit an earlier step of the same build
// already stashed under the same name still records its own credentials:
// stash_credentials runs before stash_source returns for an archive that is
// already there, so the companion is not left with an unmarked checkout.
func TestGitCheckoutSecondStepKeepsTheRecord(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	repo := t.TempDir()
	sourcesFromCacheGit(t, repo, "init", "-q", "-b", "main")
	require.NoError(t, os.MkdirAll(filepath.Join(repo, "a", "b"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "a", "b", "f.txt"), []byte("f\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "top.txt"), []byte("top\n"), 0o644))
	sourcesFromCacheGit(t, repo, "add", "-A")
	sourcesFromCacheGit(t, repo, "commit", "-q", "-m", "one")
	commit := sourcesFromCacheGit(t, repo, "rev-parse", "HEAD")

	public := credentialsGitServer(t, repo, false)
	withUser := *credentialsGitServer(t, repo, true)
	withUser.User = url.UserPassword("u", credentialsTestSecret)
	host := withUser.Hostname()

	for _, tt := range []struct{ name, sparse, key string }{
		{name: "full", key: "git:" + commit},
		{name: "sparse", sparse: "a/b", key: "git:" + commit + "-sparse-*"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stash := t.TempDir()
			environ := credentialsHome(t, "")
			environ["MELANGE_SOURCE_STASH"] = stash
			step := func(repository string) string {
				with := map[string]string{
					"repository": repository, "destination": filepath.Join(t.TempDir(), "out"), "branch": "main",
					"expected-commit": commit, "max-retries": "0",
				}
				if tt.sparse != "" {
					with["sparse-paths"] = tt.sparse
				}
				out, err := credentialsRun(t, "git-checkout", t.TempDir(), with, environ)
				require.NoError(t, err, out)
				return out
			}
			out := step(public.String())
			archive := mustGlob(t, filepath.Join(stash, tt.key+".tar.gz"))
			require.Len(t, archive, 1, out)
			record := strings.TrimSuffix(archive[0], ".tar.gz") + sourceCredentialsSuffix
			requireRecord(t, record, nil, out)

			out = step(withUser.String())
			require.NotContains(t, out, "archiving checkout as", "the second step should find the archive already stashed")
			requireRecord(t, record, []string{"authorization " + host, "userinfo " + host}, out)
			requireNoSecret(t, stash, out)
		})
	}
}

// GIT_CURL_VERBOSE makes git trace to stderr and leave GIT_TRACE_CURL's file
// empty, so the step unsets it. And a trace that shows no request at all,
// whatever kept git from writing it, is never read as "no credentials" when
// the step cloned over http(s).
func TestGitCheckoutEmptyTraceIsUnverified(t *testing.T) {
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
	helper := "[credential]\n\thelper = \"!f() { test \\\"$1\\\" = get && echo username=u && echo password=" + credentialsTestSecret + "; }; f\"\n"

	// a git that writes no trace, as any cause of a silent trace would
	realGit, err := exec.LookPath("git")
	require.NoError(t, err)
	noTrace := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(noTrace, "git"),
		[]byte("#!/bin/sh\nunset GIT_TRACE_CURL\nexec "+realGit+" \"$@\"\n"), 0o755))

	for _, tt := range []struct {
		name, repo, gitconfig string
		verbose, untraced     bool
		want                  []string
	}{
		{name: "GIT_CURL_VERBOSE with a credential helper", repo: private.String(), gitconfig: helper, verbose: true, want: []string{"authorization " + host}},
		{name: "GIT_CURL_VERBOSE on a public clone", repo: public.String(), verbose: true},
		{name: "no trace of an http clone", repo: public.String(), untraced: true, want: []string{"unverified -"}},
		{name: "no trace of a local clone", repo: repo, untraced: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stash := t.TempDir()
			environ := credentialsHome(t, tt.gitconfig)
			environ["MELANGE_SOURCE_STASH"] = stash
			if tt.verbose {
				environ["GIT_CURL_VERBOSE"] = "1"
			}
			if tt.untraced {
				environ["PATH"] = noTrace + string(os.PathListSeparator) + os.Getenv("PATH")
			}
			out, err := credentialsRun(t, "git-checkout", t.TempDir(), map[string]string{
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

// A step killed while it waits to retry a clone that sent credentials still
// removes its trace, which holds every header other than Authorization,
// Proxy-Authorization and Cookie in clear, and still fails. busybox sh does
// not run an EXIT trap on a signal.
func TestGitCheckoutKilledStepLeavesNoTrace(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	repo := t.TempDir()
	sourcesFromCacheGit(t, repo, "init", "-q", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644))
	sourcesFromCacheGit(t, repo, "add", "-A")
	sourcesFromCacheGit(t, repo, "commit", "-q", "-m", "one")
	// every request is refused, so the clone fails after sending the header
	// and the step waits to retry
	private := credentialsGitServer(t, repo, true)

	for _, tt := range []struct {
		name   string
		sig    syscall.Signal
		status int
	}{
		{name: "TERM", sig: syscall.SIGTERM, status: 143},
		{name: "INT", sig: syscall.SIGINT, status: 130},
		{name: "HUP", sig: syscall.SIGHUP, status: 129},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if signal.Ignored(tt.sig) {
				// the script inherits the disposition, and sh cannot trap a
				// signal ignored on entry (go test under nohup, say)
				t.Skipf("SIG%s is ignored in this process", tt.name)
			}
			tmp := t.TempDir()
			environ := credentialsHome(t, "[http]\n\textraHeader = \"X-Token: wrong\"\n")
			environ["MELANGE_SOURCE_STASH"], environ["TMPDIR"], environ["GIT_TERMINAL_PROMPT"] = t.TempDir(), tmp, "0"
			cmd := credentialsCommand(t, "git-checkout", t.TempDir(), map[string]string{
				"repository": private.String(), "destination": filepath.Join(t.TempDir(), "out"), "branch": "main",
				"expected-commit": strings.Repeat("0", 40), "max-retries": "3", "initial-backoff": "60",
			}, environ)
			log := filepath.Join(t.TempDir(), "log")
			f, err := os.Create(log)
			require.NoError(t, err)
			defer f.Close()
			cmd.Stdout, cmd.Stderr = f, f
			// its own process group, so the signal reaches the backoff's
			// sleep as it would a step's
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			require.NoError(t, cmd.Start())
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()

			traced := func() bool {
				found := false
				require.NoError(t, filepath.WalkDir(tmp, func(p string, d os.DirEntry, err error) error {
					if err == nil && d.Type().IsRegular() {
						if b, rerr := os.ReadFile(p); rerr == nil && strings.Contains(string(b), "X-Token: wrong") {
							found = true
						}
					}
					return err
				}))
				return found
			}
			require.Eventually(t, func() bool {
				b, _ := os.ReadFile(log)
				return strings.Contains(string(b), "before retry")
			}, 30*time.Second, 50*time.Millisecond, "the step never reached its retry backoff")
			require.True(t, traced(), "the trace must hold the header before the kill, or this test proves nothing")

			require.NoError(t, syscall.Kill(-cmd.Process.Pid, tt.sig))
			select {
			case err = <-done:
			case <-time.After(30 * time.Second):
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				t.Fatal("the step did not exit on the signal")
			}
			b, _ := os.ReadFile(log)
			require.Error(t, err, string(b))
			require.False(t, traced(), "the curl trace must be removed\n%s", b)
			var exitErr *exec.ExitError
			require.ErrorAs(t, err, &exitErr)
			require.Equal(t, tt.status, exitErr.ExitCode(), string(b))
		})
	}
}

// credentialsProxy is a forward http proxy that, with auth set, requires the
// test's basic credentials in Proxy-Authorization. It counts the requests it
// forwarded.
func credentialsProxy(t *testing.T, auth bool) (*url.URL, *atomic.Int32) {
	t.Helper()
	var forwarded atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth {
			got := r.Header.Get("Proxy-Authorization")
			if got != "Basic "+base64.StdEncoding.EncodeToString([]byte("u:"+credentialsTestSecret)) {
				w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
				http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
				return
			}
		}
		out := r.Clone(r.Context())
		out.RequestURI = ""
		out.Header.Del("Proxy-Authorization")
		resp, err := http.DefaultTransport.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		forwarded.Add(1)
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return u, &forwarded
}

// A public clone through a proxy that takes credentials sends them in
// Proxy-Authorization, which the trace match does not read: userinfo in the
// proxy URL, from the environment or git's configuration, is the signal.
func TestGitCheckoutRecordsProxyCredentials(t *testing.T) {
	t.Parallel()
	sourcesFromCacheRequireTools(t)
	repo := t.TempDir()
	sourcesFromCacheGit(t, repo, "init", "-q", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644))
	sourcesFromCacheGit(t, repo, "add", "-A")
	sourcesFromCacheGit(t, repo, "commit", "-q", "-m", "one")
	commit := sourcesFromCacheGit(t, repo, "rev-parse", "HEAD")
	public := credentialsGitServer(t, repo, false)

	for _, tt := range []struct {
		name, env, config string
		auth              bool
		want              []string
	}{
		{name: "http_proxy with userinfo", env: "http_proxy", auth: true, want: []string{"proxy 127.0.0.1"}},
		{name: "ALL_PROXY with userinfo", env: "ALL_PROXY", auth: true, want: []string{"proxy 127.0.0.1"}},
		{name: "http.proxy with userinfo", config: "http", auth: true, want: []string{"proxy 127.0.0.1"}},
		{name: "remote.origin.proxy with userinfo", config: "remote", auth: true, want: []string{"proxy 127.0.0.1"}},
		{name: "a proxy without credentials", env: "http_proxy"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			proxy, forwarded := credentialsProxy(t, tt.auth)
			if tt.auth {
				proxy.User = url.UserPassword("u", credentialsTestSecret)
			}
			gitconfig := ""
			switch tt.config {
			case "http":
				gitconfig = fmt.Sprintf("[http]\n\tproxy = %s\n", proxy)
			case "remote":
				gitconfig = fmt.Sprintf("[remote \"origin\"]\n\tproxy = %s\n", proxy)
			}
			stash := t.TempDir()
			environ := credentialsHome(t, gitconfig)
			environ["MELANGE_SOURCE_STASH"], environ["no_proxy"], environ["NO_PROXY"] = stash, "", ""
			if tt.env != "" {
				environ[tt.env] = proxy.String()
			}
			out, err := credentialsRun(t, "git-checkout", t.TempDir(), map[string]string{
				"repository": public.String(), "destination": filepath.Join(t.TempDir(), "out"), "branch": "main",
				"expected-commit": commit, "max-retries": "0",
			}, environ)
			require.NoError(t, err, out)
			require.NotZero(t, forwarded.Load(), "the clone did not go through the proxy; this case would prove nothing\n%s", out)
			requireRecord(t, filepath.Join(stash, "git:"+commit+sourceCredentialsSuffix), tt.want, out)
			requireNoSecret(t, stash, out)
		})
	}
}
