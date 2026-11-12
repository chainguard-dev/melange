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
	"math/big"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		{name: "a query that is no credential", uri: "https://example.com/foo-1.tar.gz?viasf=1"},
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
			environ := map[string]string{}
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

	for _, tt := range []struct {
		name, repo, ca  string
		config, environ bool
		want            []string
	}{
		{name: "no client certificate", repo: public, ca: publicCA},
		{name: "http.sslCert and http.sslKey", repo: private, ca: privateCA, config: true, want: []string{"sslcert " + host}},
		{name: "GIT_SSL_CERT and GIT_SSL_KEY", repo: private, ca: privateCA, environ: true, want: []string{"sslcert " + host}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gitconfig := fmt.Sprintf("[http]\n\tsslCAInfo = %s\n", tt.ca)
			if tt.config {
				gitconfig += fmt.Sprintf("[http %q]\n\tsslCert = %s\n\tsslKey = %s\n", tt.repo, clientCert, clientKey)
			}
			stash := t.TempDir()
			environ := credentialsHome(t, gitconfig)
			environ["MELANGE_SOURCE_STASH"] = stash
			if tt.environ {
				environ["GIT_SSL_CERT"], environ["GIT_SSL_KEY"] = clientCert, clientKey
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
