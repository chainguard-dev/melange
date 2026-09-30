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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	apkofs "chainguard.dev/apko/pkg/apk/fs"

	"chainguard.dev/melange/pkg/config"
)

var sourceEpoch = time.Unix(1669683910, 0)

func sourceBuild(t *testing.T, annotations map[string]string, flag bool) (*Build, string) {
	t.Helper()
	ws := t.TempDir()
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, melangeOutputDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	b := &Build{
		Configuration: &config.Configuration{
			Package:     config.Package{Name: "foo", Version: "1.2", Epoch: 3, Annotations: annotations},
			Subpackages: []config.Subpackage{{Name: "foo-dev"}},
		},
		SourceDir:       src,
		WorkspaceDir:    ws,
		WorkspaceIgnore: ".melangeignore",
		SourceDateEpoch: sourceEpoch,
		SourcePackage:   flag,
	}
	b.WorkspaceDirFS = apkofs.DirFS(t.Context(), ws) // what the packager reads from
	return b, src
}

func writeFileMode(t *testing.T, dir, name string, mode os.FileMode, body string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // WriteFile's mode is subject to umask
		t.Fatal(err)
	}
}

func TestSourcePackageOptIn(t *testing.T) {
	cases := []struct {
		name string
		ann  map[string]string
		flag bool
		want bool
	}{
		{"off by default", nil, false, false},
		{"build-wide flag", nil, true, true},
		{"annotation true", map[string]string{sourcePackageAnnotation: "true"}, false, true},
		{"annotation overrides flag off", map[string]string{sourcePackageAnnotation: "false"}, true, false},
		{"garbage annotation leaves the flag", map[string]string{sourcePackageAnnotation: "maybe"}, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, _ := sourceBuild(t, c.ann, c.flag)
			if got := b.wantsSourcePackage(t.Context()); got != c.want {
				t.Fatalf("wantsSourcePackage = %v, want %v", got, c.want)
			}
		})
	}
}

// A configuration that already declares foo-source keeps it.
func TestSourcePackageNameCollisionKeepsTheDeclaredOne(t *testing.T) {
	b, _ := sourceBuild(t, nil, true)
	b.Configuration.Subpackages = append(b.Configuration.Subpackages, config.Subpackage{Name: "foo-source"})
	if b.wantsSourcePackage(t.Context()) {
		t.Fatal("must not emit a second foo-source")
	}
}

func TestSourcePackageDefinition(t *testing.T) {
	b, _ := sourceBuild(t, nil, true)
	p := b.sourcePackage()
	if p.Name != "foo-source" {
		t.Fatalf("name %q", p.Name)
	}
	if !strings.Contains(p.Description, "foo 1.2-r3") {
		t.Fatalf("description %q should name the origin and full version", p.Description)
	}
	if p.Options == nil || !p.Options.NoDepends || !p.Options.NoProvides || !p.Options.NoCommands {
		t.Fatalf("source trees must not be analysed for deps/provides/commands: %+v", p.Options)
	}
}

func TestGuestEnvironmentOnlyStashesWhenEmitting(t *testing.T) {
	b, _ := sourceBuild(t, nil, false)
	for _, k := range []string{sourceStashEnv, sourceRestoreEnv} {
		if _, ok := b.guestEnvironment(t.Context())[k]; ok {
			t.Fatalf("%s exported although no companion is emitted", k)
		}
	}
	b.SourcePackage = true
	env := b.guestEnvironment(t.Context())
	if env[sourceStashEnv] != "/home/build/melange-out/.melange-source" {
		t.Fatalf("stash path %q", env[sourceStashEnv])
	}
	if env[sourceRestoreEnv] != "1" {
		t.Fatal("restore-from-cache not enabled for a build that emits a companion")
	}
	if env["SOURCE_DATE_EPOCH"] != "1669683910" {
		t.Fatalf("SOURCE_DATE_EPOCH lost: %v", env)
	}
}

func TestSourcePackageAssembly(t *testing.T) {
	b, src := sourceBuild(t, nil, true)
	// the overlay, as the build repository holds it
	writeFileMode(t, src, "fix.patch", 0o644, "--- a\n+++ b\n")
	writeFileMode(t, src, "deep/a/b/leaf.txt", 0o600, "leaf\n")
	writeFileMode(t, src, "run.sh", 0o700, "#!/bin/sh\n")
	writeFileMode(t, src, "noise.log", 0o644, "ignored\n")
	writeFileMode(t, src, ".melangeignore", 0o644, "*.log\n")
	// what the pipelines stashed
	stash := filepath.Join(b.WorkspaceDir, melangeOutputDirName, sourceStashDir)
	writeFileMode(t, stash, "sha256:abc", 0o644, "tarball bytes")
	writeFileMode(t, stash, "sha256:abc.uri", 0o644, "https://example.com/foo-1.2.tar.gz\n")
	writeFileMode(t, stash, "git:deadbeef.tar.gz", 0o644, "archive bytes")
	writeFileMode(t, stash, "git:deadbeef.uri", 0o644, "https://example.com/foo.git\ndeadbeef\n")
	if err := os.MkdirAll(filepath.Join(stash, "not-a-file"), 0o755); err != nil {
		t.Fatal(err)
	}

	manifest, err := b.assembleSourcePackage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(b.WorkspaceDir, melangeOutputDirName, "foo-source", "usr", "src", "foo")

	// the configuration is the same document every APK carries
	want, err := encodeConfiguration(b.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "foo.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("foo.yaml differs from the encoded configuration")
	}

	// overlay: paths kept, modes collapsed, ignore rules applied
	for name, mode := range map[string]os.FileMode{"fix.patch": 0o644, "deep/a/b/leaf.txt": 0o644, "run.sh": 0o755, ".melangeignore": 0o644} {
		fi, err := os.Stat(filepath.Join(root, "foo", filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if fi.Mode().Perm() != mode {
			t.Errorf("%s: mode %o, want %o", name, fi.Mode().Perm(), mode)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "foo", "noise.log")); err == nil {
		t.Error("noise.log should have been ignored")
	}

	// upstream: every regular stashed file, directories dropped
	for _, name := range []string{"sha256:abc", "sha256:abc.uri", "git:deadbeef.tar.gz", "git:deadbeef.uri"} {
		if _, err := os.Stat(filepath.Join(root, sourceUpstreamDir, name)); err != nil {
			t.Errorf("upstream/%s missing: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, sourceUpstreamDir, "not-a-file")); err == nil {
		t.Error("directories in the stash must not be copied")
	}

	// manifest: sha256sum format, sorted, complete, and what SOURCES.sha256 holds
	onDisk, err := os.ReadFile(filepath.Join(root, sourceManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, manifest) {
		t.Fatal("SOURCES.sha256 differs from the returned manifest")
	}
	var paths []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(manifest)), "\n") {
		sum, p, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 64 {
			t.Fatalf("bad manifest line %q", line)
		}
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(body)) != sum {
			t.Fatalf("%s: manifest hash does not match contents", p)
		}
		paths = append(paths, p)
	}
	wantPaths := []string{
		"foo.yaml",
		"foo/.melangeignore", "foo/deep/a/b/leaf.txt", "foo/fix.patch", "foo/run.sh",
		"upstream/git:deadbeef.tar.gz", "upstream/git:deadbeef.uri", "upstream/sha256:abc", "upstream/sha256:abc.uri",
	}
	slices.Sort(wantPaths)
	if !slices.Equal(paths, wantPaths) {
		t.Fatalf("manifest paths\n got %v\nwant %v", paths, wantPaths)
	}
}

// The stash is prepared as a nested repository so a recipe's `git clean` in
// the workspace leaves it alone, and that marker never reaches the companion.
func TestPrepareSourceStashIsARepositoryGitRecognises(t *testing.T) {
	testPrepareSourceStash(t)
}

// Whatever the build left under melange-out/<origin>-source is discarded
// before assembly, so a planted symlink cannot redirect the writes.
func TestSourcePackageAssemblyDiscardsWhatTheBuildLeft(t *testing.T) {
	b, src := sourceBuild(t, nil, true)
	writeFileMode(t, src, "fix.patch", 0o644, "--- a\n+++ b\n")
	outside := t.TempDir()
	companion := filepath.Join(b.WorkspaceDir, melangeOutputDirName, "foo-source")
	if err := os.MkdirAll(filepath.Join(companion, "usr", "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	// melange-out/foo-source/usr/src/foo -> somewhere else on the host
	if err := os.Symlink(outside, filepath.Join(companion, "usr", "src", "foo")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.assembleSourcePackage(t.Context()); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("assembly wrote through the planted symlink: %v", entries)
	}
	if fi, err := os.Lstat(filepath.Join(companion, "usr", "src", "foo")); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("companion root should be a fresh directory, got %v %v", fi, err)
	}
	if _, err := os.Stat(filepath.Join(companion, "usr", "src", "foo", "foo", "fix.patch")); err != nil {
		t.Fatalf("overlay not assembled into the fresh directory: %v", err)
	}
}

// A .git anywhere under the source directory never ships: it holds remote
// URLs, credentials and hooks, not source.
func TestSourcePackageAssemblySkipsGitDirectories(t *testing.T) {
	b, src := sourceBuild(t, nil, true)
	writeFileMode(t, src, "fix.patch", 0o644, "--- a\n+++ b\n")
	writeFileMode(t, src, ".git/config", 0o644, "[remote \"origin\"]\n\turl = https://user:token@example.com/r.git\n")
	writeFileMode(t, src, ".git/hooks/pre-commit", 0o755, "#!/bin/sh\n")
	writeFileMode(t, src, "vendor/lib/.git", 0o644, "gitdir: ../../.git/modules/lib\n")
	writeFileMode(t, src, "vendor/lib/keep.c", 0o644, "int x;\n")
	manifest, err := b.assembleSourcePackage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(manifest), ".git") {
		t.Fatalf("a .git entry reached the manifest:\n%s", manifest)
	}
	for _, want := range []string{"foo/fix.patch", "foo/vendor/lib/keep.c"} {
		if !strings.Contains(string(manifest), "  "+want+"\n") {
			t.Fatalf("%s missing from the manifest:\n%s", want, manifest)
		}
	}
}

// melange-out itself replaced by a link is refused outright: nothing is
// written through it.
func TestSourcePackageAssemblyRefusesLinkedMelangeOut(t *testing.T) {
	b, src := sourceBuild(t, nil, true)
	writeFileMode(t, src, "fix.patch", 0o644, "--- a\n+++ b\n")
	outside := t.TempDir()
	out := filepath.Join(b.WorkspaceDir, melangeOutputDirName)
	if err := os.RemoveAll(out); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, out); err != nil {
		t.Fatal(err)
	}
	if _, err := b.assembleSourcePackage(t.Context()); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("assembly wrote through the linked melange-out: %v", entries)
	}
}

// A build can replace the stash, which lives in the guest-writable workspace,
// with a link to a directory on the host. Following it would publish that
// directory's files as the package's upstream source.
func TestSourcePackageAssemblyRefusesLinkedStash(t *testing.T) {
	b, _ := sourceBuild(t, nil, true)
	if err := b.prepareSourceStash(); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	writeFileMode(t, outside, "credentials", 0o600, "secret\n")
	stash := filepath.Join(b.WorkspaceDir, melangeOutputDirName, sourceStashDir)
	if err := os.RemoveAll(stash); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, stash); err != nil {
		t.Fatal(err)
	}
	if _, err := b.assembleSourcePackage(t.Context()); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	root := filepath.Join(b.WorkspaceDir, melangeOutputDirName, "foo-source", "usr", "src", "foo")
	if _, err := os.Stat(filepath.Join(root, sourceUpstreamDir, "credentials")); err == nil {
		t.Fatal("a host file was copied into the companion through the linked stash")
	}
}

func TestWriteNormalizedRefusesSymlinks(t *testing.T) {
	ws := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.Symlink(outside, filepath.Join(ws, "link")); err != nil {
		t.Fatal(err)
	}
	fsys := apkofs.DirFS(t.Context(), ws)
	if err := writeNormalized(fsys, "link", strings.NewReader("x"), 0o644); err == nil {
		t.Fatal("expected a refusal to write through a symlink")
	}
	if _, err := os.Stat(outside); err == nil {
		t.Fatal("the symlink target was written")
	}
}

func testPrepareSourceStash(t *testing.T) {
	t.Helper()
	b, _ := sourceBuild(t, nil, true)
	if err := b.prepareSourceStash(); err != nil {
		t.Fatal(err)
	}
	stash := filepath.Join(b.WorkspaceDir, melangeOutputDirName, sourceStashDir)
	for _, p := range []string{".git/HEAD", ".git/objects", ".git/refs"} {
		if _, err := os.Stat(filepath.Join(stash, p)); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	writeFileMode(t, stash, "sha256:abc", 0o644, "tarball bytes")
	if _, err := b.assembleSourcePackage(t.Context()); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(b.WorkspaceDir, melangeOutputDirName, "foo-source", "usr", "src", "foo")
	if _, err := os.Stat(filepath.Join(root, sourceUpstreamDir, ".git")); err == nil {
		t.Fatal("the repository marker must not be copied into the companion")
	}
	if _, err := os.Stat(filepath.Join(root, sourceUpstreamDir, "sha256:abc")); err != nil {
		t.Fatal("the stashed artifact must still be copied")
	}
}

func TestSourcePackageAssemblyIsDeterministic(t *testing.T) {
	build := func(t *testing.T) []byte {
		b, src := sourceBuild(t, nil, true)
		writeFileMode(t, src, "fix.patch", 0o644, "--- a\n+++ b\n")
		writeFileMode(t, src, "run.sh", 0o755, "#!/bin/sh\n")
		stash := filepath.Join(b.WorkspaceDir, melangeOutputDirName, sourceStashDir)
		writeFileMode(t, stash, "sha256:abc", 0o644, "tarball bytes")
		m, err := b.assembleSourcePackage(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	if !bytes.Equal(build(t), build(t)) {
		t.Fatal("manifest differs across two assemblies from identical inputs in different directories")
	}
}

// A package with no source directory and no fetched artifacts still gets a
// companion: the configuration alone records inline runs: edits.
func TestSourcePackageAssemblyConfigurationOnly(t *testing.T) {
	b, _ := sourceBuild(t, nil, true)
	b.SourceDir = filepath.Join(t.TempDir(), "does-not-exist")
	manifest, err := b.assembleSourcePackage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(manifest)), "\n")
	if len(lines) != 1 || !strings.HasSuffix(lines[0], "  foo.yaml") {
		t.Fatalf("expected a manifest of just foo.yaml, got %q", manifest)
	}
}

func TestSbomConfigurationDeclaresTheCompanionOnlyWhenEmitting(t *testing.T) {
	b, _ := sourceBuild(t, nil, true)
	if got := b.sbomConfiguration(); got != b.Configuration {
		t.Fatal("without a manifest the configuration must be returned as is")
	}
	b.sourceManifest = []byte("x")
	got := b.sbomConfiguration()
	if len(got.Subpackages) != 2 || got.Subpackages[1].Name != "foo-source" {
		t.Fatalf("companion not declared to the SBOM generator: %+v", got.Subpackages)
	}
	if len(b.Configuration.Subpackages) != 1 {
		t.Fatal("the build configuration itself must not be modified")
	}
}

// companionAPK writes a minimal <origin>-source APK: a control section with
// .PKGINFO and .source.sha256, then a data section holding usr/src/<origin>/
// with the given files plus a SOURCES.sha256 computed over them (unless
// manifest is given, which is written as is). Returns the path and the
// manifest.
func companionAPK(t *testing.T, files map[string]string, manifest []byte, extra func(tw *tar.Writer)) (string, []byte) {
	t.Helper()
	const origin = "foo"
	if manifest == nil {
		names := make([]string, 0, len(files))
		for n := range files {
			names = append(names, n)
		}
		slices.Sort(names)
		var buf bytes.Buffer
		for _, n := range names {
			fmt.Fprintf(&buf, "%x  %s\n", sha256.Sum256([]byte(files[n])), n)
		}
		manifest = buf.Bytes()
	}
	section := func(w io.Writer, write func(tw *tar.Writer)) {
		gz := gzip.NewWriter(w)
		tw := tar.NewWriter(gz)
		write(tw)
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
	}
	reg := func(tw *tar.Writer, name string, body []byte, mode int64) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	var apk bytes.Buffer
	section(&apk, func(tw *tar.Writer) {
		reg(tw, ".PKGINFO", []byte("pkgname = "+origin+"-source\n"), 0o644)
		reg(tw, sourceManifestName, manifest, 0o644)
	})
	section(&apk, func(tw *tar.Writer) {
		root := sourceInstallRoot + "/" + origin + "/"
		for n, body := range files {
			mode := int64(0o644)
			if strings.HasSuffix(n, ".sh") {
				mode = 0o755
			}
			reg(tw, root+n, []byte(body), mode)
		}
		reg(tw, root+sourceManifestFile, manifest, 0o644)
		if extra != nil {
			extra(tw)
		}
	})
	p := filepath.Join(t.TempDir(), origin+"-source-1.0-r0.apk")
	if err := os.WriteFile(p, apk.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, manifest
}

func TestExtractSourcePackage(t *testing.T) {
	files := map[string]string{
		"foo.yaml":                 "package:\n  name: foo\n",
		"foo/fix.patch":            "--- a\n+++ b\n",
		"foo/run.sh":               "#!/bin/sh\n",
		"upstream/sha256:abc":      "tarball",
		"upstream/sha256:abc.uri":  "https://example.com/foo.tar.gz\n",
		"upstream/git:dead.tar.gz": "archive",
	}
	apk, manifest := companionAPK(t, files, nil, nil)

	sp, err := ExtractSourcePackage(apk, manifest, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if sp.Origin != "foo" || filepath.Base(sp.SourceDir) != "foo" || filepath.Base(sp.CacheDir) != sourceUpstreamDir || filepath.Base(sp.Config) != "foo.yaml" {
		t.Fatalf("unexpected layout: %+v", sp)
	}
	for n, body := range files {
		got, err := os.ReadFile(filepath.Join(sp.Root, filepath.FromSlash(n)))
		if err != nil || string(got) != body {
			t.Fatalf("%s: %q %v", n, got, err)
		}
	}
	if fi, _ := os.Stat(filepath.Join(sp.SourceDir, "run.sh")); fi == nil || fi.Mode().Perm() != 0o755 {
		t.Fatal("executable bit lost")
	}
	// no pin: contents are still verified against the manifest
	if _, err := ExtractSourcePackage(apk, nil, t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestExtractSourcePackageRejects(t *testing.T) {
	files := map[string]string{"foo.yaml": "x\n", "foo/fix.patch": "p\n"}
	good, manifest := companionAPK(t, files, nil, nil)

	t.Run("pin from another build", func(t *testing.T) {
		other := append([]byte(nil), manifest...)
		other[0] ^= 1
		if _, err := ExtractSourcePackage(good, other, t.TempDir()); err == nil || !strings.Contains(err.Error(), "pins") {
			t.Fatalf("expected the pin mismatch to be refused, got %v", err)
		}
	})
	t.Run("tampered file", func(t *testing.T) {
		bad := map[string]string{"foo.yaml": "x\n", "foo/fix.patch": "p; evil\n"}
		apk, _ := companionAPK(t, bad, manifest, nil) // manifest of the genuine files
		if _, err := ExtractSourcePackage(apk, manifest, t.TempDir()); err == nil || !strings.Contains(err.Error(), "do not match") {
			t.Fatalf("expected the tampered file to be refused, got %v", err)
		}
	})
	t.Run("extra file", func(t *testing.T) {
		apk, _ := companionAPK(t, files, manifest, func(tw *tar.Writer) {
			body := []byte("sneaky")
			_ = tw.WriteHeader(&tar.Header{Name: "usr/src/foo/foo/extra.patch", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
			_, _ = tw.Write(body)
		})
		if _, err := ExtractSourcePackage(apk, manifest, t.TempDir()); err == nil || !strings.Contains(err.Error(), "+") {
			t.Fatalf("expected the unlisted file to be refused, got %v", err)
		}
	})
	t.Run("symlink entry", func(t *testing.T) {
		apk, _ := companionAPK(t, files, manifest, func(tw *tar.Writer) {
			_ = tw.WriteHeader(&tar.Header{Name: "usr/src/foo/foo/link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
		})
		if _, err := ExtractSourcePackage(apk, manifest, t.TempDir()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("expected the symlink to be refused, got %v", err)
		}
	})
	t.Run("path escape", func(t *testing.T) {
		apk, _ := companionAPK(t, files, manifest, func(tw *tar.Writer) {
			body := []byte("x")
			_ = tw.WriteHeader(&tar.Header{Name: "usr/src/foo/../../../escape", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
			_, _ = tw.Write(body)
		})
		dest := t.TempDir()
		if _, err := ExtractSourcePackage(apk, manifest, dest); err == nil {
			t.Fatal("expected the escaping entry to be refused")
		}
		if _, err := os.Stat(filepath.Join(dest, "..", "..", "escape")); err == nil {
			t.Fatal("the escaping entry was written")
		}
	})
	t.Run("two origins", func(t *testing.T) {
		apk, _ := companionAPK(t, files, manifest, func(tw *tar.Writer) {
			body := []byte("x")
			_ = tw.WriteHeader(&tar.Header{Name: "usr/src/bar/bar.yaml", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
			_, _ = tw.Write(body)
		})
		if _, err := ExtractSourcePackage(apk, manifest, t.TempDir()); err == nil || !strings.Contains(err.Error(), "more than one") {
			t.Fatalf("expected two origins to be refused, got %v", err)
		}
	})
}
