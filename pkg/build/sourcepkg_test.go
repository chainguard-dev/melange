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
	"bytes"
	"crypto/sha256"
	"fmt"
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
	if _, ok := b.guestEnvironment(t.Context())[sourceStashEnv]; ok {
		t.Fatal("stash path exported although no companion is emitted")
	}
	b.SourcePackage = true
	env := b.guestEnvironment(t.Context())
	if env[sourceStashEnv] != "/home/build/melange-out/.melange-source" {
		t.Fatalf("stash path %q", env[sourceStashEnv])
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
