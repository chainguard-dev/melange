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
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"github.com/chainguard-dev/clog"

	"chainguard.dev/melange/pkg/config"
)

// A package's complete corresponding source travels as a companion package,
// <origin>-source, built by melange itself alongside the binaries. It carries
// everything needed to make the same binaries again: the resolved
// configuration, the --source-dir overlay (patches, configs, scripts), and
// every upstream artifact the fetch and git-checkout pipelines downloaded,
// laid out so that
//
//	melange build usr/src/<origin>/<origin>.yaml \
//	  --source-dir usr/src/<origin>/<origin>/ \
//	  --cache-dir  usr/src/<origin>/upstream/
//
// rebuilds it with no network and no access to the build repository. Every
// APK the build emits carries a manifest of the companion's contents in its
// control section, which is what ties the binaries to their source.
const (
	sourcePackageSuffix = "-source"

	// sourceManifestName is the control section entry, in every APK the build
	// emits, listing each file of the companion with its SHA-256 in
	// sha256sum(1) format.
	sourceManifestName = ".source.sha256"

	// sourcePackageAnnotation switches the companion on ("true") or off
	// ("false") for one package, overriding the build-wide setting.
	sourcePackageAnnotation = "source-package"

	// sourceStashDir, under melange-out in the guest, is where the fetch and
	// git-checkout pipelines leave the pristine artifacts they download, named
	// as the melange cache names them (sha256:<hash>, git:<commit>.tar.gz).
	// melange-out is what comes back from the guest, so the host sees them.
	sourceStashDir = ".melange-source"

	// sourceStashEnv tells the pipelines where to stash. It is only exported
	// into the guest when a companion is being emitted, so every other build
	// pays nothing for the feature.
	sourceStashEnv = "MELANGE_SOURCE_STASH"

	sourceInstallRoot  = "usr/src"
	sourceUpstreamDir  = "upstream"
	sourceManifestFile = "SOURCES.sha256"
)

func (b *Build) sourcePackageName() string {
	return b.Configuration.Package.Name + sourcePackageSuffix
}

func sourceStashPath() string {
	return filepath.Join(WorkDir, melangeOutputDirName, sourceStashDir)
}

// prepareSourceStash creates the stash before the guest starts, as a
// repository in name only: an empty .git with the three entries git needs to
// recognise one. With destination "." the checkout's work tree is the whole
// workspace, and recipes run `git clean -dfX` (autogen.sh) or `git add -A`
// there; neither descends into a nested repository, so the stash survives.
// The assembly copies only regular files, so the marker never ships.
func (b *Build) prepareSourceStash() error {
	gitDir := filepath.Join(b.WorkspaceDir, melangeOutputDirName, sourceStashDir, ".git")
	for _, d := range []string{"objects", "refs"} {
		if err := os.MkdirAll(filepath.Join(gitDir, d), 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644) // #nosec G306 -- a marker, not content
}

// wantsSourcePackage reports whether this build emits the companion: the
// build-wide switch, overridden per package by the annotation. A
// configuration that already declares a subpackage of the companion's name
// keeps it; melange will not emit a second package under that name.
func (b *Build) wantsSourcePackage(ctx context.Context) bool {
	if b.Configuration == nil {
		return false
	}
	on := b.SourcePackage
	if v, ok := b.Configuration.Package.Annotations[sourcePackageAnnotation]; ok {
		if p, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			on = p
		}
	}
	if !on {
		return false
	}
	name := b.sourcePackageName()
	for _, sp := range b.Configuration.Subpackages {
		if sp.Name == name {
			clog.FromContext(ctx).Warnf("not emitting %s: the configuration already declares a subpackage of that name", name)
			return false
		}
	}
	return true
}

// sourcePackage is the companion's definition. Nothing in it is installed to
// be run, so it is not analysed for dependencies, provides or commands.
func (b *Build) sourcePackage() *config.Package {
	p := b.Configuration.Package
	return &config.Package{
		Name:        b.sourcePackageName(),
		Description: fmt.Sprintf("Complete corresponding source for %s %s", p.Name, p.FullVersion()),
		URL:         p.URL,
		Commit:      p.Commit,
		Options:     &config.PackageOption{NoProvides: true, NoDepends: true, NoCommands: true},
	}
}

// sourceOutDir is where the companion is written: its own directory when one
// was given, so it can be published to a repository of its own.
func (b *Build) sourceOutDir() string {
	if b.SourceOutDir != "" {
		return b.SourceOutDir
	}
	return b.OutDir
}

// guestEnvironment is what melange exports into every pipeline step.
func (b *Build) guestEnvironment(ctx context.Context) map[string]string {
	env := map[string]string{
		"SOURCE_DATE_EPOCH": fmt.Sprintf("%d", b.SourceDateEpoch.Unix()),
	}
	if b.wantsSourcePackage(ctx) {
		env[sourceStashEnv] = sourceStashPath()
	}
	return env
}

// sbomConfiguration is the configuration as the SBOM generator should see it:
// with the companion declared, when one is being emitted, so it gets an SBOM
// like every other package. The companion is never written into the
// configuration itself, so .melange.yaml is unaffected.
func (b *Build) sbomConfiguration() *config.Configuration {
	if b.sourceManifest == nil {
		return b.Configuration
	}
	cfg := *b.Configuration
	cfg.Subpackages = append(slices.Clone(b.Configuration.Subpackages), config.Subpackage{
		Name:        b.sourcePackageName(),
		Description: b.sourcePackage().Description,
	})
	return &cfg
}

// sourceDirFile is one regular file the build was given through --source-dir.
type sourceDirFile struct {
	path string      // slash separated, relative to the source directory
	mode fs.FileMode // permission bits as found on disk
	size int64
}

// collectSourceDir lists the files populateWorkspace copies into the
// workspace: regular files only, with the .melangeignore rules applied. What
// ships is exactly what the build saw, no more and no less.
func (b *Build) collectSourceDir(ctx context.Context) ([]sourceDirFile, int64, error) {
	// A read-only view. apko's DirFS probes a directory by creating and
	// deleting a temporary file in it, which is a side effect on the user's
	// source tree and a race for any other process walking the same directory
	// at the same moment. populateWorkspace needs that filesystem's features;
	// this walk does not.
	fi, err := os.Stat(b.SourceDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	if !fi.IsDir() {
		return nil, 0, fmt.Errorf("source directory %s is not a directory", b.SourceDir)
	}
	src := os.DirFS(b.SourceDir)

	ignorePatterns, err := b.loadIgnoreRules(ctx)
	if err != nil {
		return nil, 0, err
	}

	var (
		files []sourceDirFile
		total int64
	)
	err = fs.WalkDir(src, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		mode := fi.Mode()
		if !mode.IsRegular() {
			return nil
		}
		for _, pat := range ignorePatterns {
			if pat.Match(p) {
				return nil
			}
		}
		files = append(files, sourceDirFile{path: p, mode: mode.Perm(), size: fi.Size()})
		total += fi.Size()
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	slices.SortFunc(files, func(a, b sourceDirFile) int { return strings.Compare(a.path, b.path) })
	return files, total, nil
}

// assembleSourcePackage lays the companion out under melange-out, where
// every other package's contents already are, and returns the manifest of
// what it contains.
//
// Everything is written through the workspace filesystem melange packages
// from: that filesystem tracks what is written through it, and files placed
// behind its back are invisible to the packager.
func (b *Build) assembleSourcePackage(ctx context.Context) ([]byte, error) {
	log := clog.FromContext(ctx)
	fsys := b.WorkspaceDirFS
	if fsys == nil {
		return nil, fmt.Errorf("assembling %s: the workspace filesystem is not open", b.sourcePackageName())
	}
	origin := b.Configuration.Package.Name
	// The companion's output directory is melange's to create. Anything the
	// guest left there -- a symlink, say, planted by a build step to make the
	// writes below land elsewhere on the host -- is discarded first, and if it
	// cannot be, the build fails rather than writing through it.
	companion := filepath.Join(melangeOutputDirName, b.sourcePackageName())
	if _, err := os.Lstat(filepath.Join(b.WorkspaceDir, companion)); err == nil {
		log.Warnf("%s exists before assembly; discarding whatever the build left there", companion)
		if err := os.RemoveAll(filepath.Join(b.WorkspaceDir, companion)); err != nil {
			return nil, fmt.Errorf("refusing to assemble %s over the build's own output: %w", b.sourcePackageName(), err)
		}
	}
	root := filepath.Join(companion, sourceInstallRoot, origin) // workspace-relative
	if err := fsys.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}

	// The resolved configuration, byte for byte the .melange.yaml every APK
	// of this build carries, under the name the build repository uses.
	cfg, err := encodeConfiguration(b.Configuration)
	if err != nil {
		return nil, fmt.Errorf("marshalling config: %w", err)
	}
	if err := writeNormalized(fsys, filepath.Join(root, origin+".yaml"), bytes.NewReader(cfg), 0o644); err != nil {
		return nil, err
	}

	// The --source-dir overlay, laid out as the build repository lays it out
	// next to the configuration: <origin>.yaml beside <origin>/.
	files, total, err := b.collectSourceDir(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing source directory %s: %w", b.SourceDir, err)
	}
	for _, f := range files {
		rel := filepath.FromSlash(f.path)
		if err := copyNormalized(fsys, filepath.Join(b.SourceDir, rel), filepath.Join(root, origin, rel), f.mode); err != nil {
			return nil, err
		}
	}

	// Whatever the fetch and git-checkout pipelines stashed: the pristine
	// upstream artifacts, already named as a --cache-dir names them.
	stash := filepath.Join(b.WorkspaceDir, melangeOutputDirName, sourceStashDir)
	entries, err := os.ReadDir(stash)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	upstream := 0
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if err := copyNormalized(fsys, filepath.Join(stash, e.Name()), filepath.Join(root, sourceUpstreamDir, e.Name()), 0o644); err != nil {
			return nil, err
		}
		upstream++
	}
	// The stash stays where it is: the workspace filesystem the later stages
	// walk was seeded from the tree as the guest left it, and the runner
	// wipes the whole workspace afterwards anyway.

	manifest, err := manifestOf(filepath.Join(b.WorkspaceDir, root))
	if err != nil {
		return nil, err
	}
	if err := writeNormalized(fsys, filepath.Join(root, sourceManifestFile), bytes.NewReader(manifest), 0o644); err != nil {
		return nil, err
	}
	log.Infof("assembled %s: configuration, %d source-dir files (%d bytes), %d upstream artifacts", b.sourcePackageName(), len(files), total, upstream)
	return manifest, nil
}

// copyNormalized copies the file at src (a host path) to dst (a workspace
// path) through the workspace filesystem.
func copyNormalized(fsys apkofs.FullFS, src, dst string, mode fs.FileMode) error {
	in, err := os.Open(src) // #nosec G304 - a file inside the build's own inputs
	if err != nil {
		return err
	}
	defer in.Close()
	return writeNormalized(fsys, dst, in, mode)
}

// writeNormalized writes r to dst through the workspace filesystem, with
// permissions collapsed to the one distinction that matters for source: is
// it a script (0755) or data (0644). Owner-only modes and the like are noise
// from whoever's checkout this is.
func writeNormalized(fsys apkofs.FullFS, dst string, r io.Reader, mode fs.FileMode) error {
	perm := fs.FileMode(0o644)
	if mode&0o111 != 0 {
		perm = 0o755
	}
	if err := fsys.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	// Never write through a link: the destination tree is freshly created,
	// so a symlink here can only be something planted to redirect the write.
	if fi, err := fsys.Lstat(dst); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write %s: it is a symlink", dst)
	}
	out, err := fsys.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return fsys.Chmod(dst, perm) // the umask may have narrowed the create mode
}

// manifestOf lists every regular file under root with its SHA-256, sorted,
// in sha256sum(1) format, so `sha256sum -c` inside root verifies it.
func manifestOf(root string) ([]byte, error) {
	var paths []string
	err := fs.WalkDir(os.DirFS(root), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(paths)
	var buf bytes.Buffer
	for _, p := range paths {
		sum, err := fileSHA256(filepath.Join(root, filepath.FromSlash(p)))
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&buf, "%x  %s\n", sum, p)
	}
	return buf.Bytes(), nil
}

func fileSHA256(name string) ([]byte, error) {
	f, err := os.Open(name) // #nosec G304 - a file inside the build's own workspace
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
