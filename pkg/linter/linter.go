// Copyright 2023 Chainguard, Inc.
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

package linter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"github.com/chainguard-dev/clog"
	"github.com/dustin/go-humanize"
	"golang.org/x/exp/maps"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v3"

	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/apk/expandapk"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/license"
)

type linterFunc func(ctx context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS) error

type linter struct {
	LinterFunc      linterFunc
	Explain         string
	defaultBehavior defaultBehavior
}

type LintResult struct {
	Linter      string
	Package     string
	Error       error
	Explanation string
}

type defaultBehavior int

const (
	// Ignore the linter (default)
	Ignore defaultBehavior = iota
	// Require the linter.
	Require
	// Warn about the linter.
	Warn
)

func allPaths(fn func(ctx context.Context, cfg *config.Configuration, pkgname, path string) error) func(ctx context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS) error {
	return func(ctx context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS) error {
		return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err != nil {
				return err
			}
			if d.IsDir() {
				// Ignore directories
				return nil
			}
			if err := fn(ctx, cfg, pkgname, path); err != nil {
				return fmt.Errorf("%w: %s", err, path)
			}
			return nil
		})
	}
}

func DefaultRequiredLinters() []string {
	l := slices.DeleteFunc(maps.Keys(linterMap), func(k string) bool { return linterMap[k].defaultBehavior != Require })
	slices.Sort(l)
	return l
}

func DefaultWarnLinters() []string {
	l := slices.DeleteFunc(maps.Keys(linterMap), func(k string) bool { return linterMap[k].defaultBehavior != Warn })
	slices.Sort(l)
	return l
}

var linterMap = map[string]linter{
	"dev": {
		LinterFunc:      allPaths(devLinter),
		Explain:         "If this package is creating /dev nodes, it should use udev instead; otherwise, remove any files in /dev",
		defaultBehavior: Require,
	},
	"documentation": {
		LinterFunc:      allPaths(documentationLinter),
		Explain:         "Place documentation into a separate package or remove it",
		defaultBehavior: Ignore, // TODO: Lots of packages write to READMEs, etc.
	},
	"opt": {
		LinterFunc:      allPaths(optLinter),
		Explain:         "This package should be a -compat package",
		defaultBehavior: Warn,
	},
	"object": {
		LinterFunc:      allPaths(objectLinter),
		Explain:         "This package contains intermediate object files (.o files)",
		defaultBehavior: Warn,
	},
	"maninfo": {
		LinterFunc:      allPaths(manInfoLinter),
		Explain:         "Place documentation into a separate package or remove it",
		defaultBehavior: Warn,
	},
	"sbom": {
		LinterFunc:      allPaths(sbomLinter),
		Explain:         "Remove any files in /var/lib/db/sbom from the package",
		defaultBehavior: Warn, // TODO: needs work to be useful
	},
	"setuidgid": {
		LinterFunc:      isSetUIDOrGIDLinter,
		Explain:         "Unset the setuid/setgid bit on the relevant files, or remove this linter",
		defaultBehavior: Require,
	},
	"srv": {
		LinterFunc:      allPaths(srvLinter),
		Explain:         "This package should be a -compat package",
		defaultBehavior: Warn,
	},
	"tempdir": {
		LinterFunc:      allPaths(tempDirLinter),
		Explain:         "Remove any offending files in temporary dirs in the pipeline",
		defaultBehavior: Require,
	},
	"usrlocal": {
		LinterFunc:      allPaths(usrLocalLinter),
		Explain:         "This package should be a -compat package",
		defaultBehavior: Warn,
	},
	"varempty": {
		LinterFunc:      allPaths(varEmptyLinter),
		Explain:         "Remove any offending files in /var/empty in the pipeline",
		defaultBehavior: Require,
	},
	"worldwrite": {
		LinterFunc:      worldWriteableLinter,
		Explain:         "Change the permissions of any permissive files in the package, disable the linter, or make this a -compat package",
		defaultBehavior: Require,
	},
	"strip": {
		LinterFunc:      strippedLinter,
		Explain:         "Properly strip all binaries in the pipeline",
		defaultBehavior: Warn,
	},
	"infodir": {
		LinterFunc:      allPaths(infodirLinter),
		Explain:         "Remove /usr/share/info/dir from the package (run split/infodir)",
		defaultBehavior: Require,
	},
	"empty": {
		LinterFunc:      emptyLinter,
		Explain:         "Verify that this package is supposed to be empty; if it is, disable this linter; otherwise check the build",
		defaultBehavior: Ignore, // TODO: Needs to ignore packages that specify no-provides.
	},
	"python/docs": {
		LinterFunc:      pythonDocsLinter,
		Explain:         "Remove all docs directories from the package",
		defaultBehavior: Warn,
	},
	"python/multiple": {
		LinterFunc:      pythonMultiplePackagesLinter,
		Explain:         "Split this package up into multiple packages and verify you are not improperly using pip install",
		defaultBehavior: Warn,
	},
	"python/test": {
		LinterFunc:      pythonTestLinter,
		Explain:         "Remove all test directories from the package",
		defaultBehavior: Warn,
	},
	"pkgconf": {
		LinterFunc:      allPaths(pkgconfTestLinter),
		Explain:         "This package provides files in a pkgconfig directory, please add the pkgconf test pipeline",
		defaultBehavior: Warn,
	},
	"lddcheck": {
		LinterFunc:      allPaths(lddcheckTestLinter),
		Explain:         "This package provides shared object files, please add the ldd-check test pipeline",
		defaultBehavior: Warn,
	},
	"usrmerge": {
		LinterFunc:      usrmergeLinter,
		Explain:         "Move binary to /usr/bin",
		defaultBehavior: Require,
	},
	"cudaruntimelib": {
		LinterFunc:      allPaths(cudaDriverLibLinter),
		Explain:         "CUDA driver-specific libraries should be passed into the container by the host. Installing them in an image could override the host libraries and break GPU support. If this library is needed for build-time linking or ldd-check tests, please use a package containing a stub library instead. For libcuda.so, use nvidia-cuda-cudart-$cuda_version. For libnvidia-ml.so, use nvidia-cuda-nvml-dev-$cuda_version.",
		defaultBehavior: Warn,
	},
	"dll": {
		LinterFunc:      allPaths(dllLinter),
		Explain:         "This package contains Windows libraries",
		defaultBehavior: Warn,
	},
	"nonlinux": {
		LinterFunc:      allPaths(nonLinuxLinter),
		Explain:         "This package contains references to non-Linux paths",
		defaultBehavior: Warn,
	},
	"unsupportedarch": {
		LinterFunc:      allPaths(unsupportedArchLinter),
		Explain:         "This package contains references to unsupported architectures (only aarch64/arm64 and amd64/x86_64 are supported)",
		defaultBehavior: Warn,
	},
	"staticarchive": {
		LinterFunc:      allPaths(staticArchiveLinter),
		Explain:         "This package contains static archives (.a files)",
		defaultBehavior: Warn,
	},
	"duplicate": {
		LinterFunc:      duplicateLinter,
		Explain:         "This package contains files with the same name and content in different directories (consider symlinking)",
		defaultBehavior: Warn,
	},
}

// Determine if a path should be ignored by a linter
func isIgnoredPath(path string) bool {
	return strings.HasPrefix(path, "var/lib/db/sbom/")
}

func devLinter(_ context.Context, _ *config.Configuration, _, path string) error {
	if strings.HasPrefix(path, "dev/") {
		return fmt.Errorf("package writes to /dev")
	}
	return nil
}

func optLinter(_ context.Context, _ *config.Configuration, pkgname, path string) error {
	if !strings.HasSuffix(pkgname, "-compat") && strings.HasPrefix(path, "opt/") {
		return fmt.Errorf("package writes to /opt")
	}

	return nil
}

func objectLinter(_ context.Context, _ *config.Configuration, _, path string) error {
	if filepath.Ext(path) == ".o" {
		return fmt.Errorf("package contains intermediate object file %q. This is usually wrong. In most cases they should be removed", path)
	}
	return nil
}

func staticArchiveLinter(_ context.Context, _ *config.Configuration, pkgname, path string) error {
	// Static archives are expected in -dev packages
	if strings.HasSuffix(pkgname, "-dev") {
		return nil
	}

	if filepath.Ext(path) == ".a" {
		return fmt.Errorf("package contains static archive %q. Static archives bloat packages and should typically be in -dev packages or removed", path)
	}
	return nil
}

func dllLinter(_ context.Context, _ *config.Configuration, _, path string) error {
	if filepath.Ext(path) == ".dll" {
		return fmt.Errorf("package contains DLL file %q", path)
	}
	return nil
}

func nonLinuxLinter(_ context.Context, _ *config.Configuration, _, path string) error {
	names := []string{"darwin", "osx", "windows"}
	paths := make([]string, 0)

	for _, n := range names {
		if strings.Contains(filepath.Dir(path), n) || strings.Contains(filepath.Base(path), n) {
			paths = append(paths, path)
		}
	}

	if len(paths) > 0 {
		return fmt.Errorf("package contains non-Linux reference(s) %q", strings.Join(paths, ","))
	}
	return nil
}

func unsupportedArchLinter(_ context.Context, _ *config.Configuration, _, path string) error {
	supported := []string{"aarch64", "arm64", "amd64", "x86_64", "x86-64"}

	archs := []string{
		"i386", "i686", "x86_32", "x86-32",
		"ppc64", "ppc64le", "powerpc",
		"s390x", "s390",
		"mips", "mipsel", "mips64",
		"riscv", "riscv64",
		"sparc", "sparc64",
		"ia64", "m68k",
	}

	pathLower := strings.ToLower(path)
	dirLower := strings.ToLower(filepath.Dir(path))
	baseLower := strings.ToLower(filepath.Base(path))

	for _, arch := range archs {
		if strings.Contains(dirLower, "/"+arch+"/") || strings.Contains(dirLower, "/"+arch) && dirLower == strings.ToLower(filepath.Dir(path)) {
			return fmt.Errorf("package contains unsupported architecture reference %q in %q", arch, path)
		}

		for _, sep := range []string{"-", "_", "."} {
			if strings.Contains(baseLower, sep+arch+sep) ||
				strings.Contains(baseLower, sep+arch+".") ||
				strings.HasSuffix(baseLower, sep+arch) {

				isSupported := false
				for _, s := range supported {
					if strings.Contains(pathLower, s) {
						isSupported = true
						break
					}
				}
				if !isSupported {
					return fmt.Errorf("package contains unsupported architecture reference %q in %q", arch, path)
				}
			}
		}
	}

	return nil
}

type duplicateInfo struct {
	paths []string
	size  int64
}

func duplicateLinter(ctx context.Context, _ *config.Configuration, _ string, fsys fs.FS) error {
	type fileKey struct {
		hash     string
		basename string
	}
	filesByKey := make(map[fileKey]*duplicateInfo)

	const minFileSizeBytes = 1024 // 1 KB

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}

		if d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		basename := filepath.Base(path)

		if isLicense, _ := license.IsLicenseFile(path); isLicense {
			return nil
		}

		if info.Size() < minFileSizeBytes {
			return nil
		}

		f, err := fsys.Open(path)
		if err != nil {
			return fmt.Errorf("opening file %s: %w", path, err)
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return fmt.Errorf("hashing file %s: %w", path, err)
		}

		hash := hex.EncodeToString(h.Sum(nil))
		key := fileKey{hash: hash, basename: basename}

		if existing, found := filesByKey[key]; found {
			existing.paths = append(existing.paths, path)
		} else {
			filesByKey[key] = &duplicateInfo{
				paths: []string{path},
				size:  info.Size(),
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	type duplicateSet struct {
		count    int
		size     int64
		wasted   int64
		paths    []string
		basename string
	}

	var duplicateSets []duplicateSet
	var totalWasted int64

	for key, info := range filesByKey {
		if len(info.paths) > 1 {
			slices.Sort(info.paths)

			wasted := int64(len(info.paths)-1) * info.size
			totalWasted += wasted

			duplicateSets = append(duplicateSets, duplicateSet{
				count:    len(info.paths),
				size:     info.size,
				wasted:   wasted,
				paths:    info.paths,
				basename: key.basename,
			})
		}
	}

	if len(duplicateSets) > 0 {
		slices.SortFunc(duplicateSets, func(a, b duplicateSet) int {
			if a.wasted > b.wasted {
				return -1
			} else if a.wasted < b.wasted {
				return 1
			}
			return 0
		})

		var output []string
		for _, ds := range duplicateSets {
			output = append(output, fmt.Sprintf(
				"  %d copies of '%s' (%s each, wasting %s):",
				ds.count,
				ds.basename,
				humanize.Bytes(uint64(ds.size)),
				humanize.Bytes(uint64(ds.wasted)),
			))

			for _, p := range ds.paths {
				output = append(output, "    "+p)
			}
		}

		summary := fmt.Sprintf("package contains %d duplicate file(s) with same name in different directories (wasting %s total)", len(duplicateSets), humanize.Bytes(uint64(totalWasted)))

		return fmt.Errorf("%s:\n%s", summary, strings.Join(output, "\n"))
	}

	return nil
}

var isDocumentationFileRegex = regexp.MustCompile(`(?:READ(?:\.?ME)?|TODO|CREDITS|\.(?:md|docx?|rst|[0-9][a-z]))$`)

func documentationLinter(_ context.Context, _ *config.Configuration, pkgname, path string) error {
	if isDocumentationFileRegex.MatchString(path) && !strings.HasSuffix(pkgname, "-doc") {
		return errors.New("package contains documentation files but is not a documentation package")
	}
	return nil
}

var (
	manRegex  = regexp.MustCompile(`^usr/(?:local/)?share/man(?:/man[0-9][^/]*)?(?:/[^/]+\.[0-9][^/]*(?:\.(?:gz|bz2|xz|lzma|Z))?)?$|^usr/man(?:/man[0-9][^/]*)?(?:/[^/]+\.[0-9][^/]*(?:\.(?:gz|bz2|xz|lzma|Z))?)?$`)
	infoRegex = regexp.MustCompile(`^usr/(?:local/)?share/info/(?:dir|[^/]+\.info(?:\-[0-9]+)?(?:\.(?:gz|bz2|xz|lzma|Z))?)$`)
)

func manInfoLinter(_ context.Context, _ *config.Configuration, pkgname, path string) error {
	if strings.HasSuffix(pkgname, "-doc") {
		return nil
	}

	if manRegex.MatchString(path) || infoRegex.MatchString(path) {
		return fmt.Errorf("package contains man/info files but is not a documentation package")
	}

	return nil
}

func modeToOctal(mode os.FileMode) string {
	perm := uint64(mode.Perm())

	if mode&os.ModeSetuid != 0 {
		perm |= 04000
	}
	if mode&os.ModeSetgid != 0 {
		perm |= 02000
	}
	if mode&os.ModeSticky != 0 {
		perm |= 01000
	}

	return strconv.FormatUint(perm, 8)
}

func isSetUIDOrGIDLinter(ctx context.Context, _ *config.Configuration, _ string, fsys fs.FS) error {
	return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if !d.Type().IsRegular() { // Don't worry about non-files
			return nil
		}

		mode := info.Mode()
		perm := modeToOctal(mode)

		bits := mode & (fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)
		if bits != 0 {
			var parts []string
			if mode&fs.ModeSetuid != 0 {
				parts = append(parts, "setuid")
			}
			if mode&fs.ModeSetgid != 0 {
				parts = append(parts, "setgid")
			}
			if mode&fs.ModeSticky != 0 {
				parts = append(parts, "sticky")
			}
			return fmt.Errorf("file with special permissions found in package: %s - %s (%s)",
				path, perm, strings.Join(parts, "+"))
		}

		return nil
	})
}

func sbomLinter(_ context.Context, _ *config.Configuration, _, path string) error {
	if filepath.Dir(path) == "var/lib/db/sbom" && !strings.HasSuffix(path, ".spdx.json") {
		return fmt.Errorf("package writes to %s", filepath.Dir(path))
	}
	return nil
}

func infodirLinter(_ context.Context, _ *config.Configuration, _, path string) error {
	if strings.HasPrefix(path, "usr/share/info/dir/") {
		return fmt.Errorf("package writes to /usr/share/info/dir/")
	}
	return nil
}

func srvLinter(_ context.Context, _ *config.Configuration, pkgname, path string) error {
	if !strings.HasSuffix(pkgname, "-compat") && strings.HasPrefix(path, "srv/") {
		return fmt.Errorf("package writes to /srv")
	}
	return nil
}

var isTempDirRegex = regexp.MustCompile("^(var/)?(tmp|run)/")

func tempDirLinter(_ context.Context, _ *config.Configuration, _, path string) error {
	if isTempDirRegex.MatchString(path) {
		return fmt.Errorf("package writes to a temp dir")
	}
	return nil
}

func usrLocalLinter(_ context.Context, _ *config.Configuration, pkgname, path string) error {
	if !strings.HasSuffix(pkgname, "-compat") && strings.HasPrefix(path, "usr/local/") {
		return fmt.Errorf("/usr/local path found in non-compat package")
	}
	return nil
}

func varEmptyLinter(_ context.Context, _ *config.Configuration, _, path string) error {
	if strings.HasPrefix(path, "var/empty/") {
		return fmt.Errorf("package writes to /var/empty")
	}
	return nil
}

func worldWriteableLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}

		if !d.Type().IsRegular() { // Don't worry about non-files
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		mode := info.Mode()
		perm := modeToOctal(mode)

		if mode&0o002 != 0 {
			if mode&0o111 != 0 {
				return fmt.Errorf("world-writeable executable file found in package (security risk): %s - %s", path, perm)
			}
			return fmt.Errorf("world-writeable file found in package: %s - %s", path, perm)
		}
		return nil
	})
}

var elfMagic = []byte{'\x7f', 'E', 'L', 'F'}

var isObjectFileRegex = regexp.MustCompile(`\.(a|so|dylib)(\..*)?`)

func strippedLinter(ctx context.Context, _ *config.Configuration, _ string, fsys fs.FS) error {
	return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}
		if isIgnoredPath(path) {
			return nil
		}

		if !d.Type().IsRegular() {
			// Don't worry about non-files
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if info.Size() < int64(len(elfMagic)) {
			// This is definitely not an ELF file.
			return nil
		}

		ext := filepath.Ext(path)
		mode := info.Mode()
		if mode&0o111 == 0 && !isObjectFileRegex.MatchString(ext) {
			// Not an executable or library
			return nil
		}

		f, err := fsys.Open(path)
		if err != nil {
			return fmt.Errorf("opening file: %w", err)
		}
		defer f.Close()

		// Both os.DirFS and go-apk return a file that implements ReaderAt.
		// We don't have any other callers, so this should never fail.
		readerAt, ok := f.(io.ReaderAt)
		if !ok {
			return fmt.Errorf("fs.File does not impl ReaderAt: %T", f)
		}

		hdr := make([]byte, len(elfMagic))
		if _, err := readerAt.ReadAt(hdr, 0); err != nil {
			return fmt.Errorf("failed to read %d bytes for magic ELF header: %w", len(elfMagic), err)
		}

		if !bytes.Equal(elfMagic, hdr) {
			// No magic header, definitely not ELF.
			return nil
		}

		file, err := elf.NewFile(readerAt)
		if err != nil {
			return fmt.Errorf("Could not open file %q as executable: %v\n", path, err)
		}
		defer file.Close()

		// No debug sections allowed
		if file.Section(".debug") != nil || file.Section(".zdebug") != nil {
			return fmt.Errorf("ELF file is not stripped")
		}
		return nil
	})
}

func emptyLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	foundfile := false
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}

		if isIgnoredPath(path) {
			return nil
		}

		if d.IsDir() {
			// Ignore directories
			return nil
		}

		foundfile = true
		return fs.SkipAll
	})
	if err != nil {
		return err
	}

	// Nothing to do
	if foundfile {
		return nil
	}

	return fmt.Errorf("package is empty but no-provides is not set")
}

func getPythonSitePackages(fsys fs.FS) (matches []string, err error) {
	pythondirs, err := fs.Glob(fsys, filepath.Join("usr", "lib", "python3.*"))
	if err != nil {
		// Shouldn't get here, per the Go docs.
		err = fmt.Errorf("error checking for Python site directories: %w", err)
		return
	}

	if len(pythondirs) == 0 {
		// Nothing to do
		return
	} else if len(pythondirs) > 1 {
		err = fmt.Errorf("more than one Python version detected: %d found", len(pythondirs))
		return
	}

	matches, err = fs.Glob(fsys, filepath.Join(pythondirs[0], "site-packages", "*"))
	if err != nil {
		// Shouldn't get here as well.
		err = fmt.Errorf("error checking for Python packages: %w", err)
		return
	}

	return
}

func pythonDocsLinter(_ context.Context, _ *config.Configuration, _ string, fsys fs.FS) error {
	packages, err := getPythonSitePackages(fsys)
	if err != nil {
		return err
	}

	for _, m := range packages {
		base := filepath.Base(m)
		if base == "doc" || base == "docs" {
			return fmt.Errorf("docs directory encountered in Python site-packages directory")
		}
	}

	return nil
}

func pythonMultiplePackagesLinter(_ context.Context, _ *config.Configuration, _ string, fsys fs.FS) error {
	packages, err := getPythonSitePackages(fsys)
	if err != nil {
		return err
	}

	// Filter matches and ignore duplicates (.so vs directories for example)
	pmatches := map[string]struct{}{}
	for _, m := range packages {
		base := filepath.Base(m)

		if strings.HasPrefix(base, "_") {
			// Ignore __pycache__ and internal packages
			continue
		}

		if base == "test" || base == "tests" {
			// Exclude tests
			continue
		}

		if base == "doc" || base == "docs" {
			// Exclude docs
			continue
		}

		ext := filepath.Ext(base)
		if ext == ".egg-info" || ext == ".dist-info" || ext == ".pth" {
			// Exclude various metadata files and .so files
			continue
		}

		if len(ext) > 0 {
			base = base[:len(ext)]
			if base == "" {
				// No empty strings
				continue
			}
		}
		pmatches[fmt.Sprintf("%q", base)] = struct{}{}
	}

	if len(pmatches) > 1 {
		i := 0
		slmatches := make([]string, len(pmatches))
		for k := range pmatches {
			slmatches[i] = k
			i++
		}
		smatches := strings.Join(slmatches, ", ")
		return fmt.Errorf("multiple Python packages detected: %d found (%s)", len(slmatches), smatches)
	}

	return nil
}

func pythonTestLinter(_ context.Context, _ *config.Configuration, _ string, fsys fs.FS) error {
	packages, err := getPythonSitePackages(fsys)
	if err != nil {
		return err
	}

	for _, m := range packages {
		base := filepath.Base(m)
		if base == "test" || base == "tests" {
			return fmt.Errorf("tests directory encountered in Python site-packages directory")
		}
	}

	return nil
}

var PkgconfDirRegex = regexp.MustCompile("^usr/(lib|share)/pkgconfig/")

func pkgconfTestLinter(_ context.Context, cfg *config.Configuration, pkgname, path string) error {
	if !PkgconfDirRegex.MatchString(path) {
		return nil
	}

	if cfg == nil {
		return fmt.Errorf("pkgconfig directory found and missing .melange.yaml")
	}

	if cfg.Package.Name == pkgname {
		if cfg.Test != nil {
			for _, test := range cfg.Test.Pipeline {
				if test.Uses == "test/pkgconf" {
					return nil
				}
			}
		}
	} else {
		for _, p := range cfg.Subpackages {
			if p.Name != pkgname {
				continue
			}

			if p.Test == nil {
				break
			}

			for _, test := range p.Test.Pipeline {
				if test.Uses == "test/pkgconf" {
					return nil
				}
			}

			break
		}
	}

	return fmt.Errorf("pkgconfig directory found")
}

var isSharedObjectFileRegex = regexp.MustCompile(`\.so(?:\.[0-9]+)*$`)

func lddcheckTestLinter(_ context.Context, cfg *config.Configuration, pkgname, path string) error {
	if !isSharedObjectFileRegex.MatchString(path) {
		return nil
	}

	if cfg == nil {
		return fmt.Errorf("shared object found and missing .melange.yaml")
	}

	if cfg.Package.Name == pkgname {
		if cfg.Test != nil {
			for _, test := range cfg.Test.Pipeline {
				if test.Uses == "test/ldd-check" || test.Uses == "test/tw/ldd-check" {
					return nil
				}
			}
		}
	} else {
		for _, p := range cfg.Subpackages {
			if p.Name != pkgname {
				continue
			}

			if p.Test == nil {
				break
			}

			for _, test := range p.Test.Pipeline {
				if test.Uses == "test/ldd-check" || test.Uses == "test/tw/ldd-check" {
					return nil
				}
			}

			break
		}
	}

	return fmt.Errorf("shared object found")
}

func formatLintResults(results []LintResult, severity string, useColor bool) string {
	if len(results) == 0 {
		return ""
	}

	// ANSI color codes
	const (
		colorReset  = "\033[0m"
		colorYellow = "\033[33m"
		colorRed    = "\033[31m"
		colorCyan   = "\033[36m"
	)

	var output strings.Builder
	output.WriteString(fmt.Sprintf("\n%s (%d):\n", strings.ToUpper(severity), len(results)))
	output.WriteString(strings.Repeat("─", 80) + "\n")

	for i, result := range results {
		if i > 0 {
			output.WriteString("\n")
		}

		// Colorize linter name based on severity (only if useColor is true)
		var linterName string
		if useColor {
			linterColor := colorCyan
			if severity == "errors" {
				linterColor = colorRed
			} else if severity == "warnings" {
				linterColor = colorYellow
			}
			linterName = fmt.Sprintf("%s%s%s", linterColor, result.Linter, colorReset)
		} else {
			linterName = result.Linter
		}

		output.WriteString(fmt.Sprintf("  [%s] %s\n", linterName, result.Error.Error()))
		if result.Explanation != "" {
			output.WriteString(fmt.Sprintf("  → %s\n", result.Explanation))
		}
	}

	return output.String()
}

// isTerminal checks if we should use colored output
func isTerminal() bool {
	// Check if NO_COLOR environment variable is set (standard)
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	// Check if we're running in a CI environment
	if os.Getenv("CI") != "" {
		return false
	}

	// Check if TERM is set to dumb
	if os.Getenv("TERM") == "dumb" {
		return false
	}

	// Check if stderr is a terminal
	if fileInfo, _ := os.Stderr.Stat(); (fileInfo.Mode() & os.ModeCharDevice) != 0 {
		return true
	}

	return false
}

func lintPackageFS(ctx context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS, linters []string) ([]LintResult, error) {
	var results []LintResult
	for _, linterName := range linters {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		linter := linterMap[linterName]
		if err := linter.LinterFunc(ctx, cfg, pkgname, fsys); err != nil {
			results = append(results, LintResult{
				Linter:      linterName,
				Package:     pkgname,
				Error:       err,
				Explanation: linter.Explain,
			})
		}
	}

	return results, nil
}

func checkLinters(linters []string) error {
	var errs []error
	for _, linterName := range linters {
		if _, found := linterMap[linterName]; !found {
			errs = append(errs, fmt.Errorf("unknown linter: %q", linterName))
		}
	}
	return errors.Join(errs...)
}

// Lint the given build directory at the given path
func LintBuild(ctx context.Context, cfg *config.Configuration, packageName string, require, warn []string, fsys apkofs.FullFS) error {
	if err := checkLinters(append(require, warn...)); err != nil {
		return err
	}

	log := clog.FromContext(ctx)
	log.Infof("linting apk: %s", packageName)

	useColor := isTerminal()

	// Run warning linters
	warnResults, err := lintPackageFS(ctx, cfg, packageName, fsys, warn)
	if err != nil {
		return err
	}
	if len(warnResults) > 0 {
		log.Warn(formatLintResults(warnResults, "warnings", useColor))
	}

	// Run required linters
	requireResults, err := lintPackageFS(ctx, cfg, packageName, fsys, require)
	if err != nil {
		return err
	}
	if len(requireResults) > 0 {
		formattedErrors := formatLintResults(requireResults, "errors", useColor)
		log.Error(formattedErrors)
		// Convert results back to errors for returning
		var errs []error
		for _, result := range requireResults {
			errs = append(errs, fmt.Errorf("linter %q failed on package %q: %w", result.Linter, result.Package, result.Error))
		}
		return errors.Join(errs...)
	}

	return nil
}

// Lint the given APK at the given path
func LintAPK(ctx context.Context, path string, require, warn []string) error {
	log := clog.FromContext(ctx)
	if err := checkLinters(append(require, warn...)); err != nil {
		return err
	}

	var r io.Reader
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		if err != nil {
			return fmt.Errorf("creating HTTP request: %w", err)
		}
		if err := auth.DefaultAuthenticators.AddAuth(ctx, req); err != nil {
			return fmt.Errorf("adding authentication to request: %w", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("getting apk %q: %w", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("getting apk %q: %s", path, resp.Status)
		}
		defer resp.Body.Close()
		r = resp.Body
	} else {
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("linting apk %q: %w", path, err)
		}
		defer file.Close()
		r = file
	}

	exp, err := expandapk.ExpandApk(ctx, r, "")
	if err != nil {
		return fmt.Errorf("expanding apk %q: %w", path, err)
	}
	defer exp.Close()

	// Get the package name
	f, err := exp.ControlFS.Open(".PKGINFO")
	if err != nil {
		return fmt.Errorf("could not open .PKGINFO file: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read from package: %w", err)
	}

	pkginfo, err := ini.Load(data)
	if err != nil {
		return fmt.Errorf("could not load .PKGINFO file: %w", err)
	}

	pkgname := pkginfo.Section("").Key("pkgname").MustString("")
	if pkgname == "" {
		return fmt.Errorf("pkgname is nonexistent")
	}

	cfg, err := parseMelangeYaml(exp.ControlFS)
	if err != nil {
		// TODO: Consider making this fatal if the universe gets rebuilt with new melange.
		clog.FromContext(ctx).Warnf("parsing .melange.yaml: %v", err)
	}

	log.Infof("linting apk: %s (size: %s)", pkgname, humanize.Bytes(uint64(exp.Size)))

	useColor := isTerminal()

	// Run warning linters
	warnResults, err := lintPackageFS(ctx, cfg, pkgname, exp.TarFS, warn)
	if err != nil {
		return err
	}
	if len(warnResults) > 0 {
		log.Warn(formatLintResults(warnResults, "warnings", useColor))
	}

	// Run required linters
	requireResults, err := lintPackageFS(ctx, cfg, pkgname, exp.TarFS, require)
	if err != nil {
		return err
	}
	if len(requireResults) > 0 {
		formattedErrors := formatLintResults(requireResults, "errors", useColor)
		log.Error(formattedErrors)
		// Convert results back to errors for returning
		var errs []error
		for _, result := range requireResults {
			errs = append(errs, fmt.Errorf("linter %q failed on package %q: %w", result.Linter, result.Package, result.Error))
		}
		return errors.Join(errs...)
	}

	return nil
}

func parseMelangeYaml(fsys fs.FS) (*config.Configuration, error) {
	my, err := fsys.Open(".melange.yaml")
	if err != nil {
		return nil, fmt.Errorf("could not open .melange.yaml file: %w", err)
	}
	defer my.Close()

	// We expect the file to be complete, so we don't need to post-process
	// it with any of the options available in ParseConfiguration.
	var cfg config.Configuration
	if err := yaml.NewDecoder(my).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func usrmergeLinter(ctx context.Context, _ *config.Configuration, _ string, fsys fs.FS) error {
	paths := []string{}
	dirs := []string{"sbin", "bin", "usr/sbin", "lib", "lib64"}

	pathInDir := func(path string, dirs ...string) bool {
		for _, d := range dirs {
			if path == d || strings.HasPrefix(path, d+"/") {
				return true
			}
		}
		return false
	}

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}

		if isIgnoredPath(path) {
			return filepath.SkipDir
		}

		// If it's not a directory of interest just skip the whole tree
		if !(path == "." || path == "usr" || pathInDir(path, dirs...)) {
			return filepath.SkipDir
		}

		if slices.Contains(dirs, path) {
			if d.IsDir() || d.Type().IsRegular() {
				paths = append(paths, path)
				return nil
			}
		}

		if pathInDir(path, dirs...) {
			paths = append(paths, path)
		}

		return nil
	})
	if err != nil {
		fmt.Print("Returned error?")
		return err
	}

	if len(paths) > 0 {
		err_string := "Package contains paths in violation of usrmerge:"
		for _, path := range paths {
			err_string = strings.Join([]string{err_string, path}, "\n")
		}
		err_string += "\n"
		return errors.New(err_string)

	}

	return nil
}

var isCudaDriverLibRegex = regexp.MustCompile(`^usr/lib/lib(cuda|nvidia-ml)\.so(\.[0-9]+)*$`)

func cudaDriverLibLinter(_ context.Context, _ *config.Configuration, _, path string) error {
	if !isCudaDriverLibRegex.MatchString(path) {
		return nil
	}

	return fmt.Errorf("CUDA driver-specific library found: %s", path)
}
