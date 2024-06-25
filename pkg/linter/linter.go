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
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"chainguard.dev/apko/pkg/apk/expandapk"
	"github.com/charmbracelet/log"
	"github.com/dustin/go-humanize"
	"golang.org/x/exp/maps"

	"gopkg.in/ini.v1"
)

type linterFunc func(ctx context.Context, pkgname string, fsys fs.FS) error

type linter struct {
	LinterFunc      linterFunc
	Explain         string
	defaultBehavior defaultBehavior
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

func allPaths(fn func(ctx context.Context, pkgname, path string) error) func(ctx context.Context, pkgname string, fsys fs.FS) error {
	return func(ctx context.Context, pkgname string, fsys fs.FS) error {
		return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if d.IsDir() {
				// Ignore directories
				return nil
			}
			if err := fn(ctx, pkgname, path); err != nil {
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
		Explain:         "This package contains intermediate object files",
		defaultBehavior: Warn,
	},
	"sbom": {
		LinterFunc:      allPaths(sbomLinter),
		Explain:         "Remove any files in /var/lib/db/sbom from the package",
		defaultBehavior: Ignore, // TODO: needs work to be useful
	},
	"setuidgid": {
		LinterFunc:      isSetUIDOrGIDLinter,
		Explain:         "Unset the setuid/setgid bit on the relevant files, or remove this linter",
		defaultBehavior: Warn,
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
		Explain:         "Change the permissions of any world-writeable files in the package, disable the linter, or make this a -compat package",
		defaultBehavior: Warn,
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
}

// Determine if a path should be ignored by a linter
func isIgnoredPath(path string) bool {
	return strings.HasPrefix(path, "var/lib/db/sbom/")
}

func devLinter(_ context.Context, _, path string) error {
	if strings.HasPrefix(path, "dev/") {
		return fmt.Errorf("package writes to /dev")
	}
	return nil
}

func optLinter(_ context.Context, _, path string) error {
	if strings.HasPrefix(path, "opt/") {
		return fmt.Errorf("package writes to /opt")
	}

	return nil
}
func objectLinter(_ context.Context, _, path string) error {
	if filepath.Ext(path) == ".o" {
		return fmt.Errorf("package contains intermediate object file %q. This is usually wrong. In most cases they should be removed", path)
	}
	return nil
}

var isDocumentationFileRegex = regexp.MustCompile(`(?:READ(?:\.?ME)?|TODO|CREDITS|\.(?:md|docx?|rst|[0-9][a-z]))$`)

func documentationLinter(_ context.Context, pkgname, path string) error {
	if isDocumentationFileRegex.MatchString(path) && !strings.HasSuffix(pkgname, "-doc") {
		return errors.New("package contains documentation files but is not a documentation package")
	}
	return nil
}

func isSetUIDOrGIDLinter(ctx context.Context, _ string, fsys fs.FS) error {
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

		info, err := d.Info()
		if err != nil {
			return err
		}

		mode := info.Mode()
		if mode&fs.ModeSetuid != 0 {
			return fmt.Errorf("file is setuid")
		} else if mode&fs.ModeSetgid != 0 {
			return fmt.Errorf("file is setgid")
		}
		return nil
	})
}

func sbomLinter(_ context.Context, _, path string) error {
	if strings.HasPrefix(path, "var/lib/db/sbom/") {
		return fmt.Errorf("package writes to %s", path)
	}
	return nil
}

func infodirLinter(_ context.Context, _, path string) error {
	if strings.HasPrefix(path, "usr/share/info/dir/") {
		return fmt.Errorf("package writes to /usr/share/info/dir/")
	}
	return nil
}

func srvLinter(_ context.Context, _, path string) error {
	if strings.HasPrefix(path, "srv/") {
		return fmt.Errorf("package writes to /srv")
	}
	return nil
}

var isTempDirRegex = regexp.MustCompile("^(var/)?(tmp|run)/")

func tempDirLinter(_ context.Context, _, path string) error {
	if isTempDirRegex.MatchString(path) {
		return fmt.Errorf("package writes to a temp dir")
	}
	return nil
}

func usrLocalLinter(_ context.Context, _, path string) error {
	if strings.HasPrefix(path, "usr/local/") {
		return fmt.Errorf("/usr/local path found in non-compat package")
	}
	return nil
}

func varEmptyLinter(_ context.Context, _, path string) error {
	if strings.HasPrefix(path, "var/empty/") {
		return fmt.Errorf("package writes to /var/empty")
	}
	return nil
}

func worldWriteableLinter(ctx context.Context, pkgname string, fsys fs.FS) error {
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

		if !d.Type().IsRegular() { // Don't worry about non-files
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		mode := info.Mode()
		if mode&0002 != 0 {
			if mode&0111 != 0 {
				return fmt.Errorf("world-writeable executable file found in package (security risk): %s")
			}
			return fmt.Errorf("world-writeable file found in package: %s", path)
		}
		return nil
	})
}

var elfMagic = []byte{'\x7f', 'E', 'L', 'F'}

var isObjectFileRegex = regexp.MustCompile(`\.(a|so|dylib)(\..*)?`)

func strippedLinter(ctx context.Context, _ string, fsys fs.FS) error {
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
		if mode&0111 == 0 && !isObjectFileRegex.MatchString(ext) {
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

func emptyLinter(_ context.Context, pkgname string, fsys fs.FS) error {
	foundfile := false
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
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

func pythonDocsLinter(_ context.Context, _ string, fsys fs.FS) error {
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

func pythonMultiplePackagesLinter(_ context.Context, _ string, fsys fs.FS) error {
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

func pythonTestLinter(_ context.Context, _ string, fsys fs.FS) error {
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

func lintPackageFS(ctx context.Context, pkgname string, fsys fs.FS, linters []string) error {
	// If this is a compat package, do nothing.
	if strings.HasSuffix(pkgname, "-compat") {
		return nil
	}

	errs := []error{}
	for _, linterName := range linters {
		if err := ctx.Err(); err != nil {
			return err
		}
		linter := linterMap[linterName]
		if err := linter.LinterFunc(ctx, linterName, fsys); err != nil {
			errs = append(errs, fmt.Errorf("linter %q failed on package %q: %w; suggest: %s", linterName, pkgname, err, linter.Explain))
		}
	}

	return errors.Join(errs...)
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
func LintBuild(ctx context.Context, packageName string, path string, require, warn []string) error {
	if err := checkLinters(append(require, warn...)); err != nil {
		return err
	}

	log := log.FromContext(ctx)
	fsys := os.DirFS(path)

	if err := lintPackageFS(ctx, packageName, fsys, warn); err != nil {
		log.Warnf(err.Error())
	}
	log.Infof("linting apk: %s", packageName)
	return lintPackageFS(ctx, packageName, fsys, require)
}

// Lint the given APK at the given path
func LintAPK(ctx context.Context, path string, require, warn []string) error {
	if err := checkLinters(append(require, warn...)); err != nil {
		return err
	}

	var r io.Reader
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		if err != nil {
			return fmt.Errorf("creating HTTP request: %w", err)
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

	cfg, err := ini.Load(data)
	if err != nil {
		return fmt.Errorf("could not load .PKGINFO file: %w", err)
	}

	pkgname := cfg.Section("").Key("pkgname").MustString("")
	if pkgname == "" {
		return fmt.Errorf("pkgname is nonexistent")
	}

	log.Infof("linting apk: %s (size: %s)", pkgname, humanize.Bytes(uint64(exp.Size)))
	if err := lintPackageFS(ctx, pkgname, exp.TarFS, warn); err != nil {
		log.Warnf(err.Error())
	}
	return lintPackageFS(ctx, pkgname, exp.TarFS, require)
}
