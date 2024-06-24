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
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"chainguard.dev/apko/pkg/apk/expandapk"
	linter_defaults "chainguard.dev/melange/pkg/linter/defaults"

	"gopkg.in/ini.v1"
)

type LinterContext struct {
	pkgname string
	fsys    fs.FS
}

func NewLinterContext(name string, fsys fs.FS) LinterContext {
	return LinterContext{name, fsys}
}

type linterFunc func(lctx LinterContext, path string, d fs.DirEntry) error

type linter struct {
	LinterFunc  linterFunc
	LinterClass linter_defaults.LinterClass
	FailOnError bool
	Explain     string
}

type postLinterFunc func(lctx LinterContext, fsys fs.FS) error

type postLinter struct {
	LinterFunc  postLinterFunc
	LinterClass linter_defaults.LinterClass
	FailOnError bool
	Explain     string
}

var linterMap = map[string]linter{
	"dev": {
		LinterFunc:  devLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "If this package is creating /dev nodes, it should use udev instead; otherwise, remove any files in /dev",
	},
	"documentation": {
		LinterFunc:  documentationLinter,
		LinterClass: linter_defaults.LinterClassApk | linter_defaults.LinterClassBuild,
		FailOnError: false,
		Explain:     "Place documentation into a separate package or remove it",
	},
	"opt": {
		LinterFunc:  optLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "This package should be a -compat package",
	},
	"object": {
		LinterFunc:  objectLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "This package contains intermediate object files",
	},
	"sbom": {
		LinterFunc:  sbomLinter,
		LinterClass: linter_defaults.LinterClassBuild,
		FailOnError: false,
		Explain:     "Remove any files in /var/lib/db/sbom from the package",
	},
	"setuidgid": {
		LinterFunc:  isSetUIDOrGIDLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Unset the setuid/setgid bit on the relevant files, or remove this linter",
	},
	"srv": {
		LinterFunc:  srvLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "This package should be a -compat package",
	},
	"tempdir": {
		LinterFunc:  tempDirLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Remove any offending files in temporary dirs in the pipeline",
	},
	"usrlocal": {
		LinterFunc:  usrLocalLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "This package should be a -compat package",
	},
	"varempty": {
		LinterFunc:  varEmptyLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Remove any offending files in /var/empty in the pipeline",
	},
	"worldwrite": {
		LinterFunc:  worldWriteableLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Change the permissions of any world-writeable files in the package, disable the linter, or make this a -compat package",
	},
	"strip": {
		LinterFunc:  strippedLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Properly strip all binaries in the pipeline",
	},
	"infodir": {
		LinterFunc:  infodirLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: true,
		Explain:     "Remove /usr/share/info/dir from the package (run split/infodir)",
	},
}

var postLinterMap = map[string]postLinter{
	"empty": {
		LinterFunc:  emptyPostLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Verify that this package is supposed to be empty; if it is, disable this linter; otherwise check the build",
	},
	"python/docs": {
		LinterFunc:  pythonDocsPostLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Remove all docs directories from the package",
	},
	"python/multiple": {
		LinterFunc:  pythonMultiplePackagesPostLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Split this package up into multiple packages and verify you are not improperly using pip install",
	},
	"python/test": {
		LinterFunc:  pythonTestPostLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Remove all test directories from the package",
	},
}

// Determine if a path should be ignored by a linter
func isIgnoredPath(path string) bool {
	return strings.HasPrefix(path, "var/lib/db/sbom/")
}

func devLinter(_ LinterContext, path string, _ fs.DirEntry) error {
	if strings.HasPrefix(path, "dev/") {
		return fmt.Errorf("package writes to /dev")
	}

	return nil
}

func optLinter(_ LinterContext, path string, _ fs.DirEntry) error {
	if strings.HasPrefix(path, "opt/") {
		return fmt.Errorf("package writes to /opt")
	}

	return nil
}
func objectLinter(_ LinterContext, path string, _ fs.DirEntry) error {
	if filepath.Ext(path) == ".o" {
		return fmt.Errorf("package contains intermediate object file '%s'. This is usually wrong. In most cases they should be removed", path)
	}

	return nil
}

var isDocumentationFileRegex = regexp.MustCompile(`(?:READ(?:\.?ME)?|TODO|CREDITS|\.(?:md|docx?|rst|[0-9][a-z]))$`)

func documentationLinter(lc LinterContext, path string, _ fs.DirEntry) error {
	if isDocumentationFileRegex.MatchString(path) && !strings.HasSuffix(lc.pkgname, "-doc") {
		return fmt.Errorf("package contains documentation files but is not a documentation package")
	}
	return nil
}

func isSetUIDOrGIDLinter(_ LinterContext, path string, d fs.DirEntry) error {
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
}

func sbomLinter(_ LinterContext, path string, _ fs.DirEntry) error {
	if strings.HasPrefix(path, "var/lib/db/sbom/") {
		return fmt.Errorf("package writes to /var/lib/db/sbom")
	}
	return nil
}

func infodirLinter(_ LinterContext, path string, _ fs.DirEntry) error {
	if strings.HasPrefix(path, "usr/share/info/dir") {
		return fmt.Errorf("package writes to /usr/share/info/dir")
	}
	return nil
}

func srvLinter(_ LinterContext, path string, _ fs.DirEntry) error {
	if strings.HasPrefix(path, "srv/") {
		return fmt.Errorf("package writes to /srv")
	}
	return nil
}

func tempDirLinter(_ LinterContext, path string, _ fs.DirEntry) error {
	if strings.HasPrefix(path, "var/tmp/") || strings.HasPrefix(path, "var/run/") {
		return fmt.Errorf("package writes to a temp dir")
	}
	return nil
}

func usrLocalLinter(_ LinterContext, path string, _ fs.DirEntry) error {
	if strings.HasPrefix(path, "usr/local/") {
		return fmt.Errorf("/usr/local path found in non-compat package")
	}
	return nil
}

func varEmptyLinter(_ LinterContext, path string, _ fs.DirEntry) error {
	if strings.HasPrefix(path, "var/empty/") {
		return fmt.Errorf("package writes to /var/empty")
	}

	return nil
}

func worldWriteableLinter(_ LinterContext, path string, d fs.DirEntry) error {
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

	mode := info.Mode()
	if mode&0002 != 0 {
		if mode&0111 != 0 {
			return fmt.Errorf("world-writeable executable file found in package (security risk)")
		}
		return fmt.Errorf("world-writeable file found in package")
	}

	return nil
}

var elfMagic = []byte{'\x7f', 'E', 'L', 'F'}

var isObjectFileRegex = regexp.MustCompile(`\.(a|so|dylib)(\..*)?`)

func strippedLinter(lctx LinterContext, path string, d fs.DirEntry) error {
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

	f, err := lctx.fsys.Open(path)
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
		// We don't particularly care if this fails otherwise.
		fmt.Printf("WARNING: Could not open file %q as executable: %v\n", path, err)
	}
	defer file.Close()

	// No debug sections allowed
	if file.Section(".debug") != nil || file.Section(".zdebug") != nil {
		return fmt.Errorf("ELF file is not stripped")
	}

	return nil
}

func emptyPostLinter(_ LinterContext, fsys fs.FS) error {
	foundfile := false
	walkCb := func(path string, d fs.DirEntry, err error) error {
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
	}

	err := fs.WalkDir(fsys, ".", walkCb)
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

func pythonDocsPostLinter(_ LinterContext, fsys fs.FS) error {
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

func pythonMultiplePackagesPostLinter(_ LinterContext, fsys fs.FS) error {
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

func pythonTestPostLinter(_ LinterContext, fsys fs.FS) error {
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

// Checks if the linters in the given slice are known linters
// Returns an empty slice if all linters are known, otherwise a slice with all the bad linters
func CheckValidLinters(check []string) []string {
	linters := []string{}
	for _, l := range check {
		_, present := linterMap[l]
		if present {
			continue
		}

		// Check post-linter map too
		_, present = postLinterMap[l]
		if !present {
			linters = append(linters, l)
		}
	}

	return linters
}

func (lctx LinterContext) lintPackageFs(warn func(error), linters []string, linterClass linter_defaults.LinterClass) error {
	// If this is a compat package, do nothing.
	if strings.HasSuffix(lctx.pkgname, "-compat") {
		return nil
	}

	// Verify all linters are known
	badLints := CheckValidLinters(linters)
	if len(badLints) > 0 {
		return fmt.Errorf("unknown linter(s): %s", strings.Join(badLints, ", "))
	}

	postLinters := []string{}
	walkCb := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error traversing tree at %s: %w", path, err)
		}

		for _, linterName := range linters {
			linter, present := linterMap[linterName]
			if !present {
				// We already checked that all linters are valid, so this must be a post linter
				postLinters = append(postLinters, linterName)
				continue
			}

			if linter.LinterClass&linterClass == 0 {
				// Linter not in class, ignored
				continue
			}

			err = linter.LinterFunc(lctx, path, d)
			if err != nil {
				if linter.FailOnError {
					return fmt.Errorf("linter %s failed at path %q: %w; suggest: %s", linterName, path, err, linter.Explain)
				}
				warn(err)
			}
		}

		return nil
	}

	if err := fs.WalkDir(lctx.fsys, ".", walkCb); err != nil {
		return err
	}

	// Run post-walking linters
	for _, linterName := range postLinters {
		linter := postLinterMap[linterName]

		if linter.LinterClass&linterClass == 0 {
			// Linter not in class, ignored
			continue
		}

		err := linter.LinterFunc(lctx, lctx.fsys)
		if err != nil {
			if linter.FailOnError {
				return fmt.Errorf("linter %s failed; suggest: %s", linterName, linter.Explain)
			}
			warn(err)
		}
	}

	return nil
}

// Lint the given build directory at the given path
func LintBuild(packageName string, path string, warn func(error), linters []string) error {
	fsys := os.DirFS(path)

	lctx := NewLinterContext(packageName, fsys)

	return lctx.lintPackageFs(warn, linters, linter_defaults.LinterClassBuild)
}

// Lint the given APK at the given path
func LintApk(ctx context.Context, path string, warn func(error), linters []string) error {
	var r io.Reader
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		resp, err := http.Get(path)
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

	lctx := NewLinterContext(pkgname, exp.TarFS)

	return lctx.lintPackageFs(warn, linters, linter_defaults.LinterClassApk)
}
