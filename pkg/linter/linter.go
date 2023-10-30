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
	"context"
	"debug/elf"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	linter_defaults "chainguard.dev/melange/pkg/linter/defaults"
	apkofs "github.com/chainguard-dev/go-apk/pkg/fs"

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
	"dev": linter{
		LinterFunc:  devLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "If this package is creating /dev nodes, it should use udev instead; otherwise, remove any files in /dev",
	},
	"opt": linter{
		LinterFunc:  optLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "This package should be a -compat package",
	},
	"sbom": linter{
		LinterFunc:  sbomLinter,
		LinterClass: linter_defaults.LinterClassBuild,
		FailOnError: false,
		Explain:     "Remove any files in /var/lib/db/sbom from the package",
	},
	"setuidgid": linter{
		LinterFunc:  isSetUidOrGidLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Unset the setuid/setgid bit on the relevant files, or remove this linter",
	},
	"srv": linter{
		LinterFunc:  srvLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "This package should be a -compat package",
	},
	"tempdir": linter{
		LinterFunc:  tempDirLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Remove any offending files in temporary dirs in the pipeline",
	},
	"usrlocal": linter{
		LinterFunc:  usrLocalLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "This package should be a -compat package",
	},
	"varempty": linter{
		LinterFunc:  varEmptyLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Remove any offending files in /var/empty in the pipeline",
	},
	"worldwrite": linter{
		LinterFunc:  worldWriteableLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Change the permissions of any world-writeable files in the package, disable the linter, or make this a -compat package",
	},
	"strip": linter{
		LinterFunc:  strippedLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Properly strip all binaries in the pipeline",
	},
}

var postLinterMap = map[string]postLinter{
	"empty": postLinter{
		LinterFunc:  emptyPostLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Verify that this package is supposed to be empty; if it is, disable this linter; otherwise check the build",
	},
	"python/docs": postLinter{
		LinterFunc:  pythonDocsPostLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Remove all docs directories from the package",
	},
	"python/multiple": postLinter{
		LinterFunc:  pythonMultiplePackagesPostLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Split this package up into multiple packages and verify you are not improperly using pip install",
	},
	"python/test": postLinter{
		LinterFunc:  pythonTestPostLinter,
		LinterClass: linter_defaults.LinterClassBuild | linter_defaults.LinterClassApk,
		FailOnError: false,
		Explain:     "Remove all test directories from the package",
	},
}

var isDevRegex = regexp.MustCompile("^dev/")
var isOptRegex = regexp.MustCompile("^opt/")
var isSrvRegex = regexp.MustCompile("^srv/")
var isTempDirRegex = regexp.MustCompile("^(var/)?(tmp|run)/")
var isUsrLocalRegex = regexp.MustCompile("^usr/local/")
var isVarEmptyRegex = regexp.MustCompile("^var/empty/")
var isCompatPackageRegex = regexp.MustCompile("-compat$")

// XXX(Elizafox) - Go's ELF parser doesn't understand .a files, which is fair given they're just an archive.
var isObjectFileRegex = regexp.MustCompile(`\.(so|dylib)(\..*)?`)
var isSbomPathRegex = regexp.MustCompile("^var/lib/db/sbom/")

// Determine if a path should be ignored by a linter
func isIgnoredPath(path string) bool {
	return isSbomPathRegex.MatchString(path)
}

func devLinter(_ LinterContext, path string, _ fs.DirEntry) error {
	if isDevRegex.MatchString(path) {
		return fmt.Errorf("Package writes to /dev")
	}

	return nil
}

func optLinter(_ LinterContext, path string, _ fs.DirEntry) error {
	if isOptRegex.MatchString(path) {
		return fmt.Errorf("Package writes to /opt")
	}

	return nil
}

func isSetUidOrGidLinter(_ LinterContext, path string, d fs.DirEntry) error {
	if isIgnoredPath(path) {
		return nil
	}

	info, err := d.Info()
	if err != nil {
		return err
	}

	mode := info.Mode()
	if mode&fs.ModeSetuid != 0 {
		return fmt.Errorf("File is setuid")
	} else if mode&fs.ModeSetgid != 0 {
		return fmt.Errorf("File is setgid")
	}

	return nil
}

func sbomLinter(lctx LinterContext, path string, _ fs.DirEntry) error {
	if isSbomPathRegex.MatchString(path) {
		return fmt.Errorf("Package writes to /var/lib/db/sbom")
	}

	return nil
}

func srvLinter(_ LinterContext, path string, _ fs.DirEntry) error {
	if isSrvRegex.MatchString(path) {
		return fmt.Errorf("Package writes to /srv")
	}

	return nil
}

func tempDirLinter(_ LinterContext, path string, _ fs.DirEntry) error {
	if isTempDirRegex.MatchString(path) {
		return fmt.Errorf("Package writes to a temp dir")
	}

	return nil
}

func usrLocalLinter(_ LinterContext, path string, _ fs.DirEntry) error {
	if isUsrLocalRegex.MatchString(path) {
		return fmt.Errorf("/usr/local path found in non-compat package")
	}

	return nil
}

func varEmptyLinter(_ LinterContext, path string, _ fs.DirEntry) error {
	if isVarEmptyRegex.MatchString(path) {
		return fmt.Errorf("Package writes to /var/empty")
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
			return fmt.Errorf("World-writeable executable file found in package (security risk)")
		} else {
			return fmt.Errorf("World-writeable file found in package")
		}
	}

	return nil
}

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

	ext := filepath.Ext(path)
	mode := info.Mode()
	if mode&0111 == 0 && !isObjectFileRegex.MatchString(ext) {
		// Not an executable or library
		return nil
	}

	reader, err := lctx.fsys.Open(path)
	if err != nil {
		return fmt.Errorf("Could not open file for reading: %v", err)
	}
	defer reader.Close()

	// TODO(Elizafox) - .a object files, which needs archive handling support.

	// XXX(Elizafox) - fs.Open doesn't support the ReaderAt interface so we copy it to a temp file.
	// This sucks but what can you do?
	tempfile, err := os.CreateTemp("", "melange.XXXXX")
	if err != nil {
		return fmt.Errorf("Could not create temporary file: %v", err)
	}
	defer tempfile.Close()
	defer os.Remove(tempfile.Name())

	_, err = io.Copy(tempfile, reader)
	if err != nil {
		return fmt.Errorf("Could not write to temporary file: %v", err)
	}

	_, err = tempfile.Seek(0, 0)
	if err != nil {
		return fmt.Errorf("Could not rewind temporary file: %v", err)
	}

	file, err := elf.NewFile(tempfile)
	if err != nil {
		// XXX(Elizafox) - I hate Go's error handling and there's no better way.
		// It literally gives us nothing but the string. Why Go... WHY...???
		if strings.Contains(err.Error(), "bad magic number") {
			// This is probably just a script or something. Filter it for less noise.
			return nil
		}

		// We don't particularly care if this fails otherwise.
		fmt.Printf("WARNING: Could not open file %q as executable: %v\n", path, err)
		return nil
	}
	defer file.Close()

	// No debug sections allowed
	if file.Section(".debug") != nil || file.Section(".zdebug") != nil {
		return fmt.Errorf("File is not stripped")
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

	return fmt.Errorf("Package is empty but no-provides is not set")
}

func getPythonSitePackages(fsys fs.FS) (matches []string, err error) {
	pythondirs, err := fs.Glob(fsys, filepath.Join("usr", "lib", "python3.*"))
	if err != nil {
		// Shouldn't get here, per the Go docs.
		err = fmt.Errorf("Error checking for Python site directories: %w", err)
		return
	}

	if len(pythondirs) == 0 {
		// Nothing to do
		return
	} else if len(pythondirs) > 1 {
		err = fmt.Errorf("More than one Python version detected: %d found", len(pythondirs))
		return
	}

	matches, err = fs.Glob(fsys, filepath.Join(pythondirs[0], "site-packages", "*"))
	if err != nil {
		// Shouldn't get here as well.
		err = fmt.Errorf("Error checking for Python packages: %w", err)
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
			return fmt.Errorf("Docs directory encountered in Python site-packages directory")
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
		return fmt.Errorf("Multiple Python packages detected: %d found (%s)", len(slmatches), smatches)
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
			return fmt.Errorf("Tests directory encountered in Python site-packages directory")
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
	if isCompatPackageRegex.MatchString(lctx.pkgname) {
		return nil
	}

	// Verify all linters are known
	badLints := CheckValidLinters(linters)
	if len(badLints) > 0 {
		return fmt.Errorf("Unknown linter(s): %s", strings.Join(badLints, ", "))
	}

	postLinters := []string{}
	walkCb := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("Error traversing tree at %s: %w", path, err)
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
					return fmt.Errorf("Linter %s failed at path %q: %w; suggest: %s", linterName, path, err, linter.Explain)
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
				return fmt.Errorf("Linter %s failed; suggest: %s", linterName, linter.Explain)
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
	apkfsctrl, err := apkofs.NewAPKFS(ctx, path, apkofs.APKFSControl)
	if err != nil {
		return fmt.Errorf("Could not open APKFS: %w", err)
	}

	// Get the package name
	f, err := apkfsctrl.Open("/.PKGINFO")
	if err != nil {
		return fmt.Errorf("Could not open .PKGINFO file: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("Could not read from package: %w", err)
	}

	cfg, err := ini.Load(data)
	if err != nil {
		return fmt.Errorf("Could not load .PKGINFO file: %w", err)
	}

	pkgname := cfg.Section("").Key("pkgname").MustString("")
	if pkgname == "" {
		return fmt.Errorf("pkgname is nonexistent")
	}

	apkfspkg, err := apkofs.NewAPKFS(ctx, path, apkofs.APKFSPackage)
	if err != nil {
		return fmt.Errorf("Could not open APKFS: %w", err)
	}

	lctx := NewLinterContext(pkgname, apkfspkg)

	return lctx.lintPackageFs(warn, linters, linter_defaults.LinterClassApk)
}
