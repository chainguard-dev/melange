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
	FailOnError bool
	Explain     string
}

type postLinterFunc func(lctx LinterContext, fsys fs.FS) error

type postLinter struct {
	LinterFunc  postLinterFunc
	FailOnError bool
	Explain     string
}

var linterMap = map[string]linter{
	"dev": linter{
		LinterFunc:  devLinter,
		FailOnError: false,
		Explain:     "If this package is creating /dev nodes, it should use udev instead; otherwise, remove any files in /dev",
	},
	"opt": linter{
		LinterFunc:  optLinter,
		FailOnError: false,
		Explain:     "This package should be a -compat package",
	},
	"setuidgid": linter{
		LinterFunc:  isSetUidOrGidLinter,
		FailOnError: false,
		Explain:     "Unset the setuid/setgid bit on the relevant files, or remove this linter",
	},
	"srv": linter{
		LinterFunc:  srvLinter,
		FailOnError: false,
		Explain:     "This package should be a -compat package",
	},
	"tempdir": linter{
		LinterFunc:  tempDirLinter,
		FailOnError: false,
		Explain:     "Remove any offending files in temporary dirs in the pipeline",
	},
	"usrlocal": linter{
		LinterFunc:  usrLocalLinter,
		FailOnError: false,
		Explain:     "This package should be a -compat package",
	},
	"varempty": linter{
		LinterFunc:  varEmptyLinter,
		FailOnError: false,
		Explain:     "Remove any offending files in /var/empty in the pipeline",
	},
	"worldwrite": linter{
		LinterFunc:  worldWriteableLinter,
		FailOnError: false,
		Explain:     "Change the permissions of any world-writeable files in the package, disable the linter, or make this a -compat package",
	},
	"strip": linter{
		LinterFunc:  strippedLinter,
		FailOnError: false,
		Explain:     "Properly strip all binaries in the pipeline",
	},
}

var postLinterMap = map[string]postLinter{
	"empty": postLinter{
		LinterFunc:  emptyPostLinter,
		FailOnError: false,
		Explain:     "Verify that this package is supposed to be empty; if it is, disable this linter; otherwise check the build",
	},
}

var isDevRegex = regexp.MustCompile("^dev/")
var isOptRegex = regexp.MustCompile("^opt/")
var isSrvRegex = regexp.MustCompile("^srv/")
var isTempDirRegex = regexp.MustCompile("^(var/)?(tmp|run)/")
var isUsrLocalRegex = regexp.MustCompile("^usr/local/")
var isVarEmptyRegex = regexp.MustCompile("^var/empty/")
var isCompatPackageRegex = regexp.MustCompile("-compat$")
var isObjectFileRegex = regexp.MustCompile(`\.(a|so|dylib)(\..*)?`)

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

func isSetUidOrGidLinter(_ LinterContext, _ string, d fs.DirEntry) error {
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
		// We don't particularly care if this fails, it means it's probably not an ELF file
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
	walkCb := func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if path == "." {
			// Skip root
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

func (lctx LinterContext) LintPackageFs(fsys fs.FS, warn func(error), linters []string) error {
	// If this is a compat package, do nothing.
	if isCompatPackageRegex.MatchString(lctx.pkgname) {
		return nil
	}

	postLinters := []string{}
	walkCb := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("Error traversing tree at %s: %w", path, err)
		}

		for _, linterName := range linters {
			linter, present := linterMap[linterName]
			if !present {
				// Check if it's a post linter instead
				_, present = postLinterMap[linterName]
				if !present {
					return fmt.Errorf("Linter %s is unknown", linterName)
				}

				postLinters = append(postLinters, linterName)
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

	if err := fs.WalkDir(fsys, ".", walkCb); err != nil {
		return err
	}

	// Run post-walking linters
	for _, linterName := range postLinters {
		linter := postLinterMap[linterName]
		err := linter.LinterFunc(lctx, fsys)
		if err != nil {
			if linter.FailOnError {
				return fmt.Errorf("Linter %s failed; suggest: %s", linterName, linter.Explain)
			}
			warn(err)
		}
	}

	return nil
}

func LintApk(ctx context.Context, path string, warn func(error), linters []string) error {
	apkfs, err := apkofs.NewAPKFS(ctx, path)
	if err != nil {
		return err
	}

	// Get the package name
	f, err := apkfs.Open("./.PKGINFO")
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	cfg, err := ini.Load(data)
	if err != nil {
		return err
	}

	pkgname := cfg.Section("").Key("pkgname").MustString("")
	if pkgname == "" {
		return fmt.Errorf("pkgname is nonexistent")
	}

	lctx := NewLinterContext(pkgname, apkfs)

	return lctx.LintPackageFs(apkfs, warn, linters)
}
