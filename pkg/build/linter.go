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

package build

import (
	"fmt"
	"io/fs"
	"regexp"

	"chainguard.dev/melange/pkg/config"
)

type LinterContext struct {
	pkgname string
	cfg     *config.Configuration
	chk     *config.Checks
}

type linterFunc func(lctx LinterContext, path string, d fs.DirEntry) error

type linter struct {
	LinterFunc linterFunc
	Explain    string
}

var linterMap = map[string]linter{
	"dev":       linter{devLinter, "If this package is creating /dev nodes, it should use udev instead; otherwise, remove any files in /dev"},
	"opt":       linter{optLinter, "This package should be a -compat package"},
	"setuidgid": linter{isSetUidOrGidLinter, "Unset the setuid/setgid bit on the relevant files, or remove this linter"},
	"srv":       linter{srvLinter, "This package should be a -compat package"},
	"tempdir":   linter{tempDirLinter, "Remove any offending files in temporary dirs in the pipeline"},
	"usrlocal":  linter{usrLocalLinter, "This package should be a -compat package"},
	"varempty":  linter{varEmptyLinter, "Remove any offending files in /var/empty in the pipeline"},
}

var isDevRegex = regexp.MustCompile("^dev/")
var isOptRegex = regexp.MustCompile("^opt/")
var isSrvRegex = regexp.MustCompile("^srv/")
var isTempDirRegex = regexp.MustCompile("^(var/)?(tmp|run)/")
var isUsrLocalRegex = regexp.MustCompile("^usr/local/")
var isVarEmptyRegex = regexp.MustCompile("^var/empty/")
var isCompatPackage = regexp.MustCompile("-compat$")

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

func lintPackageFs(lctx LinterContext, fsys fs.FS, linters []string) error {
	// If this is a compat package, do nothing.
	if isCompatPackage.MatchString(lctx.pkgname) {
		return nil
	}

	walkCb := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("Error traversing tree at %s: %w", path, err)
		}

		for _, linterName := range linters {
			linter, present := linterMap[linterName]
			if !present {
				return fmt.Errorf("Linter %s is unknown", linterName)
			}

			err = linter.LinterFunc(lctx, path, d)
			if err != nil {
				return fmt.Errorf("Linter %s failed at path \"%s\": %w; suggest: %s", linterName, path, err, linter.Explain)
			}
		}

		return nil
	}

	err := fs.WalkDir(fsys, ".", walkCb)
	if err != nil {
		return err
	}

	return nil
}
