// Copyright 2025 Chainguard, Inc.
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

package linters

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/linter/types"
)

func GetPythonSitePackages(fsys fs.FS) (matches []string, err error) {
	pythondirs, err := fs.Glob(fsys, filepath.Join("usr", "lib", "python3.*"))
	if err != nil {
		// Shouldn't get here, per the Go docs.
		err = fmt.Errorf("error checking for Python site directories: %w", err)
		return matches, err
	}

	if len(pythondirs) == 0 {
		// Nothing to do
		return matches, err
	} else if len(pythondirs) > 1 {
		err = fmt.Errorf("more than one Python version detected: %d found", len(pythondirs))
		return matches, err
	}

	matches, err = fs.Glob(fsys, filepath.Join(pythondirs[0], "site-packages", "*"))
	if err != nil {
		// Shouldn't get here as well.
		err = fmt.Errorf("error checking for Python packages: %w", err)
		return matches, err
	}

	return matches, err
}

func PythonDocsLinter(_ context.Context, _ *config.Configuration, _ string, fsys fs.FS) error {
	packages, err := GetPythonSitePackages(fsys)
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

func PythonMultiplePackagesLinter(_ context.Context, _ *config.Configuration, _ string, fsys fs.FS) error {
	packages, err := GetPythonSitePackages(fsys)
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
		slices.Sort(slmatches)

		details := &types.PythonMultipleDetails{
			Count:    len(slmatches),
			Packages: slmatches,
		}

		smatches := strings.Join(slmatches, ", ")
		message := fmt.Sprintf("multiple Python packages detected: %d found (%s)", len(slmatches), smatches)

		return types.NewStructuredError(message, details)
	}

	return nil
}

func PythonTestLinter(_ context.Context, _ *config.Configuration, _ string, fsys fs.FS) error {
	packages, err := GetPythonSitePackages(fsys)
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
