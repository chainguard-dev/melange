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

package linter

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/apk/expandapk"
	"github.com/chainguard-dev/clog"
	"github.com/dustin/go-humanize"
	"go.yaml.in/yaml/v2"
	"gopkg.in/ini.v1"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/linter/types"
)

// Lint the given APK at the given path
// If outputDir is provided, lint results will be saved to JSON files
func LintAPK(ctx context.Context, path string, require, warn []string, outputDir string) error {
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
		file, err := os.Open(path) // #nosec G304 - User-specified APK package for linting
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

	// Get the package name and metadata
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

	section := pkginfo.Section("")
	pkgname := section.Key("pkgname").MustString("")
	if pkgname == "" {
		return fmt.Errorf("pkgname is nonexistent")
	}

	// Extract version and epoch for synthetic config (for JSON file naming)
	pkgver := section.Key("pkgver").MustString("")
	epochStr := section.Key("epoch").MustString("0")
	epoch, _ := strconv.Atoi(epochStr)

	// Extract architecture from PKGINFO
	arch := section.Key("arch").MustString("")

	cfg, err := parseMelangeYaml(exp.ControlFS)
	if err != nil {
		// TODO: Consider making this fatal if the universe gets rebuilt with new melange.
		clog.FromContext(ctx).Warnf("parsing .melange.yaml: %v", err)

		// Create a synthetic config for JSON file naming
		if cfg == nil && outputDir != "" {
			// Ensure epoch is non-negative before conversion
			epochUint := uint64(0)
			if epoch > 0 {
				epochUint = uint64(epoch)
			}
			cfg = &config.Configuration{
				Package: config.Package{
					Version: pkgver,
					Epoch:   epochUint,
				},
			}
		}
	}

	// Construct full package name with version and epoch
	fullPackageName := fmt.Sprintf("%s-%s-r%d", pkgname, pkgver, epoch)

	// exp.Size is int but sizes should be non-negative
	size := uint64(0)
	if exp.Size > 0 {
		size = uint64(exp.Size)
	}
	log.Infof("linting apk: %s (size: %s)", pkgname, humanize.Bytes(size))

	// map of pkgname -> lint results
	results := make(map[string]*types.PackageLintResults)

	// Run warning linters - logs directly, ignores errors
	_ = lintPackageFS(ctx, cfg, pkgname, exp.TarFS, warn, results, fullPackageName)

	// Run required linters - logs directly, returns errors
	lintErr := lintPackageFS(ctx, cfg, pkgname, exp.TarFS, require, results, fullPackageName)

	// Save lint results to JSON file if outputDir is provided and there are findings
	if outputDir != "" && len(results) > 0 {
		log.Infof("saving %d package lint result(s) to %s", len(results), filepath.Join(outputDir, arch))
		if err := saveLintResults(ctx, cfg, results, outputDir, arch); err != nil {
			log.Warnf("failed to save lint results: %v", err)
		}
	} else if outputDir != "" {
		log.Infof("no lint findings to persist for package %s", pkgname)
	}

	return lintErr
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
