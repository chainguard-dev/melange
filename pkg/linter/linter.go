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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
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
	"chainguard.dev/melange/pkg/linter/linters"
	"chainguard.dev/melange/pkg/linter/types"
)

type linterFunc func(ctx context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS) error

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
		LinterFunc:      linters.DevLinter,
		Explain:         "If this package is creating /dev nodes, it should use udev instead; otherwise, remove any files in /dev",
		defaultBehavior: Require,
	},
	"documentation": {
		LinterFunc:      linters.DocumentationLinter,
		Explain:         "Place documentation into a separate package or remove it",
		defaultBehavior: Ignore, // TODO: Lots of packages write to READMEs, etc.
	},
	"opt": {
		LinterFunc:      linters.OptLinter,
		Explain:         "This package should be a -compat package",
		defaultBehavior: Warn,
	},
	"object": {
		LinterFunc:      linters.ObjectLinter,
		Explain:         "This package contains intermediate object files (.o files)",
		defaultBehavior: Warn,
	},
	"maninfo": {
		LinterFunc:      linters.ManInfoLinter,
		Explain:         "Place documentation into a separate package or remove it",
		defaultBehavior: Warn,
	},
	"sbom": {
		LinterFunc:      linters.SbomLinter,
		Explain:         "Remove any files in /var/lib/db/sbom from the package",
		defaultBehavior: Warn, // TODO: needs work to be useful
	},
	"setuidgid": {
		LinterFunc:      linters.IsSetUIDOrGIDLinter,
		Explain:         "Unset the setuid/setgid bit on the relevant files, or remove this linter",
		defaultBehavior: Require,
	},
	"srv": {
		LinterFunc:      linters.SrvLinter,
		Explain:         "This package should be a -compat package",
		defaultBehavior: Warn,
	},
	"tempdir": {
		LinterFunc:      linters.TempDirLinter,
		Explain:         "Remove any offending files in temporary dirs in the pipeline",
		defaultBehavior: Require,
	},
	"usrlocal": {
		LinterFunc:      linters.UsrLocalLinter,
		Explain:         "This package should be a -compat package",
		defaultBehavior: Warn,
	},
	"varempty": {
		LinterFunc:      linters.VarEmptyLinter,
		Explain:         "Remove any offending files in /var/empty in the pipeline",
		defaultBehavior: Require,
	},
	"worldwrite": {
		LinterFunc:      linters.WorldWriteableLinter,
		Explain:         "Change the permissions of any permissive files in the package, disable the linter, or make this a -compat package",
		defaultBehavior: Require,
	},
	"strip": {
		LinterFunc:      linters.StrippedLinter,
		Explain:         "Properly strip all binaries in the pipeline",
		defaultBehavior: Warn,
	},
	"infodir": {
		LinterFunc:      linters.InfodirLinter,
		Explain:         "Remove /usr/share/info/dir from the package (run split/infodir)",
		defaultBehavior: Require,
	},
	"empty": {
		LinterFunc:      linters.EmptyLinter,
		Explain:         "Verify that this package is supposed to be empty; if it is, disable this linter; otherwise check the build",
		defaultBehavior: Ignore, // TODO: Needs to ignore packages that specify no-provides.
	},
	"python/docs": {
		LinterFunc:      linters.PythonDocsLinter,
		Explain:         "Remove all docs directories from the package",
		defaultBehavior: Warn,
	},
	"python/multiple": {
		LinterFunc:      linters.PythonMultiplePackagesLinter,
		Explain:         "Split this package up into multiple packages and verify you are not improperly using pip install",
		defaultBehavior: Warn,
	},
	"python/test": {
		LinterFunc:      linters.PythonTestLinter,
		Explain:         "Remove all test directories from the package",
		defaultBehavior: Warn,
	},
	"pkgconf": {
		LinterFunc:      linters.PkgconfTestLinter,
		Explain:         "This package provides files in a pkgconfig directory, please add the pkgconf test pipeline",
		defaultBehavior: Warn,
	},
	"lddcheck": {
		LinterFunc:      linters.LddcheckTestLinter,
		Explain:         "This package provides shared object files, please add the ldd-check test pipeline",
		defaultBehavior: Warn,
	},
	"usrmerge": {
		LinterFunc:      linters.UsrmergeLinter,
		Explain:         "Move binary to /usr/bin",
		defaultBehavior: Require,
	},
	"cudaruntimelib": {
		LinterFunc:      linters.CudaDriverLibLinter,
		Explain:         "CUDA driver-specific libraries should be passed into the container by the host. Installing them in an image could override the host libraries and break GPU support. If this library is needed for build-time linking or ldd-check tests, please use a package containing a stub library instead. For libcuda.so, use nvidia-cuda-cudart-$cuda_version. For libnvidia-ml.so, use nvidia-cuda-nvml-dev-$cuda_version.",
		defaultBehavior: Warn,
	},
	"dll": {
		LinterFunc:      linters.DllLinter,
		Explain:         "This package contains Windows libraries",
		defaultBehavior: Warn,
	},
	"dylib": {
		LinterFunc:      linters.DylibLinter,
		Explain:         "This package contains macOS libraries",
		defaultBehavior: Warn,
	},
	"nonlinux": {
		LinterFunc:      linters.NonLinuxLinter,
		Explain:         "This package contains references to non-Linux paths",
		defaultBehavior: Warn,
	},
	"unsupportedarch": {
		LinterFunc:      linters.UnsupportedArchLinter,
		Explain:         "This package contains references to unsupported architectures (only aarch64/arm64 and amd64/x86_64 are supported)",
		defaultBehavior: Warn,
	},
	"binaryarch": {
		LinterFunc:      linters.BinaryArchLinter,
		Explain:         "This package contains binaries compiled for unsupported architectures (only aarch64/arm64 and amd64/x86_64 binaries are supported)",
		defaultBehavior: Warn,
	},
	"staticarchive": {
		LinterFunc:      linters.StaticArchiveLinter,
		Explain:         "This package contains static archives (.a files)",
		defaultBehavior: Warn,
	},
	"duplicate": {
		LinterFunc:      linters.DuplicateLinter,
		Explain:         "This package contains files with the same name and content in different directories (consider symlinking)",
		defaultBehavior: Warn,
	},
}

// logStructuredDetails displays itemized details for structured errors
func logStructuredDetails(log *clog.Logger, details any) {
	if details == nil {
		return
	}

	switch d := details.(type) {
	case *types.DuplicateFilesDetails:
		for _, dup := range d.Duplicates {
			log.Warnf("    - %s (%d copies, %s wasted)", dup.Basename, dup.Count, dup.WastedSize)
		}
	case *types.NonLinuxDetails:
		for _, ref := range d.References {
			log.Warnf("    - %s (%s)", ref.Path, ref.Platform)
		}
	case *types.UnsupportedArchDetails:
		for _, file := range d.Files {
			log.Warnf("    - %s (%s)", file.Path, file.Arch)
		}
	case *types.BinaryArchDetails:
		for _, bin := range d.Binaries {
			log.Warnf("    - %s (%s)", bin.Path, bin.Arch)
		}
	case *types.SpecialPermissionsDetails:
		for _, file := range d.Files {
			log.Warnf("    - %s (mode: %s, %s)", file.Path, file.Mode, strings.Join(file.Permissions, "+"))
		}
	case *types.WorldWriteableDetails:
		for _, file := range d.Files {
			perms := ""
			if len(file.Permissions) > 0 {
				perms = fmt.Sprintf(" [%s]", strings.Join(file.Permissions, "+"))
			}
			log.Warnf("    - %s (mode: %s)%s", file.Path, file.Mode, perms)
		}
	case *types.UnstrippedBinaryDetails:
		for _, bin := range d.Binaries {
			log.Warnf("    - %s", bin)
		}
	case *types.PythonMultipleDetails:
		for _, pkg := range d.Packages {
			log.Warnf("    - %s", pkg)
		}
	case *types.PathListDetails:
		for _, path := range d.Paths {
			log.Warnf("    - %s", path)
		}
	case *types.UsrMergeDetails:
		for _, path := range d.Paths {
			log.Warnf("    - %s", path)
		}
	}
}

func lintPackageFS(ctx context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS, linters []string, results map[string]*types.PackageLintResults, fullPackageName string) error {
	log := clog.FromContext(ctx)
	var errs []error

	for _, linterName := range linters {
		if err := ctx.Err(); err != nil {
			return err
		}
		linter := linterMap[linterName]
		if err := linter.LinterFunc(ctx, cfg, pkgname, fsys); err != nil {
			// Extract message and structured details if available
			var message string
			var details any

			if structErr, ok := err.(*types.StructuredError); ok {
				message = structErr.Message
				details = structErr.Details
			} else {
				message = err.Error()
			}

			// Split message into lines for better console readability
			messageLines := strings.Split(message, "\n")

			// Log multi-line errors with proper formatting
			log.Warnf("[%s] %s", linterName, messageLines[0])
			for _, line := range messageLines[1:] {
				if line != "" {
					log.Warnf("  %s", line)
				}
			}

			// Initialize package results
			if _, ok := results[pkgname]; !ok {
				results[pkgname] = &types.PackageLintResults{
					PackageName: fullPackageName,
					Findings:    make(map[string][]*types.LinterFinding),
				}
			}

			// Append finding to the linter's findings list
			finding := &types.LinterFinding{
				Message: messageLines[0], // Use first line as the summary message
				Details: details,
			}
			if linter.Explain != "" {
				log.Warnf("  → %s", linter.Explain)
				finding.Explain = linter.Explain
			}

			// Display itemized findings for structured details
			logStructuredDetails(log, details)

			results[pkgname].Findings[linterName] = append(results[pkgname].Findings[linterName], finding)

			errs = append(errs, fmt.Errorf("linter %q failed: %w", linterName, err))
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

// saveLintResults saves the lint results to JSON files in the packages directory
func saveLintResults(ctx context.Context, cfg *config.Configuration, results map[string]*types.PackageLintResults, outputDir, arch string) error {
	log := clog.FromContext(ctx)

	// If cfg is nil, we can't determine version/epoch, so skip saving
	if cfg == nil {
		log.Warnf("skipping lint results persistence: configuration is nil")
		return nil
	}

	// Ensure the package directory exists
	packageDir := filepath.Join(outputDir, arch)
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		return fmt.Errorf("creating package directory: %w", err)
	}

	// Save results for each package
	for pkgName, pkgResults := range results {
		// Generate the filename: lint-{packagename}-{version}-r{epoch}.json
		filename := fmt.Sprintf("lint-%s-%s-r%d.json", pkgName, cfg.Package.Version, cfg.Package.Epoch)
		filepath := filepath.Join(packageDir, filename)

		// Marshal to JSON with indentation for readability
		jsonData, err := json.MarshalIndent(pkgResults, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling lint results for %s: %w", pkgName, err)
		}

		// Write to file
		if err := os.WriteFile(filepath, jsonData, 0o644); err != nil {
			return fmt.Errorf("writing lint results to %s: %w", filepath, err)
		}

		log.Infof("saved lint results to %s", filepath)
	}

	return nil
}

// Lint the given build directory at the given path
// Lint results will be stored as JSON in the packages directory
func LintBuild(ctx context.Context, cfg *config.Configuration, packageName string, require, warn []string, fsys apkofs.FullFS, outputDir, arch string) error {
	if err := checkLinters(append(require, warn...)); err != nil {
		return err
	}

	// map of pkgname -> lint results
	results := make(map[string]*types.PackageLintResults)

	log := clog.FromContext(ctx)
	log.Infof("linting apk: %s", packageName)

	// Construct full package name with version and epoch
	var fullPackageName string
	if cfg != nil {
		fullPackageName = fmt.Sprintf("%s-%s-r%d", packageName, cfg.Package.Version, cfg.Package.Epoch)
	} else {
		fullPackageName = packageName
	}

	// Run warning linters - logs directly, ignores errors
	_ = lintPackageFS(ctx, cfg, packageName, fsys, warn, results, fullPackageName)

	// Run required linters - logs directly, returns errors
	lintErr := lintPackageFS(ctx, cfg, packageName, fsys, require, results, fullPackageName)

	// Save lint results to JSON file if there are any findings
	if len(results) > 0 {
		log.Infof("saving %d package lint result(s) to %s", len(results), filepath.Join(outputDir, arch))
		if err := saveLintResults(ctx, cfg, results, outputDir, arch); err != nil {
			log.Warnf("failed to save lint results: %v", err)
		}
	} else {
		log.Infof("no lint findings to persist for package %s", packageName)
	}

	return lintErr
}

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
			cfg = &config.Configuration{
				Package: config.Package{
					Version: pkgver,
					Epoch:   uint64(epoch),
				},
			}
		}
	}

	// Construct full package name with version and epoch
	fullPackageName := fmt.Sprintf("%s-%s-r%d", pkgname, pkgver, epoch)

	log.Infof("linting apk: %s (size: %s)", pkgname, humanize.Bytes(uint64(exp.Size)))

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
