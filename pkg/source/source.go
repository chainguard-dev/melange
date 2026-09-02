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

package source

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"github.com/chainguard-dev/clog"

	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/util"
)

// sourceRunStep dispatches a single source-fetching pipeline step to its native
// handler. It is a package variable so tests can stub it out.
var sourceRunStep = runStep

// runStep executes one supported source-fetching step (fetch, git-checkout, or
// patch) natively in Go. Input values are resolved through the substitution map
// (so `${{package.version}}` and friends still work) and are then used as data:
// a URL, a git remote, and argv elements.
func runStep(ctx context.Context, step config.Pipeline, sm *build.SubstitutionMap, _ bool, destDir string) error {
	// resolve returns the substituted value for a `with:` input, or "" if the
	// input was not provided. The result is used as data.
	resolve := func(key string) (string, error) {
		v, ok := step.With[key]
		if !ok {
			return "", nil
		}
		return util.MutateStringFromMap(sm.Substitutions, v)
	}

	switch step.Uses {
	case "fetch":
		return runFetchStep(ctx, resolve, destDir)
	case "git-checkout":
		return runGitCheckoutStep(ctx, resolve, destDir)
	case "patch":
		return runPatchStep(ctx, resolve, destDir)
	default:
		return fmt.Errorf("unsupported source step %q", step.Uses)
	}
}

func runFetchStep(ctx context.Context, resolve func(string) (string, error), destDir string) error {
	get := func(dst *string, key string) error {
		v, err := resolve(key)
		if err != nil {
			return err
		}
		*dst = v
		return nil
	}

	opts := &FetchOptions{WorkspaceDir: destDir}
	var stripRaw, extractRaw, deleteRaw string
	for dst, key := range map[*string]string{
		&opts.URI:            "uri",
		&opts.Directory:      "directory",
		&opts.ExpectedSHA256: "expected-sha256",
		&opts.ExpectedSHA512: "expected-sha512",
		&stripRaw:            "strip-components",
		&extractRaw:          "extract",
		&deleteRaw:           "delete",
	} {
		if err := get(dst, key); err != nil {
			return err
		}
	}

	opts.StripComponents = parseIntDefault(stripRaw, 1)
	opts.Extract = parseBoolDefault(extractRaw, true)
	opts.Delete = parseBoolDefault(deleteRaw, false)

	return Fetch(ctx, opts)
}

func runGitCheckoutStep(ctx context.Context, resolve func(string) (string, error), destDir string) error {
	repo, err := resolve("repository")
	if err != nil {
		return err
	}
	dest, err := resolve("destination")
	if err != nil {
		return err
	}
	// Keep the clone destination inside the workspace.
	if dest == "" || dest == "." {
		dest = destDir
	} else if dest, err = secureJoin(destDir, dest, "git-checkout destination"); err != nil {
		return err
	}
	expectedCommit, err := resolve("expected-commit")
	if err != nil {
		return err
	}
	cherryPicks, err := resolve("cherry-picks")
	if err != nil {
		return err
	}
	recurse, err := resolve("recurse-submodules")
	if err != nil {
		return err
	}

	return GitCheckout(ctx, &GitCheckoutOptions{
		Repository:        repo,
		Destination:       dest,
		ExpectedCommit:    expectedCommit,
		CherryPicks:       cherryPicks,
		WorkspaceDir:      destDir,
		RecurseSubmodules: parseBoolDefault(recurse, false),
	})
}

func runPatchStep(ctx context.Context, resolve func(string) (string, error), destDir string) error {
	patches, err := resolve("patches")
	if err != nil {
		return err
	}
	series, err := resolve("series")
	if err != nil {
		return err
	}
	stripRaw, err := resolve("strip-components")
	if err != nil {
		return err
	}
	fuzzRaw, err := resolve("fuzz")
	if err != nil {
		return err
	}

	// A quilt-style series file lists patch filenames, one per line (with '#'
	// comments). Fold it into the patch list when no explicit patches are given.
	if strings.TrimSpace(patches) == "" && strings.TrimSpace(series) != "" {
		// Keep the series path within the workspace directory.
		seriesPath, err := secureJoin(destDir, series, "series")
		if err != nil {
			return err
		}
		data, err := os.ReadFile(seriesPath) // #nosec G304 - series path resolves inside the workspace dir
		if err != nil {
			return fmt.Errorf("reading series file %q: %w", seriesPath, err)
		}
		var names []string
		for line := range strings.SplitSeq(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			names = append(names, line)
		}
		patches = strings.Join(names, " ")
	}

	if strings.TrimSpace(patches) == "" {
		return fmt.Errorf("patch step: neither 'patches' nor 'series' was set")
	}

	return applyPatchStep(ctx, patches, parseIntDefault(stripRaw, 1), parseIntDefault(fuzzRaw, 2), destDir)
}

func parseIntDefault(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func parseBoolDefault(s string, def bool) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	return s == "true"
}

// Function to extract the .melange.yaml from an apk package.
func extractMelangeYamlFromTarball(apkPath, destDir string) error {
	// Open the tarball file, since that's what an apk package is.
	file, err := os.Open(apkPath) // #nosec G304 - User-specified APK source package
	if err != nil {
		return fmt.Errorf("failed to open apk package: %w", err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of tarball
		}
		if err != nil {
			return fmt.Errorf("failed to read apk tar contents: %w", err)
		}

		// Look for the .melange.yaml file
		if header.Typeflag == tar.TypeReg && filepath.Base(header.Name) == ".melange.yaml" {
			if err := os.MkdirAll(destDir, 0o755); err != nil {
				return fmt.Errorf("failed to create destination directory: %w", err)
			}

			destFilePath := filepath.Join(destDir, ".melange.yaml")
			destFile, err := os.Create(destFilePath) // #nosec G304 - Extracting melange config from APK
			if err != nil {
				return fmt.Errorf("failed to create destination file: %w", err)
			}
			defer destFile.Close()

			// #nosec G110 - Extracting known .melange.yaml file from trusted APK package
			if _, err := io.Copy(destFile, tarReader); err != nil {
				return fmt.Errorf("failed to extract .melange.yaml: %w", err)
			}

			return nil
		}
	}

	return fmt.Errorf("target package does not contain melange metadata")
}

// FetchSourceFromMelange tries its best to fetch the source from a melange yaml or an apk package.
func FetchSourceFromMelange(ctx context.Context, filePath, destDir string) (*config.Configuration, error) {
	log := clog.FromContext(ctx)

	// Make sure destDir is an absolute path
	destDir, err := filepath.Abs(destDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for destination directory: %w", err)
	}

	// Temporary directory for all ephemeral stuff. Best to keep this separate
	// as we'll be extracting our pipelines code there, and we wouldn't want
	// anyone to cause harm by overwriting the pipelines code.
	tmpDir, err := os.MkdirTemp("", "melange-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Check if the file is an apk package
	isApk := false
	if filepath.Ext(filePath) == ".apk" {
		if err := extractMelangeYamlFromTarball(filePath, tmpDir); err != nil {
			return nil, fmt.Errorf("failed to extract melange yaml from apk package: %w", err)
		}
		filePath = filepath.Join(tmpDir, ".melange.yaml")
		isApk = true
	}

	// Parsing the configuration file. It's still not ready for 'consumption'
	// though!
	cfg, err := config.ParseConfiguration(ctx, filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse melange config: %w", err)
	}

	// Prepare the substitution map so that input values referencing built-in
	// variables (e.g. ${{package.version}}) resolve correctly. The supported
	// source steps are dispatched to native Go handlers below, which treat
	// every substituted value as data.
	sm, err := build.NewSubstitutionMap(cfg, "amd64", "gnu", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create substitution map: %w", err)
	}

	// During command execution we change the working directory. We need to
	// make sure we change it back to the original working directory afterwards.
	wd, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}
	defer os.Chdir(wd) //nolint:errcheck

	// Also, if we're handling a melange yaml file, check if next to it there is a
	// directory called the same name as the melange yaml file, and if so, copy its
	// contents to the destination directory. This is needed for patch and others.
	if !isApk {
		pkgd := strings.TrimSuffix(filePath, filepath.Ext(filePath))

		if _, err := os.Stat(pkgd); err == nil {
			log.Infof("Found melange directory: %s\nCopying contents to %s\n", pkgd, destDir)
			srcFS := apkofs.DirFS(ctx, pkgd)
			err := os.CopyFS(destDir, srcFS)
			if err != nil {
				return nil, fmt.Errorf("failed to copy melange directory contents: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("error checking melange directory: %w", err)
		}
	}

	// Iterate over the pipeline steps and look for any source fetching steps.
	for _, step := range cfg.Pipeline {
		if step.Uses != "git-checkout" && step.Uses != "fetch" && step.Uses != "patch" {
			continue
		}

		if step.Uses == "patch" && isApk {
			log.Warnf("Skipping patch step as we do not have patches available inside apk metadata yet.")
			continue
		}

		log.Infof("Found source fetching step: %s.\nFetching source to %s\n", step.Uses, destDir)
		// Always make sure we're operating in the destDir directory.
		err = os.MkdirAll(destDir, 0o755)
		if err != nil {
			return nil, fmt.Errorf("failed to create destination directory: %w", err)
		}
		err = os.Chdir(destDir)
		if err != nil {
			return nil, fmt.Errorf("failed to change directory: %w", err)
		}
		err = sourceRunStep(ctx, step, sm, isApk, destDir)
		if err != nil {
			return nil, fmt.Errorf("failed to run step: %w", err)
		}
	}

	return cfg, nil
}
