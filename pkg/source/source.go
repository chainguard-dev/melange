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
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"github.com/chainguard-dev/clog"

	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
)

// Variable to allow mocking the runCommand function in tests.
var sourceRunPipelineStep = runPipelineStep

// Simple wrapper for executing pipeline steps.
func runPipelineStep(ctx context.Context, step config.Pipeline) error {
	var stdout, stderr io.Writer
	outputBuf := &bytes.Buffer{}
	log := clog.FromContext(ctx)
	stdout = outputBuf
	stderr = outputBuf

	cmd := []string{"/bin/sh", "-c", step.Pipeline[0].Runs}
	// #nosec G204 - Executing pipeline step from trusted melange configuration
	proc := exec.Command(cmd[0], cmd[1:]...)
	proc.Stdout = stdout
	proc.Stderr = stderr
	log.Debugf("Command output:\n%s", outputBuf.String())

	return proc.Run()
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

	// Temporarily copy out the embedded files and directories from f into a
	// temporary directory. We want to pass it later on to the pipeline
	// compilation.
	err = os.CopyFS(tmpDir, build.PipelinesFS)
	if err != nil {
		return nil, fmt.Errorf("failed to copy embedded pilelines: %w", err)
	}

	// Prepare the substitution map and compile the pipelines, making sure that
	// the resulting pipeline run statements are all substituted with the
	// correct values and ready for execution.
	c := &build.Compiled{
		PipelineDirs: []string{tmpDir},
	}

	// Now also try looking if the base directory of filePath has a pipelines
	// directory. Add those to the list of directories to search for pipelines.
	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path of file: %w", err)
	}
	baseDir := filepath.Dir(absFilePath)
	pipelinesDir := filepath.Join(baseDir, "pipelines")

	if _, err := os.Stat(pipelinesDir); err == nil {
		log.Infof("Found pipelines directory in base directory: %s", pipelinesDir)
		c.PipelineDirs = append(c.PipelineDirs, pipelinesDir)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("error checking pipelines directory: %w", err)
	}

	sm, err := build.NewSubstitutionMap(cfg, "amd64", "gnu", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create substitution map: %w", err)
	}
	err = c.CompilePipelines(ctx, sm, cfg.Pipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to compile pipelines: %w", err)
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
		if step.Uses == "patch" && isApk {
			log.Warnf("Skipping patch step as we do not have patches available inside apk metadata yet.")
			continue
		}

		if step.Uses != "git-checkout" && step.Uses != "fetch" && step.Uses != "patch" {
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
		err = sourceRunPipelineStep(ctx, step)
		if err != nil {
			return nil, fmt.Errorf("failed to run step: %w", err)
		}
	}

	return cfg, nil
}
