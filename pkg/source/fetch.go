// Copyright 2026 Chainguard, Inc.
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
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
)

// FetchOptions describes a native equivalent of the built-in `fetch` pipeline.
// Values come from the melange config and are used only as data: a URL, a
// filename, and argv elements.
type FetchOptions struct {
	URI             string
	Directory       string // where to extract; relative to WorkspaceDir
	WorkspaceDir    string // root that the download and extraction are confined to
	StripComponents int
	Extract         bool
	ExpectedSHA256  string
	ExpectedSHA512  string
	Delete          bool
}

// Fetch downloads the artifact named by opts.URI into the workspace directory,
// optionally verifies its checksum, and optionally extracts it. The URI is
// parsed and used as data (never passed to a shell), and the extraction
// directory is confined to the workspace.
func Fetch(ctx context.Context, opts *FetchOptions) error {
	log := clog.FromContext(ctx)

	workDir := opts.WorkspaceDir
	if workDir == "" {
		var err error
		if workDir, err = os.Getwd(); err != nil {
			return fmt.Errorf("determining working directory: %w", err)
		}
	}

	// Resolve the extraction directory up front so an unusable `directory:`
	// fails before anything is written to disk.
	extractDir := workDir
	if opts.Extract && opts.Directory != "" {
		var err error
		if extractDir, err = secureJoin(workDir, opts.Directory, "fetch directory"); err != nil {
			return err
		}
	}

	u, err := url.Parse(opts.URI)
	if err != nil {
		return fmt.Errorf("invalid fetch uri %q: %w", opts.URI, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid fetch uri %q: only http and https schemes are supported", opts.URI)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid fetch uri %q: missing host", opts.URI)
	}

	// Derive the local filename from the URL path only (not the raw string), so
	// query strings or crafted values can't influence the on-disk name.
	base := path.Base(u.Path)
	if base == "" || base == "." || base == ".." || base == "/" {
		return fmt.Errorf("could not determine a filename from uri %q", opts.URI)
	}

	archive := filepath.Join(workDir, base)

	log.Infof("Fetching %s", opts.URI)
	if err := download(ctx, opts.URI, archive); err != nil {
		return err
	}

	if err := verifyChecksum(archive, opts.ExpectedSHA256, opts.ExpectedSHA512); err != nil {
		return err
	}

	if opts.Extract {
		// tar is invoked with an explicit argv, so the filename and directory
		// are passed as plain arguments. tar auto-detects the compression
		// format, matching the built-in pipeline.
		// #nosec G204 - argv-only invocation; extractDir resolves inside the workspace
		cmd := exec.CommandContext(ctx, "tar", "-x",
			fmt.Sprintf("--strip-components=%d", opts.StripComponents),
			"--no-same-owner", "-C", extractDir, "-f", archive)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("extracting %q: %w", base, err)
		}
	}

	if opts.Delete {
		if err := os.Remove(archive); err != nil {
			return fmt.Errorf("deleting %q: %w", base, err)
		}
	}

	return nil
}

// download streams uri to the file named dest in the current working directory.
func download(ctx context.Context, uri, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return fmt.Errorf("creating request for %s: %w", uri, err)
	}

	resp, err := http.DefaultClient.Do(req) // #nosec G107 - uri scheme validated to http(s) by caller
	if err != nil {
		return fmt.Errorf("fetching %s: %w", uri, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching %s: unexpected status %d", uri, resp.StatusCode)
	}

	// #nosec G304 - dest is a sanitized basename written into the workspace dir
	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("creating %q: %w", dest, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("writing %q: %w", dest, err)
	}

	return nil
}

// verifyChecksum checks the downloaded file against the expected digests, when
// provided. A missing checksum is not fatal here, as license-check is
// best-effort.
func verifyChecksum(file, expectedSHA256, expectedSHA512 string) error {
	check := func(h hash.Hash, expected, algo string) error {
		f, err := os.Open(file) // #nosec G304 - file is a sanitized basename in the workspace dir
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		got := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(got, strings.TrimSpace(expected)) {
			return fmt.Errorf("%s mismatch for %q: expected %s, got %s", algo, file, expected, got)
		}
		return nil
	}

	if expectedSHA256 != "" {
		return check(sha256.New(), expectedSHA256, "sha256")
	}
	if expectedSHA512 != "" {
		return check(sha512.New(), expectedSHA512, "sha512")
	}
	return nil
}

// applyPatchStep applies patch files, a native equivalent of the built-in
// `patch` pipeline. Each patch path is resolved relative to workDir, opened in
// Go, and fed to `patch` on stdin.
func applyPatchStep(ctx context.Context, patches string, stripComponents, fuzz int, workDir string) error {
	log := clog.FromContext(ctx)

	for patch := range strings.FieldsSeq(patches) {
		// Keep patch paths within the workspace directory.
		patchPath, err := secureJoin(workDir, patch, "patch")
		if err != nil {
			return err
		}

		log.Infof("Applying patch %s", patchPath)

		f, err := os.Open(patchPath) // #nosec G304 G703 - patch path resolves inside the workspace dir
		if err != nil {
			return fmt.Errorf("opening patch %q: %w", patchPath, err)
		}

		// #nosec G204 - argv-only invocation; strip/fuzz are ints, no shell
		cmd := exec.CommandContext(ctx, "patch",
			fmt.Sprintf("-p%d", stripComponents),
			fmt.Sprintf("--fuzz=%d", fuzz))
		cmd.Dir = workDir
		cmd.Stdin = f
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
		f.Close()
		if err != nil {
			return fmt.Errorf("applying patch %q: %w", patchPath, err)
		}
	}

	return nil
}
