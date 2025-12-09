// Copyright 2022 Chainguard, Inc.
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

package cache

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/dprotaso/go-yit"
	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/renovate"
	"chainguard.dev/melange/pkg/util"
)

// CacheConfig contains the configuration data for a bump
// renovator.
type CacheConfig struct {
	CacheDir       string
	packageName    string
	packageVersion string
}

// Option sets a config option on a CacheConfig.
type Option func(cfg *CacheConfig) error

// WithCacheDir sets the desired target directory for cache
// artifacts to be fetched to.
func WithCacheDir(cacheDir string) Option {
	return func(cfg *CacheConfig) error {
		cfg.CacheDir = cacheDir
		return nil
	}
}

// New returns a renovator which fetches cache dependencies.
func New(opts ...Option) renovate.Renovator {
	cfg := CacheConfig{}

	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return func(context.Context, *renovate.RenovationContext) error {
				return fmt.Errorf("while constructing: %w", err)
			}
		}
	}

	if cfg.CacheDir == "" {
		return func(context.Context, *renovate.RenovationContext) error {
			return fmt.Errorf("cache directory is not set")
		}
	}

	return func(ctx context.Context, rc *renovate.RenovationContext) error {
		log := clog.FromContext(ctx)

		// Find the package.name and package.version nodes.
		packageNode, err := renovate.NodeFromMapping(rc.Configuration.Root().Content[0], "package")
		if err != nil {
			return err
		}

		nameNode, err := renovate.NodeFromMapping(packageNode, "name")
		if err != nil {
			return err
		}
		cfg.packageName = nameNode.Value

		versionNode, err := renovate.NodeFromMapping(packageNode, "version")
		if err != nil {
			return err
		}
		cfg.packageVersion = versionNode.Value

		log.Infof("fetching artifacts relating to %s-%s", cfg.packageName, cfg.packageVersion)

		// Find our main pipeline YAML node.
		pipelineNode, err := renovate.NodeFromMapping(rc.Configuration.Root().Content[0], "pipeline")
		if err != nil {
			// The main pipeline doesn't exist. This is valid for empty virtual and metapackages so
			// we will just return early instead of throwing an error
			if strings.Contains(err.Error(), "not found in mapping") {
				log.Infof("no main pipeline found, will not cache any artifacts")
				return nil
			}
			return err
		}

		// Look for fetch nodes.
		it := yit.FromNode(pipelineNode).
			RecurseNodes().
			Filter(yit.WithMapValue("fetch"))

		for fetchNode, ok := it(); ok; fetchNode, ok = it() {
			if err := visitFetch(ctx, rc, fetchNode, cfg); err != nil {
				return err
			}
		}

		return nil
	}
}

// visitFetch takes a "fetch" pipeline node
func visitFetch(ctx context.Context, rc *renovate.RenovationContext, node *yaml.Node, cfg CacheConfig) error {
	log := clog.FromContext(ctx)
	withNode, err := renovate.NodeFromMapping(node, "with")
	if err != nil {
		return err
	}

	uriNode, err := renovate.NodeFromMapping(withNode, "uri")
	if err != nil {
		return err
	}

	log.Infof("processing fetch node:")

	evaluatedURI, err := util.MutateStringFromMap(rc.Vars, uriNode.Value)
	if err != nil {
		return err
	}
	log.Infof("  uri: %s", uriNode.Value)
	log.Infof("  evaluated: %s", evaluatedURI)

	downloadedFile, err := downloadFile(ctx, evaluatedURI)
	if err != nil {
		return err
	}
	defer os.Remove(downloadedFile)
	log.Infof("  fetched-as: %s", downloadedFile)

	// Calculate SHA2-256 and SHA2-512 hashes.
	fileSHA256, err := hashFile(downloadedFile, sha256.New())
	if err != nil {
		return err
	}
	log.Infof("  actual-sha256: %s", fileSHA256)

	fileSHA512, err := hashFile(downloadedFile, sha512.New())
	if err != nil {
		return err
	}
	log.Infof("  actual-sha512: %s", fileSHA512)

	// Update expected hash nodes.
	nodeSHA256, err := renovate.NodeFromMapping(withNode, "expected-sha256")
	if err == nil {
		if err := addFileToCache(ctx, cfg, downloadedFile, fileSHA256, nodeSHA256.Value, "sha256"); err != nil {
			return err
		}
	}

	nodeSHA512, err := renovate.NodeFromMapping(withNode, "expected-sha512")
	if err == nil {
		if err := addFileToCache(ctx, cfg, downloadedFile, fileSHA512, nodeSHA512.Value, "sha512"); err != nil {
			return err
		}
	}

	return nil
}

// addFileToCache adds a file to the CacheDir.
func addFileToCache(ctx context.Context, cfg CacheConfig, downloadedFile string, compHash string, cfgHash string, hashFamily string) error {
	log := clog.FromContext(ctx)
	if compHash != cfgHash {
		return fmt.Errorf("%s mismatch: %s != %s", hashFamily, compHash, cfgHash)
	}

	filename := fmt.Sprintf("%s:%s", hashFamily, cfgHash)
	destinationPath := path.Join(cfg.CacheDir, filename)

	// TODO: Remove this when callers stop passing --cache-dir=gs://...
	if strings.HasPrefix(cfg.CacheDir, "gs://") {
		log.Warnf("cache directory is a GCS bucket, not copying file: %s", cfg.CacheDir)
		return nil
	}
	destinationFile, err := os.Create(destinationPath) // #nosec G304 - Creating cached file in download directory
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	sourceFile, err := os.Open(downloadedFile) // #nosec G304 - Reading downloaded file from cache
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	if _, err := io.Copy(destinationFile, sourceFile); err != nil {
		return err
	}

	log.Infof("  wrote: %s", destinationPath)

	return nil
}

// downloadFile downloads a file and returns a path to it in temporary storage.
func downloadFile(ctx context.Context, uri string) (string, error) {
	targetFile, err := os.CreateTemp("", "melange-update-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer targetFile.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// delete the referer header else redirects with sourceforge do not work well.  See https://stackoverflow.com/questions/67203383/downloading-from-sourceforge-wait-and-redirect
			req.Header.Del("Referer")
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set accept header to match the expected MIME types and avoid 403's for some servers like https://www.netfilter.org
	req.Header.Set("Accept", "text/html")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch URL %s: %w", uri, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code %d (%s) when fetching %s", resp.StatusCode, resp.Status, uri)
	}

	if _, err := io.Copy(targetFile, resp.Body); err != nil {
		return "", err
	}

	return targetFile.Name(), nil
}

// hashFile calculates the hash for a file and returns it as a hex string.
func hashFile(downloadedFile string, digest hash.Hash) (string, error) {
	hashedFile, err := os.Open(downloadedFile) // #nosec G304 - Reading downloaded file for hashing
	if err != nil {
		return "", err
	}
	defer hashedFile.Close()

	if _, err := io.Copy(digest, hashedFile); err != nil {
		return "", err
	}

	return hex.EncodeToString(digest.Sum(nil)), nil
}
