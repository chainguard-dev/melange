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
	"chainguard.dev/melange/pkg/build"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/dprotaso/go-yit"
	"gopkg.in/yaml.v3"

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
func New(opts ...Option) build.Renovator {
	cfg := CacheConfig{}

	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return func(rc *build.RenovationContext) error {
				return fmt.Errorf("while constructing: %w", err)
			}
		}
	}

	if cfg.CacheDir == "" {
		return func(rc *build.RenovationContext) error {
			return fmt.Errorf("cache directory is not set")
		}
	}

	return func(rc *build.RenovationContext) error {
		// Find the package.name and package.version nodes.
		packageNode, err := build.NodeFromMapping(rc.Root.Content[0], "package")
		if err != nil {
			return err
		}

		nameNode, err := build.NodeFromMapping(packageNode, "name")
		if err != nil {
			return err
		}
		cfg.packageName = nameNode.Value

		versionNode, err := build.NodeFromMapping(packageNode, "version")
		if err != nil {
			return err
		}
		cfg.packageVersion = versionNode.Value

		log.Printf("fetching artifacts relating to %s-%s", cfg.packageName, cfg.packageVersion)

		// Find our main pipeline YAML node.
		pipelineNode, err := build.NodeFromMapping(rc.Root.Content[0], "pipeline")
		if err != nil {
			return err
		}

		// Look for fetch nodes.
		it := yit.FromNode(pipelineNode).
			RecurseNodes().
			Filter(yit.WithMapValue("fetch"))

		for fetchNode, ok := it(); ok; fetchNode, ok = it() {
			if err := visitFetch(fetchNode, cfg); err != nil {
				return err
			}
		}

		return nil
	}
}

// visitFetch takes a "fetch" pipeline node
func visitFetch(node *yaml.Node, cfg CacheConfig) error {
	withNode, err := build.NodeFromMapping(node, "with")
	if err != nil {
		return err
	}

	uriNode, err := build.NodeFromMapping(withNode, "uri")
	if err != nil {
		return err
	}

	log.Printf("processing fetch node:")

	// Fetch the new sources.
	evaluatedUri := strings.ReplaceAll(uriNode.Value, "${{package.version}}", cfg.packageVersion)
	evaluatedUri = strings.ReplaceAll(evaluatedUri, "${{package.name}}", cfg.packageName)
	log.Printf("  uri: %s", uriNode.Value)
	log.Printf("  evaluated: %s", evaluatedUri)

	downloadedFile, err := util.DownloadFile(evaluatedUri)
	if err != nil {
		return err
	}
	defer os.Remove(downloadedFile)
	log.Printf("  fetched-as: %s", downloadedFile)

	// Calculate SHA2-256 and SHA2-512 hashes.
	fileSHA256, err := util.HashFile(downloadedFile, sha256.New())
	if err != nil {
		return err
	}
	log.Printf("  actual-sha256: %s", fileSHA256)

	fileSHA512, err := util.HashFile(downloadedFile, sha512.New())
	if err != nil {
		return err
	}
	log.Printf("  actual-sha512: %s", fileSHA512)

	// Update expected hash nodes.
	nodeSHA256, err := build.NodeFromMapping(withNode, "expected-sha256")
	if err == nil {
		if err := addFileToCache(cfg, downloadedFile, fileSHA256, nodeSHA256.Value, "sha256"); err != nil {
			return err
		}
	}

	nodeSHA512, err := build.NodeFromMapping(withNode, "expected-sha512")
	if err == nil {
		if err := addFileToCache(cfg, downloadedFile, fileSHA512, nodeSHA512.Value, "sha512"); err != nil {
			return err
		}
	}

	return nil
}

// addFileToCache adds a file to the CacheDir.
func addFileToCache(cfg CacheConfig, downloadedFile string, compHash string, cfgHash string, hashFamily string) error {
	if compHash != cfgHash {
		return fmt.Errorf("%s mismatch: %s != %s", hashFamily, compHash, cfgHash)
	}

	filename := fmt.Sprintf("%s:%s", hashFamily, cfgHash)
	destinationPath := path.Join(cfg.CacheDir, filename)

	var destinationFile io.WriteCloser
	if strings.HasPrefix(cfg.CacheDir, "gs://") {
		cctx := context.TODO()

		bucket, prefix, _ := strings.Cut(strings.TrimPrefix(cfg.CacheDir, "gs://"), "/")
		client, err := storage.NewClient(cctx)
		if err != nil {
			return err
		}
		destinationFile = client.Bucket(bucket).Object(path.Join(prefix, filename)).NewWriter(cctx)
	} else {
		var err error
		destinationFile, err = os.Create(destinationPath)
		if err != nil {
			return err
		}
	}
	defer destinationFile.Close()

	sourceFile, err := os.Open(downloadedFile)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	if _, err := io.Copy(destinationFile, sourceFile); err != nil {
		return err
	}

	log.Printf("  wrote: %s", destinationPath)

	return nil
}
