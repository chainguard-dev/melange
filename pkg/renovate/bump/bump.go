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

package bump

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dprotaso/go-yit"
	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/renovate"
)

// BumpConfig contains the configuration data for a bump
// renovator.
type BumpConfig struct {
	TargetVersion string
}

// Option sets a config option on a BumpConfig.
type Option func(cfg *BumpConfig) error

// WithTargetVersion sets the desired target version for the
// bump renovator.
func WithTargetVersion(targetVersion string) Option {
	return func(cfg *BumpConfig) error {
		cfg.TargetVersion = targetVersion
		return nil
	}
}

// New returns a renovator which performs a version bump.
func New(opts ...Option) renovate.Renovator {
	bcfg := BumpConfig{}

	for _, opt := range opts {
		if err := opt(&bcfg); err != nil {
			return func(rc *renovate.RenovationContext) error {
				return fmt.Errorf("while constructing: %w", err)
			}
		}
	}

	return func(rc *renovate.RenovationContext) error {
		log.Printf("attempting to bump version to %s", bcfg.TargetVersion)

		// Find the package.version node first and change it.
		packageNode, err := renovate.NodeFromMapping(rc.Root.Content[0], "package")
		if err != nil {
			return err
		}

		versionNode, err := renovate.NodeFromMapping(packageNode, "version")
		if err != nil {
			return err
		}
		versionNode.Value = bcfg.TargetVersion
		versionNode.Style = yaml.LiteralStyle

		epochNode, err := renovate.NodeFromMapping(packageNode, "epoch")
		if err != nil {
			return err
		}
		epochNode.Value = "0"

		// Find our main pipeline YAML node.
		pipelineNode, err := renovate.NodeFromMapping(rc.Root.Content[0], "pipeline")
		if err != nil {
			return err
		}

		// Look for fetch nodes.
		it := yit.FromNode(pipelineNode).
			RecurseNodes().
			Filter(yit.WithMapValue("fetch"))

		for fetchNode, ok := it(); ok; fetchNode, ok = it() {
			if err := updateFetch(fetchNode, bcfg.TargetVersion); err != nil {
				return err
			}
		}

		return nil
	}
}

// downloadFile downloads a file and returns a path to it in temporary storage.
func downloadFile(uri string) (string, error) {
	targetFile, err := os.CreateTemp("", "melange-update-*")
	if err != nil {
		return "", err
	}
	defer targetFile.Close()

	resp, err := http.Get(uri)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("got %s when fetching %s", resp.Status, filepath.Base(uri))
	}

	if _, err := io.Copy(targetFile, resp.Body); err != nil {
		return "", err
	}

	return targetFile.Name(), nil
}

// hashFile calculates the hash for a file and returns it as a hex string.
func hashFile(downloadedFile string, digest hash.Hash) (string, error) {
	hashedFile, err := os.Open(downloadedFile)
	if err != nil {
		return "", err
	}
	defer hashedFile.Close()

	if _, err := io.Copy(digest, hashedFile); err != nil {
		return "", err
	}

	return hex.EncodeToString(digest.Sum(nil)), nil
}

// updateFetch takes a "fetch" pipeline node and updates the parameters of it.
func updateFetch(node *yaml.Node, targetVersion string) error {
	withNode, err := renovate.NodeFromMapping(node, "with")
	if err != nil {
		return err
	}

	uriNode, err := renovate.NodeFromMapping(withNode, "uri")
	if err != nil {
		return err
	}

	log.Printf("processing fetch node:")

	// Fetch the new sources.
	evaluatedUri := strings.ReplaceAll(uriNode.Value, "${{package.version}}", targetVersion)
	log.Printf("  uri: %s", uriNode.Value)
	log.Printf("  evaluated: %s", evaluatedUri)

	downloadedFile, err := downloadFile(evaluatedUri)
	if err != nil {
		return err
	}
	defer os.Remove(downloadedFile)
	log.Printf("  fetched-as: %s", downloadedFile)

	// Calculate SHA2-256 and SHA2-512 hashes.
	fileSHA256, err := hashFile(downloadedFile, sha256.New())
	if err != nil {
		return err
	}
	log.Printf("  expected-sha256: %s", fileSHA256)

	fileSHA512, err := hashFile(downloadedFile, sha512.New())
	if err != nil {
		return err
	}
	log.Printf("  expected-sha512: %s", fileSHA512)

	// Update expected hash nodes.
	nodeSHA256, err := renovate.NodeFromMapping(withNode, "expected-sha256")
	if err == nil {
		nodeSHA256.Value = fileSHA256
	}

	nodeSHA512, err := renovate.NodeFromMapping(withNode, "expected-sha512")
	if err == nil {
		nodeSHA512.Value = fileSHA512
	}

	return nil
}
