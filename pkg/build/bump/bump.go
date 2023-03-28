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
	"chainguard.dev/melange/pkg/build"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/dprotaso/go-yit"
	"gopkg.in/yaml.v3"
	"log"
	"os"

	"chainguard.dev/melange/pkg/util"
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
func New(opts ...Option) build.Renovator {
	bcfg := BumpConfig{}

	for _, opt := range opts {
		if err := opt(&bcfg); err != nil {
			return func(rc *build.RenovationContext) error {
				return fmt.Errorf("while constructing: %w", err)
			}
		}
	}

	return func(rc *build.RenovationContext) error {
		log.Printf("attempting to bump version to %s", bcfg.TargetVersion)

		// Find the package.version node first and change it.
		packageNode, err := build.NodeFromMapping(rc.Root.Content[0], "package")
		if err != nil {
			return err
		}

		versionNode, err := build.NodeFromMapping(packageNode, "version")
		if err != nil {
			return err
		}
		versionNode.Value = bcfg.TargetVersion
		versionNode.Style = yaml.FlowStyle
		versionNode.Tag = "!!str"

		epochNode, err := build.NodeFromMapping(packageNode, "epoch")
		if err != nil {
			return err
		}
		epochNode.Value = "0"

		// Find our main pipeline YAML node.
		pipelineNode, err := build.NodeFromMapping(rc.Root.Content[0], "pipeline")
		if err != nil {
			return err
		}

		// Look for fetch nodes.
		it := yit.FromNode(pipelineNode).
			RecurseNodes().
			Filter(yit.WithMapValue("fetch"))

		c, err := build.ParseConfiguration(rc.Context.ConfigFile)
		if err != nil {
			return err
		}

		pctx := &build.PipelineContext{
			Package: &build.Package{Version: bcfg.TargetVersion},
			Context: &build.Context{
				Configuration: *c,
			},
		}

		mutations, err := build.MutateWith(pctx, map[string]string{})
		if err != nil {
			return err
		}

		for fetchNode, ok := it(); ok; fetchNode, ok = it() {
			if err := updateFetch(mutations, fetchNode, bcfg.TargetVersion); err != nil {
				return err
			}
		}
		return nil
	}
}

// updateFetch takes a "fetch" pipeline node and updates the parameters of it.
func updateFetch(m map[string]string, node *yaml.Node, targetVersion string) error {
	withNode, err := build.NodeFromMapping(node, "with")
	if err != nil {
		return err
	}

	uriNode, err := build.NodeFromMapping(withNode, "uri")
	if err != nil {
		return err
	}

	log.Printf("processing fetch node:")

	// evaluate var substitutions
	evaluatedUri, err := build.MutateStringFromMap(m, uriNode.Value)
	if err != nil {
		return err
	}

	// Fetch the new sources.
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
	log.Printf("  expected-sha256: %s", fileSHA256)

	fileSHA512, err := util.HashFile(downloadedFile, sha512.New())
	if err != nil {
		return err
	}
	log.Printf("  expected-sha512: %s", fileSHA512)

	// Update expected hash nodes.
	nodeSHA256, err := build.NodeFromMapping(withNode, "expected-sha256")
	if err == nil {
		nodeSHA256.Value = fileSHA256
	}

	nodeSHA512, err := build.NodeFromMapping(withNode, "expected-sha512")
	if err == nil {
		nodeSHA512.Value = fileSHA512
	}

	return nil
}
