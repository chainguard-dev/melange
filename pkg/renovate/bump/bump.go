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
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/dprotaso/go-yit"
	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/renovate"
	"chainguard.dev/melange/pkg/util"
)

// BumpConfig contains the configuration data for a bump
// renovator.
type BumpConfig struct {
	TargetVersion  string
	ExpectedCommit string
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

// WithExpectedCommit sets the desired target expected commit for the
// bump renovator.
func WithExpectedCommit(expectedCommit string) Option {
	return func(cfg *BumpConfig) error {
		cfg.ExpectedCommit = expectedCommit
		return nil
	}
}

// New returns a renovator which performs a version bump.
func New(ctx context.Context, opts ...Option) renovate.Renovator {
	log := clog.FromContext(ctx)
	bcfg := BumpConfig{}

	for _, opt := range opts {
		if err := opt(&bcfg); err != nil {
			return func(context.Context, *renovate.RenovationContext) error {
				return fmt.Errorf("while constructing: %w", err)
			}
		}
	}

	return func(ctx context.Context, rc *renovate.RenovationContext) error {
		log.Infof("attempting to bump version to %s", bcfg.TargetVersion)

		packageNode, err := renovate.NodeFromMapping(rc.Configuration.Root().Content[0], "package")
		if err != nil {
			return err
		}

		versionNode, err := renovate.NodeFromMapping(packageNode, "version")
		if err != nil {
			return err
		}

		// if the version is changing then reset the epoch to 0 else if the version is the same then increment the epoch by 1
		epochNode, err := renovate.NodeFromMapping(packageNode, "epoch")
		if err != nil {
			return err
		}

		if versionNode.Value != bcfg.TargetVersion {
			epochNode.Value = "0"
		} else {
			epoch, err := strconv.Atoi(epochNode.Value)
			if err != nil {
				return err
			}
			epochNode.Value = fmt.Sprintf("%d", epoch+1)
		}

		versionNode.Value = strings.TrimSpace(bcfg.TargetVersion)
		versionNode.Style = yaml.DoubleQuotedStyle
		versionNode.Tag = "!!str"

		rc.Vars[config.SubstitutionPackageVersion] = bcfg.TargetVersion
		rc.Vars[config.SubstitutionPackageEpoch] = epochNode.Value

		// Recompute variable transforms
		err = rc.Configuration.PerformVarSubstitutions(rc.Vars)
		if err != nil {
			return err
		}

		// Find our main pipeline YAML node.
		pipelineNode, err := renovate.NodeFromMapping(rc.Configuration.Root().Content[0], "pipeline")
		if err != nil {
			// The main pipeline doesn't exist. This is valid for empty virtual and metapackages so
			// we will just return early instead of throwing an error
			if strings.Contains(err.Error(), "not found in mapping") {
				log.Infof("no main pipeline found, will not update expected commits or checksums")
				return nil
			}
			return err
		}

		// Look for fetch nodes.
		it := yit.FromNode(pipelineNode).
			RecurseNodes().
			Filter(yit.WithMapValue("fetch"))

		for fetchNode, ok := it(); ok; fetchNode, ok = it() {
			if err := updateFetch(ctx, rc, fetchNode, bcfg.TargetVersion); err != nil {
				return err
			}
		}

		// Look for git-checkout nodes.
		it = yit.FromNode(pipelineNode).
			RecurseNodes().
			Filter(yit.WithMapValue("git-checkout"))

		for gitCheckoutNode, ok := it(); ok; gitCheckoutNode, ok = it() {
			if err := updateGitCheckout(ctx, gitCheckoutNode, bcfg.ExpectedCommit); err != nil {
				return err
			}
		}
		return nil
	}
}

// updateFetch takes a "fetch" pipeline node and updates the parameters of it.
func updateFetch(ctx context.Context, rc *renovate.RenovationContext, node *yaml.Node, _ string) error {
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

	// Fetch the new sources.
	evaluatedURI, err := util.MutateStringFromMap(rc.Vars, uriNode.Value)
	if err != nil {
		return err
	}
	log.Infof("  uri: %s", uriNode.Value)
	log.Infof("  evaluated: %s", evaluatedURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, evaluatedURI, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch %s: %s", evaluatedURI, resp.Status)
	}
	defer resp.Body.Close()

	sha256 := sha256.New()
	sha512 := sha512.New()
	mw := io.MultiWriter(sha256, sha512)
	if _, err := io.Copy(mw, resp.Body); err != nil {
		return err
	}
	fileSHA256 := hex.EncodeToString(sha256.Sum(nil))
	log.Infof("  expected-sha256: %s", fileSHA256)

	fileSHA512 := hex.EncodeToString(sha512.Sum(nil))
	log.Infof("  expected-sha512: %s", fileSHA512)

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

// updateGitCheckout takes a "git-checkout" pipeline node and updates the parameters of it.
func updateGitCheckout(ctx context.Context, node *yaml.Node, expectedGitSha string) error {
	log := clog.FromContext(ctx)

	withNode, err := renovate.NodeFromMapping(node, "with")
	if err != nil {
		return err
	}

	// If the tag does not contain a version substitution then we assume it is not the main checkout so we skip updating the expected-commit sha.
	tag, err := renovate.NodeFromMapping(withNode, "tag")
	if err != nil {
		log.Infof("git-checkout node does not contain a tag, assume we need to update the expected-commit sha")
	} else if !strings.Contains(tag.Value, "${{package.version}}") && !strings.Contains(tag.Value, "${{vars.mangled-package-version}}") {
		log.Infof("Skipping git-checkout node as it does not contain a version substitution so assuming it is not the main checkout")
		return nil
	}

	log.Infof("processing git-checkout node")

	if expectedGitSha != "" {
		// Update expected hash nodes.
		nodeCommit, err := renovate.NodeFromMapping(withNode, "expected-commit")
		if err == nil && !strings.Contains(nodeCommit.Value, "${{") {
			nodeCommit.Value = expectedGitSha
			log.Infof("  expected-commit: %s", expectedGitSha)
		}
	}

	return nil
}
