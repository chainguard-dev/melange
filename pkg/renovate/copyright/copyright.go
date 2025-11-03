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

package copyright

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/chainguard-dev/clog"

	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/license"
	"chainguard.dev/melange/pkg/renovate"
)

// CopyrightConfig contains the configuration data for a copyright update
// renovator.
type CopyrightConfig struct {
	Licenses []license.License
	Diffs    []license.LicenseDiff
	Format   string // "simple" or "flat"
}

// Option sets a config option on a CopyrightConfig.
type Option func(cfg *CopyrightConfig) error

// WithTargetVersion sets the licenses to be used for the
// renovator.
func WithLicenses(licenses []license.License) Option {
	return func(cfg *CopyrightConfig) error {
		cfg.Licenses = licenses
		return nil
	}
}

// WithLicenses sets the differences to consider for the
// renovator.
func WithDiffs(diffs []license.LicenseDiff) Option {
	return func(cfg *CopyrightConfig) error {
		cfg.Diffs = diffs
		return nil
	}
}

// WithFormat sets whether the copyright should be populated with a single
// node containing all detected licenses joined together (simple), or with
// multiple nodes, one per license (flat).
func WithFormat(format string) Option {
	return func(cfg *CopyrightConfig) error {
		cfg.Format = format
		return nil
	}
}

// New returns a renovator which performs a copyright update.
func New(ctx context.Context, opts ...Option) renovate.Renovator {
	log := clog.FromContext(ctx)
	ccfg := CopyrightConfig{}

	for _, opt := range opts {
		if err := opt(&ccfg); err != nil {
			return func(context.Context, *renovate.RenovationContext) error {
				return fmt.Errorf("while constructing: %w", err)
			}
		}
	}

	return func(ctx context.Context, rc *renovate.RenovationContext) error {
		log.Infof("attempting to update copyright")

		// Check if there's any licenses that were properly detected.
		// If not, we probably shouldn't do anything.
		canFix := slices.ContainsFunc(ccfg.Licenses, license.IsLicenseMatchConfident)
		if !canFix {
			log.Infof("no confident licenses found to update")
			return nil
		}

		// Also, don't renovate if there is no differences detected.
		if len(ccfg.Diffs) == 0 {
			log.Infof("no actionable license differences detected")
			return nil
		}

		packageNode, err := renovate.NodeFromMapping(rc.Configuration.Root().Content[0], "package")
		if err != nil {
			return err
		}

		copyrightNode, err := renovate.NodeFromMapping(packageNode, "copyright")
		if err != nil {
			return err
		}

		// Let's clear out the copyrightNode and then repopulate it with the
		// detected licenses.
		copyrightNode.Content = nil

		// Repopulate the copyrightNode with detected licenses
		if ccfg.Format == "simple" {
			// Make the copyright field a single node with all licenses joined together
			if err = populateSimpleCopyright(ctx, copyrightNode, ccfg.Licenses); err != nil {
				return err
			}
		} else {
			// Use flat license listing (original behavior)
			if err = populateFlatCopyright(ctx, copyrightNode, ccfg.Licenses); err != nil {
				return err
			}
		}

		return nil
	}
}

// populateFlatCopyright populates the copyright node with the detected licenses,
// one entry per license.
func populateFlatCopyright(ctx context.Context, copyrightNode *yaml.Node, licenses []license.License) error {
	log := clog.FromContext(ctx)

	for _, l := range licenses {
		// Skip licenses we don't have full confidence in.
		if !license.IsLicenseMatchConfident(l) {
			log.Infof("skipping unconfident license %s", l.Source)
			continue
		}

		licenseNode := &yaml.Node{
			Kind:    yaml.MappingNode,
			Style:   yaml.FlowStyle,
			Content: []*yaml.Node{},
		}

		licenseNode.Content = append(licenseNode.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Value: "license",
			Tag:   "!!str",
			Style: yaml.FlowStyle,
		}, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Value: l.Name,
			Tag:   "!!str",
			Style: yaml.FlowStyle,
		})

		licenseNode.Content = append(licenseNode.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Value: "license-path",
			Tag:   "!!str",
			Style: yaml.FlowStyle,
		}, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Value: l.Source,
			Tag:   "!!str",
			Style: yaml.FlowStyle,
		})

		copyrightNode.Content = append(copyrightNode.Content, licenseNode)
	}

	return nil
}

// populateSimpleCopyright populates the copyright field with a single node
// with all detected licenses joined together.
func populateSimpleCopyright(ctx context.Context, copyrightNode *yaml.Node, licenses []license.License) error {
	log := clog.FromContext(ctx)

	// Gather all the license names and concatenate them with AND statements
	licenseMap := make(map[string]struct{})
	for _, l := range licenses {
		if !license.IsLicenseMatchConfident(l) {
			log.Infof("skipping unconfident license %s", l.Source)
			continue
		}
		licenseMap[l.Name] = struct{}{}
	}

	if len(licenseMap) == 0 {
		log.Infof("no confident licenses found to populate copyright")
		return nil
	}

	// Join the license names with " AND ", sorting them first for consistency
	ls := slices.Collect(maps.Keys(licenseMap))
	slices.Sort(ls)
	combined := strings.Join(ls, " AND ")

	// Create a single license entry with the combined license string
	licenseNode := &yaml.Node{
		Kind:    yaml.MappingNode,
		Style:   yaml.FlowStyle,
		Content: []*yaml.Node{},
	}

	licenseNode.Content = append(licenseNode.Content, &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: "license",
		Tag:   "!!str",
		Style: yaml.FlowStyle,
	}, &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: combined,
		Tag:   "!!str",
		Style: yaml.FlowStyle,
	})

	copyrightNode.Content = append(copyrightNode.Content, licenseNode)

	return nil
}
