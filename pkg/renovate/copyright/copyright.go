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
	"path/filepath"

	"github.com/chainguard-dev/clog"

	"chainguard.dev/melange/pkg/license"
	"chainguard.dev/melange/pkg/renovate"
	"gopkg.in/yaml.v3"
)

// CopyrightConfig contains the configuration data for a copyright update
// renovator.
type CopyrightConfig struct {
	Licenses   []license.License
	Diffs      []license.LicenseDiff
	Structured bool // Enable structured license grouping by directory
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

// WithStructured enables structured license grouping by directory.
// When enabled, licenses are grouped by directory level with OR operators
// within directories and AND operators between directories.
func WithStructured(structured bool) Option {
	return func(cfg *CopyrightConfig) error {
		cfg.Structured = structured
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
		canFix := false
		for _, l := range ccfg.Licenses {
			if license.IsLicenseMatchConfident(l) {
				canFix = true
				break
			}
		}
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

		if ccfg.Structured {
			// Use structured grouping by directory
			if err := populateStructuredCopyright(copyrightNode, ccfg.Licenses, log); err != nil {
				return err
			}
		} else {
			// Use flat license listing (original behavior)
			if err := populateFlatCopyright(copyrightNode, ccfg.Licenses, log); err != nil {
				return err
			}
		}

		return nil
	}
}

// populateFlatCopyright populates the copyright node with a flat list of licenses (original behavior).
func populateFlatCopyright(copyrightNode *yaml.Node, licenses []license.License, log *clog.Logger) error {
	for _, l := range licenses {
		// Skip licenses we don't have full confidence in.
		if !license.IsLicenseMatchConfident(l) {
			log.Infof("skipping unconfident license %s", l.Source)
			continue
		}

		licenseNode := createSimpleLicenseNode(l)
		copyrightNode.Content = append(copyrightNode.Content, licenseNode)
	}
	return nil
}

// populateStructuredCopyright populates the copyright node with structured license grouping by directory.
func populateStructuredCopyright(copyrightNode *yaml.Node, licenses []license.License, log *clog.Logger) error {
	// Filter out unconfident licenses
	confidentLicenses := make([]license.License, 0, len(licenses))
	for _, l := range licenses {
		if !license.IsLicenseMatchConfident(l) {
			log.Infof("skipping unconfident license %s", l.Source)
			continue
		}
		confidentLicenses = append(confidentLicenses, l)
	}

	if len(confidentLicenses) == 0 {
		return nil
	}

	// Group licenses by directory
	licenseGroups := groupLicensesByDirectory(confidentLicenses)

	// If we only have one directory group, check if we need nested structure
	if len(licenseGroups) == 1 {
		// If there's only one directory with one license, use simple format
		for _, licenses := range licenseGroups {
			if len(licenses) == 1 {
				licenseNode := createSimpleLicenseNode(licenses[0])
				copyrightNode.Content = append(copyrightNode.Content, licenseNode)
				return nil
			}
		}
	}

	// Create structured copyright entries
	for _, dirLicenses := range licenseGroups {
		if len(dirLicenses) == 1 {
			// Single license in directory - use simple entry
			licenseNode := createSimpleLicenseNode(dirLicenses[0])
			copyrightNode.Content = append(copyrightNode.Content, licenseNode)
		} else {
			// Multiple licenses in same directory - group with OR
			groupNode := createLicenseGroupNode("OR", dirLicenses)
			copyrightNode.Content = append(copyrightNode.Content, groupNode)
		}
	}

	// If we have multiple directory groups, we need to wrap everything in an AND group
	if len(licenseGroups) > 1 {
		// Move all current content to a new AND group
		originalContent := copyrightNode.Content
		copyrightNode.Content = nil

		andGroupNode := &yaml.Node{
			Kind:    yaml.MappingNode,
			Content: []*yaml.Node{},
		}

		// Add operator field
		andGroupNode.Content = append(andGroupNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "operator", Tag: "!!str"},
			&yaml.Node{Kind: yaml.ScalarNode, Value: "AND", Tag: "!!str"},
		)

		// Add licenses field
		andGroupNode.Content = append(andGroupNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "licenses", Tag: "!!str"},
			&yaml.Node{Kind: yaml.SequenceNode, Content: originalContent},
		)

		copyrightNode.Content = append(copyrightNode.Content, andGroupNode)
	}

	return nil
}

// groupLicensesByDirectory groups licenses by their directory path.
func groupLicensesByDirectory(licenses []license.License) map[string][]license.License {
	groups := make(map[string][]license.License)

	for _, l := range licenses {
		dir := filepath.Dir(l.Source)
		if dir == "" || dir == "." {
			dir = "." // Root directory
		}
		groups[dir] = append(groups[dir], l)
	}

	return groups
}

// createSimpleLicenseNode creates a simple license node with license and license-path fields.
func createSimpleLicenseNode(l license.License) *yaml.Node {
	licenseNode := &yaml.Node{
		Kind:    yaml.MappingNode,
		Content: []*yaml.Node{},
	}

	licenseNode.Content = append(licenseNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: "license", Tag: "!!str"},
		&yaml.Node{Kind: yaml.ScalarNode, Value: l.Name, Tag: "!!str"},
	)

	licenseNode.Content = append(licenseNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: "license-path", Tag: "!!str"},
		&yaml.Node{Kind: yaml.ScalarNode, Value: l.Source, Tag: "!!str"},
	)

	return licenseNode
}

// createLicenseGroupNode creates a license group node with an operator and list of licenses.
func createLicenseGroupNode(operator string, licenses []license.License) *yaml.Node {
	groupNode := &yaml.Node{
		Kind:    yaml.MappingNode,
		Content: []*yaml.Node{},
	}

	// Add operator field
	groupNode.Content = append(groupNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: "operator", Tag: "!!str"},
		&yaml.Node{Kind: yaml.ScalarNode, Value: operator, Tag: "!!str"},
	)

	// Create licenses sequence
	licensesSeq := &yaml.Node{
		Kind:    yaml.SequenceNode,
		Content: []*yaml.Node{},
	}

	for _, l := range licenses {
		licenseNode := createSimpleLicenseNode(l)
		licensesSeq.Content = append(licensesSeq.Content, licenseNode)
	}

	// Add licenses field
	groupNode.Content = append(groupNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: "licenses", Tag: "!!str"},
		licensesSeq,
	)

	return groupNode
}
