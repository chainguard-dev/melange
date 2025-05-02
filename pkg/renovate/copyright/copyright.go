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

	"github.com/chainguard-dev/clog"

	"chainguard.dev/melange/pkg/license"
	"chainguard.dev/melange/pkg/renovate"
	"gopkg.in/yaml.v3"
)

// CopyrightConfig contains the configuration data for a copyright update
// renovator.
type CopyrightConfig struct {
	Licenses []license.License
}

// Option sets a config option on a CopyrightConfig.
type Option func(cfg *CopyrightConfig) error

// WithTargetVersion sets the desired target version for the
// bump renovator.
func WithLicenses(licenses []license.License) Option {
	return func(cfg *CopyrightConfig) error {
		cfg.Licenses = licenses
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

		// Funny thing: we first have to parse the configuration afresh for license linting.
		// The reason is that for determining the license information, we need to fetch the
		// source code of the package. And to get that, we need the config tree to be already
		// substituted, with all the variables resolved. We can't use rc.Configuration for that
		// as it would mean the renovated config would already contain the substitutions.

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
		for _, license := range ccfg.Licenses {
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
				Value: license.Name,
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
				Value: license.Source,
				Tag:   "!!str",
				Style: yaml.FlowStyle,
			})

			copyrightNode.Content = append(copyrightNode.Content, licenseNode)
		}

		return nil
	}
}
