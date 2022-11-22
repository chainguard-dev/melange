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
	"fmt"

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
		fmt.Printf("renovating with %v", bcfg)
		return nil
	}
}
