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

package edit_vars

import (
	"context"
	"fmt"
	"strings"

	"github.com/chainguard-dev/clog"
	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/renovate"
)

type EditVarsConfig struct {
	Variables map[string]string
}

type Option func(cfg *EditVarsConfig) error

func WithVariables(args string) Option {
	// Parse the argument string into a map of variables.
	variables := make(map[string]string)
	pairs := strings.Split(args, " ")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return func(cfg *EditVarsConfig) error {
				return fmt.Errorf("invalid variable format: %s, expected key=value", pair)
			}
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		if key == "" || value == "" {
			return func(cfg *EditVarsConfig) error {
				return fmt.Errorf("invalid variable format: %s, key and value must not be empty", pair)
			}
		}
		variables[key] = value
	}
	return func(cfg *EditVarsConfig) error {
		cfg.Variables = variables
		return nil
	}
}

// New returns a renovator which edits variables in the melange configuration.
func New(ctx context.Context, opts ...Option) renovate.Renovator {
	log := clog.FromContext(ctx)
	cfg := &EditVarsConfig{
		Variables: make(map[string]string),
	}

	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return func(context.Context, *renovate.RenovationContext) error {
				return fmt.Errorf("while constructing edit vars renovator: %w", err)
			}
		}
	}

	return func(ctx context.Context, rc *renovate.RenovationContext) error {
		log.Infof("attempting to edit variables: %v", cfg.Variables)

		// Find the root node
		rootNode := rc.Configuration.Root().Content[0]

		// Look for vars node
		varsNode, err := renovate.NodeFromMapping(rootNode, "vars")
		if err != nil {
			// If vars section doesn't exist, skip the entire operation
			log.Infof("vars section not found, skipping edit operation")
			return nil
		}

		// Update variables in the vars section
		for key, value := range cfg.Variables {
			updated, err := updateVariable(varsNode, key, value, log)
			if err != nil {
				return fmt.Errorf("failed to update variable %s: %w", key, err)
			}
			if updated {
				log.Infof("updated variable: %s = %s", key, value)
			}
		}

		return nil
	}
}

func updateVariable(varsNode *yaml.Node, key, value string, log *clog.Logger) (bool, error) {
	// Look for existing variable
	for i := 0; i < len(varsNode.Content); i += 2 {
		if varsNode.Content[i].Value == key {
			// Update existing variable
			varsNode.Content[i+1].Value = value
			varsNode.Content[i+1].Style = yaml.DoubleQuotedStyle
			varsNode.Content[i+1].Tag = "!!str"
			return true, nil
		}
	}

	// Variable not found, log and skip
	log.Infof("variable '%s' not found, skipping", key)
	return false, nil
}
