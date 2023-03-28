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

package build

import (
	"os"

	"gopkg.in/yaml.v3"
)

// RenovateContext contains the default settings for renovations.
type RenovateContext struct {
	ConfigFile string
}

type RenovateOption func(ctx *Context) error

// WithRenovateConfig sets the config file to do renovations on.
func WithRenovateConfig(configFile string) Option {
	return func(ctx *Context) error {
		ctx.ConfigFile = configFile
		return nil
	}
}

// NewRenovate creates a new renovation context.
func NewRenovate(opts ...Option) (*Context, error) {
	c := Context{}

	for _, opt := range opts {
		if err := opt(&c); err != nil {
			return nil, err
		}
	}

	return &c, nil
}

// RenovationContext encapsulates state relating to an
// ongoing renovation.
type RenovationContext struct {
	Context *Context
	Root    yaml.Node
}

// Renovator performs a renovation.
type Renovator func(rc *RenovationContext) error

// Renovate loads a config file, applies a chain of Renovators
// to perform a renovation, and writes the result back.
func (c *Context) Renovate(renovators ...Renovator) error {
	rc := RenovationContext{Context: c}

	if err := rc.LoadConfig(); err != nil {
		return err
	}

	for _, ren := range renovators {
		if err := ren(&rc); err != nil {
			return err
		}
	}

	if err := rc.WriteConfig(); err != nil {
		return err
	}

	return nil
}

// LoadConfig loads the configuration data into an AST for renovation.
func (rc *RenovationContext) LoadConfig() error {
	configData, err := os.ReadFile(rc.Context.ConfigFile)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(configData, &rc.Root); err != nil {
		return err
	}

	return nil
}

// WriteConfig writes the modified configuration data back to the config
// file.
func (rc *RenovationContext) WriteConfig() error {
	configFile, err := os.Create(rc.Context.ConfigFile)
	if err != nil {
		return err
	}
	defer configFile.Close()

	enc := yaml.NewEncoder(configFile)
	defer enc.Close()
	enc.SetIndent(2)

	if err := enc.Encode(rc.Root.Content[0]); err != nil {
		return err
	}

	return nil
}
