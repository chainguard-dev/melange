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

package renovate

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Context contains the default settings for renovations.
type Context struct {
	ConfigFile string
}

type Option func(ctx *Context) error

// WithConfig sets the config file to do renovations on.
func WithConfig(configFile string) Option {
	return func(ctx *Context) error {
		ctx.ConfigFile = configFile
		return nil
	}
}

// RenovationContext encapsulates state relating to an
// ongoing renovation.
type RenovationContext struct {
	Context *Context
	Root    yaml.Node
}

// RenovationConfig encapsulates configuration data relating
// to a Renovator.
type RenovationConfig any

// RenovationOption encapsulates mutation of a RenovationConfig.
type RenovationOption func(cfg *RenovationConfig) error

// Renovator performs a renovation.
type Renovator func(rc *RenovationContext) error

// Renovate loads a config file, applies a chain of Renovators
// to perform a renovation, and writes the result back.
func (c *Context) Renovate(renovators ...Renovator) error {
	rc := RenovationContext{Context: c}

	if err := rc.loadConfig(); err != nil {
		return err
	}

	for _, ren := range renovators {
		if err := ren(&rc); err != nil {
			return err
		}
	}

	if err := rc.writeConfig(); err != nil {
		return err
	}

	return nil
}

// loadConfig loads the configuration data into an AST for renovation.
func (rc *RenovationContext) loadConfig() error {
	configData, err := os.ReadFile(rc.Context.ConfigFile)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(configData, &rc.Root); err != nil {
		return err
	}

	return nil
}

// writeConfig writes the modified configuration data back to the config
// file.
func (rc *RenovationContext) writeConfig() error {
	configFile, err := os.Create(rc.Context.ConfigFile)
	if err != nil {
		return err
	}
	defer configFile.Close()

	enc := yaml.NewEncoder(configFile)
	defer enc.Close()

	if err := enc.Encode(rc.Root); err != nil {
		return err
	}

	return nil
}
