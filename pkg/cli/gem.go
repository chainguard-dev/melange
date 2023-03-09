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

package cli

import (
	"fmt"

	"chainguard.dev/melange/pkg/gem"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type gemOptions struct {
	rubyVersion   string
	baseURIFormat string
}

// GemBuild is the top-level `convert gem` cobra command
//
// TODO: add a --version flag to switch the version of the gem
func GemBuild(cOpt *convertOptions) *cobra.Command {
	o := &gemOptions{}
	cmd := &cobra.Command{
		Use:   "gem",
		Short: "Converts an gem into a melange.yaml",
		Long:  `Converts an gem into a melange.yaml.`,
		Example: `
# Convert the latest fluentd gem
convert gem fluentd`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			if len(args) != 1 {
				return errors.New("too many arguments, expected only 1")
			}

			return o.gemBuild(cOpt, args[0])
		},
	}

	cmd.Flags().StringVar(
		&o.rubyVersion, "ruby-version", gem.DefaultRubyVersion,
		"version of ruby to use throughout generated manifests",
	)
	cmd.Flags().StringVar(
		&o.baseURIFormat, "base-uri-format", gem.DefaultBaseURIFormat,
		"URI to use for querying gems for provided package name",
	)
	return cmd
}

// gemBuild is the main cli function. It just sets up the GemBuild context and
// then executes the manifest generation.
func (o gemOptions) gemBuild(cOpt *convertOptions, packageName string) error {
	context, err := gem.New()
	if err != nil {
		return errors.Wrap(err, "initialising gem command")
	}

	context.RubyVersion = o.rubyVersion
	context.AdditionalRepositories = cOpt.additionalRepositories
	context.AdditionalKeyrings = cOpt.additionalKeyrings
	context.OutDir = cOpt.outDir
	context.BaseURIFormat = o.baseURIFormat
	configFilename := fmt.Sprintf(o.baseURIFormat, packageName)

	context.Logger.Printf("generating convert config files for gem %s", configFilename)

	return context.Generate(packageName)
}
