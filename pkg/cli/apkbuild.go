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

	"chainguard.dev/melange/pkg/convert"
	"github.com/pkg/errors"

	"github.com/spf13/cobra"
)

type apkbuildOptions struct {
	baseURIFormat   string
	excludePackages []string
}

func ApkBuild(cOpts *convertOptions) *cobra.Command {
	o := &apkbuildOptions{}
	cmd := &cobra.Command{
		Use:     "apkbuild",
		Short:   "Converts an APKBUILD package into a melange.yaml",
		Long:    `Converts an APKBUILD package into a melange.yaml.`,
		Example: `  convert apkbuild libx11`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			if len(args) != 1 {
				return errors.New("too many arguments, expected only 1")
			}

			return o.ApkBuildCmd(cOpts, args[0])
		},
	}

	return cmd
}

func (o apkbuildOptions) ApkBuildCmd(cOpts *convertOptions, packageName string) error {
	context, err := convert.New()
	if err != nil {
		return errors.Wrap(err, "initialising convert command")
	}

	context.AdditionalRepositories = cOpts.additionalRepositories
	context.AdditionalKeyrings = cOpts.additionalKeyrings
	context.OutDir = cOpts.outDir
	context.ExcludePackages = o.excludePackages
	configFilename := fmt.Sprintf(o.baseURIFormat, packageName)

	context.Logger.Printf("generating convert config files for APKBUILD %s", configFilename)

	err = context.Generate(configFilename, packageName)
	if err != nil {
		return errors.Wrap(err, "generating convert configuration")
	}

	return nil
}
