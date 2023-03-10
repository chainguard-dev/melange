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
	"context"
	"fmt"

	"chainguard.dev/melange/pkg/convert"
	"github.com/pkg/errors"

	"github.com/spf13/cobra"
)

type apkbuildOptions struct {
	outDir                 string
	baseURIFormat          string
	additionalRepositories []string
	additionalKeyrings     []string
	excludePackages        []string
}

func ApkBuild() *cobra.Command {
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

			return o.ApkBuildCmd(cmd.Context(), args[0])
		},
	}

	cmd.Flags().StringVar(&o.baseURIFormat, "base-uri-format", "https://git.alpinelinux.org/aports/plain/main/%s/APKBUILD", "URI to use for querying APKBUILD for provided package name")
	cmd.Flags().StringArrayVar(&o.excludePackages, "exclude-packages", []string{}, "packages to exclude from auto generation of melange configs when detected in APKBUILD files")

	var err error
	o.additionalKeyrings, err = convertRoot.Flags().GetStringArray("additional-keyrings")
	if err != nil {
		return nil
	}
	o.additionalRepositories, err = convertRoot.Flags().GetStringArray("additional-repositories")
	if err != nil {
		return nil
	}
	o.outDir, err = convertRoot.Flags().GetString("out-dir")
	if err != nil {
		return nil
	}

	return cmd
}

func (o apkbuildOptions) ApkBuildCmd(ctx context.Context, packageName string) error {
	apkContext, err := convert.New()
	if err != nil {
		return errors.Wrap(err, "initialising convert command")
	}

	apkContext.AdditionalRepositories = o.additionalRepositories
	apkContext.AdditionalKeyrings = o.additionalKeyrings
	apkContext.OutDir = o.outDir
	apkContext.ExcludePackages = o.excludePackages
	configFilename := fmt.Sprintf(o.baseURIFormat, packageName)

	apkContext.Logger.Printf("generating convert config files for APKBUILD %s", configFilename)

	err = apkContext.Generate(configFilename, packageName)
	if err != nil {
		return errors.Wrap(err, "generating convert configuration")
	}

	return nil
}
