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

	"github.com/pkg/errors"

	"chainguard.dev/melange/pkg/convert/apkbuild"
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

			var err error
			// Note we pass false here to avoid the default behaviour of adding
			// the wolfi repo and keyring. This is because we don't want to
			// add them by default for apkbuilds, but we do want to add them
			// but we want them for others.
			o.outDir, o.additionalRepositories, o.additionalKeyrings, err = getCommonValues(cmd, false)
			if err != nil {
				return err
			}
			return o.ApkBuildCmd(cmd.Context(), args[0])
		},
	}

	cmd.Flags().StringVar(&o.baseURIFormat, "base-uri-format", "https://git.alpinelinux.org/aports/plain/main/%s/APKBUILD", "URI to use for querying APKBUILD for provided package name")
	cmd.Flags().StringArrayVar(&o.excludePackages, "exclude-packages", []string{}, "packages to exclude from auto generation of melange configs when detected in APKBUILD files")

	return cmd
}

func (o apkbuildOptions) ApkBuildCmd(ctx context.Context, packageName string) error {
	context, err := apkbuild.New(ctx)
	if err != nil {
		return errors.Wrap(err, "initialising convert command")
	}

	context.AdditionalRepositories = o.additionalRepositories
	context.AdditionalKeyrings = o.additionalKeyrings
	context.OutDir = o.outDir
	context.ExcludePackages = o.excludePackages
	configFilename := fmt.Sprintf(o.baseURIFormat, packageName)

	context.Logger.Printf("generating convert config files for APKBUILD %s", configFilename)

	err = context.Generate(ctx, configFilename, packageName)
	if err != nil {
		return errors.Wrap(err, "generating convert configuration")
	}

	return nil
}
