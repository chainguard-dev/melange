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

	"chainguard.dev/melange/pkg/convert/python"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type pythonOptions struct {
	outDir                 string
	additionalRepositories []string
	additionalKeyrings     []string
	baseURIFormat          string
	pythonVersion          string
	packageVersion         string
}

// PythonBuild is the top-level `convert python` cobra command
func PythonBuild() *cobra.Command {
	o := &pythonOptions{}
	cmd := &cobra.Command{
		Use:   "python",
		Short: "Converts a python package into a melange.yaml",
		Long:  `Converts an python package into a melange.yaml.`,
		Example: `
# Convert the latest botocore python package
convert python botocore`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			if len(args) != 1 {
				return errors.New("too many arguments, expected only 1")
			}

			return o.pythonBuild(cmd.Context(), args[0])
		},
	}

	cmd.Flags().StringVar(&o.outDir, "out-dir", "./generated", "directory where convert config will be output")
	cmd.Flags().StringVar(&o.packageVersion, "package-version", "", "version of the python package to convert")
	cmd.Flags().StringVar(&o.baseURIFormat, "base-uri-format", "https://pypi.org",
		"URI to use for querying gems for provided package name")
	cmd.Flags().StringVar(&o.pythonVersion, "python-version", "3.11", "version of the python to build the package")
	cmd.Flags().StringArrayVar(&o.additionalRepositories, "additional-repositories", []string{}, "additional repositories to be added to convert environment config")
	cmd.Flags().StringArrayVar(&o.additionalKeyrings, "additional-keyrings", []string{}, "additional repositories to be added to convert environment config")

	return cmd
}

// pythonBuild is the main cli function. It just sets up the PythonBuild context and
// then executes the manifest generation.
func (o pythonOptions) pythonBuild(ctx context.Context, packageName string) error {

	pythonContext, err := python.New(packageName)
	if err != nil {
		return errors.Wrap(err, "initialising python command")
	}

	pythonContext.AdditionalRepositories = o.additionalRepositories
	pythonContext.AdditionalKeyrings = o.additionalKeyrings
	pythonContext.OutDir = o.outDir
	pythonContext.BaseURIFormat = o.baseURIFormat
	pythonContext.PackageVersion = o.packageVersion
	pythonContext.PythonVersion = o.pythonVersion
	pythonContext.PackageName = packageName

	pythonContext.Logger.Printf("generating convert config files for python package %s version: %s on python version: %s", pythonContext.PackageName, pythonContext.PythonVersion, pythonContext.PackageVersion)

	return pythonContext.Generate()

}
