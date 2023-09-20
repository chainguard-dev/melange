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
	"io"
	"net/http"
	"os"
	"strings"

	"chainguard.dev/melange/pkg/index"

	"chainguard.dev/melange/pkg/convert/python"
	"chainguard.dev/melange/pkg/convert/relmon"

	"github.com/google/go-github/v54/github"
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
	ghClient               *github.Client
	mf                     *relmon.MonitorFinder
	useExistingPackages    bool
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

			var err error
			// Note we pass true here to get the default behaviour of adding
			// the wolfi repo and keyring. This is because we want to add them
			// by default for python.
			o.outDir, o.additionalRepositories, o.additionalKeyrings, err = getCommonValues(cmd, true)
			if err != nil {
				return err
			}
			o.ghClient, err = getGithubClient(cmd.Context(), cmd)
			if err != nil {
				return err
			}
			o.mf, err = getRelaseMonitoringClient(cmd)
			if err != nil {
				return err
			}
			return o.pythonBuild(cmd.Context(), args[0])
		},
	}

	cmd.Flags().StringVar(&o.packageVersion, "package-version", "", "version of the python package to convert")
	cmd.Flags().StringVar(&o.baseURIFormat, "base-uri-format", "https://pypi.org",
		"URI to use for querying gems for provided package name")
	cmd.Flags().StringVar(&o.pythonVersion, "python-version", "3", "version of the python to build the package")

	// Experimental flag to use the already existing packages in the Wolfi APK repo
	cmd.Flags().BoolVar(&o.useExistingPackages, "use-existing", false, "**experimental** if true, use the existing packages in the Wolfi APK repo")

	return cmd
}

func (o pythonOptions) pythonBuild(ctx context.Context, arg string) error {
	var (
		r   io.ReadCloser
		err error
	)

	switch {
	case strings.HasPrefix(arg, "http://"), strings.HasPrefix(arg, "https://"):
		resp, err := http.Get(arg)
		if err != nil {
			return errors.Wrapf(err, "getting %s", arg)
		}
		r = resp.Body
	case strings.Contains(arg, "/"), strings.Contains(arg, "requirements"):
		r, err = os.Open(arg)
	default:
		// If we neither have a HTTP(s) URL, nor a file path, we assume it's a
		// package name, and try to convert it as-is way.
		return o.pythonPackageBuild(ctx, arg, nil)
	}

	if err != nil {
		return errors.Wrap(err, "read")
	}

	pkgs, err := python.ParseRequirementsTxt(r)
	if err != nil {
		return errors.Wrap(err, "parse requirements")
	}

	return o.pythonPackageBuild(ctx, arg, pkgs)
}

// pythonPackageBuild is the main cli function. It just sets up the PythonBuild context and
// then executes the manifest generation.
func (o pythonOptions) pythonPackageBuild(ctx context.Context, packageName string, initialDeps []string) error {
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
	pythonContext.ToCheck = initialDeps

	// These two are conditionally set above, and if nil, they are unused.
	pythonContext.GithubClient = o.ghClient
	pythonContext.MonitoringClient = o.mf

	if o.useExistingPackages {
		ep, err := getExistedPythonPackagesFromIndex()
		if err != nil {
			return errors.Wrap(err, "existing packages from index")
		}
		pythonContext.ExistingPackages = ep
	}

	pythonContext.Logger.Printf("generating convert config files for python package %s version: %s on python version: %s", pythonContext.PackageName, pythonContext.PythonVersion, pythonContext.PackageVersion)

	if len(pythonContext.ToCheck) > 0 {
		return pythonContext.GenerateFromRequirements(ctx)
	}

	return pythonContext.GenerateFromIndex(ctx)
}

func getExistedPythonPackagesFromIndex() ([]string, error) {
	ic, err := index.New(index.WithExpectedArch("x86_64"))
	if err != nil {
		return nil, err
	}
	if err := ic.LoadIndex("https://packages.wolfi.dev/os"); err != nil {
		return nil, err
	}
	var existedPackages []string
	for _, pkg := range ic.Index.Packages {
		if strings.HasPrefix(pkg.Name, "py3") {
			existedPackages = append(existedPackages, pkg.Name)
		}
	}
	return existedPackages, nil
}
