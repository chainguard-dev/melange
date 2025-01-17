// Copyright 2023 Chainguard, Inc.
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

	"github.com/spf13/cobra"
)

const (
	wolfiRepo    = "https://packages.wolfi.dev/os"
	wolfiKeyring = "https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"
)

type convertCmd struct {
	outDir        string
	wolfiDefaults bool
	useRelMon     bool
	useGithub     bool
}

func convert() *cobra.Command {
	c := &convertCmd{}
	cmd := &cobra.Command{
		Use:               "convert",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		//TraverseChildren:  true,
		Short: "EXPERIMENTAL COMMAND - Attempts to convert packages/gems/apkbuild files into melange configuration files",
		Long: `Convert is an EXPERIMENTAL COMMAND - Attempts to convert packages/gems/apkbuild files into melange configuration files
								Check that the build executes and builds the apk as expected, using the wolfi-dev/sdk to test the install of built apk
								Dependencies are recursively generated and a lot of assumptions are made for you, there be dragons here.
							`,
	}
	// Add out-dir, as well as additional-repos and additiona-keyrings flag to
	// all subcommands
	cmd.PersistentFlags().StringVarP(&c.outDir, "out-dir", "o", ".", "directory where convert config will be output")
	cmd.PersistentFlags().StringArray(
		"additional-repositories", []string{},
		"additional repositories to be added to convert environment config",
	)
	cmd.PersistentFlags().StringArray(
		"additional-keyrings", []string{},
		"additional repositories to be added to convert environment config",
	)

	// To support backwards compatibility, keep the default behavior of adding
	// wolfi repos, unless this flag is given, and it's not apk build which did
	// not add them by default.
	cmd.PersistentFlags().BoolVar(&c.wolfiDefaults, "wolfi-defaults", true, "if true, adds wolfi repo, and keyring to config")

	// Experimental flag to see if we can fetch monitoring release data, and
	// hence use it for Update section.
	cmd.PersistentFlags().BoolVar(&c.useRelMon, "use-relmon", false, "**experimental** if true, tries to use release-monitoring to fetch release monitoring data.")

	// Experimental flag to see if we can fetch github repo details and use that
	// in pipeline to fetch instead of the ftp.
	cmd.PersistentFlags().BoolVar(&c.useGithub, "use-github", true, "**experimental** if true, tries to use github to figure out the release commit details (python only for now). To prevent rate limiting, you can set the GITHUB_TOKEN env variable to a github token.")

	cmd.AddCommand(
		ApkBuild(),
		GemBuild(),
	)
	return cmd
}

// Helper function for getting the out-dir, additional-repositories and
// additional-keyrings since that's common to all subcommands.
// apkBuild did not add by default the wolfi repos, we we have to account for
// that to override the default behavior.
func getCommonValues(cmd *cobra.Command, honorWolfiDefaults bool) (string, []string, []string, error) {
	outDir, err := cmd.Flags().GetString("out-dir")
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to get out-dir flag: %w", err)
	}

	additionalRepositories, err := cmd.Flags().GetStringArray("additional-repositories")
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to get additional-repositories flag: %w", err)
	}

	additionalKeyrings, err := cmd.Flags().GetStringArray("additional-keyrings")
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to get additional-keyrings flag: %w", err)
	}
	// To ensure backwards compatibility while we migrate to the
	// explicitly specifying the wolfi repos, we add them by default
	// unless instructed not to.
	wolfiDefaults, err := cmd.Flags().GetBool("wolfi-defaults")
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to get wolfi-defaults flag: %w", err)
	}

	if honorWolfiDefaults && wolfiDefaults {
		additionalRepositories = append(additionalRepositories, wolfiRepo)
		additionalKeyrings = append(additionalKeyrings, wolfiKeyring)
	}
	return outDir, additionalRepositories, additionalKeyrings, nil
}
