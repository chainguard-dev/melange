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

type convertOptions struct {
	outDir                 string
	additionalRepositories []string
	additionalKeyrings     []string
}

var convertRoot = &cobra.Command{
	Use:               "convert",
	DisableAutoGenTag: false,
	SilenceUsage:      true,
	Short:             "EXPERIMENTAL COMMAND - Attempts to convert packages/gems/apkbuild files into melange configuration files",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		fmt.Println("This command is EXPERIMENTAL. Verify and test melange configuration output before submitting a PR")
	},
}

func Convert() *cobra.Command {
	o := &convertOptions{}

	convertRoot.PersistentFlags().StringVar(&o.outDir, "out-dir", "./generated", "directory where convert config will be output")
	convertRoot.PersistentFlags().StringArrayVar(&o.additionalRepositories, "additional-repositories", []string{}, "additional repositories to be added to convert environment config")
	convertRoot.PersistentFlags().StringArrayVar(&o.additionalKeyrings, "additional-keyrings", []string{}, "additional repositories to be added to convert environment config")

	convertRoot.AddCommand(
		GemBuild(),
		ApkBuild(),
		PythonBuild(),
	)

	return convertRoot
}
