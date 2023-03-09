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

import "github.com/spf13/cobra"

type convertOptions struct {
	outDir                 string
	additionalRepositories []string
	additionalKeyrings     []string
}

func Convert() *cobra.Command {
	o := &convertOptions{}
	cmd := &cobra.Command{
		Use:               "convert",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		Short:             "EXPERIMENTAL COMMAND - Attempts to convert packages/gems/apkbuild files into melange configuration files",
	}

	cmd.Flags().StringVar(&o.outDir, "out-dir", "./generated", "directory where convert config will be output")
	cmd.Flags().StringArrayVar(&o.additionalRepositories, "additional-repositories", []string{}, "additional repositories to be added to convert environment config")
	cmd.Flags().StringArrayVar(&o.additionalKeyrings, "additional-keyrings", []string{}, "additional repositories to be added to convert environment config")

	cmd.AddCommand(
		ApkBuild(o),
		GemBuild(o),
		PythonBuild(o),
	)
	return cmd
}
