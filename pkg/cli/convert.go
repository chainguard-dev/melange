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

func Convert() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "convert",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		Short:             "EXPERIMENTAL COMMAND - Attempts to convert packages/gems/apkbuild files into melange configuration files",
		Long: `Convert is an EXPERIMENTAL COMMAND - Attempts to convert packages/gems/apkbuild files into melange configuration files
								Check that the build executes and builds the apk as expected, using the wolfi-dev/sdk to test the install of built apk
								Dependencies are recursively generated and a lot of assumptions are made for you, there be dragons here. 
							`,
	}
	cmd.AddCommand(
		ApkBuild(),
		GemBuild(),
		PythonBuild(),
	)
	return cmd
}
