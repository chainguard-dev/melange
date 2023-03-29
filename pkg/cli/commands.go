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
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "melange",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
	}

	cmd.AddCommand(Completion())
	cmd.AddCommand(Build())
	cmd.AddCommand(Bump())
	cmd.AddCommand(Keygen())
	cmd.AddCommand(Index())
	cmd.AddCommand(SignIndex())
	cmd.AddCommand(UpdateCache())
	cmd.AddCommand(Convert())
	cmd.AddCommand(PackageVersion())
	cmd.AddCommand(Query())
	cmd.AddCommand(version.Version())
	return cmd
}
