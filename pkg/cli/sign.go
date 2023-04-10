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

	"chainguard.dev/melange/internal/sign"
	"github.com/spf13/cobra"
)

func SignIndex() *cobra.Command {
	var signingKey string

	cmd := &cobra.Command{
		Use:     "sign-index",
		Short:   "Sign an APK index",
		Long:    `Sign an APK index.`,
		Example: `  melange sign-index [--signing-key=key.rsa] <APKINDEX.tar.gz>`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return SignIndexCmd(cmd.Context(), signingKey, args[0])
		},
	}

	cmd.Flags().StringVar(&signingKey, "signing-key", "melange.rsa", "the signing key to use")

	return cmd
}

func SignIndexCmd(ctx context.Context, signingKey string, indexFile string) error {
	return sign.SignIndex(LogDefault(), signingKey, indexFile)
}
