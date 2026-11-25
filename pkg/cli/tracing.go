// Copyright 2026 Chainguard, Inc.
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

	"github.com/spf13/cobra"

	"chainguard.dev/melange/internal/tracing"
)

func withBuildTracing(flags *BuildFlags, run func(*cobra.Command, []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		// Preserve the existing file exporter even when OTLP is requested through
		// environment variables. In particular, do not replace its TracerProvider.
		if flags.TraceFile != "" {
			return run(cmd, args)
		}
		original := cmd.Context()
		return tracing.Run(original, "melange", "melange build", func(ctx context.Context) error {
			cmd.SetContext(ctx)
			defer cmd.SetContext(original)
			return run(cmd, args)
		})
	}
}
