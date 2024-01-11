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
	"fmt"
	"log/slog"
	"net/http"

	"chainguard.dev/apko/pkg/log"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"
)

func New() *cobra.Command {
	var logPolicy []string
	var logLevel string
	cmd := &cobra.Command{
		Use:               "melange",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		SilenceErrors:     true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			http.DefaultTransport = userAgentTransport{http.DefaultTransport}

			// Enable printing warnings and progress from GGCR.
			//logs.Warn.SetOutput(writer)
			//logs.Progress.SetOutput(writer)

			var level slog.Level
			switch logLevel {
			case "debug":
				level = slog.LevelDebug
			case "info":
				level = slog.LevelInfo
			case "warn":
				level = slog.LevelWarn
			case "error":
				level = slog.LevelError
			default:
				return fmt.Errorf("invalid log level: %s", logLevel)
			}

			slog.SetDefault(slog.New(log.Handler(logPolicy, level)))

			return nil
		},
	}
	cmd.PersistentFlags().StringSliceVar(&logPolicy, "log-policy", []string{"builtin:stderr"}, "log policy (e.g. builtin:stderr, /tmp/log/foo)")
	cmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level (e.g. debug, info, warn, error)")

	cmd.AddCommand(Build())
	cmd.AddCommand(Bump())
	cmd.AddCommand(Completion())
	cmd.AddCommand(Convert())
	cmd.AddCommand(Index())
	cmd.AddCommand(Keygen())
	cmd.AddCommand(Lint())
	cmd.AddCommand(PackageVersion())
	cmd.AddCommand(Query())
	cmd.AddCommand(Sign())
	cmd.AddCommand(SignIndex())
	cmd.AddCommand(Test())
	cmd.AddCommand(UpdateCache())
	cmd.AddCommand(version.Version())
	return cmd
}

type userAgentTransport struct{ t http.RoundTripper }

func (u userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", fmt.Sprintf("melange/%s", version.GetVersionInfo().GitVersion))
	return u.t.RoundTrip(req)
}
