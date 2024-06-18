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
	"github.com/chainguard-dev/clog/gcp"
	charmlog "github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"
)

func New() *cobra.Command {
	var level log.CharmLogLevel
	var gcplog bool
	cmd := &cobra.Command{
		Use:               "melange",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		SilenceErrors:     true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			http.DefaultTransport = userAgentTransport{http.DefaultTransport}

			if gcplog {
				slog.SetDefault(slog.New(gcp.NewHandler(slog.Level(level))))
			} else {
				out, err := log.Writer([]string{"builtin:stderr"})
				if err != nil {
					return fmt.Errorf("failed to create log writer: %w", err)
				}
				slog.SetDefault(slog.New(charmlog.NewWithOptions(out, charmlog.Options{ReportTimestamp: true, Level: charmlog.Level(level)})))
			}

			return nil
		},
	}
	cmd.PersistentFlags().Var(&level, "log-level", "log level (e.g. debug, info, warn, error)")
	cmd.PersistentFlags().BoolVar(&gcplog, "gcplog", false, "use GCP logging")
	_ = cmd.PersistentFlags().MarkHidden("gcplog")

	cmd.AddCommand(Build())
	cmd.AddCommand(Bump())
	cmd.AddCommand(Completion())
	cmd.AddCommand(Compile())
	cmd.AddCommand(Convert())
	cmd.AddCommand(Index())
	cmd.AddCommand(Keygen())
	cmd.AddCommand(Lint())
	cmd.AddCommand(Package())
	cmd.AddCommand(PackageVersion())
	cmd.AddCommand(Query())
	cmd.AddCommand(Scan())
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
