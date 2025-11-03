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
	"os"

	"github.com/chainguard-dev/clog/gcp"
	"github.com/chainguard-dev/clog/slag"
	charmlog "github.com/charmbracelet/log"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"
)

func New() *cobra.Command {
	var level slag.Level
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
				slog.SetDefault(slog.New(charmlog.NewWithOptions(os.Stderr, charmlog.Options{ReportTimestamp: true, Level: charmlog.Level(level)})))
			}

			return nil
		},
	}
	cmd.PersistentFlags().Var(&level, "log-level", "log level (e.g. debug, info, warn, error)")
	cmd.PersistentFlags().BoolVar(&gcplog, "gcplog", false, "use GCP logging")
	_ = cmd.PersistentFlags().MarkHidden("gcplog")

	cmd.AddCommand(buildCmd())
	cmd.AddCommand(bumpCmd())
	cmd.AddCommand(completion())
	cmd.AddCommand(compile())
	cmd.AddCommand(indexCmd())
	cmd.AddCommand(keygen())
	cmd.AddCommand(licenseCheck())
	cmd.AddCommand(lint())
	cmd.AddCommand(packageVersion())
	cmd.AddCommand(query())
	cmd.AddCommand(scan())
	cmd.AddCommand(signCmd())
	cmd.AddCommand(signIndex())
	cmd.AddCommand(test())
	cmd.AddCommand(updateCache())
	cmd.AddCommand(version.Version())
	cmd.AddCommand(rebuild())
	return cmd
}

type userAgentTransport struct{ t http.RoundTripper }

func (u userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", fmt.Sprintf("melange/%s", version.GetVersionInfo().GitVersion))
	return u.t.RoundTrip(req)
}
