// Copyright 2025 Chainguard, Inc.
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

package linter

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/chainguard-dev/clog"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/linter/types"
)

func lintPackageFS(ctx context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS, linters []string, results map[string]*types.PackageLintResults, fullPackageName string) error {
	log := clog.FromContext(ctx)
	var errs []error

	for _, linterName := range linters {
		if err := ctx.Err(); err != nil {
			return err
		}
		linter := linterMap[linterName]
		if err := linter.LinterFunc(ctx, cfg, pkgname, fsys); err != nil {
			// Extract message and structured details if available
			var message string
			var details any

			structErr := &types.StructuredError{}
			if errors.As(err, &structErr) {
				message = structErr.Message
				details = structErr.Details
			} else {
				message = err.Error()
			}

			// Split message into lines for better console readability
			messageLines := strings.Split(message, "\n")

			// Log multi-line errors with proper formatting
			log.Warnf("[%s] %s", linterName, messageLines[0])
			for _, line := range messageLines[1:] {
				if line != "" {
					log.Warnf("  %s", line)
				}
			}

			// Initialize package results
			if _, ok := results[pkgname]; !ok {
				results[pkgname] = &types.PackageLintResults{
					PackageName: fullPackageName,
					Findings:    make(map[string][]*types.LinterFinding),
				}
			}

			// Append finding to the linter's findings list
			finding := &types.LinterFinding{
				Message: messageLines[0], // Use first line as the summary message
				Details: details,
			}
			if linter.Explain != "" {
				log.Warnf("  → %s", linter.Explain)
				finding.Explain = linter.Explain
			}

			// Display itemized findings for structured details
			logStructuredDetails(log, details)

			results[pkgname].Findings[linterName] = append(results[pkgname].Findings[linterName], finding)

			errs = append(errs, fmt.Errorf("linter %q failed: %w", linterName, err))
		}
	}

	return errors.Join(errs...)
}
