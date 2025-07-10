package cli

import (
	"context"
	"errors"
	"strings"

	"github.com/spf13/cobra"

	"chainguard.dev/melange/pkg/configlint"
)

type lintConfigOptions struct {
	args      []string
	list      bool
	skipRules []string
	severity  string
}

func lintConfigCmd() *cobra.Command {
	o := &lintConfigOptions{}
	cmd := &cobra.Command{
		Use:               "lint-config",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Short:             "Lint melange configuration files",
		RunE: func(cmd *cobra.Command, args []string) error {
			o.args = args
			return o.lint(cmd.Context())
		},
	}
	cmd.Flags().BoolVarP(&o.list, "list", "l", false, "prints all available rules and exits")
	cmd.Flags().StringArrayVarP(&o.skipRules, "skip-rule", "", []string{}, "list of rules to skip")
	cmd.Flags().StringVarP(&o.severity, "severity", "s", "warning", "minimum severity level to report (error, warning, info)")
	return cmd
}

func (o lintConfigOptions) lint(ctx context.Context) error {
	l := configlint.New(o.makeOptions()...)

	if o.list {
		l.PrintRules(ctx)
		return nil
	}

	minSeverity := configlint.SeverityWarning
	switch strings.ToLower(o.severity) {
	case "error":
		minSeverity = configlint.SeverityError
	case "info":
		minSeverity = configlint.SeverityInfo
	}

	result, err := l.Lint(ctx, minSeverity)
	if err != nil {
		return err
	}
	if result.HasErrors() {
		l.Print(ctx, result)
		for _, res := range result {
			for _, e := range res.Errors {
				if e.Rule.Severity.Value == configlint.SeverityErrorLevel {
					return errors.New("linting failed")
				}
			}
		}
	}
	return nil
}

func (o lintConfigOptions) makeOptions() []configlint.Option {
	if len(o.args) == 0 {
		o.args = []string{"."}
	}
	return []configlint.Option{
		configlint.WithPath(o.args[0]),
		configlint.WithSkipRules(o.skipRules),
	}
}
