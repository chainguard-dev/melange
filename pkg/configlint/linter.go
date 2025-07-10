package configlint

import (
	"context"
	"fmt"
	"sort"

	"golang.org/x/exp/slices"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/chainguard-dev/clog"
)

// Linter represents a linter instance.
type Linter struct {
	options Options
}

// New initializes a new instance of Linter.
func New(opts ...Option) *Linter {
	o := Options{}
	for _, opt := range opts {
		opt(&o)
	}
	return &Linter{options: o}
}

// Lint evaluates all rules and returns the result.
func (l *Linter) Lint(ctx context.Context, minSeverity Severity) (Result, error) {
	log := clog.FromContext(ctx)
	rules := AllRules(l)

	namesToPkg, err := ReadAllPackagesFromRepo(ctx, l.options.Path)
	if err != nil {
		return Result{}, err
	}

	// reset host tracking for each run
	seenHosts = map[string]bool{}

	results := make(Result, 0)

	sortedNames := make([]string, 0, len(namesToPkg))
	for n := range namesToPkg {
		sortedNames = append(sortedNames, n)
	}
	sort.Strings(sortedNames)

	for _, name := range sortedNames {
		failedRules := make(EvalRuleErrors, 0)
		for _, rule := range rules {
			shouldEvaluate := true
			if len(rule.ConditionFuncs) > 0 {
				for _, cond := range rule.ConditionFuncs {
					if !cond() {
						shouldEvaluate = false
						break
					}
				}
			}
			if !shouldEvaluate {
				log.Debugf("%s: skipping rule %s because condition is not met\n", name, rule.Name)
				continue
			}
			if slices.Contains(l.options.SkipRules, rule.Name) {
				log.Debugf("%s: skipping rule %s because --skip-rule flag set\n", name, rule.Name)
				continue
			}
			if slices.Contains(namesToPkg[name].NoLint, rule.Name) {
				log.Debugf("%s: skipping rule %s because file contains #nolint:%s\n", name, rule.Name, rule.Name)
				continue
			}
			if err := rule.LintFunc(namesToPkg[name].Config); err != nil {
				if rule.Severity.Value <= minSeverity.Value {
					msg := fmt.Sprintf("[%s]: %s (%s)", rule.Name, err.Error(), rule.Severity.Name)
					failedRules = append(failedRules, EvalRuleError{Rule: rule, Error: fmt.Errorf("%s", msg)})
				}
			}
		}
		if failedRules.WrapErrors() != nil {
			results = append(results, EvalResult{File: name, Errors: failedRules})
		}
	}

	return results, nil
}

// Print prints lint results.
func (l *Linter) Print(ctx context.Context, result Result) {
	log := clog.FromContext(ctx)
	foundAny := false
	for _, res := range result {
		if res.Errors.WrapErrors() != nil {
			foundAny = true
			log.Errorf("Package: %s: %s", res.File, res.Errors.WrapErrors())
		}
	}
	if !foundAny {
		log.Infof("No linting issues found!")
	}
}

// PrintRules prints the rules to stdout.
func (l *Linter) PrintRules(ctx context.Context) {
	log := clog.FromContext(ctx)
	log.Info("Available rules:")
	for _, rule := range AllRules(l) {
		log.Infof("* %s: %s\n", rule.Name, cases.Title(language.Und).String(rule.Description))
	}
}
