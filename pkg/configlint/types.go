package configlint

import "errors"

import "chainguard.dev/melange/pkg/config"

// Function lints a single configuration.
type Function func(config.Configuration) error

// ConditionFunc returns whether a rule should be executed.
type ConditionFunc func() bool

// Severity represents a severity level.
type Severity struct {
	Name  string
	Value int
}

const (
	SeverityErrorLevel = iota
	SeverityWarningLevel
	SeverityInfoLevel
)

var (
	SeverityError   = Severity{"ERROR", SeverityErrorLevel}
	SeverityWarning = Severity{"WARNING", SeverityWarningLevel}
	SeverityInfo    = Severity{"INFO", SeverityInfoLevel}
)

// Rule represents a linter rule.
type Rule struct {
	Name           string
	Description    string
	Severity       Severity
	LintFunc       Function
	ConditionFuncs []ConditionFunc
}

// Rules is a list of Rule.
type Rules []Rule

// EvalRuleError is an error during rule evaluation.
type EvalRuleError struct {
	Rule  Rule
	Error error
}

// EvalRuleErrors is a list of EvalRuleError.
type EvalRuleErrors []EvalRuleError

// EvalResult is the result for a configuration file.
type EvalResult struct {
	File   string
	Errors EvalRuleErrors
}

// Result is a list of EvalResult.
type Result []EvalResult

// HasErrors returns true if any EvalResult contains errors.
func (r Result) HasErrors() bool {
	for _, res := range r {
		if res.Errors.WrapErrors() != nil {
			return true
		}
	}
	return false
}

// WrapErrors joins errors into one.
func (e EvalRuleErrors) WrapErrors() error {
	errs := []error{}
	for _, er := range e {
		errs = append(errs, er.Error)
	}
	return errors.Join(errs...)
}
