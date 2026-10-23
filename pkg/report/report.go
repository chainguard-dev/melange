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

// Package report records what a melange build or test did: every stage,
// the guest environment it ran in, every (nested) pipeline step and the
// logs each step produced. The result is written as JSON and as a
// self-contained HTML page.
//
// All methods are nil-safe, so callers can thread an optional report
// through the build without checking whether reporting is enabled.
package report

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"chainguard.dev/melange/pkg/config"
)

type Status string

const (
	StatusRunning Status = "running"
	StatusSuccess Status = "success"
	StatusFailed  Status = "failed"
	StatusSkipped Status = "skipped"
)

// Report is the top-level record of one `melange build` or `melange test`
// invocation for a single architecture.
type Report struct {
	Kind       string `json:"kind"`
	Package    string `json:"package"`
	Version    string `json:"version"`
	Epoch      uint64 `json:"epoch"`
	Arch       string `json:"arch"`
	ConfigFile string `json:"configFile"`
	Runner     string `json:"runner"`
	Status     Status `json:"status"`
	Error      string `json:"error,omitempty"`
	// Failure summarizes what went wrong, so a reader (human or agent) does
	// not have to walk the stages to find it.
	Failure    *Failure  `json:"failure,omitempty"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	DurationMS int64     `json:"durationMs"`
	Stages     []*Stage  `json:"stages"`
	// Logs is every log line emitted while the report was attached, in order.
	Logs []LogLine `json:"logs"`

	redact []string
	mu     sync.Mutex
}

// Stage is one guest environment and the pipeline that ran in it, such as
// the main package build or a subpackage test.
type Stage struct {
	Name        string       `json:"name"`
	Package     string       `json:"package"`
	Status      Status       `json:"status"`
	Error       string       `json:"error,omitempty"`
	StartedAt   time.Time    `json:"startedAt"`
	FinishedAt  time.Time    `json:"finishedAt"`
	DurationMS  int64        `json:"durationMs"`
	Environment *Environment `json:"environment,omitempty"`
	Steps       []*Step      `json:"steps"`
	// Logs holds lines logged during the stage outside of any step, such
	// as the guest environment being assembled.
	Logs []LogLine `json:"logs,omitempty"`

	report *Report
}

// Environment describes the guest a stage ran in.
type Environment struct {
	// Requested is the package list from the configuration (locked to
	// versions for builds).
	Requested    []string          `json:"requested"`
	Installed    []Package         `json:"installed"`
	Repositories []string          `json:"repositories,omitempty"`
	Env          map[string]string `json:"env,omitempty"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Failure points at the stage and the innermost step that failed.
type Failure struct {
	Stage   string `json:"stage,omitempty"`
	Package string `json:"package,omitempty"`
	// StepID and StepPath identify the innermost failed step, e.g. "3.1"
	// and "go/build > runs".
	StepID   string            `json:"stepId,omitempty"`
	StepPath string            `json:"stepPath,omitempty"`
	Uses     string            `json:"uses,omitempty"`
	With     map[string]string `json:"with,omitempty"`
	Runs     string            `json:"runs,omitempty"`
	WorkDir  string            `json:"workdir,omitempty"`
	Error    string            `json:"error"`
	// LogTail is the last lines logged by the failed step (or stage, or
	// run, when no step failed), formatted as "LEVEL message".
	LogTail []string `json:"logTail"`
}

// failureLogTail is how many log lines Failure.LogTail keeps.
const failureLogTail = 50

// Step is one pipeline step. Steps from `uses:` pipelines are nested.
type Step struct {
	// ID is the step's position within its stage: "2" is the second
	// top-level step, "2.1" the first step nested in it.
	ID      string            `json:"id"`
	Name    string            `json:"name,omitempty"`
	Uses    string            `json:"uses,omitempty"`
	With    map[string]string `json:"with,omitempty"`
	If      string            `json:"if,omitempty"`
	Runs    string            `json:"runs,omitempty"`
	WorkDir string            `json:"workdir,omitempty"`
	// Env holds only the variables that differ from the stage's
	// environment.env; the step ran with both.
	Env        map[string]string `json:"env,omitempty"`
	Status     Status            `json:"status"`
	Error      string            `json:"error,omitempty"`
	StartedAt  time.Time         `json:"startedAt"`
	FinishedAt time.Time         `json:"finishedAt"`
	DurationMS int64             `json:"durationMs"`
	Logs       []LogLine         `json:"logs,omitempty"`
	Steps      []*Step           `json:"steps,omitempty"`

	report *Report
}

type LogLine struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

// New returns an empty report. Environment variables named in redact, or
// whose name looks like a credential, are masked in the output.
func New(kind string, cfg *config.Configuration, arch, configFile, runner string, redact []string) *Report {
	if abs, err := filepath.Abs(configFile); err == nil {
		configFile = abs
	}
	return &Report{
		Kind:       kind,
		Package:    cfg.Package.Name,
		Version:    cfg.Package.Version,
		Epoch:      cfg.Package.Epoch,
		Arch:       arch,
		ConfigFile: configFile,
		Runner:     runner,
		Status:     StatusRunning,
		StartedAt:  time.Now(),
		Stages:     []*Stage{},
		redact:     redact,
	}
}

type (
	stageKey struct{}
	stepKey  struct{}
)

// Attach returns a context whose logger also records into the report.
func (r *Report) Attach(ctx context.Context) context.Context {
	if r == nil {
		return ctx
	}
	return withRecorder(ctx, r, nil, nil)
}

// Finish marks the report as done, with err as the overall outcome. Stages
// still running (because the run bailed out early) share that outcome.
func (r *Report) Finish(err error) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Status, r.Error = outcome(err)
	r.FinishedAt = time.Now()
	r.DurationMS = r.FinishedAt.Sub(r.StartedAt).Milliseconds()
	for _, s := range r.Stages {
		if s.Status == StatusRunning {
			s.finish(err)
		}
	}
	r.Failure = r.findFailure()
}

func (r *Report) findFailure() *Failure {
	for _, s := range r.Stages {
		if s.Status != StatusFailed {
			continue
		}
		f := &Failure{Stage: s.Name, Package: s.Package, Error: s.Error, LogTail: tail(s.Logs)}
		if st, path := deepestFailed(s.Steps, nil); st != nil {
			f.StepID, f.StepPath = st.ID, strings.Join(path, " > ")
			f.Uses, f.With, f.Runs, f.WorkDir = st.Uses, st.With, st.Runs, st.WorkDir
			f.Error, f.LogTail = st.Error, tail(st.Logs)
		}
		return f
	}
	if r.Status == StatusFailed {
		return &Failure{Error: r.Error, LogTail: tail(r.Logs)}
	}
	return nil
}

// deepestFailed returns the innermost failed step and the titles leading to it.
func deepestFailed(steps []*Step, path []string) (*Step, []string) {
	for _, st := range steps {
		if st.Status != StatusFailed {
			continue
		}
		path := append(slices.Clone(path), st.Title())
		if child, childPath := deepestFailed(st.Steps, path); child != nil {
			return child, childPath
		}
		return st, path
	}
	return nil, nil
}

func tail(lines []LogLine) []string {
	lines = lines[max(0, len(lines)-failureLogTail):]
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, l.Level+" "+l.Message)
	}
	return out
}

// StartStage adds a stage and returns a context carrying it, so that
// SetEnvironment and StartStep calls further down attach to it.
func (r *Report) StartStage(ctx context.Context, name, pkg string) (context.Context, *Stage) {
	if r == nil {
		return ctx, nil
	}
	s := &Stage{Name: name, Package: pkg, Status: StatusRunning, StartedAt: time.Now(), Steps: []*Step{}, report: r}
	r.mu.Lock()
	r.Stages = append(r.Stages, s)
	r.mu.Unlock()
	ctx = context.WithValue(ctx, stageKey{}, s)
	ctx = context.WithValue(ctx, stepKey{}, (*Step)(nil))
	return withRecorder(ctx, r, s, nil), s
}

// StageFromContext returns the stage started by StartStage, if any.
func StageFromContext(ctx context.Context) *Stage {
	s, _ := ctx.Value(stageKey{}).(*Stage)
	return s
}

// Finish marks the stage as done with err as its outcome.
func (s *Stage) Finish(err error) {
	if s == nil {
		return
	}
	s.report.mu.Lock()
	defer s.report.mu.Unlock()
	s.finish(err)
}

func (s *Stage) finish(err error) {
	s.Status, s.Error = outcome(err)
	s.FinishedAt = time.Now()
	s.DurationMS = s.FinishedAt.Sub(s.StartedAt).Milliseconds()
}

// SetPackages records the packages of the stage's guest environment.
func (s *Stage) SetPackages(requested []string, installed []Package, repos []string) {
	if s == nil {
		return
	}
	s.report.mu.Lock()
	defer s.report.mu.Unlock()
	slices.SortFunc(installed, func(a, b Package) int { return cmp.Compare(a.Name, b.Name) })
	s.env().Requested = slices.Clone(requested)
	s.env().Installed = installed
	s.env().Repositories = slices.Clone(repos)
}

// SetEnv records the environment variables of the stage's guest.
func (s *Stage) SetEnv(env map[string]string) {
	if s == nil {
		return
	}
	s.report.mu.Lock()
	defer s.report.mu.Unlock()
	s.env().Env = s.report.redactEnv(env)
}

// ShareEnvironment records that the stage ran in the same guest as from.
func (s *Stage) ShareEnvironment(from *Stage) {
	if s == nil || from == nil {
		return
	}
	s.report.mu.Lock()
	defer s.report.mu.Unlock()
	s.Environment = from.Environment
}

func (s *Stage) env() *Environment {
	if s.Environment == nil {
		s.Environment = &Environment{}
	}
	return s.Environment
}

// StartStep records a pipeline step under the current step (or stage) in
// ctx and returns a context whose logs are captured into the new step.
// env is the full environment the step's command runs with.
func StartStep(ctx context.Context, p *config.Pipeline, env map[string]string) (context.Context, *Step) {
	stage := StageFromContext(ctx)
	if stage == nil {
		return ctx, nil
	}
	r := stage.report
	st := &Step{
		Name:      p.Name,
		Uses:      p.Uses,
		With:      maps.Clone(p.With),
		If:        p.If,
		Runs:      p.Runs,
		WorkDir:   p.WorkDir,
		Status:    StatusRunning,
		StartedAt: time.Now(),
		report:    r,
	}
	r.mu.Lock()
	if parent, _ := ctx.Value(stepKey{}).(*Step); parent != nil {
		st.ID = fmt.Sprintf("%s.%d", parent.ID, len(parent.Steps)+1)
		parent.Steps = append(parent.Steps, st)
	} else {
		st.ID = fmt.Sprint(len(stage.Steps) + 1)
		stage.Steps = append(stage.Steps, st)
	}
	var stageEnv map[string]string
	if stage.Environment != nil {
		stageEnv = stage.Environment.Env
	}
	for k, v := range r.redactEnv(env) {
		if sv, ok := stageEnv[k]; !ok || sv != v {
			if st.Env == nil {
				st.Env = map[string]string{}
			}
			st.Env[k] = v
		}
	}
	r.mu.Unlock()

	ctx = context.WithValue(ctx, stepKey{}, st)
	return withRecorder(ctx, r, stage, st), st
}

// Title is a short human-readable label for the step.
func (st *Step) Title() string {
	switch {
	case st.Name != "" && st.Uses != "":
		return st.Name + " (" + st.Uses + ")"
	case st.Name != "":
		return st.Name
	case st.Uses != "":
		return st.Uses
	}
	return "runs"
}

// Skip marks a step whose `if:` evaluated to false.
func (st *Step) Skip() {
	if st == nil {
		return
	}
	st.finish(StatusSkipped, "")
}

// Finish marks the step as done with err as its outcome.
func (st *Step) Finish(err error) {
	if st == nil {
		return
	}
	st.finish(outcome(err))
}

func (st *Step) finish(status Status, errMsg string) {
	st.report.mu.Lock()
	defer st.report.mu.Unlock()
	st.Status, st.Error = status, errMsg
	st.FinishedAt = time.Now()
	st.DurationMS = st.FinishedAt.Sub(st.StartedAt).Milliseconds()
}

func (r *Report) record(s *Stage, st *Step, line LogLine) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Logs = append(r.Logs, line)
	switch {
	case st != nil:
		st.Logs = append(st.Logs, line)
	case s != nil:
		s.Logs = append(s.Logs, line)
	}
}

func outcome(err error) (Status, string) {
	if err != nil {
		return StatusFailed, err.Error()
	}
	return StatusSuccess, ""
}

var secretish = regexp.MustCompile(`(?i)(token|secret|passw(or)?d|credential|api_?key|auth)`)

func (r *Report) redactEnv(env map[string]string) map[string]string {
	out := make(map[string]string, len(env))
	for k, v := range env {
		if slices.Contains(r.redact, k) || secretish.MatchString(k) {
			v = "<redacted>"
		}
		out[k] = v
	}
	return out
}

// Write writes the report to dir as JSON, Markdown and HTML, returning the
// paths. The Markdown file is a compact summary that leads with the
// failure, meant for quick reading by people and coding agents alike.
func (r *Report) Write(dir string) ([]string, error) {
	if r == nil {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating report dir: %w", err)
	}
	base := filepath.Join(dir, fmt.Sprintf("%s-%s-r%d-%s.%s", r.Package, r.Version, r.Epoch, r.Arch, r.Kind))

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding report: %w", err)
	}
	// #nosec G306 - Report is meant to be shared
	if err := os.WriteFile(base+".json", data, 0o644); err != nil {
		return nil, fmt.Errorf("writing report: %w", err)
	}

	view := reportView{Report: r, JSONFile: filepath.Base(base + ".json")}
	if err := render(base+".md", markdownTemplate, view); err != nil {
		return nil, err
	}
	if err := render(base+".html", htmlTemplate, view); err != nil {
		return nil, err
	}

	return []string{base + ".json", base + ".md", base + ".html"}, nil
}
