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

package build

import (
	"context"
	"embed"
	"fmt"
	"maps"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	apkoTypes "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"

	"chainguard.dev/melange/pkg/cond"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/container"
	"chainguard.dev/melange/pkg/util"
)

const WorkDir = "/home/build"

func (sm *SubstitutionMap) MutateWith(with map[string]string) (map[string]string, error) {
	nw := maps.Clone(sm.Substitutions)

	for k, v := range with {
		// already mutated?
		if strings.HasPrefix(k, "${{") {
			nw[k] = v
		} else {
			nk := fmt.Sprintf("${{inputs.%s}}", k)
			nw[nk] = v
		}
	}

	// do the actual mutations
	for k, v := range nw {
		nval, err := util.MutateStringFromMap(nw, v)
		if err != nil {
			return nil, err
		}
		nw[k] = nval
	}

	return nw, nil
}

type SubstitutionMap struct {
	Substitutions map[string]string
}

func (sm *SubstitutionMap) Subpackage(subpkg *config.Subpackage) *SubstitutionMap {
	nw := maps.Clone(sm.Substitutions)
	nw[config.SubstitutionSubPkgName] = subpkg.Name
	nw[config.SubstitutionContextName] = subpkg.Name
	nw[config.SubstitutionSubPkgDir] = fmt.Sprintf("/home/build/melange-out/%s", subpkg.Name)
	nw[config.SubstitutionTargetsContextdir] = nw[config.SubstitutionSubPkgDir]

	return &SubstitutionMap{nw}
}

func NewSubstitutionMap(cfg *config.Configuration, arch apkoTypes.Architecture, flavor string, buildOpts []string) (*SubstitutionMap, error) {
	pkg := cfg.Package

	nw := map[string]string{
		config.SubstitutionPackageName:        pkg.Name,
		config.SubstitutionPackageVersion:     pkg.Version,
		config.SubstitutionPackageEpoch:       strconv.FormatUint(pkg.Epoch, 10),
		config.SubstitutionPackageFullVersion: fmt.Sprintf("%s-r%d", pkg.Version, pkg.Epoch),
		config.SubstitutionPackageSrcdir:      "/home/build",
		config.SubstitutionTargetsOutdir:      "/home/build/melange-out",
		config.SubstitutionTargetsDestdir:     fmt.Sprintf("/home/build/melange-out/%s", pkg.Name),
		config.SubstitutionTargetsContextdir:  fmt.Sprintf("/home/build/melange-out/%s", pkg.Name),
		config.SubstitutionContextName:        pkg.Name,
	}

	nw[config.SubstitutionHostTripletGnu] = arch.ToTriplet(flavor)
	nw[config.SubstitutionHostTripletRust] = arch.ToRustTriplet(flavor)
	nw[config.SubstitutionCrossTripletGnuGlibc] = arch.ToTriplet("gnu")
	nw[config.SubstitutionCrossTripletGnuMusl] = arch.ToTriplet("musl")
	nw[config.SubstitutionCrossTripletRustGlibc] = arch.ToRustTriplet("gnu")
	nw[config.SubstitutionCrossTripletRustMusl] = arch.ToRustTriplet("musl")
	nw[config.SubstitutionBuildArch] = arch.ToAPK()
	nw[config.SubstitutionBuildGoArch] = arch.String()

	// Retrieve vars from config
	subst_nw, err := cfg.GetVarsFromConfig()
	if err != nil {
		return nil, err
	}

	maps.Copy(nw, subst_nw)

	// Perform substitutions on current map
	if err := cfg.PerformVarSubstitutions(nw); err != nil {
		return nil, err
	}

	packageNames := []string{pkg.Name}
	for _, sp := range cfg.Subpackages {
		packageNames = append(packageNames, sp.Name)
	}

	for _, pn := range packageNames {
		k := fmt.Sprintf("${{targets.package.%s}}", pn)
		nw[k] = fmt.Sprintf("/home/build/melange-out/%s", pn)
	}

	for k := range cfg.Options {
		nk := fmt.Sprintf("${{options.%s.enabled}}", k)
		nw[nk] = "false"
	}

	for _, opt := range buildOpts {
		nk := fmt.Sprintf("${{options.%s.enabled}}", opt)
		nw[nk] = "true"
	}

	return &SubstitutionMap{nw}, nil
}

func validateWith(data map[string]string, inputs map[string]config.Input) (map[string]string, error) {
	if data == nil {
		data = make(map[string]string)
	}
	for k, v := range inputs {
		if data[k] == "" {
			data[k] = v.Default
		}
		if data[k] != "" {
			switch k {
			case "expected-sha256", "expected-sha512":
				if !matchValidShaChars(data[k]) || len(data[k]) != expectedShaLength(k) {
					return data, fmt.Errorf("checksum input %q for pipeline, invalid length", k)
				}
			case "expected-commit":
				if !matchValidShaChars(data[k]) || len(data[k]) != expectedShaLength(k) {
					return data, fmt.Errorf("expected commit %q for pipeline contains invalid characters or invalid sha length", k)
				}
			}
		}
		if v.Required && data[k] == "" {
			return data, fmt.Errorf("required input %q for pipeline is missing", k)
		}
	}

	return data, nil
}

func matchValidShaChars(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// Build a script to run as part of evalRun
func buildEvalRunCommand(_ *config.Pipeline, debugOption rune, workdir string, fragment string) []string {
	script := fmt.Sprintf(`set -e%c
[ -d '%s' ] || mkdir -p '%s'
cd '%s'
%s
exit 0`, debugOption, workdir, workdir, workdir, fragment)
	return []string{"/bin/sh", "-c", script}
}

type pipelineRunner struct {
	debug       bool
	interactive bool
	config      *container.Config
	runner      container.Runner
}

func (r *pipelineRunner) runPipeline(ctx context.Context, pipeline *config.Pipeline) (bool, error) {
	log := clog.FromContext(ctx)

	if result, err := shouldRun(pipeline.If); !result {
		return result, err
	}

	debugOption := ' '
	if r.debug {
		debugOption = 'x'
	}

	// Pipelines can have their own environment variables, which override the global ones.
	envOverride := map[string]string{
		// NOTE: This does not currently override PATH in the qemu runner, that's set at openssh build time
		"PATH": "/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin",
	}

	maps.Copy(envOverride, pipeline.Environment)

	workdir := WorkDir
	if pipeline.WorkDir != "" {
		if filepath.IsAbs(pipeline.WorkDir) {
			workdir = pipeline.WorkDir
		} else {
			workdir = filepath.Join(WorkDir, pipeline.WorkDir)
		}
	}

	// We might have called signal.Ignore(os.Interrupt) as part of a previous debug step,
	// so create a new context to make it possible to cancel the Run.
	if r.interactive {
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt)
		defer stop()
	}

	if id := identity(pipeline); id != unidentifiablePipeline {
		log.Infof("running step %q", id)
	}

	command := buildEvalRunCommand(pipeline, debugOption, workdir, pipeline.Runs)
	if err := r.runner.Run(ctx, r.config, envOverride, command...); err != nil {
		if err := r.maybeDebug(ctx, pipeline.Runs, envOverride, command, workdir, err); err != nil {
			return false, err
		}
	}

	steps := 0

	for _, p := range pipeline.Pipeline {
		// Merge nested pipeline environment with parent environment
		mergedEnv := maps.Clone(envOverride)
		maps.Copy(mergedEnv, p.Environment)
		p.Environment = mergedEnv
		if ran, err := r.runPipelineWithRetry(ctx, &p); err != nil {
			return false, fmt.Errorf("unable to run pipeline: %w", err)
		} else if ran {
			steps++
		}
	}

	if assert := pipeline.Assertions; assert != nil {
		if want := assert.RequiredSteps; want != steps {
			return false, fmt.Errorf("pipeline did not run the required %d steps, only %d", want, steps)
		}
	}

	return true, nil
}

func (r *pipelineRunner) maybeDebug(ctx context.Context, fragment string, envOverride map[string]string, cmd []string, workdir string, runErr error) error {
	if !r.interactive {
		return runErr
	}

	log := clog.FromContext(ctx)

	dbg, ok := r.runner.(container.Debugger)
	if !ok {
		log.Errorf("TODO: Implement Debug() for Runner: %T", r.runner)
		return runErr
	}

	// This is a bit of a hack but I want non-busybox shells to have a working history during interactive debugging,
	// and I suspect busybox is the least helpful here, so just make everything read from $HOME/.ash_history.
	if home, ok := envOverride["HOME"]; ok {
		envOverride["HISTFILE"] = path.Join(home, ".ash_history")
	} else if home, ok := r.config.Environment["HOME"]; ok {
		envOverride["HISTFILE"] = path.Join(home, ".ash_history")
	}

	// Required for many TUIs (emacs, make menuconfig, etc)
	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}
	envOverride["TERM"] = termType

	log.Errorf("Step failed: %v\n%s", runErr, strings.Join(cmd, " "))
	log.Info(fmt.Sprintf("Execing into pod %q to debug interactively.", r.config.PodID), "workdir", workdir)
	log.Infof("Type 'exit 0' to continue the next pipeline step or 'exit 1' to abort.")

	// If the context has already been cancelled, return before we mess with it.
	if err := ctx.Err(); err != nil {
		return err
	}

	// Don't cancel the context if we hit ctrl+C while debugging.
	signal.Ignore(os.Interrupt)

	// Populate $HOME/.ash_history with the current command so you can hit up arrow to repeat it.
	// #nosec G306 - Shell history file in workspace directory
	if err := os.WriteFile(filepath.Join(r.config.WorkspaceDir, ".ash_history"), []byte(fragment), 0o644); err != nil {
		return fmt.Errorf("failed to write history file: %w", err)
	}

	if dbgErr := dbg.Debug(ctx, r.config, envOverride, []string{"/bin/sh", "-c", fmt.Sprintf("cd %s && exec /bin/sh", workdir)}...); dbgErr != nil {
		return fmt.Errorf("failed to debug: %w; original error: %w", dbgErr, runErr)
	}

	// Reset to the default signal handling.
	signal.Reset(os.Interrupt)

	// If Debug() returns successfully (via exit 0), it is a signal to continue execution.
	return nil
}

func (r *pipelineRunner) runPipelines(ctx context.Context, pipelines []config.Pipeline) error {
	for _, p := range pipelines {
		if _, err := r.runPipelineWithRetry(ctx, &p); err != nil {
			return fmt.Errorf("unable to run pipeline: %w", err)
		}
	}

	return nil
}

func shouldRun(ifs string) (bool, error) {
	if ifs == "" {
		return true, nil
	}

	result, err := cond.Evaluate(ifs)
	if err != nil {
		return false, fmt.Errorf("evaluating if-conditional %q: %w", ifs, err)
	}

	return result, nil
}

// parseDuration parses a duration string, returning the default if parsing fails or string is empty.
func parseDuration(s string, defaultDuration time.Duration) (time.Duration, error) {
	if s == "" {
		return defaultDuration, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	return d, nil
}

// calculateBackoff calculates the backoff delay for a given retry attempt.
func calculateBackoff(strategy string, attemptNum int, initialDelay, maxDelay time.Duration) time.Duration {
	var delay time.Duration

	switch strategy {
	case "constant":
		delay = initialDelay
	case "linear":
		delay = time.Duration(attemptNum+1) * initialDelay
	case "exponential":
		// 2^attemptNum * initialDelay
		multiplier := 1 << attemptNum
		delay = time.Duration(multiplier) * initialDelay
	default:
		// Default to exponential
		multiplier := 1 << attemptNum
		delay = time.Duration(multiplier) * initialDelay
	}

	if delay > maxDelay {
		delay = maxDelay
	}

	return delay
}

// runPipelineWithRetry wraps runPipeline with retry logic based on the pipeline's retry configuration.
func (r *pipelineRunner) runPipelineWithRetry(ctx context.Context, pipeline *config.Pipeline) (bool, error) {
	log := clog.FromContext(ctx)

	// If no retry config, just run the pipeline once
	if pipeline.Retry == nil {
		return r.runPipeline(ctx, pipeline)
	}

	// Parse and apply defaults to retry configuration
	attempts := pipeline.Retry.Attempts
	if attempts < 1 {
		attempts = 1
	}

	backoff := pipeline.Retry.Backoff
	if backoff == "" {
		backoff = "exponential"
	}

	initialDelay, err := parseDuration(pipeline.Retry.InitialDelay, 1*time.Second)
	if err != nil {
		return false, fmt.Errorf("invalid initial-delay: %w", err)
	}

	maxDelay, err := parseDuration(pipeline.Retry.MaxDelay, 60*time.Second)
	if err != nil {
		return false, fmt.Errorf("invalid max-delay: %w", err)
	}

	// Execute pipeline with retry logic
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			// Calculate backoff delay
			delay := calculateBackoff(backoff, attempt-1, initialDelay, maxDelay)

			if id := identity(pipeline); id != unidentifiablePipeline {
				log.Infof("retrying step %q (attempt %d/%d) after %v", id, attempt+1, attempts, delay)
			} else {
				log.Infof("retrying pipeline (attempt %d/%d) after %v", attempt+1, attempts, delay)
			}

			// Wait for backoff delay, respecting context cancellation
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(delay):
			}
		}

		ran, err := r.runPipeline(ctx, pipeline)
		if err == nil {
			// Success
			return ran, nil
		}

		lastErr = err

		// If this is not the last attempt, continue to retry
		if attempt < attempts-1 {
			if id := identity(pipeline); id != unidentifiablePipeline {
				log.Warnf("step %q failed (attempt %d/%d): %v", id, attempt+1, attempts, err)
			} else {
				log.Warnf("pipeline failed (attempt %d/%d): %v", attempt+1, attempts, err)
			}
		}
	}

	// All attempts exhausted
	if id := identity(pipeline); id != unidentifiablePipeline {
		return false, fmt.Errorf("step %q failed after %d attempts: %w", id, attempts, lastErr)
	}
	return false, fmt.Errorf("pipeline failed after %d attempts: %w", attempts, lastErr)
}

func expectedShaLength(shaType string) int {
	switch shaType {
	case "expected-sha256":
		return 64
	case "expected-sha512":
		return 128
	case "expected-commit":
		return 40
	}
	return 0
}

//go:embed pipelines/*
var PipelinesFS embed.FS
