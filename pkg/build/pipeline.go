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

	apkoTypes "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/cond"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/container"
	"chainguard.dev/melange/pkg/util"
	"github.com/chainguard-dev/clog"
	"golang.org/x/crypto/ssh"
)

// ErrSkipStep is returned when a pipeline step should be skipped
var ErrSkipStep = fmt.Errorf("skip this pipeline step")

// ErrStopPipeline is returned when remaining pipeline steps should be skipped
var ErrStopPipeline = fmt.Errorf("stop remaining pipeline steps")

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

	for k, v := range subst_nw {
		nw[k] = v
	}

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
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// Build a script to run as part of evalRun
func buildEvalRunCommand(pipeline *config.Pipeline, debugOption rune, workdir string, fragment string) []string {
	script := fmt.Sprintf(`set -e%c
[ -d '%s' ] || mkdir -p '%s'
cd '%s'
%s
exit 0`, debugOption, workdir, workdir, workdir, fragment)
	return []string{"/bin/sh", "-c", script}
}

type pipelineRunner struct {
	debug         bool
	interactive   bool
	saveScripts   bool
	exportScripts string // Directory path to export scripts to host

	config      *container.Config
	runner      container.Runner
	scriptCount int // Counter for sequential script naming
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

	for k, v := range pipeline.Environment {
		envOverride[k] = v
	}

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

	// Note: Script generation is now handled in the pre-generation phase
	// This ensures all scripts are available even if breakpoints interrupt execution

	// Check for breakpoint before executing the pipeline step
	if pipeline.BreakBefore {
		if err := r.breakpointDebug(ctx, pipeline, workdir, envOverride, command); err != nil {
			if err == ErrSkipStep {
				log.Info("Skipping pipeline step as requested from breakpoint")
				return true, nil // true means we "ran" but actually skipped
			}
			if err == ErrStopPipeline {
				log.Info("Stopping remaining pipeline steps as requested from breakpoint")
				return false, nil // false means stop pipeline execution, nil means no error
			}
			return false, err
		}
	}

	if err := r.runner.Run(ctx, r.config, envOverride, command...); err != nil {
		if err := r.maybeDebug(ctx, pipeline.Runs, envOverride, command, workdir, err); err != nil {
			return false, err
		}
	}

	// Handle pipeline control options
	if pipeline.StopAfter {
		log.Info("Pipeline marked with stop-after, halting pipeline execution but continuing to packaging")
		return false, nil // false means stop pipeline execution, nil means no error
	}

	if pipeline.SkipRemaining {
		log.Info("Pipeline marked with skip-remaining, skipping remaining pipeline steps")
		return false, nil // false means stop pipeline execution, nil means no error
	}

	steps := 0

	for _, p := range pipeline.Pipeline {
		if ran, err := r.runPipeline(ctx, &p); err != nil {
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
	if err := os.WriteFile(filepath.Join(r.config.WorkspaceDir, ".ash_history"), []byte(fragment), 0o644); err != nil {
		return fmt.Errorf("failed to write history file: %w", err)
	}

	if dbgErr := dbg.Debug(ctx, r.config, envOverride, []string{"/bin/sh", "-c", fmt.Sprintf("cd %s && exec /bin/sh", workdir)}...); dbgErr != nil {
		return fmt.Errorf("failed to debug: %w; original error: %w", dbgErr, runErr)
	}

	// Reset to the default signal handling.
	signal.Reset(os.Interrupt)

	// If Debug() returns succesfully (via exit 0), it is a signal to continue execution.
	return nil
}

func (r *pipelineRunner) runPipelines(ctx context.Context, pipelines []config.Pipeline) error {
	// Phase 1: Pre-generate all scripts before execution
	// This ensures that even if breakpoints stop execution, all scripts are available
	if r.saveScripts || r.exportScripts != "" {
		if err := r.preGenerateScripts(ctx, pipelines); err != nil {
			return fmt.Errorf("unable to pre-generate scripts: %w", err)
		}
	}

	// Phase 2: Execute pipelines (with breakpoint support)
	for _, p := range pipelines {
		if _, err := r.runPipeline(ctx, &p); err != nil {
			return fmt.Errorf("unable to run pipeline: %w", err)
		}
	}

	return nil
}

// preGenerateScripts generates all pipeline scripts before execution starts
// This ensures script export works even when breakpoints interrupt execution
func (r *pipelineRunner) preGenerateScripts(ctx context.Context, pipelines []config.Pipeline) error {
	log := clog.FromContext(ctx)
	log.Info("Pre-generating pipeline scripts for export...")

	for _, pipeline := range pipelines {
		if err := r.preGenerateSingleScript(ctx, &pipeline); err != nil {
			return fmt.Errorf("failed to pre-generate script for step '%s': %w", pipeline.Name, err)
		}
	}

	// Generate helper scripts (run-all.sh, environment.sh)
	scriptsDir := "/home/build/.melange-scripts"
	if err := r.createHelperScripts(ctx, scriptsDir); err != nil {
		return fmt.Errorf("failed to create helper scripts: %w", err)
	}

	log.Infof("Successfully pre-generated scripts for %d pipeline steps", len(pipelines))
	return nil
}

// preGenerateSingleScript generates the script for a single pipeline step
func (r *pipelineRunner) preGenerateSingleScript(ctx context.Context, pipeline *config.Pipeline) error {
	// Skip script generation for build-only steps
	if pipeline.BuildOnly {
		return nil
	}

	// Skip if no script content and no nested pipelines
	if pipeline.Runs == "" && pipeline.Uses == "" && len(pipeline.Pipeline) == 0 {
		return nil
	}

	// Skip conditional steps that won't run
	if result, err := shouldRun(pipeline.If); !result {
		if err != nil {
			return err
		}
		return nil
	}

	// Create environment override map (similar to runPipeline)
	envOverride := map[string]string{}
	for k, v := range r.config.Environment {
		envOverride[k] = v
	}
	for k, v := range pipeline.Environment {
		envOverride[k] = v
	}

	// Determine working directory
	workdir := "/home/build"
	if pipeline.WorkDir != "" {
		workdir = pipeline.WorkDir
	}

	var scriptContent string

	// Handle nested pipelines (from compiled 'uses:' directives)
	if len(pipeline.Pipeline) > 0 {
		// Process nested pipelines and combine their content
		var combinedCommands []string
		for _, nestedPipeline := range pipeline.Pipeline {
			// Skip conditional nested pipelines that won't run
			if nestedPipeline.If != "" {
				if result, err := shouldRun(nestedPipeline.If); err != nil {
					return err
				} else if !result {
					continue
				}
			}

			// Use nested pipeline's working directory if specified
			nestedWorkdir := workdir
			if nestedPipeline.WorkDir != "" {
				nestedWorkdir = nestedPipeline.WorkDir
			}

			// Create environment for nested pipeline
			nestedEnvOverride := map[string]string{}
			for k, v := range envOverride {
				nestedEnvOverride[k] = v
			}
			for k, v := range nestedPipeline.Environment {
				nestedEnvOverride[k] = v
			}

			if nestedPipeline.Runs != "" {
				// Add working directory change if different from parent
				if nestedWorkdir != workdir {
					combinedCommands = append(combinedCommands, fmt.Sprintf("cd '%s'", nestedWorkdir))
				}
				// Add environment variables for this nested step
				for k, v := range nestedPipeline.Environment {
					combinedCommands = append(combinedCommands, fmt.Sprintf("export %s='%s'", k, v))
				}
				// Add the actual command
				combinedCommands = append(combinedCommands, nestedPipeline.Runs)
			}
		}

		if len(combinedCommands) > 0 {
			scriptContent = strings.Join(combinedCommands, "\n")
		} else {
			// No actual commands in nested pipelines, create minimal content
			scriptContent = "# Nested pipeline with no executable content"
		}
	} else {
		// Handle regular pipeline.Runs content
		debugOption := ' '
		if r.debug {
			debugOption = 'x'
		}

		command := buildEvalRunCommand(pipeline, debugOption, workdir, pipeline.Runs)

		// Extract script content from command
		// buildEvalRunCommand typically returns ["/bin/sh", "-c", "script content"]
		if len(command) >= 3 && command[0] == "/bin/sh" && command[1] == "-c" {
			scriptContent = command[2]
		} else {
			// Fallback to pipeline.Runs if command format is unexpected
			scriptContent = pipeline.Runs
		}
	}

	// Generate the script
	return r.saveScript(ctx, pipeline, workdir, scriptContent, envOverride)
}

// saveScript saves the pipeline script to the scripts directory
func (r *pipelineRunner) saveScript(ctx context.Context, pipeline *config.Pipeline, workdir, fragment string, envOverride map[string]string) error {
	// Create scripts directory
	scriptsDir := "/home/build/.melange-scripts"
	if err := r.runner.Run(ctx, r.config, nil, "/bin/sh", "-c", fmt.Sprintf("mkdir -p %s", scriptsDir)); err != nil {
		return fmt.Errorf("failed to create scripts directory: %w", err)
	}

	// Generate script name
	r.scriptCount++
	var scriptName string
	if pipeline.Name != "" {
		scriptName = fmt.Sprintf("%s.sh", pipeline.Name)
	} else {
		scriptName = fmt.Sprintf("unnamed-step-%02d.sh", r.scriptCount)
	}

	// Create the script content
	debugOption := ' '
	if r.debug {
		debugOption = 'x'
	}

	scriptContent := fmt.Sprintf(`#!/bin/sh
# Generated by Melange - Pipeline Script
# Step: %s
# Working Directory: %s
#
# This script can be run from any directory and will set up the proper
# build environment and working directory automatically.

set -e%c

# Ensure we're working with absolute paths
MELANGE_WORKDIR='%s'
MELANGE_SCRIPT_DIR='/home/build/.melange-scripts'

# Set up build environment
export HOME="${HOME:-/home/build}"
export USER="${USER:-build}"
export SHELL="${SHELL:-/bin/sh}"

# Create and change to working directory
[ -d "$MELANGE_WORKDIR" ] || mkdir -p "$MELANGE_WORKDIR"
cd "$MELANGE_WORKDIR"

# Environment Variables
%s

# Pipeline Script Content
%s
%s
`, pipeline.Name, workdir, debugOption, workdir, r.formatEnvVars(envOverride), fragment, r.conditionalExit(fragment))

	// Save the script in container
	scriptPath := fmt.Sprintf("%s/%s", scriptsDir, scriptName)
	saveCmd := fmt.Sprintf("cat > %s << 'EOF'\n%s\nEOF", scriptPath, scriptContent)
	if err := r.runner.Run(ctx, r.config, nil, "/bin/sh", "-c", saveCmd); err != nil {
		return fmt.Errorf("failed to save script %s: %w", scriptName, err)
	}

	// Make script executable in container
	if err := r.runner.Run(ctx, r.config, nil, "/bin/sh", "-c", fmt.Sprintf("chmod +x %s", scriptPath)); err != nil {
		return fmt.Errorf("failed to make script executable %s: %w", scriptName, err)
	}

	// Also export to host filesystem if requested
	if r.exportScripts != "" {
		if err := r.exportSingleScriptToHost(scriptName, scriptContent); err != nil {
			return fmt.Errorf("failed to export script to host %s: %w", scriptName, err)
		}
	}

	// Create helper scripts on first run
	if r.scriptCount == 1 {
		if err := r.createHelperScripts(ctx, scriptsDir); err != nil {
			return fmt.Errorf("failed to create helper scripts: %w", err)
		}
	}

	return nil
}

// conditionalExit adds exit 0 only if the fragment doesn't already end with it
func (r *pipelineRunner) conditionalExit(fragment string) string {
	trimmed := strings.TrimSpace(fragment)
	if strings.HasSuffix(trimmed, "exit 0") {
		return ""
	}
	return "\nexit 0"
}

// formatEnvVars formats environment variables for script inclusion
func (r *pipelineRunner) formatEnvVars(envOverride map[string]string) string {
	if len(envOverride) == 0 {
		return "# No additional environment variables"
	}

	var envLines []string
	for key, value := range envOverride {
		// Escape single quotes in the value
		escapedValue := strings.ReplaceAll(value, "'", "'\"'\"'")
		envLines = append(envLines, fmt.Sprintf("export %s='%s'", key, escapedValue))
	}
	return strings.Join(envLines, "\n")
}

// createHelperScripts creates run-all.sh and environment.sh scripts
func (r *pipelineRunner) createHelperScripts(ctx context.Context, scriptsDir string) error {
	// Create run-all.sh
	runAllContent := `#!/bin/sh
# Generated by Melange - Run All Scripts
# This script runs all pipeline scripts in order
#
# Usage:
#   # From the melange project root:
#   ./path/to/.melange-scripts/run-all.sh
#
#   # From any directory (if copied):
#   /home/build/.melange-scripts/run-all.sh
#
#   # Individual scripts can also be run directly:
#   /home/build/.melange-scripts/step-01-basic.sh
#
# The scripts will automatically:
#   - Set up the correct working directory (/home/build)
#   - Load environment variables
#   - Execute pipeline steps in the proper context

set -e

SCRIPT_DIR="/home/build/.melange-scripts"

echo "=== Running All Melange Pipeline Scripts ==="
echo "Script directory: $SCRIPT_DIR"
echo "Current directory: $(pwd)"
echo ""

# Check if script directory exists
if [ ! -d "$SCRIPT_DIR" ]; then
    echo "ERROR: Script directory does not exist: $SCRIPT_DIR"
    exit 1
fi

# Source environment if it exists
if [ -f "$SCRIPT_DIR/environment.sh" ]; then
    echo "Loading environment..."
    . "$SCRIPT_DIR/environment.sh"
fi

# Run all script files (excluding helper scripts)
for script in "$SCRIPT_DIR"/*.sh; do
    if [ -f "$script" ] && [ -x "$script" ]; then
        script_name="$(basename "$script")"
        # Skip helper scripts
        if [ "$script_name" != "run-all.sh" ] && [ "$script_name" != "environment.sh" ]; then
            echo "=== Running $script_name ==="

            # Run the script and capture return code
            "$script"
            ret_code=$?

            case $ret_code in
                0)
                    echo "✓ $script_name completed successfully"
                    ;;
                2)
                    echo "→ $script_name completed with stop-after signal"
                    echo "Stopping pipeline execution as requested"
                    echo ""
                    echo "=== Pipeline stopped by $script_name - packaging may continue ==="
                    exit 0
                    ;;
                3)
                    echo "→ $script_name completed with skip-remaining signal"
                    echo "Skipping remaining pipeline steps as requested"
                    echo ""
                    echo "=== Remaining steps skipped by $script_name ==="
                    exit 0
                    ;;
                *)
                    echo "✗ $script_name failed with exit code $ret_code"
                    echo "Stopping execution due to script failure"
                    exit $ret_code
                    ;;
            esac
            echo ""
        fi
    fi
done

echo "=== All pipeline scripts completed successfully ==="
`

	runAllCmd := fmt.Sprintf("cat > %s/run-all.sh << 'EOF'\n%s\nEOF", scriptsDir, runAllContent)
	if err := r.runner.Run(ctx, r.config, nil, "/bin/sh", "-c", runAllCmd); err != nil {
		return fmt.Errorf("failed to create run-all.sh: %w", err)
	}

	// Make run-all.sh executable
	if err := r.runner.Run(ctx, r.config, nil, "/bin/sh", "-c", fmt.Sprintf("chmod +x %s/run-all.sh", scriptsDir)); err != nil {
		return fmt.Errorf("failed to make run-all.sh executable: %w", err)
	}

	// Export run-all.sh to host if requested
	if r.exportScripts != "" {
		if err := r.exportSingleScriptToHost("run-all.sh", runAllContent); err != nil {
			return fmt.Errorf("failed to export run-all.sh to host: %w", err)
		}
	}

	// Create environment.sh
	envContent := `#!/bin/sh
# Generated by Melange - Environment Setup
# This script sets up the environment for pipeline execution
# Can be sourced from any directory to set up the Melange build environment

# Default environment for Melange builds
export HOME="${HOME:-/home/build}"
export USER="${USER:-build}"
export SHELL="${SHELL:-/bin/sh}"
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"

# Melange-specific variables
export MELANGE_WORKSPACE_DIR="/home/build"
export MELANGE_SCRIPT_DIR="/home/build/.melange-scripts"

# Ensure essential directories exist
mkdir -p "$HOME" 2>/dev/null || true
mkdir -p "$MELANGE_WORKSPACE_DIR" 2>/dev/null || true

# Set up PATH to include common binary locations
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"

# Change to workspace directory if it exists
if [ -d "$MELANGE_WORKSPACE_DIR" ]; then
    cd "$MELANGE_WORKSPACE_DIR"
fi

echo "Melange environment loaded"
echo "  HOME: $HOME"
echo "  USER: $USER"
echo "  WORKSPACE: $MELANGE_WORKSPACE_DIR"
echo "  SCRIPT_DIR: $MELANGE_SCRIPT_DIR"
echo "  PWD: $(pwd)"
`

	envCmd := fmt.Sprintf("cat > %s/environment.sh << 'EOF'\n%s\nEOF", scriptsDir, envContent)
	if err := r.runner.Run(ctx, r.config, nil, "/bin/sh", "-c", envCmd); err != nil {
		return fmt.Errorf("failed to create environment.sh: %w", err)
	}

	// Make environment.sh executable
	if err := r.runner.Run(ctx, r.config, nil, "/bin/sh", "-c", fmt.Sprintf("chmod +x %s/environment.sh", scriptsDir)); err != nil {
		return fmt.Errorf("failed to make environment.sh executable: %w", err)
	}

	// Export environment.sh to host if requested
	if r.exportScripts != "" {
		if err := r.exportSingleScriptToHost("environment.sh", envContent); err != nil {
			return fmt.Errorf("failed to export environment.sh to host: %w", err)
		}
	}

	return nil
}

// exportScriptsToHost copies scripts from container to host filesystem
func (r *pipelineRunner) exportScriptsToHost(ctx context.Context) error {
	if r.exportScripts == "" {
		return nil
	}

	log := clog.FromContext(ctx)

	// Create the host export directory
	if err := os.MkdirAll(r.exportScripts, 0755); err != nil {
		return fmt.Errorf("failed to create export directory %s: %w", r.exportScripts, err)
	}

	log.Infof("Scripts will be exported to: %s after build completion", r.exportScripts)
	return nil
}

// exportSingleScriptToHost exports a single script to the host filesystem
func (r *pipelineRunner) exportSingleScriptToHost(scriptName, scriptContent string) error {
	if r.exportScripts == "" {
		return nil
	}

	// Ensure the export directory exists
	if err := os.MkdirAll(r.exportScripts, 0755); err != nil {
		return fmt.Errorf("failed to create export directory %s: %w", r.exportScripts, err)
	}

	hostScriptPath := filepath.Join(r.exportScripts, scriptName)

	// Write script to host filesystem
	if err := os.WriteFile(hostScriptPath, []byte(scriptContent), 0755); err != nil {
		return fmt.Errorf("failed to write script to host %s: %w", hostScriptPath, err)
	}

	return nil
}

// breakpointDebug drops into interactive debugging before a pipeline step
func (r *pipelineRunner) breakpointDebug(ctx context.Context, pipeline *config.Pipeline, workdir string, envOverride map[string]string, command []string) error {
	log := clog.FromContext(ctx)

	dbg, ok := r.runner.(container.Debugger)
	if !ok {
		log.Errorf("Interactive debugging not supported for runner type: %T", r.runner)
		log.Errorf("Use --runner=qemu or --runner=docker for interactive debugging")
		return fmt.Errorf("breakpoint debugging not supported for this runner")
	}

	// Set up history file similar to maybeDebug
	if home, ok := envOverride["HOME"]; ok {
		envOverride["HISTFILE"] = path.Join(home, ".ash_history")
	}

	log.Infof("🛑 BREAKPOINT: Pausing before pipeline step '%s'", pipeline.Name)
	log.Info("=== PIPELINE STEP DETAILS ===")
	log.Infof("Step name: %s", pipeline.Name)
	if pipeline.Label != "" {
		log.Infof("Step label: %s", pipeline.Label)
	}
	log.Infof("Working directory: %s", workdir)
	log.Info("Environment variables:")
	for key, value := range envOverride {
		log.Infof("  %s=%s", key, value)
	}
	log.Info("Command that would be executed:")
	log.Infof("  %s", strings.Join(command, " "))
	log.Info("")
	log.Info("=== INTERACTIVE DEBUGGING ===")
	log.Infof("Dropping into interactive shell in pod %q", r.config.PodID)
	log.Info("You can:")
	log.Info("  • Examine the current environment")
	log.Info("  • Test commands manually")
	log.Info("  • Check file states")
	log.Info("  • Modify files for testing")
	log.Info("")
	log.Info("When ready:")
	log.Info("  • Type 'exit 0' to SKIP this step and continue with the next")
	log.Info("  • Type 'exit 1' to ABORT the entire build")
	log.Info("  • Type 'exit 2' to CONTINUE and run this pipeline step")
	log.Info("  • Type 'exit 3' to STOP here and skip all remaining pipeline steps")

	debugErr := dbg.Debug(ctx, r.config, envOverride, []string{"/bin/sh", "-c", fmt.Sprintf("cd %s && exec /bin/sh", workdir)}...)
	if debugErr != nil {
		if exitErr, ok := debugErr.(*ssh.ExitError); ok {
			switch exitErr.ExitStatus() {
			case 0:
				log.Info("⏭️ Skipping this pipeline step as requested")
				return ErrSkipStep
			case 1:
				log.Info("🚫 Aborting build as requested")
				return fmt.Errorf("build aborted by user at breakpoint before step '%s'", pipeline.Name)
			case 2:
				log.Info("✅ Continuing with pipeline step execution...")
				return nil
			case 3:
				log.Info("🛑 Stopping remaining pipeline steps as requested")
				return ErrStopPipeline
			default:
				log.Warnf("Unexpected exit code %d, treating as abort", exitErr.ExitStatus())
				return fmt.Errorf("build aborted by user at breakpoint before step '%s' (exit code %d)", pipeline.Name, exitErr.ExitStatus())
			}
		}
		return fmt.Errorf("breakpoint debugging failed: %w", debugErr)
	}

	log.Info("✅ Continuing with pipeline step execution...")
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
