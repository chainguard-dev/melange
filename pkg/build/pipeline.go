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

	"github.com/chainguard-dev/clog"
	purl "github.com/package-url/packageurl-go"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/cond"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/container"
	"chainguard.dev/melange/pkg/util"
)

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
	nw[config.SubstitutionSubPkgDir] = fmt.Sprintf("/home/build/melange-out/%s", subpkg.Name)
	nw[config.SubstitutionTargetsContextdir] = nw[config.SubstitutionSubPkgDir]

	return &SubstitutionMap{nw}
}

func NewSubstitutionMap(cfg *config.Configuration, arch apko_types.Architecture, flavor string, buildOpts []string) (*SubstitutionMap, error) {
	pkg := cfg.Package

	nw := map[string]string{
		config.SubstitutionPackageName:        pkg.Name,
		config.SubstitutionPackageVersion:     pkg.Version,
		config.SubstitutionPackageEpoch:       strconv.FormatUint(pkg.Epoch, 10),
		config.SubstitutionPackageFullVersion: fmt.Sprintf("%s-r%s", config.SubstitutionPackageVersion, config.SubstitutionPackageEpoch),
		config.SubstitutionTargetsDestdir:     fmt.Sprintf("/home/build/melange-out/%s", pkg.Name),
		config.SubstitutionTargetsContextdir:  fmt.Sprintf("/home/build/melange-out/%s", pkg.Name),
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

		if v.Required && data[k] == "" {
			return data, fmt.Errorf("required input %q for pipeline is missing", k)
		}
	}

	return data, nil
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
		"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}

	for k, v := range pipeline.Environment {
		envOverride[k] = v
	}

	workdir := "/home/build"
	if pipeline.WorkDir != "" {
		workdir = pipeline.WorkDir
	}

	// We might have called signal.Ignore(os.Interrupt) as part of a previous debug step,
	// so create a new context to make it possible to cancel the Run.
	if r.interactive {
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt)
		defer stop()
	}

	if id := identity(pipeline); id != "???" {
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
	if err := os.WriteFile(filepath.Join(r.config.WorkspaceDir, ".ash_history"), []byte(fragment), 0644); err != nil {
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
	for _, p := range pipelines {
		if _, err := r.runPipeline(ctx, &p); err != nil {
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

// computeExternalRefs generates PURLs for subpipelines
func computeExternalRefs(uses string, with map[string]string) ([]purl.PackageURL, error) {
	var purls []purl.PackageURL
	var newpurl purl.PackageURL

	switch uses {
	case "fetch":
		args := make(map[string]string)
		args["download_url"] = with["${{inputs.uri}}"]
		if len(with["${{inputs.expected-sha256}}"]) > 0 {
			args["checksum"] = "sha256:" + with["${{inputs.expected-sha256}}"]
		}
		if len(with["${{inputs.expected-sha512}}"]) > 0 {
			args["checksum"] = "sha512:" + with["${{inputs.expected-sha512}}"]
		}
		newpurl = purl.PackageURL{
			Type:       "generic",
			Name:       with["${{inputs.purl-name}}"],
			Version:    with["${{inputs.purl-version}}"],
			Qualifiers: purl.QualifiersFromMap(args),
		}
		if err := newpurl.Normalize(); err != nil {
			return nil, err
		}
		purls = append(purls, newpurl)

	case "git-checkout":
		repository := with["${{inputs.repository}}"]
		if strings.HasPrefix(repository, "https://github.com/") {
			namespace, name, _ := strings.Cut(strings.TrimPrefix(repository, "https://github.com/"), "/")
			versions := []string{
				with["${{inputs.tag}}"],
				with["${{inputs.expected-commit}}"],
			}
			for _, version := range versions {
				if version != "" {
					newpurl = purl.PackageURL{
						Type:      "github",
						Namespace: namespace,
						Name:      name,
						Version:   version,
					}
					if err := newpurl.Normalize(); err != nil {
						return nil, err
					}
					purls = append(purls, newpurl)
				}
			}
		} else {
			// Create nice looking package name, last component of uri, without .git
			name := strings.TrimSuffix(filepath.Base(repository), ".git")
			// Encode vcs_url with git+ prefix and @commit suffix
			vcsUrl := "git+" + repository
			if len(with["${{inputs.expected-commit}}"]) > 0 {
				vcsUrl = vcsUrl + "@" + with["${{inputs.expected-commit}}"]
			}
			// Use tag as version
			version := ""
			if len(with["${{inputs.tag}}"]) > 0 {
				version = with["${{inputs.tag}}"]
			}
			newpurl = purl.PackageURL{
				Type:       "generic",
				Name:       name,
				Version:    version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{"vcs_url": vcsUrl}),
			}
			if err := newpurl.Normalize(); err != nil {
				return nil, err
			}
			purls = append(purls, newpurl)
		}
	}
	return purls, nil
}

//go:embed pipelines/*
var f embed.FS
