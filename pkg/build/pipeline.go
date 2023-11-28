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
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel"

	"gopkg.in/yaml.v3"

	apko_types "chainguard.dev/apko/pkg/build/types"
	apko_log "chainguard.dev/apko/pkg/log"

	"chainguard.dev/melange/pkg/cond"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/container"
	"chainguard.dev/melange/pkg/logger"
	"chainguard.dev/melange/pkg/util"
)

type PipelineContext struct {
	Pipeline        *config.Pipeline
	Environment     *apko_types.ImageConfiguration
	WorkspaceConfig *container.Config
	// Ordered list of pipeline directories to search for pipelines
	PipelineDirs []string
	logger       apko_log.Logger
	steps        int
}

func NewPipelineContext(p *config.Pipeline, environment *apko_types.ImageConfiguration, config *container.Config, pipelineDirs []string, log apko_log.Logger) *PipelineContext {
	if log == nil {
		log = logger.NopLogger{}
	}
	return &PipelineContext{
		Pipeline:        p,
		PipelineDirs:    pipelineDirs,
		Environment:     environment,
		WorkspaceConfig: config,
		logger:          log,
		steps:           0,
	}
}

type PipelineBuild struct {
	Build      *Build
	Test       *Test
	Package    *config.Package
	Subpackage *config.Subpackage
}

// GetConfiguration returns the configuration for the current pipeline.
// This is either for the Test or the Build
func (pb *PipelineBuild) GetConfiguration() *config.Configuration {
	if pb.Test != nil {
		return &pb.Test.Configuration
	}
	return &pb.Build.Configuration
}

// GetRunner returns the runner for the current pipeline.
// This is either for the Test or the Build
func (pb *PipelineBuild) GetRunner() container.Runner {
	if pb.Test != nil {
		return pb.Test.Runner
	}
	return pb.Build.Runner
}

func (pctx *PipelineContext) Identity() string {
	if pctx.Pipeline.Name != "" {
		return pctx.Pipeline.Name
	}
	if pctx.Pipeline.Uses != "" {
		return pctx.Pipeline.Uses
	}
	return "???"
}

func MutateWith(pb *PipelineBuild, with map[string]string) (map[string]string, error) {
	nw, err := substitutionMap(pb)
	if err != nil {
		return nil, err
	}

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

func substitutionMap(pb *PipelineBuild) (map[string]string, error) {
	nw := map[string]string{
		config.SubstitutionPackageName:        pb.Package.Name,
		config.SubstitutionPackageVersion:     pb.Package.Version,
		config.SubstitutionPackageEpoch:       strconv.FormatUint(pb.Package.Epoch, 10),
		config.SubstitutionPackageFullVersion: fmt.Sprintf("%s-r%s", config.SubstitutionPackageVersion, config.SubstitutionPackageEpoch),
		config.SubstitutionTargetsDestdir:     fmt.Sprintf("/home/build/melange-out/%s", pb.Package.Name),
		config.SubstitutionTargetsContextdir:  fmt.Sprintf("/home/build/melange-out/%s", pb.Package.Name),
	}

	// These are not really meaningful for Test, so only use them for build.
	if pb.Build != nil {
		nw[config.SubstitutionHostTripletGnu] = pb.Build.BuildTripletGnu()
		nw[config.SubstitutionHostTripletRust] = pb.Build.BuildTripletRust()
		nw[config.SubstitutionCrossTripletGnuGlibc] = pb.Build.Arch.ToTriplet("gnu")
		nw[config.SubstitutionCrossTripletGnuMusl] = pb.Build.Arch.ToTriplet("musl")
		nw[config.SubstitutionBuildArch] = pb.Build.Arch.ToAPK()
	}

	// Retrieve vars from config
	subst_nw, err := pb.GetConfiguration().GetVarsFromConfig()
	if err != nil {
		return nil, err
	}

	for k, v := range subst_nw {
		nw[k] = v
	}

	// Perform substitutions on current map
	err = pb.GetConfiguration().PerformVarSubstitutions(nw)
	if err != nil {
		return nil, err
	}

	if pb.Subpackage != nil {
		nw[config.SubstitutionSubPkgDir] = fmt.Sprintf("/home/build/melange-out/%s", pb.Subpackage.Name)
		nw[config.SubstitutionTargetsContextdir] = nw[config.SubstitutionSubPkgDir]
	}

	packageNames := []string{pb.Package.Name}
	for _, sp := range pb.GetConfiguration().Subpackages {
		packageNames = append(packageNames, sp.Name)
	}

	for _, pn := range packageNames {
		k := fmt.Sprintf("${{targets.package.%s}}", pn)
		nw[k] = fmt.Sprintf("/home/build/melange-out/%s", pn)
	}

	for k := range pb.GetConfiguration().Options {
		nk := fmt.Sprintf("${{options.%s.enabled}}", k)
		nw[nk] = "false"
	}

	if pb.Build != nil {
		for _, opt := range pb.Build.EnabledBuildOptions {
			nk := fmt.Sprintf("${{options.%s.enabled}}", opt)
			nw[nk] = "true"
		}
	}

	return nw, nil
}

func validateWith(data map[string]string, inputs map[string]config.Input) (map[string]string, error) {
	if data == nil {
		data = make(map[string]string)
	}

	for k, v := range inputs {
		if data[k] == "" && v.Default != "" {
			data[k] = v.Default
		}

		if v.Required && data[k] == "" {
			return data, fmt.Errorf("required input %q for pipeline is missing", k)
		}
	}

	return data, nil
}

func loadPipelineData(dir string, uses string) ([]byte, error) {
	if dir == "" {
		return []byte{}, fmt.Errorf("pipeline directory not specified")
	}

	data, err := os.ReadFile(filepath.Join(dir, uses+".yaml"))
	if err != nil {
		return []byte{}, err
	}

	return data, nil
}

func (pctx *PipelineContext) loadUse(pb *PipelineBuild, uses string, with map[string]string) error {
	var data []byte
	// Set this to fail up front in case there are no pipeline dirs specified
	// and we can't find them.
	err := fmt.Errorf("could not find 'uses' pipeline %q", uses)
	// See first if we can read from the specified pipeline dirs
	// and if we can't, below we'll try from the embedded pipelines.
	for _, pd := range pctx.PipelineDirs {
		pctx.logger.Debugf("trying to load pipeline %q from %q", uses, pd)
		data, err = loadPipelineData(pd, uses)
		if err == nil {
			pctx.logger.Printf("Found pipeline %s", string(data))
			break
		}
	}
	if err != nil {
		pctx.logger.Debugf("trying to load pipeline %q from embedded fs pipelines/%q.yaml", uses, uses)
		data, err = f.ReadFile("pipelines/" + uses + ".yaml")
		if err != nil {
			return fmt.Errorf("unable to load pipeline: %w", err)
		}
	}

	if err := yaml.Unmarshal(data, &pctx.Pipeline); err != nil {
		return fmt.Errorf("unable to parse pipeline %q: %w", uses, err)
	}

	validated, err := validateWith(with, pctx.Pipeline.Inputs)
	if err != nil {
		return fmt.Errorf("unable to construct pipeline: %w", err)
	}
	pctx.Pipeline.With, err = MutateWith(pb, validated)
	if err != nil {
		return err
	}

	// allow input mutations on needs.packages
	for p := range pctx.Pipeline.Needs.Packages {
		pctx.Pipeline.Needs.Packages[p], err = util.MutateStringFromMap(pctx.Pipeline.With, pctx.Pipeline.Needs.Packages[p])
		if err != nil {
			return err
		}
	}

	for k := range pctx.Pipeline.Pipeline {
		pctx.Pipeline.Pipeline[k].With = util.RightJoinMap(pctx.Pipeline.With, pctx.Pipeline.Pipeline[k].With)
	}

	return nil
}

func (pctx *PipelineContext) dumpWith() {
	for k, v := range pctx.Pipeline.With {
		pctx.logger.Debugf("    %s: %s", k, v)
	}
}

func (pctx *PipelineContext) evalUse(ctx context.Context, pb *PipelineBuild) error {
	spctx := NewPipelineContext(&config.Pipeline{}, pctx.Environment, pctx.WorkspaceConfig, pctx.PipelineDirs, pctx.logger)

	if err := spctx.loadUse(pb, pctx.Pipeline.Uses, pctx.Pipeline.With); err != nil {
		return err
	}
	spctx.Pipeline.WorkDir = pctx.Pipeline.WorkDir

	pctx.logger.Printf("  using %s", pctx.Pipeline.Uses)
	spctx.dumpWith()

	ran, err := spctx.Run(ctx, pb)
	if err != nil {
		return err
	}

	if ran {
		pctx.steps++
	}

	return nil
}

// Build a script to run as part of evalRun
func (pctx *PipelineContext) buildEvalRunCommand(debugOption rune, sysPath string, workdir string, fragment string) []string {
	envExport := "export %s='%s'"
	envArr := []string{}
	for k, v := range pctx.Pipeline.Environment {
		envArr = append(envArr, fmt.Sprintf(envExport, k, v))
	}
	envString := strings.Join(envArr, "\n")
	script := fmt.Sprintf(`set -e%c
export PATH='%s'
%s
[ -d '%s' ] || mkdir -p '%s'
cd '%s'
%s
exit 0`, debugOption, sysPath, envString, workdir, workdir, workdir, fragment)
	return []string{"/bin/sh", "-c", script}
}

func (pctx *PipelineContext) evalRun(ctx context.Context, pb *PipelineBuild) error {
	var err error
	pctx.Pipeline.With, err = MutateWith(pb, pctx.Pipeline.With)
	if err != nil {
		return err
	}
	pctx.dumpWith()

	debugOption := ' '
	if (pb.Build != nil && pb.Build.Debug) || (pb.Test != nil && pb.Test.Debug) {
		debugOption = 'x'
	}

	sysPath := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

	workdir := "/home/build"
	if pctx.Pipeline.WorkDir != "" {
		workdir, err = util.MutateStringFromMap(pctx.Pipeline.With, pctx.Pipeline.WorkDir)
		if err != nil {
			return err
		}
	}

	fragment, err := util.MutateStringFromMap(pctx.Pipeline.With, pctx.Pipeline.Runs)
	if err != nil {
		return err
	}

	command := pctx.buildEvalRunCommand(debugOption, sysPath, workdir, fragment)
	if err := pb.GetRunner().Run(ctx, pctx.WorkspaceConfig, command...); err != nil {
		return err
	}

	return nil
}

func (pctx *PipelineContext) evaluateBranchConditional(pb *PipelineBuild) bool {
	if pctx.Pipeline.If == "" {
		return true
	}

	lookupWith := func(key string) (string, error) {
		mutated, err := MutateWith(pb, pctx.Pipeline.With)
		if err != nil {
			return "", err
		}
		nk := fmt.Sprintf("${{%s}}", key)
		return mutated[nk], nil
	}

	result, err := cond.Evaluate(pctx.Pipeline.If, lookupWith)
	if err != nil {
		panic(fmt.Errorf("could not evaluate if-conditional '%s': %w", pctx.Pipeline.If, err))
	}

	pctx.logger.Printf("evaluating if-conditional '%s' --> %t", pctx.Pipeline.If, result)

	return result
}

func (pctx *PipelineContext) isContinuationPoint(pb *PipelineBuild) bool {
	if pb.Build == nil {
		return true
	}
	b := pb.Build

	if b.ContinueLabel == "" {
		return true
	}

	if b.ContinueLabel == pctx.Pipeline.Label {
		b.foundContinuation = true
	}

	return b.foundContinuation
}

func (pctx *PipelineContext) shouldEvaluateBranch(pb *PipelineBuild) bool {
	if !pctx.isContinuationPoint(pb) {
		return false
	}

	return pctx.evaluateBranchConditional(pb)
}

func (pctx *PipelineContext) evaluateBranch(ctx context.Context, pb *PipelineBuild) error {
	if pctx.Identity() != "???" {
		pctx.logger.Printf("running step %s", pctx.Identity())
	}

	if pctx.Pipeline.Uses != "" {
		return pctx.evalUse(ctx, pb)
	}

	if pctx.Pipeline.Runs != "" {
		return pctx.evalRun(ctx, pb)
	}

	return nil
}

func (pctx *PipelineContext) checkAssertions(pb *PipelineBuild) error {
	if pctx.Pipeline.Assertions.RequiredSteps > 0 && pctx.steps < pctx.Pipeline.Assertions.RequiredSteps {
		return fmt.Errorf("pipeline did not run the required %d steps, only %d", pctx.Pipeline.Assertions.RequiredSteps, pctx.steps)
	}

	return nil
}

func (pctx *PipelineContext) Run(ctx context.Context, pb *PipelineBuild) (bool, error) {
	ctx, span := otel.Tracer("melange").Start(ctx, "Pipeline.Run")
	defer span.End()

	if pctx.Pipeline.Label != "" && pctx.Pipeline.Label == pb.Build.BreakpointLabel {
		return false, fmt.Errorf("stopping execution at breakpoint: %s", pctx.Pipeline.Label)
	}

	if !pctx.shouldEvaluateBranch(pb) {
		return false, nil
	}

	if err := pctx.evaluateBranch(ctx, pb); err != nil {
		return false, err
	}

	for _, sp := range pctx.Pipeline.Pipeline {
		spctx := NewPipelineContext(&sp, pctx.Environment, pctx.WorkspaceConfig, pctx.PipelineDirs, pctx.logger)
		if spctx.Pipeline.WorkDir == "" {
			spctx.Pipeline.WorkDir = pctx.Pipeline.WorkDir
		}

		ran, err := spctx.Run(ctx, pb)

		if err != nil {
			return false, err
		}

		if ran {
			pctx.steps++
		}
	}

	if err := pctx.checkAssertions(pb); err != nil {
		return false, err
	}

	return true, nil
}

// TODO(kaniini): Precompile pipeline before running / evaluating its
// needs.
func (pctx *PipelineContext) ApplyNeeds(pb *PipelineBuild) error {
	for _, pkg := range pctx.Pipeline.Needs.Packages {
		pctx.logger.Printf("  adding package %q for pipeline %q", pkg, pctx.Identity())
		pctx.Environment.Contents.Packages = append(pctx.Environment.Contents.Packages, pkg)
	}

	if pctx.Pipeline.Uses != "" {
		spctx := NewPipelineContext(nil, pctx.Environment, pctx.WorkspaceConfig, pctx.PipelineDirs, pctx.logger)

		if err := spctx.loadUse(pb, pctx.Pipeline.Uses, pctx.Pipeline.With); err != nil {
			return err
		}

		if err := spctx.ApplyNeeds(pb); err != nil {
			return err
		}
	}

	pctx.Environment.Contents.Packages = util.Dedup(pctx.Environment.Contents.Packages)

	for _, sp := range pctx.Pipeline.Pipeline {
		spctx := NewPipelineContext(&sp, pctx.Environment, pctx.WorkspaceConfig, pctx.PipelineDirs, pctx.logger)

		if err := spctx.ApplyNeeds(pb); err != nil {
			return err
		}
	}

	return nil
}

//go:embed pipelines/*
var f embed.FS
