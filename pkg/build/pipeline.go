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
	"embed"
	"fmt"
	"github.com/pkg/errors"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/cond"
)

const (
	substitutionPackageName          = "${{package.name}}"
	substitutionPackageVersion       = "${{package.version}}"
	substitutionPackageEpoch         = "${{package.epoch}}"
	substitutionTargetsDestdir       = "${{targets.destdir}}"
	substitutionSubPkgDir            = "${{targets.subpkgdir}}"
	substitutionHostTripletGnu       = "${{host.triplet.gnu}}"
	substitutionHostTripletRust      = "${{host.triplet.rust}}"
	substitutionCrossTripletGnuGlibc = "${{cross.triplet.gnu.glibc}}"
	substitutionCrossTripletGnuMusl  = "${{cross.triplet.gnu.musl}}"
	substitutionBuildArch            = "${{build.arch}}"
)

type PipelineContext struct {
	Context    *Context
	Package    *Package
	Subpackage *Subpackage
}

func (p *Pipeline) Identity() string {
	if p.Name != "" {
		return p.Name
	}
	if p.Uses != "" {
		return p.Uses
	}
	return "???"
}

func mutateWith(ctx *PipelineContext, with map[string]string) (map[string]string, error) {
	nw, err := substitutionMap(ctx)
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
		nval, err := mutateStringFromMap(nw, v)
		if err != nil {
			return nil, err
		}
		nw[k] = nval
	}

	return nw, nil
}

func substitutionMap(ctx *PipelineContext) (map[string]string, error) {
	nw := map[string]string{
		substitutionPackageName:          ctx.Package.Name,
		substitutionPackageVersion:       ctx.Package.Version,
		substitutionPackageEpoch:         strconv.FormatUint(ctx.Package.Epoch, 10),
		substitutionTargetsDestdir:       fmt.Sprintf("/home/build/melange-out/%s", ctx.Package.Name),
		substitutionHostTripletGnu:       ctx.Context.BuildTripletGnu(),
		substitutionHostTripletRust:      ctx.Context.BuildTripletRust(),
		substitutionCrossTripletGnuGlibc: ctx.Context.Arch.ToTriplet("gnu"),
		substitutionCrossTripletGnuMusl:  ctx.Context.Arch.ToTriplet("musl"),
		substitutionBuildArch:            ctx.Context.Arch.ToAPK(),
	}

	if ctx.Subpackage != nil {
		nw[substitutionSubPkgDir] = fmt.Sprintf("/home/build/melange-out/%s", ctx.Subpackage.Name)
	}

	for k, v := range ctx.Context.Configuration.Vars {
		nk := fmt.Sprintf("${{vars.%s}}", k)

		nv, err := mutateStringFromMap(nw, v)
		if err != nil {
			return nil, err
		}

		nw[nk] = nv
	}

	for k := range ctx.Context.Configuration.Options {
		nk := fmt.Sprintf("${{options.%s.enabled}}", k)
		nw[nk] = "false"
	}

	for _, opt := range ctx.Context.EnabledBuildOptions {
		nk := fmt.Sprintf("${{options.%s.enabled}}", opt)
		nw[nk] = "true"
	}

	for _, v := range ctx.Context.Configuration.VarTransforms {
		nk := fmt.Sprintf("${{vars.%s}}", v.To)
		from, err := mutateStringFromMap(nw, v.From)
		if err != nil {
			return nil, err
		}

		re, err := regexp.Compile(v.Match)
		if err != nil {
			return nil, errors.Wrapf(err, "match value: %s string does not compile into a regex", v.Match)
		}

		output := re.ReplaceAllString(from, v.Replace)
		nw[nk] = output
	}

	return nw, nil
}

func mutateStringFromMap(with map[string]string, input string) (string, error) {
	lookupWith := func(key string) (string, error) {
		if val, ok := with[key]; ok {
			return val, nil
		}

		nk := fmt.Sprintf("${{%s}}", key)
		if val, ok := with[nk]; ok {
			return val, nil
		}

		return "", fmt.Errorf("variable %s not defined", key)
	}

	return cond.Subst(input, lookupWith)
}

func rightJoinMap(left map[string]string, right map[string]string) map[string]string {
	// this is the worst case possible length, assuming no overlap.
	length := len(left) + len(right)
	output := make(map[string]string, length)

	// copy the left-side first
	for k, v := range left {
		output[k] = v
	}

	// overlay the right-side on top
	for k, v := range right {
		output[k] = v
	}

	return output
}

func validateWith(data map[string]string, inputs map[string]Input) (map[string]string, error) {
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

func (p *Pipeline) loadUse(ctx *PipelineContext, uses string, with map[string]string) error {
	data, err := loadPipelineData(ctx.Context.PipelineDir, uses)
	if err != nil {
		data, err = loadPipelineData(ctx.Context.BuiltinPipelineDir, uses)
		if err != nil {
			data, err = f.ReadFile("pipelines/" + uses + ".yaml")
			if err != nil {
				return fmt.Errorf("unable to load pipeline: %w", err)
			}
		}
	}

	if err := yaml.Unmarshal(data, p); err != nil {
		return fmt.Errorf("unable to parse pipeline: %w", err)
	}

	validated, err := validateWith(with, p.Inputs)
	if err != nil {
		return fmt.Errorf("unable to construct pipeline: %w", err)
	}
	p.With, err = mutateWith(ctx, validated)
	if err != nil {
		return err
	}

	for k := range p.Pipeline {
		p.Pipeline[k].With = rightJoinMap(p.With, p.Pipeline[k].With)
	}

	return nil
}

func (p *Pipeline) dumpWith() {
	for k, v := range p.With {
		p.logger.Printf("    %s: %s", k, v)
	}
}

func (p *Pipeline) evalUse(ctx *PipelineContext) error {
	sp, err := NewPipeline(ctx)
	if err != nil {
		return err
	}
	sp.WorkDir = p.WorkDir

	if err := sp.loadUse(ctx, p.Uses, p.With); err != nil {
		return err
	}

	p.logger.Printf("  using %s", p.Uses)
	sp.dumpWith()

	ran, err := sp.Run(ctx)
	if err != nil {
		return err
	}

	if ran {
		p.steps++
	}

	return nil
}

func (p *Pipeline) evalRun(ctx *PipelineContext) error {
	var err error
	p.With, err = mutateWith(ctx, p.With)
	if err != nil {
		return err
	}
	p.dumpWith()

	workdir := "/home/build"
	if p.WorkDir != "" {
		workdir, err = mutateStringFromMap(p.With, p.WorkDir)
		if err != nil {
			return err
		}
	}

	fragment, err := mutateStringFromMap(p.With, p.Runs)
	if err != nil {
		return err
	}

	debugOption := ' '
	if ctx.Context.Debug {
		debugOption = 'x'
	}

	sysPath := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	script := fmt.Sprintf(`set -e%c
export PATH='%s'
[ -d '%s' ] || mkdir -p '%s'
cd '%s'
%s
exit 0`, debugOption, sysPath, workdir, workdir, workdir, fragment)
	command := []string{"/bin/sh", "-c", script}
	config := ctx.Context.WorkspaceConfig()

	if err := ctx.Context.Runner.Run(config, command...); err != nil {
		return err
	}

	return nil
}

func (p *Pipeline) evaluateBranchConditional(pctx *PipelineContext) bool {
	if p.If == "" {
		return true
	}

	lookupWith := func(key string) (string, error) {
		mutated, err := mutateWith(pctx, p.With)
		if err != nil {
			return "", err
		}
		nk := fmt.Sprintf("${{%s}}", key)
		return mutated[nk], nil
	}

	result, err := cond.Evaluate(p.If, lookupWith)
	if err != nil {
		panic(fmt.Errorf("could not evaluate if-conditional '%s': %w", p.If, err))
	}

	p.logger.Printf("evaluating if-conditional '%s' --> %t", p.If, result)

	return result
}

func (p *Pipeline) isContinuationPoint(pctx *PipelineContext) bool {
	ctx := pctx.Context

	if ctx.ContinueLabel == "" {
		return true
	}

	if ctx.ContinueLabel == p.Label {
		ctx.foundContinuation = true
	}

	return ctx.foundContinuation
}

func (p *Pipeline) shouldEvaluateBranch(pctx *PipelineContext) bool {
	if !p.isContinuationPoint(pctx) {
		return false
	}

	return p.evaluateBranchConditional(pctx)
}

func (p *Pipeline) evaluateBranch(ctx *PipelineContext) error {
	if p.Identity() != "???" {
		p.logger.Printf("running step %s", p.Identity())
	}

	if p.Uses != "" {
		return p.evalUse(ctx)
	}

	if p.Runs != "" {
		return p.evalRun(ctx)
	}

	return nil
}

func (p *Pipeline) checkAssertions(ctx *PipelineContext) error {
	if p.Assertions.RequiredSteps > 0 && p.steps < p.Assertions.RequiredSteps {
		return fmt.Errorf("pipeline did not run the required %d steps, only %d", p.Assertions.RequiredSteps, p.steps)
	}

	return nil
}

func (p *Pipeline) Run(ctx *PipelineContext) (bool, error) {
	if p.Label != "" && p.Label == ctx.Context.BreakpointLabel {
		return false, fmt.Errorf("stopping execution at breakpoint: %s", p.Label)
	}

	if p.logger == nil {
		if err := p.initializeFromContext(ctx); err != nil {
			return false, err
		}
	}

	if p.shouldEvaluateBranch(ctx) {
		if err := p.evaluateBranch(ctx); err != nil {
			return false, err
		}
	} else {
		return false, nil
	}

	for _, sp := range p.Pipeline {
		if sp.WorkDir == "" {
			sp.WorkDir = p.WorkDir
		}

		ran, err := sp.Run(ctx)

		if err != nil {
			return false, err
		}

		if ran {
			p.steps++
		}
	}

	if err := p.checkAssertions(ctx); err != nil {
		return false, err
	}

	return true, nil
}

func (p *Pipeline) initializeFromContext(ctx *PipelineContext) error {
	name := ctx.Package.Name
	if ctx.Subpackage != nil {
		name = ctx.Subpackage.Name
	}
	p.logger = log.New(log.Writer(), fmt.Sprintf("melange (%s/%s): ", name, ctx.Context.Arch.ToAPK()), log.LstdFlags|log.Lmsgprefix)

	return nil
}

func NewPipeline(ctx *PipelineContext) (*Pipeline, error) {
	p := Pipeline{}

	if err := p.initializeFromContext(ctx); err != nil {
		return nil, err
	}

	return &p, nil
}

// TODO(kaniini): Precompile pipeline before running / evaluating its
// needs.
func (p *Pipeline) ApplyNeeds(ctx *PipelineContext) error {
	ic := &ctx.Context.Configuration.Environment

	for _, pkg := range p.Needs.Packages {
		p.logger.Printf("  adding package %q for pipeline %q", pkg, p.Identity())
		ic.Contents.Packages = append(ic.Contents.Packages, pkg)
	}

	if p.Uses != "" {
		sp, err := NewPipeline(ctx)
		if err != nil {
			return err
		}

		if err := sp.loadUse(ctx, p.Uses, p.With); err != nil {
			return err
		}

		if err := sp.ApplyNeeds(ctx); err != nil {
			return err
		}
	}

	ic.Contents.Packages = dedup(ic.Contents.Packages)

	for _, sp := range p.Pipeline {
		if err := sp.ApplyNeeds(ctx); err != nil {
			return err
		}
	}

	return nil
}

//go:embed pipelines/*
var f embed.FS
