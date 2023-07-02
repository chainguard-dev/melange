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
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"

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

type PipelineBuild struct {
	Build      *Build
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
		nval, err := MutateStringFromMap(nw, v)
		if err != nil {
			return nil, err
		}
		nw[k] = nval
	}

	return nw, nil
}

func substitutionMap(pb *PipelineBuild) (map[string]string, error) {
	nw := map[string]string{
		substitutionPackageName:          pb.Package.Name,
		substitutionPackageVersion:       pb.Package.Version,
		substitutionPackageEpoch:         strconv.FormatUint(pb.Package.Epoch, 10),
		substitutionTargetsDestdir:       fmt.Sprintf("/home/build/melange-out/%s", pb.Package.Name),
		substitutionHostTripletGnu:       pb.Build.BuildTripletGnu(),
		substitutionHostTripletRust:      pb.Build.BuildTripletRust(),
		substitutionCrossTripletGnuGlibc: pb.Build.Arch.ToTriplet("gnu"),
		substitutionCrossTripletGnuMusl:  pb.Build.Arch.ToTriplet("musl"),
		substitutionBuildArch:            pb.Build.Arch.ToAPK(),
	}

	if pb.Subpackage != nil {
		nw[substitutionSubPkgDir] = fmt.Sprintf("/home/build/melange-out/%s", pb.Subpackage.Name)
	}

	for k, v := range pb.Build.Configuration.Vars {
		nk := fmt.Sprintf("${{vars.%s}}", k)

		nv, err := MutateStringFromMap(nw, v)
		if err != nil {
			return nil, err
		}

		nw[nk] = nv
	}

	for k := range pb.Build.Configuration.Options {
		nk := fmt.Sprintf("${{options.%s.enabled}}", k)
		nw[nk] = "false"
	}

	for _, opt := range pb.Build.EnabledBuildOptions {
		nk := fmt.Sprintf("${{options.%s.enabled}}", opt)
		nw[nk] = "true"
	}

	for _, v := range pb.Build.Configuration.VarTransforms {
		nk := fmt.Sprintf("${{vars.%s}}", v.To)
		from, err := MutateStringFromMap(nw, v.From)
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

func MutateStringFromMap(with map[string]string, input string) (string, error) {
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

func (p *Pipeline) loadUse(pb *PipelineBuild, uses string, with map[string]string) error {
	data, err := loadPipelineData(pb.Build.PipelineDir, uses)
	if err != nil {
		data, err = loadPipelineData(pb.Build.BuiltinPipelineDir, uses)
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
	p.With, err = MutateWith(pb, validated)
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
		p.logger.Debugf("    %s: %s", k, v)
	}
}

func (p *Pipeline) evalUse(ctx context.Context, pb *PipelineBuild) error {
	sp, err := NewPipeline(pb)
	if err != nil {
		return err
	}
	sp.WorkDir = p.WorkDir

	if err := sp.loadUse(pb, p.Uses, p.With); err != nil {
		return err
	}

	p.logger.Printf("  using %s", p.Uses)
	sp.dumpWith()

	ran, err := sp.Run(ctx, pb)
	if err != nil {
		return err
	}

	if ran {
		p.steps++
	}

	return nil
}

func (p *Pipeline) evalRun(ctx context.Context, pb *PipelineBuild) error {
	var err error
	p.With, err = MutateWith(pb, p.With)
	if err != nil {
		return err
	}
	p.dumpWith()

	workdir := "/home/build"
	if p.WorkDir != "" {
		workdir, err = MutateStringFromMap(p.With, p.WorkDir)
		if err != nil {
			return err
		}
	}

	fragment, err := MutateStringFromMap(p.With, p.Runs)
	if err != nil {
		return err
	}

	debugOption := ' '
	if pb.Build.Debug {
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
	config := pb.Build.WorkspaceConfig()

	if err := pb.Build.Runner.Run(ctx, config, command...); err != nil {
		return err
	}

	return nil
}

func (p *Pipeline) evaluateBranchConditional(pb *PipelineBuild) bool {
	if p.If == "" {
		return true
	}

	lookupWith := func(key string) (string, error) {
		mutated, err := MutateWith(pb, p.With)
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

func (p *Pipeline) isContinuationPoint(pb *PipelineBuild) bool {
	b := pb.Build

	if b.ContinueLabel == "" {
		return true
	}

	if b.ContinueLabel == p.Label {
		b.foundContinuation = true
	}

	return b.foundContinuation
}

func (p *Pipeline) shouldEvaluateBranch(pb *PipelineBuild) bool {
	if !p.isContinuationPoint(pb) {
		return false
	}

	return p.evaluateBranchConditional(pb)
}

func (p *Pipeline) evaluateBranch(ctx context.Context, pb *PipelineBuild) error {
	if p.Identity() != "???" {
		p.logger.Printf("running step %s", p.Identity())
	}

	if p.Uses != "" {
		return p.evalUse(ctx, pb)
	}

	if p.Runs != "" {
		return p.evalRun(ctx, pb)
	}

	return nil
}

func (p *Pipeline) checkAssertions(pb *PipelineBuild) error {
	if p.Assertions.RequiredSteps > 0 && p.steps < p.Assertions.RequiredSteps {
		return fmt.Errorf("pipeline did not run the required %d steps, only %d", p.Assertions.RequiredSteps, p.steps)
	}

	return nil
}

func (p *Pipeline) Run(ctx context.Context, pb *PipelineBuild) (bool, error) {
	if p.Label != "" && p.Label == pb.Build.BreakpointLabel {
		return false, fmt.Errorf("stopping execution at breakpoint: %s", p.Label)
	}

	if p.logger == nil {
		if err := p.initializeFromPipelineBuild(pb); err != nil {
			return false, err
		}
	}

	if p.shouldEvaluateBranch(pb) {
		if err := p.evaluateBranch(ctx, pb); err != nil {
			return false, err
		}
	} else {
		return false, nil
	}

	for _, sp := range p.Pipeline {
		if sp.WorkDir == "" {
			sp.WorkDir = p.WorkDir
		}

		ran, err := sp.Run(ctx, pb)

		if err != nil {
			return false, err
		}

		if ran {
			p.steps++
		}
	}

	if err := p.checkAssertions(pb); err != nil {
		return false, err
	}

	return true, nil
}

func (p *Pipeline) initializeFromPipelineBuild(pb *PipelineBuild) error {
	if l := pb.Build.Logger; l != nil {
		p.logger = pb.Build.Logger
	} else {
		p.logger = nopLogger{}
	}

	return nil
}

func NewPipeline(pb *PipelineBuild) (*Pipeline, error) {
	p := Pipeline{}

	if err := p.initializeFromPipelineBuild(pb); err != nil {
		return nil, err
	}

	return &p, nil
}

// TODO(kaniini): Precompile pipeline before running / evaluating its
// needs.
func (p *Pipeline) ApplyNeeds(pb *PipelineBuild) error {
	ic := &pb.Build.Configuration.Environment

	for _, pkg := range p.Needs.Packages {
		p.logger.Printf("  adding package %q for pipeline %q", pkg, p.Identity())
		ic.Contents.Packages = append(ic.Contents.Packages, pkg)
	}

	if p.Uses != "" {
		sp, err := NewPipeline(pb)
		if err != nil {
			return err
		}

		if err := sp.loadUse(pb, p.Uses, p.With); err != nil {
			return err
		}

		if err := sp.ApplyNeeds(pb); err != nil {
			return err
		}
	}

	ic.Contents.Packages = dedup(ic.Contents.Packages)

	for _, sp := range p.Pipeline {
		if err := sp.ApplyNeeds(pb); err != nil {
			return err
		}
	}

	return nil
}

//go:embed pipelines/*
var f embed.FS
