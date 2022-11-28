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
	"bufio"
	"embed"
	"errors"
	"fmt"
	"io"
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

func replacerFromMap(with map[string]string) *strings.Replacer {
	replacements := []string{}
	for k, v := range with {
		replacements = append(replacements, k, v)
	}
	return strings.NewReplacer(replacements...)
}

func mutateWith(ctx *PipelineContext, with map[string]string) map[string]string {
	nw := substitutionMap(ctx)

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
		nw[k] = mutateStringFromMap(nw, v)
	}

	return nw
}

func substitutionMap(ctx *PipelineContext) map[string]string {
	nw := map[string]string{
		substitutionPackageName:          ctx.Package.Name,
		substitutionPackageVersion:       ctx.Package.Version,
		substitutionPackageEpoch:         strconv.FormatUint(ctx.Package.Epoch, 10),
		substitutionTargetsDestdir:       fmt.Sprintf("/home/build/melange-out/%s", ctx.Package.Name),
		substitutionHostTripletGnu:       ctx.Context.BuildTripletGnu(),
		substitutionHostTripletRust:      ctx.Context.BuildTripletRust(),
		substitutionCrossTripletGnuGlibc: ctx.Context.Arch.ToTriplet("gnu"),
		substitutionCrossTripletGnuMusl:  ctx.Context.Arch.ToTriplet("musl"),
	}

	if ctx.Subpackage != nil {
		nw[substitutionSubPkgDir] = fmt.Sprintf("/home/build/melange-out/%s", ctx.Subpackage.Name)
	}

	return nw
}

func mutateStringFromMap(with map[string]string, input string) string {
	re := regexp.MustCompile(`\${{[a-zA-Z0-9\.-]*}}`)
	replacer := replacerFromMap(with)
	output := replacer.Replace(input)
	return re.ReplaceAllString(output, "")
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

func (p *Pipeline) loadUse(ctx *PipelineContext, uses string, with map[string]string) error {
	data, err := os.ReadFile(filepath.Join(ctx.Context.PipelineDir, uses+".yaml"))
	if errors.Is(err, os.ErrNotExist) {
		// fallback to the builtin pipeline directory search if the given file doesn't exist in the given pipeline directory

		// search the given pipeline within the built-in pipeline directory which is `/usr/share/melange/pipelines` in this case
		data, err = os.ReadFile(filepath.Join(ctx.Context.BuiltinPipelineDir, uses+".yaml"))
		if errors.Is(err, os.ErrNotExist) {
			// fallback to the embedded pipelines compiled into the binary.

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
	p.With = mutateWith(ctx, validated)

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

	if err := sp.loadUse(ctx, p.Uses, p.With); err != nil {
		return err
	}

	p.logger.Printf("  using %s", p.Uses)
	sp.dumpWith()

	if err := sp.Run(ctx); err != nil {
		return err
	}

	return nil
}

func (p *Pipeline) monitorPipe(pipe io.ReadCloser, finish chan struct{}) {
	defer pipe.Close()

	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		p.logger.Printf("%s", scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		p.logger.Printf("warning: %v", err)
	}

	finish <- struct{}{}
}

func (p *Pipeline) evalRun(ctx *PipelineContext) error {
	p.With = mutateWith(ctx, p.With)
	p.dumpWith()

	fragment := mutateStringFromMap(p.With, p.Runs)
	sys_path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	script := fmt.Sprintf("#!/bin/sh\nset -e\nexport PATH=%s\n%s\nexit 0\n", sys_path, fragment)
	command := []string{"/bin/sh", "-c", script}

	cmd, err := ctx.Context.WorkspaceCmd(command...)
	if err != nil {
		return err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	finishStdout := make(chan struct{})
	finishStderr := make(chan struct{})

	go p.monitorPipe(stdout, finishStdout)
	go p.monitorPipe(stderr, finishStderr)

	if err := cmd.Wait(); err != nil {
		return err
	}

	<-finishStdout
	<-finishStderr

	return nil
}

func (p *Pipeline) evaluateBranchConditional(pctx *PipelineContext) bool {
	if p.If == "" {
		return true
	}

	lookupWith := func(key string) (string, error) {
		mutated := mutateWith(pctx, p.With)
		nk := fmt.Sprintf("${{%s}}", key)
		return mutated[nk], nil
	}

	result, err := cond.Evaluate(p.If, lookupWith)
	if err != nil {
		panic(fmt.Errorf("could not evaluate if-conditional '%s': %w", p.If, err))
		return false
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

func (p *Pipeline) Run(ctx *PipelineContext) error {
	if p.Label != "" && p.Label == ctx.Context.BreakpointLabel {
		return fmt.Errorf("stopping execution at breakpoint: %s", p.Label)
	}

	if p.logger == nil {
		if err := p.initializeFromContext(ctx); err != nil {
			return err
		}
	}

	if p.shouldEvaluateBranch(ctx) {
		if err := p.evaluateBranch(ctx); err != nil {
			return err
		}
	}

	for _, sp := range p.Pipeline {
		if err := sp.Run(ctx); err != nil {
			return err
		}
	}

	return nil
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

	return nil
}

//go:embed pipelines/*
var f embed.FS
