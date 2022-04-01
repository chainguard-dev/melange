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
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
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
	nw := map[string]string{
		"${{package.name}}":    ctx.Package.Name,
		"${{package.version}}": ctx.Package.Version,
		"${{package.epoch}}":   strconv.FormatUint(ctx.Package.Epoch, 10),
		"${{targets.destdir}}": fmt.Sprintf("/home/build/melange-out/%s", ctx.Package.Name),
	}

	if ctx.Subpackage != nil {
		nw["${{targets.subpkgdir}}"] = fmt.Sprintf("/home/build/melange-out/%s", ctx.Subpackage.Name)
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
		nw[k] = mutateStringFromMap(nw, v)
	}

	return nw
}

func mutateStringFromMap(with map[string]string, input string) string {
	re := regexp.MustCompile(`\${{[a-zA-Z0-9\.]*}}`)
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
	if err != nil {
		return fmt.Errorf("unable to load pipeline: %w", err)
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

func (p *Pipeline) monitorPipe(pipe io.ReadCloser) {
	defer pipe.Close()

	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		p.logger.Printf("%s", scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		p.logger.Printf("warning: %v", err)
	}
}

func (p *Pipeline) evalRun(ctx *PipelineContext) error {
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

	go p.monitorPipe(stdout)
	go p.monitorPipe(stderr)

	if err := cmd.Wait(); err != nil {
		return err
	}

	return nil
}

func (p *Pipeline) Run(ctx *PipelineContext) error {
	if p.logger == nil {
		if err := p.initializeFromContext(ctx); err != nil {
			return err
		}
	}

	if p.Identity() != "???" {
		p.logger.Printf("running step %s", p.Identity())
	}

	if p.Uses != "" {
		return p.evalUse(ctx)
	}
	if p.Runs != "" {
		return p.evalRun(ctx)
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
