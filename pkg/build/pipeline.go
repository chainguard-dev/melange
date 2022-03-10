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

	replacer := replacerFromMap(nw)
	for k, v := range nw {
		nw[k] = replacer.Replace(v)
	}

	return nw
}

func (p *Pipeline) loadUse(ctx *PipelineContext, uses string, with map[string]string) error {
	data, err := os.ReadFile(filepath.Join(ctx.Context.PipelineDir, uses+".yaml"))
	if err != nil {
		return fmt.Errorf("unable to load pipeline: %w", err)
	}

	if err := yaml.Unmarshal(data, p); err != nil {
		return fmt.Errorf("unable to parse pipeline: %w", err)
	}

	p.With = mutateWith(ctx, with)

	// TODO(kaniini): merge, rather than replace sub-pipeline withs
	for k, _ := range p.Pipeline {
		p.Pipeline[k].With = p.With
	}

	return nil
}

func (p *Pipeline) dumpWith() {
	for k, v := range p.With {
		log.Printf("    %s: %s", k, v)
	}
}

func (p *Pipeline) evalUse(ctx *PipelineContext) error {
	sp := Pipeline{}

	if err := sp.loadUse(ctx, p.Uses, p.With); err != nil {
		return err
	}

	log.Printf("  using %s", p.Uses)
	sp.dumpWith()

	if err := sp.Run(ctx); err != nil {
		return err
	}

	return nil
}

func monitorPipe(pipe io.ReadCloser) {
	defer pipe.Close()

	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		log.Printf("%s", scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Printf("warning: %v", err)
	}
}

func (p *Pipeline) evalRun(ctx *PipelineContext) error {
	replacer := replacerFromMap(p.With)
	fragment := replacer.Replace(p.Runs)
	script := fmt.Sprintf("#!/bin/sh\nset -e\n%s\nexit 0\n", fragment)
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

	go monitorPipe(stdout)
	go monitorPipe(stderr)

	if err := cmd.Wait(); err != nil {
		return err
	}

	return nil
}

func (p *Pipeline) Run(ctx *PipelineContext) error {
	if p.Identity() != "???" {
		log.Printf("running step %s", p.Identity())
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
