// Copyright 2023 Chainguard, Inc.
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
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"chainguard.dev/melange/pkg/cond"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/util"
	"github.com/chainguard-dev/clog"
	"gopkg.in/yaml.v3"
	"mvdan.cc/sh/v3/syntax"
)

const unidentifiablePipeline = "???"

func (t *Test) Compile(ctx context.Context) error {
	cfg := t.Configuration

	// TODO: Make this parameter go away when we revisit subtitutions.
	flavor := "gnu"

	sm, err := NewSubstitutionMap(&cfg, t.Arch, flavor, nil)
	if err != nil {
		return err
	}

	ignore := &Compiled{
		PipelineDirs: t.PipelineDirs,
		Environment:  make(map[string]string),
	}

	// We want to evaluate this but not accumulate its deps.
	if err := ignore.CompilePipelines(ctx, sm, cfg.Pipeline); err != nil {
		return fmt.Errorf("compiling package %q pipelines: %w", t.Package, err)
	}

	for i, sp := range cfg.Subpackages {
		sm := sm.Subpackage(&sp)
		if sp.If != "" {
			sp.If, err = util.MutateAndQuoteStringFromMap(sm.Substitutions, sp.If)
			if err != nil {
				return fmt.Errorf("mutating subpackage if: %w", err)
			}
		}

		// We want to evaluate this but not accumulate its deps.
		if err := ignore.CompilePipelines(ctx, sm, sp.Pipeline); err != nil {
			return fmt.Errorf("compiling subpackage %q: %w", sp.Name, err)
		}

		if sp.Test == nil {
			continue
		}

		test := &Compiled{
			PipelineDirs: t.PipelineDirs,
			Environment:  make(map[string]string),
		}

		te := &cfg.Subpackages[i].Test.Environment

		// Append the subpackage that we're testing to be installed.
		te.Contents.Packages = append(te.Contents.Packages, sp.Name)

		if err := test.CompilePipelines(ctx, sm, sp.Test.Pipeline); err != nil {
			return fmt.Errorf("compiling subpackage %q tests: %w", sp.Name, err)
		}

		// Append anything this subpackage test needs.
		te.Contents.Packages = append(te.Contents.Packages, test.Needs...)

		// Sort and remove duplicates.
		te.Contents.Packages = slices.Compact(slices.Sorted(slices.Values(te.Contents.Packages)))

		// Append the environment this subpackage test needs.
		if te.Environment == nil {
			te.Environment = make(map[string]string)
		}
		for k, v := range test.Environment {
			te.Environment[k] = v
		}
	}

	if cfg.Test != nil {
		test := &Compiled{
			PipelineDirs: t.PipelineDirs,
			Environment:  make(map[string]string),
		}

		te := &t.Configuration.Test.Environment

		// Append the main test package to be installed unless explicitly specified by the command line.
		if t.Package != "" {
			te.Contents.Packages = append(te.Contents.Packages, t.Package)
		} else {
			te.Contents.Packages = append(te.Contents.Packages, t.Configuration.Package.Name)
		}

		if err := test.CompilePipelines(ctx, sm, cfg.Test.Pipeline); err != nil {
			return fmt.Errorf("compiling %q test pipelines: %w", t.Package, err)
		}

		// Append anything the main package test needs.
		te.Contents.Packages = append(te.Contents.Packages, test.Needs...)

		// Sort and remove duplicates.
		te.Contents.Packages = slices.Compact(slices.Sorted(slices.Values(te.Contents.Packages)))

		// Append the environment the main package test needs.
		if te.Environment == nil {
			te.Environment = make(map[string]string)
		}
		for k, v := range test.Environment {
			te.Environment[k] = v
		}
	}

	return nil
}

// Compile compiles all configuration, including tests, by loading any pipelines and substituting all variables.
func (b *Build) Compile(ctx context.Context) error {
	cfg := b.Configuration
	sm, err := NewSubstitutionMap(cfg, b.Arch, b.buildFlavor(), b.EnabledBuildOptions)
	if err != nil {
		return err
	}

	c := &Compiled{
		PipelineDirs: b.PipelineDirs,
		Environment:  make(map[string]string),
	}

	if err := c.CompilePipelines(ctx, sm, cfg.Pipeline); err != nil {
		return fmt.Errorf("compiling %q pipelines: %w", cfg.Package.Name, err)
	}

	for i, sp := range cfg.Subpackages {
		sm := sm.Subpackage(&sp)

		if sp.If != "" {
			sp.If, err = util.MutateAndQuoteStringFromMap(sm.Substitutions, sp.If)
			if err != nil {
				return fmt.Errorf("mutating subpackage %q, if: %w", sp.Name, err)
			}
		}

		if err := c.CompilePipelines(ctx, sm, sp.Pipeline); err != nil {
			return fmt.Errorf("compiling subpackage %q: %w", sp.Name, err)
		}

		if sp.Test == nil {
			continue
		}

		tc := &Compiled{
			PipelineDirs: b.PipelineDirs,
			Environment:  make(map[string]string),
		}
		if err := tc.CompilePipelines(ctx, sm, sp.Test.Pipeline); err != nil {
			return fmt.Errorf("compiling subpackage %q tests: %w", sp.Name, err)
		}

		te := &cfg.Subpackages[i].Test.Environment

		// Append the subpackage that we're testing to be installed.
		te.Contents.Packages = append(te.Contents.Packages, sp.Name)

		// Append anything this subpackage test needs.
		te.Contents.Packages = append(te.Contents.Packages, tc.Needs...)

		// Sort and remove duplicates.
		te.Contents.Packages = slices.Compact(slices.Sorted(slices.Values(te.Contents.Packages)))

		// Append environment this subpackage test needs.
		if te.Environment == nil {
			te.Environment = make(map[string]string)
		}
		for k, v := range tc.Environment {
			te.Environment[k] = v
		}
	}

	ic := &b.Configuration.Environment

	// Append anything the main package build needs.
	ic.Contents.Packages = append(ic.Contents.Packages, c.Needs...)
	// Append any environment the main package build needs.
	if ic.Environment == nil {
		ic.Environment = make(map[string]string)
	}
	for k, v := range c.Environment {
		ic.Environment[k] = v
	}

	if cfg.Test != nil {
		tc := &Compiled{
			PipelineDirs: b.PipelineDirs,
			Environment:  make(map[string]string),
		}

		if err := tc.CompilePipelines(ctx, sm, cfg.Test.Pipeline); err != nil {
			return fmt.Errorf("compiling %q test pipelines: %w", cfg.Package.Name, err)
		}

		te := &b.Configuration.Test.Environment

		// Append anything the main package test needs.
		te.Contents.Packages = append(te.Contents.Packages, tc.Needs...)
		// Append environment the main package test needs.
		if te.Environment == nil {
			te.Environment = make(map[string]string)
		}
		for k, v := range tc.Environment {
			te.Environment[k] = v
		}

		// This can be overridden by the command line but in the context of a build, just use the main package.
		te.Contents.Packages = append(te.Contents.Packages, b.Configuration.Package.Name)

		// Sort and remove duplicates.
		te.Contents.Packages = slices.Compact(slices.Sorted(slices.Values(te.Contents.Packages)))
	}

	return nil
}

type Compiled struct {
	PipelineDirs []string
	Needs        []string
	Environment  map[string]string
}

func (c *Compiled) CompilePipelines(ctx context.Context, sm *SubstitutionMap, pipelines []config.Pipeline) error {
	for i := range pipelines {
		if err := c.compilePipeline(ctx, sm, &pipelines[i], nil); err != nil {
			return fmt.Errorf("compiling Pipeline[%d]: %w", i, err)
		}

		if err := c.gatherDeps(ctx, &pipelines[i]); err != nil {
			return fmt.Errorf("gathering deps for Pipeline[%d]: %w", i, err)
		}

		if err := c.gatherEnvironment(ctx, &pipelines[i]); err != nil {
			return fmt.Errorf("gathering deps for Pipeline[%d]: %w", i, err)
		}
	}

	return nil
}

func (c *Compiled) compilePipeline(ctx context.Context, sm *SubstitutionMap, pipeline *config.Pipeline, parent map[string]string) error {
	log := clog.FromContext(ctx)
	name, uses, with := pipeline.Name, pipeline.Uses, maps.Clone(pipeline.With)

	// When compiling an already-compiled config, `uses` will be redundant and FYI only,
	// so ignore it if there is also a `pipelines` spelled out.
	if uses != "" && len(pipeline.Pipeline) == 0 {
		var data []byte
		// Set this to fail up front in case there are no pipeline dirs specified
		// and we can't find them.
		err := fmt.Errorf("could not find 'uses' pipeline %q", uses)

		for _, pd := range c.PipelineDirs {
			log.Debugf("trying to load pipeline %q from %q", uses, pd)
			data, err = os.ReadFile(filepath.Join(pd, uses+".yaml"))
			if err == nil {
				log.Debugf("Found pipeline %s", string(data))
				break
			}
		}
		if err != nil {
			log.Debugf("trying to load pipeline %q from embedded fs pipelines/%q.yaml", uses, uses)
			data, err = PipelinesFS.ReadFile("pipelines/" + uses + ".yaml")
			if err != nil {
				return fmt.Errorf("unable to load pipeline: %w", err)
			}
		}

		if err := yaml.Unmarshal(data, pipeline); err != nil {
			return fmt.Errorf("unable to parse pipeline %q: %w", uses, err)
		}

		for k := range with {
			if _, ok := pipeline.Inputs[k]; !ok {
				return fmt.Errorf("undefined input %q to pipeline %q", k, pipeline.Uses)
			}
		}

		// We want to keep the original name here because loading the pipeline will overwrite it.
		pipeline.Name = name
	}

	if parent != nil {
		m := maps.Clone(parent)
		maps.Copy(m, with)
		with = m
	}

	validated, err := validateWith(with, pipeline.Inputs)
	if err != nil {
		return fmt.Errorf("unable to validate with: %w", err)
	}

	mutated, err := sm.MutateWith(validated)
	if err != nil {
		return fmt.Errorf("mutating with: %w", err)
	}

	// allow input mutations on needs.packages
	if pipeline.Needs != nil {
		for i := range pipeline.Needs.Packages {
			pipeline.Needs.Packages[i], err = util.MutateStringFromMap(mutated, pipeline.Needs.Packages[i])
			if err != nil {
				return fmt.Errorf("mutating needs: %w", err)
			}
		}
		for k := range pipeline.Needs.Environment {
			pipeline.Needs.Environment[k], err = util.MutateStringFromMap(mutated, pipeline.Needs.Environment[k])
			if err != nil {
				return fmt.Errorf("mutating needs: %w", err)
			}
		}
	}

	if pipeline.WorkDir != "" {
		pipeline.WorkDir, err = util.MutateStringFromMap(mutated, pipeline.WorkDir)
		if err != nil {
			return fmt.Errorf("mutating workdir: %w", err)
		}
	}

	pipeline.Runs, err = util.MutateStringFromMap(mutated, pipeline.Runs)
	if err != nil {
		return fmt.Errorf("mutating runs: %w", err)
	}

	// Drop any comments to avoid leaking things into .melange.json.
	pipeline.Runs, err = stripComments(pipeline.Runs)
	if err != nil {
		return fmt.Errorf("stripping runs comments: %w", err)
	}

	if pipeline.If != "" {
		pipeline.If, err = util.MutateAndQuoteStringFromMap(mutated, pipeline.If)
		if err != nil {
			return fmt.Errorf("mutating if: %w", err)
		}
	}

	for i := range pipeline.Pipeline {
		p := &pipeline.Pipeline[i]

		// Inherit workdir from parent pipeline unless overridden.
		if p.WorkDir == "" {
			p.WorkDir = pipeline.WorkDir
		}

		if err := c.compilePipeline(ctx, sm, p, mutated); err != nil {
			return fmt.Errorf("compiling Pipeline[%d]: %w", i, err)
		}
	}

	// We only want to include "with"s that have non-default values.
	defaults := map[string]string{}
	for k, v := range pipeline.Inputs {
		defaults[k] = v.Default
	}
	cleaned := map[string]string{}
	for k := range with {
		nk := fmt.Sprintf("${{inputs.%s}}", k)

		nv := mutated[nk]
		if nv != defaults[k] {
			cleaned[k] = nv
		}
	}
	pipeline.With = cleaned

	// We don't care about the documented inputs.
	pipeline.Inputs = nil

	return nil
}

func identity(p *config.Pipeline) string {
	if p.Name != "" {
		return p.Name
	}
	if p.Uses != "" {
		return p.Uses
	}

	return unidentifiablePipeline
}

func (c *Compiled) gatherEnvironment(ctx context.Context, pipeline *config.Pipeline) error {
	log := clog.FromContext(ctx)

	id := identity(pipeline)

	if pipeline.Needs != nil {
		if pipeline.Needs.Environment != nil {
			if c.Environment == nil {
				c.Environment = map[string]string{}
			}
			for k, v := range pipeline.Needs.Environment {
				log.Debugf("  adding environment %q=%q for pipeline %q", k, v, id)
				c.Environment[k] = v
			}
		}
		pipeline.Needs = nil
	}

	for _, p := range pipeline.Pipeline {
		if err := c.gatherEnvironment(ctx, &p); err != nil {
			return err
		}
	}

	return nil
}

func (c *Compiled) gatherDeps(ctx context.Context, pipeline *config.Pipeline) error {
	log := clog.FromContext(ctx)

	id := identity(pipeline)

	if pipeline.If != "" {
		if result, err := cond.Evaluate(pipeline.If); err != nil {
			return fmt.Errorf("evaluating conditional %q: %w", pipeline.If, err)
		} else if !result {
			return nil
		}
	}

	if pipeline.Needs != nil {
		for _, pkg := range pipeline.Needs.Packages {
			log.Debugf("  adding package %q for pipeline %q", pkg, id)
		}
		c.Needs = append(c.Needs, pipeline.Needs.Packages...)
	}

	for _, p := range pipeline.Pipeline {
		if err := c.gatherDeps(ctx, &p); err != nil {
			return err
		}
	}

	return nil
}

func maybeIncludeSyntaxError(runs string, err error) error {
	var perr syntax.ParseError
	if !errors.As(err, &perr) {
		return err
	}

	line := perr.Pos.Line()
	lines := strings.Split(runs, "\n")
	if line <= 0 || line > uint(len(lines)) {
		return err
	}

	padding := len("> ") + int(perr.Pos.Col())

	// For example...
	// 14:13: not a valid test operator: -m
	// > if [[ uname -m == 'x86_64']]; then
	//               ^
	return fmt.Errorf("%w:\n> %s\n%*s", err, lines[line-1], padding, "^")
}

func stripComments(runs string) (string, error) {
	parser := syntax.NewParser(syntax.KeepComments(false))
	printer := syntax.NewPrinter()

	builder := strings.Builder{}

	// The KeepComments(false) option drops comments, including the shebang.
	// We don't want to do that, so keep the first line if it starts with #!
	if idx := strings.IndexRune(runs, '\n'); idx != -1 {
		firstLine := runs[0 : idx+1]
		if strings.HasPrefix(firstLine, "#!") {
			builder.WriteString(firstLine)
		}
	}

	var perr error
	if err := parser.Stmts(strings.NewReader(runs), func(stmt *syntax.Stmt) bool {
		perr = printer.Print(&builder, stmt)
		builder.WriteRune('\n')
		return perr == nil
	}); err != nil || perr != nil {
		return "", maybeIncludeSyntaxError(runs, errors.Join(err, perr))
	}

	return builder.String(), nil
}
