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

	"github.com/chainguard-dev/clog"
	"mvdan.cc/sh/v3/syntax"

	"chainguard.dev/melange/pkg/cond"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/util"
)

const unidentifiablePipeline = "???"

// CompileOption adjusts what a Compile produces.
type CompileOption func(*Compiled)

// WithDependenciesOnly narrows compilation to what a caller resolving build
// dependencies needs, which is the `uses:` tree and the packages it pulls in.
//
// The compiled pipelines are not runnable: each step's `runs:` keeps the
// comments and formatting it was written with, because normalizing it is the
// single most expensive part of compiling and a caller that only reads
// .environment.contents.packages discards it. Everything else — substitution,
// validation, conditionals and the resolved dependency list — is unchanged, so
// a definition that fails to compile still fails the same way.
//
// Do not use this to produce a configuration that will be built or recorded:
// use a plain Compile for that.
func WithDependenciesOnly() CompileOption {
	return func(c *Compiled) {
		c.dependenciesOnly = true
	}
}

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
		}

		te := &cfg.Subpackages[i].Test.Environment.Contents

		// Append the subpackage that we're testing to be installed.
		te.Packages = append(te.Packages, sp.Name)

		if err := test.CompilePipelines(ctx, sm, sp.Test.Pipeline); err != nil {
			return fmt.Errorf("compiling subpackage %q tests: %w", sp.Name, err)
		}

		// Append anything this subpackage test needs.
		te.Packages = append(te.Packages, test.Needs...)

		// Sort and remove duplicates.
		te.Packages = slices.Compact(slices.Sorted(slices.Values(te.Packages)))
	}

	if cfg.Test != nil {
		test := &Compiled{
			PipelineDirs: t.PipelineDirs,
		}

		te := &t.Configuration.Test.Environment.Contents

		// Append the main test package to be installed unless explicitly specified by the command line.
		if t.Package != "" {
			te.Packages = append(te.Packages, t.Package)
		} else {
			te.Packages = append(te.Packages, t.Configuration.Package.Name)
		}

		if err := test.CompilePipelines(ctx, sm, cfg.Test.Pipeline); err != nil {
			return fmt.Errorf("compiling %q test pipelines: %w", t.Package, err)
		}

		// Append anything the main package test needs.
		te.Packages = append(te.Packages, test.Needs...)

		// Sort and remove duplicates.
		te.Packages = slices.Compact(slices.Sorted(slices.Values(te.Packages)))
	}

	return nil
}

// Compile compiles all configuration, including tests, by loading any pipelines and substituting all variables.
func (b *Build) Compile(ctx context.Context, opts ...CompileOption) error {
	cfg := b.Configuration
	sm, err := NewSubstitutionMap(cfg, b.Arch, b.buildFlavor(), b.EnabledBuildOptions)
	if err != nil {
		return err
	}

	c := newCompiled(b.PipelineDirs, opts)

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

		tc := newCompiled(b.PipelineDirs, opts)
		if err := tc.CompilePipelines(ctx, sm, sp.Test.Pipeline); err != nil {
			return fmt.Errorf("compiling subpackage %q tests: %w", sp.Name, err)
		}

		te := &cfg.Subpackages[i].Test.Environment.Contents

		// Append the subpackage that we're testing to be installed.
		te.Packages = append(te.Packages, sp.Name)

		// Append anything this subpackage test needs.
		te.Packages = append(te.Packages, tc.Needs...)

		// Sort and remove duplicates.
		te.Packages = slices.Compact(slices.Sorted(slices.Values(te.Packages)))
	}

	ic := &b.Configuration.Environment.Contents
	ic.Packages = append(ic.Packages, c.Needs...)

	if cfg.Test != nil {
		tc := newCompiled(b.PipelineDirs, opts)

		if err := tc.CompilePipelines(ctx, sm, cfg.Test.Pipeline); err != nil {
			return fmt.Errorf("compiling %q test pipelines: %w", cfg.Package.Name, err)
		}

		te := &b.Configuration.Test.Environment.Contents
		te.Packages = append(te.Packages, tc.Needs...)

		// This can be overridden by the command line but in the context of a build, just use the main package.
		te.Packages = append(te.Packages, b.Configuration.Package.Name)

		// Sort and remove duplicates.
		te.Packages = slices.Compact(slices.Sorted(slices.Values(te.Packages)))
	}

	return nil
}

type Compiled struct {
	PipelineDirs []string
	Needs        []string

	// dependenciesOnly skips producing runnable `runs:` bodies. See
	// WithDependenciesOnly.
	dependenciesOnly bool
}

func newCompiled(pipelineDirs []string, opts []CompileOption) *Compiled {
	c := &Compiled{PipelineDirs: pipelineDirs}
	for _, opt := range opts {
		opt(c)
	}

	return c
}

func (c *Compiled) CompilePipelines(ctx context.Context, sm *SubstitutionMap, pipelines []config.Pipeline) error {
	for i := range pipelines {
		if err := c.compilePipeline(ctx, sm, &pipelines[i], nil); err != nil {
			return fmt.Errorf("compiling Pipeline[%d]: %w", i, err)
		}

		if err := c.gatherDeps(ctx, &pipelines[i]); err != nil {
			return fmt.Errorf("gathering deps for Pipeline[%d]: %w", i, err)
		}
	}

	return nil
}

func (c *Compiled) compilePipeline(ctx context.Context, sm *SubstitutionMap, pipeline *config.Pipeline, parent map[string]string) error {
	name, uses, with := pipeline.Name, pipeline.Uses, maps.Clone(pipeline.With)

	// When compiling an already-compiled config, `uses` will be redundant and FYI only,
	// so ignore it if there is also a `pipelines` spelled out.
	if uses != "" && len(pipeline.Pipeline) == 0 {
		// Validate that 'uses' does not contain path traversal sequences or absolute paths.
		if filepath.IsAbs(uses) || strings.Contains(uses, "..") {
			return fmt.Errorf("invalid pipeline 'uses' value %q: must not contain absolute paths or '..' sequences", uses)
		}

		// Reading and parsing the definition only happens the first time it
		// is used; see usesDocument.
		doc, err := usesDocument(c.PipelineDirs, uses, func() ([]byte, error) {
			return c.readUses(ctx, uses)
		})
		if err != nil {
			return err
		}
		if doc != nil {
			if err := doc.Decode(pipeline); err != nil {
				return fmt.Errorf("unable to parse pipeline %q: %w", uses, err)
			}
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

	// Drop any comments to avoid leaking things into .melange.json. Parsing
	// the script to do it costs more than the rest of compiling the step, so
	// a caller that is only resolving dependencies skips it.
	if !c.dependenciesOnly {
		pipeline.Runs, err = stripComments(pipeline.Runs)
		if err != nil {
			return fmt.Errorf("stripping runs comments: %w", err)
		}
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

// readUses reads the definition named by uses from the configured pipeline
// directories, falling back to the ones built into melange.
func (c *Compiled) readUses(ctx context.Context, uses string) ([]byte, error) {
	log := clog.FromContext(ctx)

	var data []byte
	// Set this to fail up front in case there are no pipeline dirs specified
	// and we can't find them.
	err := fmt.Errorf("could not find 'uses' pipeline %q", uses)

	for _, pd := range c.PipelineDirs {
		log.Debugf("trying to load pipeline %q from %q", uses, pd)
		target := filepath.Join(pd, uses+".yaml")
		// Verify the resolved path is still within the pipeline directory.
		if rel, err := filepath.Rel(pd, filepath.Clean(target)); err != nil || strings.HasPrefix(rel, "..") {
			return nil, fmt.Errorf("pipeline 'uses' value %q resolves outside pipeline directory %q", uses, pd)
		}
		data, err = os.ReadFile(target) // #nosec G304 - Loading pipeline definition from configured directory
		if err == nil {
			log.Debugf("Found pipeline %s", string(data))
			break
		}
	}
	if err != nil {
		log.Debugf("trying to load pipeline %q from embedded fs pipelines/%q.yaml", uses, uses)
		data, err = PipelinesFS.ReadFile("pipelines/" + uses + ".yaml")
		if err != nil {
			return nil, fmt.Errorf("unable to load pipeline: %w", err)
		}
	}

	return data, nil
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

		pipeline.Needs = nil
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

	// perr.Pos.Col() returns uint, convert to int for padding calculation
	// Column numbers are small in practice, so this conversion is safe
	padding := len("> ") + int(perr.Pos.Col()) // #nosec G115 - column numbers are always small

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

	for stmt, err := range parser.StmtsSeq(strings.NewReader(runs)) {
		if err != nil {
			return "", maybeIncludeSyntaxError(runs, err)
		}
		perr := printer.Print(&builder, stmt)
		if perr != nil {
			return "", maybeIncludeSyntaxError(runs, perr)
		}
		builder.WriteRune('\n')
	}

	return builder.String(), nil
}
