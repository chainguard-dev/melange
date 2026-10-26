// Copyright 2026 Chainguard, Inc.
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
	"fmt"
	"path"
	"slices"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/config"
)

// sourceStrictEnv makes the scripts of the strict step kinds fail on a cache
// miss instead of fetching.
const sourceStrictEnv = "MELANGE_SOURCE_STRICT"

// strictSourceKinds are the step kinds --strict-sources-from-cache accepts, each
// named by the embedded pipeline that implements it.
var strictSourceKinds = []string{"git-checkout"}

// normalizeStrictSources validates kinds, which must name members of strictSourceKinds,
// and returns them without duplicates. nil means the flag was not given; an
// empty list means it was given no value, which is refused rather than read as
// nil because a templated value that came out empty is a mistake, not a request
// for the default.
func normalizeStrictSources(kinds []string) ([]string, error) {
	if kinds == nil {
		return nil, nil
	}
	accepted := strings.Join(strictSourceKinds, ", ")
	if len(kinds) == 0 {
		return nil, fmt.Errorf("--strict-sources-from-cache: empty value; accepted: %s", accepted)
	}
	for _, k := range kinds {
		if !slices.Contains(strictSourceKinds, k) {
			return nil, fmt.Errorf("--strict-sources-from-cache: unknown step kind %q; accepted: %s", k, accepted)
		}
	}
	out := slices.Clone(kinds)
	slices.Sort(out)
	return slices.Compact(out), nil
}

// withEmbeddedSources makes compilation take the definitions of the given step
// kinds from the ones built into melange.
func withEmbeddedSources(kinds []string) CompileOption {
	return func(c *Compiled) { c.embeddedSources = kinds }
}

// sourceStep returns the member of strictSourceKinds that uses names, however
// it is spelled: a cleaned path matches whatever resolves to the same file, the
// comparison ignores case for file systems that do, and invisible format
// characters are dropped so they cannot hide a name from it.
func sourceStep(uses string) string {
	c := path.Clean(strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, uses))
	for _, name := range strictSourceKinds {
		if strings.EqualFold(c, name) {
			return name
		}
	}
	return ""
}

// compiledShape reports whether p's children are what compiling a source step
// leaves: the one script, with nothing nested in it.
func compiledShape(p *config.Pipeline) bool {
	if p.Runs != "" || len(p.Pipeline) != 1 {
		return false
	}
	c := p.Pipeline[0]
	return c.Runs != "" && c.Uses == "" && len(c.Pipeline) == 0
}

// strictStep is sourceStep, but "" for a kind that kinds does not enable.
func strictStep(kinds []string, uses string) string {
	if s := sourceStep(uses); slices.Contains(kinds, s) {
		return s
	}
	return ""
}

// document returns the definition uses names: melange's own when embedded,
// which is parsed afresh each time because usesCache keys are made of directory
// names and any key could be one a caller's directories spell, otherwise the
// first one found in the pipeline directories, which is read and parsed only
// the first time it is used; see usesDocument.
func (c *Compiled) document(ctx context.Context, uses string, embedded bool) (*yaml.Node, error) {
	if !embedded {
		return usesDocument(c.PipelineDirs, uses, func() ([]byte, error) {
			return c.readUses(ctx, uses)
		})
	}
	data, err := PipelinesFS.ReadFile("pipelines/" + uses + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("unable to load pipeline: %w", err)
	}
	doc := &yaml.Node{}
	if err := yaml.Unmarshal(data, doc); err != nil {
		return nil, fmt.Errorf("unable to parse pipeline %q: %w", uses, err)
	}
	return doc, nil
}
