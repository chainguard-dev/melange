/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package build

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/config"
)

// definition is a pipeline definition of the shape `uses:` loads: it names
// some keys and leaves others out.
const definition = `name: definition name
inputs:
  version:
    description: the version
    default: "1.0"
needs:
  packages:
    - busybox
pipeline:
  - runs: echo hi
`

// loadUses does what compilePipeline does with a document: fetch it, then
// decode it onto the pipeline.
func loadUses(dirs []string, uses string, load func() ([]byte, error), pipeline *config.Pipeline) error {
	doc, err := usesDocument(dirs, uses, load)
	if err != nil {
		return err
	}
	if doc == nil {
		return nil
	}

	return doc.Decode(pipeline)
}

func serve(data string, calls *atomic.Int64) func() ([]byte, error) {
	return func() ([]byte, error) {
		if calls != nil {
			calls.Add(1)
		}

		return []byte(data), nil
	}
}

// TestUsesDocumentMatchesUnmarshal pins that loading a definition through the
// cache leaves the target in the state yaml.Unmarshal would, on both the parse
// and the cached path, and that the definition is only read once. Keys the
// definition sets are applied; the ones it omits keep the values the step
// brought with it.
func TestUsesDocumentMatchesUnmarshal(t *testing.T) {
	step := func() *config.Pipeline {
		return &config.Pipeline{
			Uses:    "some/pipeline",
			With:    map[string]string{"version": "2.0"},
			If:      "true",
			WorkDir: "/home/build",
		}
	}

	want := step()
	if err := yaml.Unmarshal([]byte(definition), want); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}

	dirs := []string{t.TempDir()}
	var calls atomic.Int64

	for _, when := range []string{"parsed", "cached"} {
		got := step()
		if err := loadUses(dirs, "some/pipeline", serve(definition, &calls), got); err != nil {
			t.Fatalf("%s: %v", when, err)
		}

		if got.Name != want.Name {
			t.Errorf("%s: name: got = %q, want = %q", when, got.Name, want.Name)
		}
		if got.WorkDir != want.WorkDir {
			t.Errorf("%s: workdir: got = %q, want = %q", when, got.WorkDir, want.WorkDir)
		}
		if got.If != want.If {
			t.Errorf("%s: if: got = %q, want = %q", when, got.If, want.If)
		}
		if len(got.With) != len(want.With) || got.With["version"] != want.With["version"] {
			t.Errorf("%s: with: got = %v, want = %v", when, got.With, want.With)
		}
		if len(got.Inputs) != len(want.Inputs) {
			t.Errorf("%s: inputs: got = %d, want = %d", when, len(got.Inputs), len(want.Inputs))
		}
		if got.Needs == nil || len(got.Needs.Packages) != 1 || got.Needs.Packages[0] != "busybox" {
			t.Errorf("%s: needs: got = %v, want = [busybox]", when, got.Needs)
		}
		if len(got.Pipeline) != 1 || got.Pipeline[0].Runs != "echo hi" {
			t.Errorf("%s: pipeline: got = %v", when, got.Pipeline)
		}
	}

	// The point of the cache: the definition is read from disk once, not once
	// per package that names it.
	if got := calls.Load(); got != 1 {
		t.Errorf("loads: got = %d, want = 1", got)
	}
}

// TestUsesDocumentKeyedByPipelineDirs checks that two pipeline directory sets
// resolving the same name to different definitions do not share an entry.
func TestUsesDocumentKeyedByPipelineDirs(t *testing.T) {
	first := []string{t.TempDir()}
	second := []string{t.TempDir()}

	one := &config.Pipeline{}
	if err := loadUses(first, "shared", serve("name: one\n", nil), one); err != nil {
		t.Fatal(err)
	}

	two := &config.Pipeline{}
	if err := loadUses(second, "shared", serve("name: two\n", nil), two); err != nil {
		t.Fatal(err)
	}

	if one.Name != "one" {
		t.Errorf("first dirs: got = %q, want = %q", one.Name, "one")
	}
	if two.Name != "two" {
		t.Errorf("second dirs: got = %q, want = %q", two.Name, "two")
	}
}

// TestUsesDocumentEmptyDefinition checks that an empty definition is the no-op
// yaml.Unmarshal makes of it rather than an error, and that it is not read a
// second time.
func TestUsesDocumentEmptyDefinition(t *testing.T) {
	for _, data := range []string{"", "\n", "# just a comment\n"} {
		want := &config.Pipeline{Uses: "empty"}
		if err := yaml.Unmarshal([]byte(data), want); err != nil {
			t.Fatalf("yaml.Unmarshal(%q): %v", data, err)
		}

		dirs := []string{t.TempDir()}
		var calls atomic.Int64

		for range 2 {
			got := &config.Pipeline{Uses: "empty"}
			if err := loadUses(dirs, "empty", serve(data, &calls), got); err != nil {
				t.Errorf("%q: %v", data, err)
				continue
			}
			if got.Uses != want.Uses {
				t.Errorf("%q: uses: got = %q, want = %q", data, got.Uses, want.Uses)
			}
		}

		if got := calls.Load(); got != 1 {
			t.Errorf("%q: loads: got = %d, want = 1", data, got)
		}
	}
}

// TestUsesDocumentLoadError checks that a definition that cannot be read
// reports the loader's own error and is not cached.
func TestUsesDocumentLoadError(t *testing.T) {
	dirs := []string{t.TempDir()}
	want := errors.New("could not find 'uses' pipeline")

	for range 2 {
		_, err := usesDocument(dirs, "missing", func() ([]byte, error) { return nil, want })
		if !errors.Is(err, want) {
			t.Fatalf("got = %v, want = %v", err, want)
		}
	}

	// A failure must not be remembered as an empty definition.
	got := &config.Pipeline{}
	if err := loadUses(dirs, "missing", serve("name: recovered\n", nil), got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "recovered" {
		t.Errorf("name: got = %q, want = %q", got.Name, "recovered")
	}
}

// TestUsesDocumentConcurrent decodes one cached definition from many goroutines
// at once. Cached documents are shared across the goroutines that compile a
// tree of packages in parallel, so decoding must not write to the document it
// decodes from. Run under -race for this to mean anything.
func TestUsesDocumentConcurrent(t *testing.T) {
	dirs := []string{t.TempDir()}

	// Seed the entry so every goroutine below takes the cached path.
	if err := loadUses(dirs, "concurrent", serve(definition, nil), &config.Pipeline{}); err != nil {
		t.Fatal(err)
	}

	const goroutines = 32
	results := make([]*config.Pipeline, goroutines)
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range goroutines {
		wg.Go(func() {
			<-start
			p := &config.Pipeline{Uses: "concurrent", WorkDir: "/home/build"}
			errs[i] = loadUses(dirs, "concurrent", serve(definition, nil), p)
			results[i] = p
		})
	}
	close(start)
	wg.Wait()

	for i := range goroutines {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		got := results[i]
		if got.Name != "definition name" || got.WorkDir != "/home/build" {
			t.Errorf("goroutine %d: got name = %q workdir = %q", i, got.Name, got.WorkDir)
		}
		if got.Needs == nil || len(got.Needs.Packages) != 1 {
			t.Errorf("goroutine %d: needs: got = %v", i, got.Needs)
		}
		if len(got.Pipeline) != 1 || got.Pipeline[0].Runs != "echo hi" {
			t.Errorf("goroutine %d: pipeline: got = %v", i, got.Pipeline)
		}
	}
}
