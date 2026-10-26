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

package renovate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
)

// A config whose pipeline has a comment block with a blank line on each
// side. yaml.v3 stores the trailing blank line inside the head comment of
// the next item; with gap expressions yam reproduces the layout, without
// them it emits "comment, blank line, item", which yaml.v3 parses next time
// as a foot comment on that item's first key.
const commentedConfig = `package:
  name: example
  version: 1.0.0
  epoch: 0
  description: example package

environment:
  contents:
    packages:
      - busybox

pipeline:
  - runs: |
      echo first

  # A note about the next step, kept as a standalone block.
  # It spans two lines.

  - runs: |
      echo second
`

const yamConfig = `gap:
  - "."
  - ".pipeline"
indent: 2
`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// renovateNoop runs Renovate with no renovators, which only re-encodes the
// file, and returns the result.
func renovateNoop(t *testing.T, configPath string) string {
	t.Helper()
	rctx, err := New(WithConfig(configPath))
	if err != nil {
		t.Fatal(err)
	}
	if err := rctx.Renovate(t.Context()); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestWriteConfig_UsesRepositoryYamConfig(t *testing.T) {
	// The test binary's working directory is this package directory, which
	// has no .yam.yaml, so AutomaticConfig would find nothing.
	if _, err := os.Stat(".yam.yaml"); err == nil {
		t.Fatal("unexpected .yam.yaml in the test working directory")
	}

	t.Run("config next to the file", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "example.yaml")
		writeFile(t, filepath.Join(dir, ".yam.yaml"), yamConfig)
		writeFile(t, configPath, commentedConfig)

		got := renovateNoop(t, configPath)
		if diff := cmp.Diff(commentedConfig, got); diff != "" {
			t.Errorf("layout changed (-want +got):\n%s", diff)
		}
	})

	t.Run("config in a parent directory", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "os", "example.yaml")
		writeFile(t, filepath.Join(dir, ".yam.yaml"), yamConfig)
		writeFile(t, configPath, commentedConfig)

		got := renovateNoop(t, configPath)
		if diff := cmp.Diff(commentedConfig, got); diff != "" {
			t.Errorf("layout changed (-want +got):\n%s", diff)
		}
	})

	t.Run("second pass keeps the comment above its step", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "example.yaml")
		writeFile(t, filepath.Join(dir, ".yam.yaml"), yamConfig)
		writeFile(t, configPath, commentedConfig)

		renovateNoop(t, configPath)
		got := renovateNoop(t, configPath)

		var root yaml.Node
		if err := yaml.Unmarshal([]byte(got), &root); err != nil {
			t.Fatalf("second pass produced invalid YAML: %v\n%s", err, got)
		}
		if diff := cmp.Diff(commentedConfig, got); diff != "" {
			t.Errorf("second pass changed the layout (-want +got):\n%s", diff)
		}
	})

	t.Run("without any yam config the gaps are lost", func(t *testing.T) {
		// Control case documenting the behaviour this change avoids: with no
		// .yam.yaml reachable, the encoder has no gap expressions and the blank
		// line before the comment block disappears.
		dir := t.TempDir()
		configPath := filepath.Join(dir, "example.yaml")
		writeFile(t, configPath, commentedConfig)

		got := renovateNoop(t, configPath)
		if got == commentedConfig {
			t.Skip("working directory supplied a yam config; control case not applicable")
		}
		var root yaml.Node
		if err := yaml.Unmarshal([]byte(got), &root); err != nil {
			t.Fatalf("no-config pass produced invalid YAML: %v\n%s", err, got)
		}
	})
}
