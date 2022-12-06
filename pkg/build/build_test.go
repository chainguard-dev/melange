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
	"os"
	"path/filepath"
	"testing"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestLoadConfiguration(t *testing.T) {
	contents := `
package:
  name: nginx
  version: 100
  test: ${{package.name}}
`
	expected := &Configuration{
		Package: Package{
			Name:    "nginx",
			Version: "100",
		},
		Subpackages: []Subpackage{},
	}
	expected.Environment.Accounts.Users = []apko_types.User{{
		UserName: "build",
		UID:      1000,
		GID:      1000,
	}}
	expected.Environment.Accounts.Groups = []apko_types.Group{{
		GroupName: "build",
		GID:       1000,
		Members:   []string{"build"},
	}}
	expected.Environment.Environment = map[string]string{
		"HOME": "/home/build",
		"GOPATH": "/home/build/.cache/go",
	}

	f := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(f, []byte(contents), 0755); err != nil {
		t.Fatal(err)
	}

	ctx := Context{ConfigFile: f}
	cfg := &Configuration{}
	if err := cfg.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if d := cmp.Diff(expected, cfg); d != "" {
		t.Fatalf("actual didn't match expected: %s", d)
	}
}

func TestLoadConfiguration_RangeSubpackages(t *testing.T) {
	contents := `
package:
  name: hello
  version: world

pipeline:
- name: hello
  runs: world

data:
  - name: ninja-turtles
    items:
      Michelangelo: orange
      Raphael: red
      Leonardo: blue
      Donatello: purple
  - name: animals
    items:
      dogs: loyal
      cats: angry
      turtles: slow

subpackages:
  - range: animals
    name: ${{range.key}}
    pipeline:
      - runs: ${{range.key}} are ${{range.value}}
  - range: ninja-turtles
    name: ${{range.key}}
    pipeline:
      - runs: ${{range.key}}'s color is ${{range.value}}
`

	expected := []Subpackage{{
		Name: "cats",
		Pipeline: []Pipeline{{
			Runs: "cats are angry",
		}},
	}, {
		Name: "dogs",
		Pipeline: []Pipeline{{
			Runs: "dogs are loyal",
		}},
	}, {
		Name: "turtles",
		Pipeline: []Pipeline{{
			Runs: "turtles are slow",
		}},
	}, {
		Name: "Donatello",
		Pipeline: []Pipeline{{
			Runs: "Donatello's color is purple",
		}},
	}, {
		Name: "Leonardo",
		Pipeline: []Pipeline{{
			Runs: "Leonardo's color is blue",
		}},
	}, {
		Name: "Michelangelo",
		Pipeline: []Pipeline{{
			Runs: "Michelangelo's color is orange",
		}},
	}, {
		Name: "Raphael",
		Pipeline: []Pipeline{{
			Runs: "Raphael's color is red",
		}},
	}}

	f := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(f, []byte(contents), 0755); err != nil {
		t.Fatal(err)
	}

	ctx := Context{ConfigFile: f}
	cfg := &Configuration{}
	if err := cfg.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if d := cmp.Diff(expected, cfg.Subpackages, cmpopts.IgnoreUnexported(Pipeline{})); d != "" {
		t.Fatalf("actual didn't match expected: %s", d)
	}
}
