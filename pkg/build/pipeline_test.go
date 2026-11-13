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
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/util"

	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/require"
)

func Test_mutateStringFromMap(t *testing.T) {
	keys := map[string]string{
		"${{inputs.foo}}": "foo",
		"${{inputs.bar}}": "bar",
	}

	input1 := "${{inputs.foo}} ${{inputs.baz-bah-boom}}"
	_, err := util.MutateStringFromMap(keys, input1)

	require.Error(t, err)
}

func Test_substitutionMap(t *testing.T) {
	tests := []struct {
		initialVersion string
		match          string
		replace        string
		expected       string
	}{
		{initialVersion: "1.2.3.9", match: `\.(\d+)$`, replace: "+$1", expected: "1.2.3+9"},
	}
	for _, tt := range tests {
		pkg := config.Package{
			Name:    "foo",
			Version: tt.initialVersion,
		}

		t.Run("sub", func(t *testing.T) {
			cfg := config.Configuration{
				Package: pkg,
				VarTransforms: []config.VarTransforms{
					{
						From:    "${{package.version}}",
						Match:   tt.match,
						Replace: tt.replace,
						To:      "mangled-package-version",
					},
				},
			}
			m, err := NewSubstitutionMap(&cfg, "", "", nil)
			require.NoError(t, err)
			require.Equal(t, tt.expected, m.Substitutions["${{vars.mangled-package-version}}"])
		})
	}
}

func Test_MutateWith(t *testing.T) {
	for _, tc := range []struct {
		version string
		epoch   uint64
		want    string
	}{{
		version: "1.2.3",
		epoch:   0,
		want:    "1.2.3-r0",
	}, {
		version: "1.2.3",
		epoch:   3,
		want:    "1.2.3-r3",
	}} {
		cfg := config.Configuration{
			Package: config.Package{
				Version: tc.version,
				Epoch:   tc.epoch,
			},
		}
		sm, err := NewSubstitutionMap(&cfg, "", "", nil)
		require.NoError(t, err)
		got, err := sm.MutateWith(map[string]string{})
		if err != nil {
			t.Fatalf("MutateWith failed with: %v", err)
		}
		gotFullVer := got[config.SubstitutionPackageFullVersion]
		if gotFullVer != tc.want {
			t.Errorf("got %s, want %s", gotFullVer, tc.want)
		}
	}
}

// Regression: a nested `uses:` that forwards a same-named input (compile.go
// merges the parent's resolved "${{inputs.X}}" with the child's own "X") must
// resolve deterministically regardless of Go's random map order.
func Test_MutateWith_ForwardedSameNamedInput(t *testing.T) {
	sm := &SubstitutionMap{Substitutions: map[string]string{}}

	for _, tc := range []struct {
		name  string
		with  map[string]string
		wants map[string]string // key -> expected resolved value
	}{{
		name: "forwarded self-reference resolves to parent value",
		with: map[string]string{
			"${{inputs.admin-password}}": "adminpw",                    // inherited from parent
			"admin-password":             "${{inputs.admin-password}}", // forwarded down
		},
		wants: map[string]string{"${{inputs.admin-password}}": "adminpw"},
	}, {
		name: "literal override wins over inherited value",
		with: map[string]string{
			"${{inputs.admin-password}}": "adminpw",
			"admin-password":             "literalsecret",
		},
		wants: map[string]string{"${{inputs.admin-password}}": "literalsecret"},
	}, {
		name: "child default wins over inherited parent value",
		with: map[string]string{
			"${{inputs.tls-cert-dir}}": "/tmp/tls", // parent's value
			"tls-cert-dir":             "",         // child's default (validateWith filled it)
		},
		wants: map[string]string{"${{inputs.tls-cert-dir}}": ""},
	}, {
		name:  "plain input with no collision resolves normally",
		with:  map[string]string{"foo": "bar"},
		wants: map[string]string{"${{inputs.foo}}": "bar"},
	}, {
		// Order-independence here comes from the final mutation loop
		// re-resolving every entry, not from the input-loop order.
		name: "sibling reference resolves regardless of order",
		with: map[string]string{
			"a": "${{inputs.b}}",
			"b": "bee",
		},
		wants: map[string]string{
			"${{inputs.a}}": "bee",
			"${{inputs.b}}": "bee",
		},
	}, {
		name: "multiple forwarded inputs all resolve to parent values",
		with: map[string]string{
			"${{inputs.password}}": "pw",
			"password":             "${{inputs.password}}",
			"${{inputs.cert-dir}}": "/d",
			"cert-dir":             "${{inputs.cert-dir}}",
		},
		wants: map[string]string{
			"${{inputs.password}}": "pw",
			"${{inputs.cert-dir}}": "/d",
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			// Run many times to defeat randomized map iteration order.
			for i := range 1000 {
				got, err := sm.MutateWith(tc.with)
				if err != nil {
					t.Fatalf("MutateWith: %v", err)
				}
				for k, want := range tc.wants {
					if v := got[k]; v != want {
						t.Fatalf("iter %d: %s: got %q, want %q", i, k, v, want)
					}
				}
			}
		})
	}
}

// Forwarding the same-named input down many levels must keep resolving to the
// top value at any depth (each level passes a fully-resolved map to the next).
func Test_MutateWith_DeepForwarding(t *testing.T) {
	sm := &SubstitutionMap{Substitutions: map[string]string{}}
	for i := range 1000 {
		// Top level: the input takes its real value.
		m, err := sm.MutateWith(map[string]string{"admin-password": "adminpw"})
		if err != nil {
			t.Fatalf("iter %d top: %v", i, err)
		}
		// Each deeper level inherits the parent's resolved map and forwards the
		// same-named input (the self-referential `X: ${{inputs.X}}`).
		for lvl := 1; lvl <= 5; lvl++ {
			child := maps.Clone(m)
			child["admin-password"] = "${{inputs.admin-password}}"
			m, err = sm.MutateWith(child)
			if err != nil {
				t.Fatalf("iter %d level %d: %v", i, lvl, err)
			}
		}
		if v := m["${{inputs.admin-password}}"]; v != "adminpw" {
			t.Fatalf("iter %d: 6-level forwarded value = %q, want %q", i, v, "adminpw")
		}
	}
}

// Functional: compile a 3-level nested `uses:` (parent->child->grandchild) that
// forwards a same-named input down to a `runs:` block. Pre-fix this
// intermittently failed stripComments with "invalid parameter name".
func Test_CompilePipelines_NestedForwardedInput(t *testing.T) {
	ctx := slogtest.Context(t)
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644))
	}
	write("parent.yaml", `
inputs:
  password:
    default: defaultpw
pipeline:
  - uses: child
    with:
      password: ${{inputs.password}}
`)
	write("child.yaml", `
inputs:
  password:
    default: childdefault
pipeline:
  - uses: grandchild
    with:
      password: ${{inputs.password}}
`)
	write("grandchild.yaml", `
inputs:
  password:
    default: grandchilddefault
pipeline:
  - runs: |
      echo "pw=${{inputs.password}}"
`)

	// repeats is an iteration count (NOT nesting depth); the pre-fix bug was
	// intermittent (random map order), so repeat to fail reliably.
	const repeats = 200
	for i := range repeats {
		cfg := config.Configuration{
			Package: config.Package{Name: "foo", Version: "1.2.3"},
			Pipeline: []config.Pipeline{{
				Uses: "parent",
				With: map[string]string{"password": "topsecret"},
			}},
		}
		c := &Compiled{PipelineDirs: []string{dir}}
		sm, err := NewSubstitutionMap(&cfg, "", "", nil)
		require.NoError(t, err)

		require.NoError(t, c.CompilePipelines(ctx, sm, cfg.Pipeline), "iter %d", i)

		// parent -> child -> grandchild -> runs step
		runs := cfg.Pipeline[0].Pipeline[0].Pipeline[0].Pipeline[0].Runs
		require.Contains(t, runs, "pw=topsecret", "iter %d: runs=%q", i, runs)
		require.NotContains(t, runs, "${{", "iter %d: unresolved template in runs=%q", i, runs)
	}
}

func Test_substitutionNeedPackages(t *testing.T) {
	ctx := slogtest.Context(t)
	pkg := config.Package{
		Name:    "foo",
		Version: "1.2.3",
	}

	cfg := config.Configuration{
		Package: pkg,
		Pipeline: []config.Pipeline{
			{
				Uses: "go/build",
				With: map[string]string{
					"go-package": "go-5.4.3",
					"output":     "foo",
					"packages":   "./bar",
				},
			},
		},
	}
	pipelineDirs := []string{"pipelines"}

	c := &Compiled{PipelineDirs: pipelineDirs}
	sm, err := NewSubstitutionMap(&cfg, "", "", nil)
	require.NoError(t, err)

	err = c.CompilePipelines(ctx, sm, cfg.Pipeline)
	require.NoError(t, err)
	require.Equal(t, "go-5.4.3", c.Needs[0])
}

func Test_buildEvalRunCommand(t *testing.T) {
	p := &config.Pipeline{
		Environment: map[string]string{"FOO": "bar"},
	}

	debugOption := 'x'
	workdir := "/bar"
	fragment := "baz"
	command := buildEvalRunCommand(p, debugOption, workdir, fragment)
	// Note: shellquote.Join() only adds quotes when necessary
	// Simple paths like /bar don't need quotes, so they're returned unquoted
	expected := []string{"/bin/sh", "-c", `set -exo pipefail
[ -d /bar ] || mkdir -p /bar
cd /bar
baz
exit 0`}
	require.Equal(t, expected, command)
}

func TestAllPipelines(t *testing.T) {
	// Get all the yamls in pipelines/*/*.yaml and test that they unmarshal
	pipelines, err := filepath.Glob("pipelines/*/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pipeline := &config.Pipeline{}
	for _, p := range pipelines {
		t.Run(p, func(t *testing.T) {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := yaml.Unmarshal(b, pipeline); err != nil {
				t.Errorf("unexpected error unmarshalling pipeline: %v", err)
			}
		})
	}
}

func Test_validateWith(t *testing.T) {
	tests := []struct {
		name        string
		data        map[string]string
		inputs      map[string]config.Input
		expected    map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid SHA256 checksum",
			data: map[string]string{
				"expected-sha256": "a3c2567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			},
			inputs: map[string]config.Input{
				"expected-sha256": {Default: "", Required: true},
			},
			expected: map[string]string{
				"expected-sha256": "a3c2567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			},
			expectError: false,
		},
		{
			// Digests are checked after substitution, by validateDigests, so a
			// forwarded "${{inputs.X}}" reference must pass through untouched.
			name: "Unsubstituted SHA256 reference",
			data: map[string]string{
				"expected-sha256": "${{inputs.sha256}}",
			},
			inputs: map[string]config.Input{
				"expected-sha256": {Default: "", Required: true},
			},
			expected: map[string]string{
				"expected-sha256": "${{inputs.sha256}}",
			},
			expectError: false,
		},
		{
			name: "Missing required input",
			data: map[string]string{},
			inputs: map[string]config.Input{
				"expected-commit": {Default: "", Required: true},
			},
			expectError: true,
			errorMsg:    "required input \"expected-commit\" for pipeline is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateWith(tt.data, tt.inputs)

			if tt.expectError {
				require.Error(t, err)
				require.EqualError(t, err, tt.errorMsg)
				return // Skip further checks if error is expected
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected, result)
		})
	}
}

func Test_validateDigests(t *testing.T) {
	sha256 := strings.Repeat("a", 64)
	sha512 := strings.Repeat("b", 128)
	commit := strings.Repeat("c", 40)
	inputs := map[string]config.Input{
		"expected-sha256": {},
		"expected-sha512": {},
		"expected-commit": {},
		"other":           {},
	}

	for _, tt := range []struct {
		name     string
		inputs   map[string]config.Input // defaults to inputs above
		mutated  map[string]string
		errorMsg string
	}{{
		name: "valid digests",
		mutated: map[string]string{
			"${{inputs.expected-sha256}}": sha256,
			"${{inputs.expected-sha512}}": sha512,
			"${{inputs.expected-commit}}": commit,
		},
	}, {
		name:    "empty digests are not checked",
		mutated: map[string]string{},
	}, {
		name:    "other inputs are not checked",
		mutated: map[string]string{"${{inputs.other}}": "abcdef"},
	}, {
		name:     "invalid SHA256 length",
		mutated:  map[string]string{"${{inputs.expected-sha256}}": "abcdef"},
		errorMsg: `checksum input "expected-sha256" for pipeline, invalid length`,
	}, {
		name:     "invalid SHA512 characters",
		mutated:  map[string]string{"${{inputs.expected-sha512}}": strings.Repeat("z", 128)},
		errorMsg: `checksum input "expected-sha512" for pipeline, invalid length`,
	}, {
		name:     "invalid commit",
		mutated:  map[string]string{"${{inputs.expected-commit}}": "abcdef"},
		errorMsg: `expected commit "expected-commit" for pipeline contains invalid characters or invalid sha length`,
	}, {
		name:     "required digest that resolved to empty",
		inputs:   map[string]config.Input{"expected-sha256": {Required: true}},
		mutated:  map[string]string{"${{inputs.expected-sha256}}": ""},
		errorMsg: `required input "expected-sha256" for pipeline is missing`,
	}, {
		name:    "required non-digest input is left to validateWith",
		inputs:  map[string]config.Input{"other": {Required: true}},
		mutated: map[string]string{"${{inputs.other}}": ""},
	}} {
		t.Run(tt.name, func(t *testing.T) {
			in := inputs
			if tt.inputs != nil {
				in = tt.inputs
			}
			err := validateDigests(tt.mutated, in)
			if tt.errorMsg != "" {
				require.EqualError(t, err, tt.errorMsg)
				return
			}
			require.NoError(t, err)
		})
	}
}

// Digest inputs are validated after substitution, so a digest may be
// forwarded to a nested pipeline or come from vars or another input; the
// result must still be a well-formed digest. They used to be validated before
// substitution, so the literal "${{inputs...}}" failed the length check.
func Test_CompilePipelines_ForwardedDigest(t *testing.T) {
	ctx := slogtest.Context(t)
	sha256 := strings.Repeat("a", 64)
	commit := strings.Repeat("c", 40)

	// wrapper forwards its "digest" input to checker's "<name>" input, which
	// echoes it from a runs step.
	wrapper := func(name string) string {
		return `
inputs:
  digest: {}
pipeline:
  - uses: checker
    with:
      ` + name + `: ${{inputs.digest}}
`
	}
	checker := func(name, input string) string {
		return `
inputs:
  ` + name + `:
` + input + `
pipeline:
  - runs: |
      echo "digest=${{inputs.` + name + `}}"
`
	}

	for _, tt := range []struct {
		name      string
		pipelines map[string]string
		with      map[string]string // passed to the top-level step
		vars      map[string]string
		want      string // value expected in checker's runs step
		errorMsg  string
	}{{
		name: "sha256 forwarded through a nested pipeline",
		pipelines: map[string]string{
			"top":     wrapper("expected-sha256"),
			"checker": checker("expected-sha256", "    required: true"),
		},
		with: map[string]string{"digest": sha256},
		want: sha256,
	}, {
		name: "invalid forwarded sha256 is rejected",
		pipelines: map[string]string{
			"top":     wrapper("expected-sha256"),
			"checker": checker("expected-sha256", "    required: true"),
		},
		with:     map[string]string{"digest": "abcdef"},
		errorMsg: `checksum input "expected-sha256" for pipeline, invalid length`,
	}, {
		name: "commit forwarded through a nested pipeline",
		pipelines: map[string]string{
			"top":     wrapper("expected-commit"),
			"checker": checker("expected-commit", "    required: true"),
		},
		with: map[string]string{"digest": commit},
		want: commit,
	}, {
		name: "invalid forwarded commit is rejected",
		pipelines: map[string]string{
			"top":     wrapper("expected-commit"),
			"checker": checker("expected-commit", "    required: true"),
		},
		with:     map[string]string{"digest": "zz"},
		errorMsg: `expected commit "expected-commit" for pipeline contains invalid characters or invalid sha length`,
	}, {
		name: "sha256 from vars in a with value",
		pipelines: map[string]string{
			"top": checker("expected-sha256", "    required: true"),
		},
		with: map[string]string{"expected-sha256": "${{vars.sha}}"},
		vars: map[string]string{"sha": sha256},
		want: sha256,
	}, {
		name: "invalid sha256 from vars in a with value is rejected",
		pipelines: map[string]string{
			"top": checker("expected-sha256", "    required: true"),
		},
		with:     map[string]string{"expected-sha256": "${{vars.sha}}"},
		vars:     map[string]string{"sha": "abcdef"},
		errorMsg: `checksum input "expected-sha256" for pipeline, invalid length`,
	}, {
		name: "sha256 from vars in an input default",
		pipelines: map[string]string{
			"top": checker("expected-sha256", "    default: ${{vars.sha}}"),
		},
		vars: map[string]string{"sha": sha256},
		want: sha256,
	}, {
		name: "invalid sha256 from vars in an input default is rejected",
		pipelines: map[string]string{
			"top": checker("expected-sha256", "    default: ${{vars.sha}}"),
		},
		vars:     map[string]string{"sha": "abcdef"},
		errorMsg: `checksum input "expected-sha256" for pipeline, invalid length`,
	}, {
		name: "sha256 defaulting to a sibling input",
		pipelines: map[string]string{
			"top": `
inputs:
  other: {}
  expected-sha256:
    default: ${{inputs.other}}
pipeline:
  - runs: |
      echo "digest=${{inputs.expected-sha256}}"
`,
		},
		with: map[string]string{"other": sha256},
		want: sha256,
	}, {
		name: "invalid sha256 defaulting to a sibling input is rejected",
		pipelines: map[string]string{
			"top": `
inputs:
  other: {}
  expected-sha256:
    default: ${{inputs.other}}
pipeline:
  - runs: |
      echo "digest=${{inputs.expected-sha256}}"
`,
		},
		with:     map[string]string{"other": "abcdef"},
		errorMsg: `checksum input "expected-sha256" for pipeline, invalid length`,
	}, {
		name: "required sha256 forwarded from an unset input is rejected",
		pipelines: map[string]string{
			"top":     wrapper("expected-sha256"),
			"checker": checker("expected-sha256", "    required: true"),
		},
		errorMsg: `required input "expected-sha256" for pipeline is missing`,
	}, {
		name: "optional sha256 forwarded from an unset input is allowed",
		pipelines: map[string]string{
			"top":     wrapper("expected-sha256"),
			"checker": checker("expected-sha256", "    default: \"\""),
		},
		want: "",
	}} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range tt.pipelines {
				require.NoError(t, os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(body), 0o644))
			}
			cfg := config.Configuration{
				Package:  config.Package{Name: "foo", Version: "1.2.3"},
				Vars:     tt.vars,
				Pipeline: []config.Pipeline{{Uses: "top", With: tt.with}},
			}
			c := &Compiled{PipelineDirs: []string{dir}}
			sm, err := NewSubstitutionMap(&cfg, "", "", nil)
			require.NoError(t, err)

			err = c.CompilePipelines(ctx, sm, cfg.Pipeline)
			if tt.errorMsg != "" {
				require.ErrorContains(t, err, tt.errorMsg)
				return
			}
			require.NoError(t, err)

			// Descend to the runs step, which is the innermost pipeline.
			p := &cfg.Pipeline[0]
			for len(p.Pipeline) > 0 {
				p = &p.Pipeline[0]
			}
			require.Contains(t, p.Runs, `digest=`+tt.want+`"`)
			require.NotContains(t, p.Runs, "${{")
		})
	}
}
