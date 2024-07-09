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

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/util"
	"gopkg.in/yaml.v3"

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
	}{{version: "1.2.3",
		epoch: 0,
		want:  "1.2.3-r0",
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

func Test_substitutionNeedPackages(t *testing.T) {
	ctx := slogtest.TestContextWithLogger(t)
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
	expected := []string{"/bin/sh", "-c", `set -ex
[ -d '/bar' ] || mkdir -p '/bar'
cd '/bar'
baz
exit 0`}
	require.Equal(t, command, expected)
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
