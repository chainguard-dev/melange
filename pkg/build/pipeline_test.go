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
	"testing"

	"chainguard.dev/melange/pkg/logger"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/util"

	"github.com/stretchr/testify/require"
)

func Test_mutateStringFromMap(t *testing.T) {
	keys := map[string]string{
		"${{inputs.foo}}": "foo",
		"${{inputs.bar}}": "bar",
	}

	input1 := "${{inputs.foo}} ${{inputs.baz-bah-boom}}"
	output1, err := util.MutateStringFromMap(keys, input1)

	require.NoError(t, err)
	require.Equal(t, output1, "foo ", "bogus variable substitution not deleted")
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
		pkgctx, err := NewPackageContext(
			&config.Package{
				Name:    "foo",
				Version: tt.initialVersion,
			},
		)
		if err != nil {
			t.Fatalf("NewPackageContext() = %v", err)
		}

		t.Run("sub", func(t *testing.T) {
			pb := &PipelineBuild{
				Package: pkgctx,
				Build: &Build{
					Configuration: config.Configuration{
						VarTransforms: []config.VarTransforms{
							{
								From:    "${{package.version}}",
								Match:   tt.match,
								Replace: tt.replace,
								To:      "mangled-package-version",
							},
						},
					},
				},
			}
			m, err := substitutionMap(pb)
			require.NoError(t, err)
			require.Equal(t, tt.expected, m["${{vars.mangled-package-version}}"])
		})
	}
}

func Test_substitutionNeedPackages(t *testing.T) {
	pkgctx, err := NewPackageContext(
		&config.Package{
			Name:    "foo",
			Version: "1.2.3",
		},
	)
	require.NoError(t, err)

	p := &config.Pipeline{
		Needs: struct{ Packages []string }{Packages: []string{"foo", "${{inputs.go-package}}"}},
		Inputs: map[string]config.Input{
			"go-package": {
				Default: "go",
			},
		},
	}

	log := logger.NopLogger{}
	pctx, err := NewPipelineContext(p, log)
	require.NoError(t, err)

	pb := &PipelineBuild{
		Package: pkgctx,
		Build: &Build{
			PipelineDir: "pipelines",
			Configuration: config.Configuration{
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
			},
		},
	}

	err = pctx.loadUse(pb, "go/build", pb.Build.Configuration.Pipeline[0].With)
	require.NoError(t, err)
	require.Equal(t, "go-5.4.3", pb.Build.Configuration.Pipeline[0].With["go-package"])
}
