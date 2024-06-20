// Copyright 2024 Chainguard, Inc.
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
	"slices"
	"testing"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/config"
)

func TestCompileEmpty(t *testing.T) {
	test := &Test{
		Configuration: config.Configuration{
			Subpackages: []config.Subpackage{{}},
		},
	}

	if err := test.Compile(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	build := &Build{
		Configuration: config.Configuration{
			Subpackages: []config.Subpackage{{}},
		},
	}

	if err := build.Compile(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInheritWorkdir(t *testing.T) {
	build := &Build{
		Configuration: config.Configuration{
			Pipeline: []config.Pipeline{{
				WorkDir: "/work",
				Pipeline: []config.Pipeline{{}, {
					WorkDir: "/do-not-inherit",
				}},
			}},
		},
	}

	if err := build.Compile(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := build.Configuration.Pipeline[0].Pipeline[0].WorkDir, "/work"; want != got {
		t.Fatalf("workdir[0]: want %q, got %q", want, got)
	}
	if got, want := build.Configuration.Pipeline[0].Pipeline[1].WorkDir, "/do-not-inherit"; want != got {
		t.Fatalf("workdir[1]: want %q, got %q", want, got)
	}
}

func TestCompileTest(t *testing.T) {
	test := &Test{
		Package: "main",
		Configuration: config.Configuration{
			Test: &config.Test{
				Environment: apko_types.ImageConfiguration{
					Contents: apko_types.ImageContents{
						Packages: []string{"main-base"},
					},
				},
				Pipeline: []config.Pipeline{{
					Needs: &config.Needs{
						Packages: []string{"main-need"},
					},
				}},
			},
			Subpackages: []config.Subpackage{{
				Name: "subpackage",
				Test: &config.Test{
					Environment: apko_types.ImageConfiguration{
						Contents: apko_types.ImageContents{
							Packages: []string{"subpackage-base"},
						},
					},
					Pipeline: []config.Pipeline{{
						Needs: &config.Needs{
							Packages: []string{"subpackage-need"},
						},
					}},
				},
			}},
		},
	}

	if err := test.Compile(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := test.Configuration.Test.Environment.Contents.Packages, []string{"main-base", "main", "main-need"}; !slices.Equal(got, want) {
		t.Errorf("main test packages: want %v, got %v", want, got)
	}

	if got, want := test.Configuration.Subpackages[0].Test.Environment.Contents.Packages, []string{"subpackage-base", "subpackage", "subpackage-need"}; !slices.Equal(got, want) {
		t.Errorf("subpackage test packages: want %v, got %v", want, got)
	}
}
