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
		Configuration: &config.Configuration{
			Subpackages: []config.Subpackage{{}},
		},
	}

	if err := build.Compile(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInheritWorkdir(t *testing.T) {
	build := &Build{
		Configuration: &config.Configuration{
			Pipeline: []config.Pipeline{{
				WorkDir: "/work",
				Pipeline: []config.Pipeline{{}, {
					WorkDir: "/do-not-inherit",
					Runs:    "#!/bin/bash\n# hunter2\necho $SECRET",
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
	if got, want := build.Configuration.Pipeline[0].Pipeline[1].Runs, "#!/bin/bash\necho $SECRET\n"; want != got {
		t.Fatalf("runs[1]: should strip comments, want %q, got %q", want, got)
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

	if got, want := test.Configuration.Test.Environment.Contents.Packages, []string{"main", "main-base", "main-need"}; !slices.Equal(got, want) {
		t.Errorf("main test packages: want %v, got %v", want, got)
	}

	if got, want := test.Configuration.Subpackages[0].Test.Environment.Contents.Packages, []string{"subpackage", "subpackage-base", "subpackage-need"}; !slices.Equal(got, want) {
		t.Errorf("subpackage test packages: want %v, got %v", want, got)
	}
}

func TestCompileCapabilities(t *testing.T) {
	// Capabilities declared in the manifest and capabilities needed by a
	// pipeline should both end up on the runner as a deduplicated union, not
	// have one overwrite the other.
	needs := func() *config.Needs {
		return &config.Needs{
			Capabilities: config.Capabilities{
				// A new capability, plus a duplicate of a manifest one.
				Add:  []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN"},
				Drop: []string{"CAP_MKNOD"},
			},
		}
	}

	manifestCaps := func() config.Capabilities {
		return config.Capabilities{
			Add:  []string{"CAP_NET_ADMIN"},
			Drop: []string{"CAP_MKNOD"},
		}
	}

	wantUnionAdd := []string{"CAP_NET_ADMIN", "CAP_SYS_ADMIN"}
	wantUnionDrop := []string{"CAP_MKNOD"}

	// Under `melange test`, a test pipeline's capabilities are merged with the
	// manifest's as a deduplicated union.
	t.Run("test merges union", func(t *testing.T) {
		test := &Test{
			Package: "main",
			Configuration: config.Configuration{
				Capabilities: manifestCaps(),
				Test: &config.Test{
					Pipeline: []config.Pipeline{{Needs: needs()}},
				},
			},
		}

		if err := test.Compile(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := test.Configuration.Capabilities.Add; !slices.Equal(got, wantUnionAdd) {
			t.Errorf("add capabilities: want %v, got %v", wantUnionAdd, got)
		}
		if got := test.Configuration.Capabilities.Drop; !slices.Equal(got, wantUnionDrop) {
			t.Errorf("drop capabilities: want %v, got %v", wantUnionDrop, got)
		}
	})

	// A build pipeline's capabilities are merged into the build runner.
	t.Run("build pipeline merges union", func(t *testing.T) {
		build := &Build{
			Configuration: &config.Configuration{
				Capabilities: manifestCaps(),
				Pipeline:     []config.Pipeline{{Needs: needs()}},
			},
		}

		if err := build.Compile(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := build.Configuration.Capabilities.Add; !slices.Equal(got, wantUnionAdd) {
			t.Errorf("add capabilities: want %v, got %v", wantUnionAdd, got)
		}
		if got := build.Configuration.Capabilities.Drop; !slices.Equal(got, wantUnionDrop) {
			t.Errorf("drop capabilities: want %v, got %v", wantUnionDrop, got)
		}
	})

	// `melange build` never runs test pipelines, so capabilities they declare
	// must not leak into the build runner; only the manifest's remain.
	t.Run("build does not leak test caps", func(t *testing.T) {
		build := &Build{
			Configuration: &config.Configuration{
				Package:      config.Package{Name: "main"},
				Capabilities: manifestCaps(),
				Test: &config.Test{
					Pipeline: []config.Pipeline{{Needs: needs()}},
				},
			},
		}

		if err := build.Compile(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := build.Configuration.Capabilities.Add, []string{"CAP_NET_ADMIN"}; !slices.Equal(got, want) {
			t.Errorf("add capabilities leaked from test pipeline: want %v, got %v", want, got)
		}
		if got, want := build.Configuration.Capabilities.Drop, []string{"CAP_MKNOD"}; !slices.Equal(got, want) {
			t.Errorf("drop capabilities: want %v, got %v", want, got)
		}
	})
}

func Test_stripComments(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"# foo\n", ""},
		{"\n", ""},
		{"#!/bin/bash\n", "#!/bin/bash\n"},
		{"#!/bin/bash\n# foo\n", "#!/bin/bash\n"},
		{"#!/bin/bash\nfoo\n", "#!/bin/bash\nfoo\n"},
		{"#!/bin/bash\nfoo\n# bar\n", "#!/bin/bash\nfoo\n"},
		{"#!/bin/bash\nfoo\nbar\n", "#!/bin/bash\nfoo\nbar\n"},
		{"#!/bin/bash\nfoo\n# bar\nbaz\n", "#!/bin/bash\nfoo\nbaz\n"},
	}

	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			got, err := stripComments(test.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != test.want {
				t.Errorf("stripComments(%q): want %q, got %q", test.in, test.want, got)
			}
		})
	}

	wantErr := "1:13: not a valid test operator: `-m`:\n> if [[ uname -m == 'x86_64']]; then\n              ^"

	got, err := stripComments("if [[ uname -m == 'x86_64']]; then")
	if err == nil {
		t.Errorf("expected error, got %q", got)
	} else if err.Error() != wantErr {
		t.Errorf("want:\n%s\ngot:\n%s", wantErr, err)
	}
}
