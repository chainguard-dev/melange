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
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	needs := func(adds ...string) *config.Needs {
		return &config.Needs{Capabilities: config.NeedsCapabilities{Add: adds}}
	}

	manifestCaps := func() config.Capabilities {
		return config.Capabilities{Add: []string{"CAP_NET_ADMIN"}}
	}

	// A test pipeline's capabilities are gathered onto the test they belong to,
	// not onto the shared top-level capabilities, so they stay scoped to that
	// test's runner and do not widen the build or sibling tests.
	t.Run("test caps are scoped to the test", func(t *testing.T) {
		test := &Test{
			Package: "main",
			Configuration: config.Configuration{
				Capabilities: manifestCaps(),
				Test: &config.Test{
					Pipeline: []config.Pipeline{{Needs: needs("CAP_SYS_ADMIN")}},
				},
			},
		}

		if err := test.Compile(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := test.Configuration.Test.Capabilities.Add, []string{"CAP_SYS_ADMIN"}; !slices.Equal(got, want) {
			t.Errorf("test capabilities: want %v, got %v", want, got)
		}
		// The shared top-level set keeps only the manifest's caps.
		if got, want := test.Configuration.Capabilities.Add, []string{"CAP_NET_ADMIN"}; !slices.Equal(got, want) {
			t.Errorf("top-level capabilities changed: want %v, got %v", want, got)
		}
	})

	// One subpackage test using a capability must not grant it to sibling
	// subpackage tests or the main test.
	t.Run("subpackage caps do not leak to siblings", func(t *testing.T) {
		test := &Test{
			Package: "main",
			Configuration: config.Configuration{
				Test: &config.Test{Pipeline: []config.Pipeline{{Runs: "true"}}},
				Subpackages: []config.Subpackage{
					{Name: "sub-a", Test: &config.Test{Pipeline: []config.Pipeline{{Needs: needs("CAP_SYS_ADMIN")}}}},
					{Name: "sub-b", Test: &config.Test{Pipeline: []config.Pipeline{{Runs: "true"}}}},
				},
			},
		}

		if err := test.Compile(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := test.Configuration.Subpackages[0].Test.Capabilities.Add, []string{"CAP_SYS_ADMIN"}; !slices.Equal(got, want) {
			t.Errorf("sub-a capabilities: want %v, got %v", want, got)
		}
		if got := test.Configuration.Subpackages[1].Test.Capabilities.Add; len(got) != 0 {
			t.Errorf("sub-b capabilities should be empty, got %v", got)
		}
		if got := test.Configuration.Test.Capabilities.Add; len(got) != 0 {
			t.Errorf("main test capabilities should be empty, got %v", got)
		}
	})

	// A build pipeline's capabilities apply to the build runner, deduplicated
	// against the manifest's.
	t.Run("build pipeline caps apply to build runner", func(t *testing.T) {
		build := &Build{
			Configuration: &config.Configuration{
				Capabilities: manifestCaps(),
				// Duplicate CAP_NET_ADMIN to exercise dedup.
				Pipeline: []config.Pipeline{{Needs: needs("CAP_SYS_ADMIN", "CAP_NET_ADMIN")}},
			},
		}

		if err := build.Compile(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := build.Configuration.Capabilities.Add, []string{"CAP_NET_ADMIN", "CAP_SYS_ADMIN"}; !slices.Equal(got, want) {
			t.Errorf("build capabilities: want %v, got %v", want, got)
		}
	})

	// `melange build` never runs test pipelines, so caps they declare must not
	// reach the build runner.
	t.Run("build does not apply test caps", func(t *testing.T) {
		build := &Build{
			Configuration: &config.Configuration{
				Package:      config.Package{Name: "main"},
				Capabilities: manifestCaps(),
				Test: &config.Test{
					Pipeline: []config.Pipeline{{Needs: needs("CAP_SYS_ADMIN")}},
				},
			},
		}

		if err := build.Compile(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := build.Configuration.Capabilities.Add, []string{"CAP_NET_ADMIN"}; !slices.Equal(got, want) {
			t.Errorf("test caps leaked into build runner: want %v, got %v", want, got)
		}
	})

	// Capabilities declared via needs: in a pipeline loaded through uses: are
	// gathered the same way, exercising the yaml round-trip and the
	// pipeline.Needs = nil handling in gatherDeps.
	t.Run("uses pipeline round-trip", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "cap.yaml"), []byte(
			"needs:\n  capabilities:\n    add:\n      - CAP_SYS_ADMIN\npipeline:\n  - runs: \"true\"\n",
		), 0o644); err != nil {
			t.Fatal(err)
		}

		test := &Test{
			Package:      "main",
			PipelineDirs: []string{dir},
			Configuration: config.Configuration{
				Test: &config.Test{Pipeline: []config.Pipeline{{Uses: "cap"}}},
			},
		}

		if err := test.Compile(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got, want := test.Configuration.Test.Capabilities.Add, []string{"CAP_SYS_ADMIN"}; !slices.Equal(got, want) {
			t.Errorf("uses capabilities: want %v, got %v", want, got)
		}
	})

	// A misspelled capability is rejected while compiling, rather than by the
	// runner once the container is created.
	t.Run("unknown capability fails compile", func(t *testing.T) {
		build := &Build{
			Configuration: &config.Configuration{
				Pipeline: []config.Pipeline{{Needs: needs("CAP_SYS_ADMN")}},
			},
		}

		err := build.Compile(context.Background())
		if err == nil {
			t.Fatal("expected an error for an unknown capability, got none")
		}
		if !strings.Contains(err.Error(), "CAP_SYS_ADMN") {
			t.Errorf("error should name the offending capability, got: %v", err)
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
