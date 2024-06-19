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
	"testing"

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
