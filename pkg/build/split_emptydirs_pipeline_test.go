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

package build

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// These tests check that split/lib, split/dev and split/static leave no
// empty directories behind in the parent package. Before the fix, each
// removed at most the one directory a move emptied, so a package whose
// files all moved out shipped bare usr/lib and usr entries. They reuse the
// harness from split_manpages_pipeline_test.go.

// relDirs returns every directory under root, relative to it, excluding root.
func relDirs(t *testing.T, root string) []string {
	t.Helper()
	var got []string
	if err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() || p == root {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		got = append(got, rel)
		return nil
	}); err != nil {
		t.Fatalf("Walk(%s): %v", root, err)
	}
	return got
}

func TestSplitPipelinesRemoveEmptiedDirs(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	tests := []struct {
		name     string
		pipeline string
		tree     splitTree
		links    []splitLink
		wantSub  []string // files that must be in the subpackage
		wantPkg  []string // files that must stay in the parent package
		wantDirs []string // exact set of directories left in the parent
	}{
		{
			// The case this exists for: a library-only package whose
			// libraries all move to the lib subpackage.
			name:     "lib: package left empty keeps no directories",
			pipeline: "lib",
			tree:     splitTree{"usr/lib/libfoo.so.1.2.3": "lib"},
			links:    []splitLink{{from: "usr/lib/libfoo.so.1", to: "libfoo.so.1.2.3"}},
			wantSub:  []string{"usr/lib/libfoo.so.1.2.3", "usr/lib/libfoo.so.1"},
		},
		{
			name:     "lib: emptied usr/lib goes, usr with other files stays",
			pipeline: "lib",
			tree: splitTree{
				"usr/lib/libfoo.so.1": "lib",
				"usr/bin/foo":         "bin",
			},
			wantSub:  []string{"usr/lib/libfoo.so.1"},
			wantPkg:  []string{"usr/bin/foo"},
			wantDirs: []string{"usr", "usr/bin"},
		},
		{
			// Another split still needs usr/lib, so it must survive.
			name:     "lib: usr/lib with files left in it stays",
			pipeline: "lib",
			tree: splitTree{
				"usr/lib/libfoo.so.1": "lib",
				"usr/lib/libfoo.a":    "static",
			},
			wantSub:  []string{"usr/lib/libfoo.so.1"},
			wantPkg:  []string{"usr/lib/libfoo.a"},
			wantDirs: []string{"usr", "usr/lib"},
		},
		{
			// An empty directory the package ships on purpose is not one
			// the split emptied, so it stays.
			name:     "lib: unrelated empty directory is kept",
			pipeline: "lib",
			tree: splitTree{
				"usr/lib/libfoo.so.1": "lib",
				"var/lib/foo/":        "",
			},
			wantSub:  []string{"usr/lib/libfoo.so.1"},
			wantDirs: []string{"var", "var/lib", "var/lib/foo"},
		},
		{
			name:     "dev: package left empty keeps no directories",
			pipeline: "dev",
			tree: splitTree{
				"usr/include/foo/foo.h":     "h",
				"usr/lib/pkgconfig/foo.pc":  "pc",
				"usr/lib/cmake/foo/foo.cmk": "cmake",
			},
			links: []splitLink{{from: "usr/lib/libfoo.so", to: "libfoo.so.1"}},
			wantSub: []string{
				"usr/include/foo/foo.h",
				"usr/lib/pkgconfig/foo.pc",
				"usr/lib/cmake/foo/foo.cmk",
				"usr/lib/libfoo.so",
			},
		},
		{
			name:     "dev: runtime library and its directory stay",
			pipeline: "dev",
			tree: splitTree{
				"usr/include/foo.h":   "h",
				"usr/lib/libfoo.so.1": "lib",
			},
			links:    []splitLink{{from: "usr/lib/libfoo.so", to: "libfoo.so.1"}},
			wantSub:  []string{"usr/include/foo.h", "usr/lib/libfoo.so"},
			wantPkg:  []string{"usr/lib/libfoo.so.1"},
			wantDirs: []string{"usr", "usr/lib"},
		},
		{
			// `find . -name include` yields ./include, whose parent is the
			// package directory itself: it must not be removed, and GNU
			// rmdir must not be handed ".".
			name:     "dev: top-level include directory",
			pipeline: "dev",
			tree:     splitTree{"include/foo.h": "h", "usr/bin/foo": "bin"},
			wantSub:  []string{"include/foo.h"},
			wantPkg:  []string{"usr/bin/foo"},
			wantDirs: []string{"usr", "usr/bin"},
		},
		{
			name:     "static: package left empty keeps no directories",
			pipeline: "static",
			tree:     splitTree{"usr/lib/libfoo.a": "a", "usr/lib/foo/libbar.a": "a"},
			wantSub:  []string{"usr/lib/libfoo.a", "usr/lib/foo/libbar.a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			script, pkgDir, subDir := compileSplitPipeline(t, tt.pipeline, nil, tmp)
			writeSplitTree(t, pkgDir, tt.tree, tt.links)

			if out, err := runSplitPipeline(t, script, tmp); err != nil {
				t.Fatalf("split/%s failed: %v\n%s", tt.pipeline, err, out)
			}

			if fi, err := os.Stat(pkgDir); err != nil || !fi.IsDir() {
				t.Fatalf("package directory %s was removed: %v", pkgDir, err)
			}
			sub := relPaths(t, subDir)
			for _, want := range tt.wantSub {
				if !hasPath(sub, want) {
					t.Errorf("subpackage is missing %s; has %v", want, sub)
				}
			}
			pkg := relPaths(t, pkgDir)
			for _, want := range tt.wantPkg {
				if !hasPath(pkg, want) {
					t.Errorf("package is missing %s; has %v", want, pkg)
				}
			}
			dirs := relDirs(t, pkgDir)
			slices.Sort(dirs)
			want := slices.Clone(tt.wantDirs)
			slices.Sort(want)
			if !slices.Equal(dirs, want) {
				t.Errorf("package directories = %v, want %v", dirs, want)
			}
		})
	}
}
