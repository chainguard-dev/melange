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
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"chainguard.dev/melange/pkg/config"
)

// These tests compile the real pipelines/split/manpages.yaml and run the
// resulting script, so they cover the substitution as well as the shell. That
// matters: `paths` is spliced into the script as text, so a newline in it is a
// syntax error rather than a bad value, and no amount of shell-level
// validation can catch that.
//
// The failure cases are here rather than in e2e-tests/ because that harness
// has no expected-failure convention -- every yaml in it must build cleanly.
// Half of what this pipeline now does is fail loudly, which cannot be
// expressed there.

// splitTree is a package layout to build under a temp dir: a map of relative
// path to contents. A path ending in "/" is an empty directory.
type splitTree map[string]string

// symlink and hardlink requests, applied after the regular files.
type splitLink struct {
	from, to string // from -> to, both relative to the package dir
	hard     bool
}

func writeSplitTree(t *testing.T, root string, tree splitTree, links []splitLink) {
	t.Helper()
	for p, contents := range tree {
		full := filepath.Join(root, p)
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatalf("MkdirAll(%s): %v", full, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll(%s): %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(contents), 0o644); err != nil {
			t.Fatalf("WriteFile(%s): %v", full, err)
		}
	}
	for _, l := range links {
		from := filepath.Join(root, l.from)
		if err := os.MkdirAll(filepath.Dir(from), 0o755); err != nil {
			t.Fatalf("MkdirAll(%s): %v", filepath.Dir(from), err)
		}
		var err error
		if l.hard {
			err = os.Link(filepath.Join(root, l.to), from)
		} else {
			err = os.Symlink(l.to, from)
		}
		if err != nil {
			t.Fatalf("link %s -> %s: %v", l.from, l.to, err)
		}
	}
}

// compileSplitPipeline compiles pipelines/split/<name>.yaml with the given
// inputs, pointing targets.* at directories under tmp, and returns the script
// together with the package and subpackage directories.
func compileSplitPipeline(t *testing.T, name string, with map[string]string, tmp string) (script, pkgDir, ctxDir string) {
	t.Helper()

	outDir := filepath.Join(tmp, "melange-out")
	pkgDir = filepath.Join(outDir, "foo")
	ctxDir = filepath.Join(outDir, "foo-doc")
	for _, d := range []string{pkgDir, ctxDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("MkdirAll(%s): %v", d, err)
		}
	}
	// The subpackage directory is created by melange before the pipeline
	// runs, but an empty one must not look like an existing destination.
	if err := os.Remove(ctxDir); err != nil {
		t.Fatalf("Remove(%s): %v", ctxDir, err)
	}

	pipeline := config.Pipeline{
		Uses: "split/" + name,
		With: with,
	}
	sm := &SubstitutionMap{
		Substitutions: map[string]string{
			config.SubstitutionTargetsOutdir:     outDir,
			config.SubstitutionTargetsDestdir:    pkgDir,
			config.SubstitutionTargetsContextdir: ctxDir,
		},
	}

	c := &Compiled{}
	if err := c.compilePipeline(context.Background(), sm, &pipeline, nil); err != nil {
		t.Fatalf("compilePipeline: %v", err)
	}

	if len(pipeline.Pipeline) > 0 {
		script = pipeline.Pipeline[0].Runs
	} else {
		script = pipeline.Runs
	}
	if script == "" {
		t.Fatal("compiled pipeline has no script")
	}
	return script, pkgDir, ctxDir
}

// runSplitPipeline runs the script the way melange does, under `set -e`, from
// a working directory that is not the package directory -- which is what makes
// a glob in `paths` expand against the wrong tree.
func runSplitPipeline(t *testing.T, script, cwd string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", "-c", "set -e\n"+script)
	cmd.Dir = cwd
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func relPaths(t *testing.T, root string) []string {
	t.Helper()
	var got []string
	if err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.Mode().IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		got = append(got, rel)
		return nil
	}); err != nil && !os.IsNotExist(err) {
		t.Fatalf("Walk(%s): %v", root, err)
	}
	return got
}

func hasPath(paths []string, want string) bool {
	return slices.Contains(paths, want)
}

// TestSplitManpagesSucceeds covers the cases that must produce a subpackage.
func TestSplitManpagesSucceeds(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	tests := []struct {
		name     string
		with     map[string]string
		tree     splitTree
		links    []splitLink
		wantDoc  []string // must be present in the subpackage
		wantPkg  []string // must still be in the parent package
		absentIn []string // must not exist in the subpackage
	}{
		{
			// The case the whole change exists for: `mv src/man1 dst/`
			// fails with "Directory not empty" once dst/man1 is there, so
			// a package shipping pages in two roots could not be split.
			name: "two roots both with man1 are merged",
			tree: splitTree{
				"usr/share/man/man1/a.1":       "A",
				"usr/local/share/man/man1/b.1": "B",
			},
			wantDoc: []string{"usr/share/man/man1/a.1", "usr/share/man/man1/b.1"},
		},
		{
			name: "locale subtrees two levels down are merged",
			tree: splitTree{
				"usr/share/man/fr/man1/a.1":       "A",
				"usr/local/share/man/fr/man1/b.1": "B",
			},
			wantDoc: []string{"usr/share/man/fr/man1/a.1", "usr/share/man/fr/man1/b.1"},
		},
		{
			name: "hidden files are moved too",
			tree: splitTree{
				"usr/share/man/man1/a.1":         "A",
				"usr/local/share/man/man1/.keep": "H",
			},
			wantDoc: []string{"usr/share/man/man1/a.1", "usr/share/man/man1/.keep"},
		},
		{
			// A compat symlink whose target was taken by an earlier root is
			// dangling by the time the loop reaches it. -d is false, so it
			// is skipped -- not treated as the symlinked-root error.
			name: "dangling compat symlink root is skipped",
			tree: splitTree{"usr/share/man/man1/a.1": "A"},
			links: []splitLink{
				{from: "usr/man", to: "../share/man"},
			},
			wantDoc: []string{"usr/share/man/man1/a.1"},
		},
		{
			name: "alias pages survive a merge that does not collide",
			tree: splitTree{
				"usr/share/man/man1/b.1":       "BTARGET",
				"usr/local/share/man/man1/c.1": "OTHER",
			},
			links: []splitLink{
				{from: "usr/share/man/man1/a.1", to: "b.1"},
			},
			wantDoc: []string{
				"usr/share/man/man1/a.1",
				"usr/share/man/man1/b.1",
				"usr/share/man/man1/c.1",
			},
		},
		{
			name: "paths entry is relocated by default",
			with: map[string]string{"paths": "opt/example/share/man"},
			tree: splitTree{"opt/example/share/man/man1/o.1": "O"},
			wantDoc: []string{
				"usr/share/man/man1/o.1",
			},
			absentIn: []string{"opt/example/share/man/man1/o.1"},
		},
		{
			// A YAML block scalar produces a trailing newline, and the value
			// is spliced into the script as text. Before the fix this was
			// `syntax error: unexpected ";" (expecting "do")`.
			name: "newline-separated paths are both split",
			with: map[string]string{
				"paths": "usr/lib/llvm-99/share/man\nopt/example/share/man\n",
			},
			tree: splitTree{
				"usr/lib/llvm-99/share/man/man1/v.1": "V",
				"opt/example/share/man/man5/o.5":     "O",
			},
			wantDoc: []string{"usr/share/man/man1/v.1", "usr/share/man/man5/o.5"},
		},
		{
			// preserve-path applies only to `paths`. The standard roots
			// always relocate: usr/man is outside man(1)'s search path and
			// pages under usr/local trip the usrlocal linter.
			name: "preserve-path keeps paths entries and still relocates standard roots",
			with: map[string]string{
				"paths":         "usr/lib/llvm-99/share/man",
				"preserve-path": "true",
			},
			tree: splitTree{
				"usr/lib/llvm-99/share/man/man1/v.1": "V",
				"usr/local/share/man/man1/l.1":       "L",
				"usr/man/man8/u.8":                   "U",
			},
			wantDoc: []string{
				"usr/lib/llvm-99/share/man/man1/v.1",
				"usr/share/man/man1/l.1",
				"usr/share/man/man8/u.8",
			},
			absentIn: []string{"usr/local/share/man/man1/l.1", "usr/man/man8/u.8"},
		},
		{
			name: "non-man files are left in the parent package",
			tree: splitTree{
				"usr/share/man/man1/a.1": "A",
				"usr/bin/foo":            "ELF",
			},
			wantDoc: []string{"usr/share/man/man1/a.1"},
			wantPkg: []string{"usr/bin/foo"},
		},
		{
			name:    "a package with no manuals is a no-op",
			tree:    splitTree{"usr/bin/foo": "ELF"},
			wantPkg: []string{"usr/bin/foo"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			script, pkgDir, ctxDir := compileSplitPipeline(t, "manpages", tt.with, tmp)
			writeSplitTree(t, pkgDir, tt.tree, tt.links)

			// A directory that is neither the package nor the subpackage,
			// standing in for melange's /home/build source tree.
			cwd := filepath.Join(tmp, "src")
			if err := os.MkdirAll(cwd, 0o755); err != nil {
				t.Fatal(err)
			}

			out, err := runSplitPipeline(t, script, cwd)
			if err != nil {
				t.Fatalf("script failed: %v\nOutput: %s", err, out)
			}

			doc := relPaths(t, ctxDir)
			for _, want := range tt.wantDoc {
				if !hasPath(doc, want) {
					t.Errorf("subpackage is missing %q; has %v", want, doc)
				}
			}
			for _, absent := range tt.absentIn {
				if hasPath(doc, absent) {
					t.Errorf("subpackage should not contain %q; has %v", absent, doc)
				}
			}
			pkg := relPaths(t, pkgDir)
			for _, want := range tt.wantPkg {
				if !hasPath(pkg, want) {
					t.Errorf("parent package is missing %q; has %v", want, pkg)
				}
			}
			// Nothing the subpackage took may remain in the parent.
			for _, got := range tt.wantDoc {
				base := filepath.Base(got)
				for _, left := range pkg {
					if filepath.Base(left) == base && !hasPath(tt.wantPkg, left) {
						t.Errorf("%q was copied, not moved: still in parent at %q", base, left)
					}
				}
			}
		})
	}
}

// TestSplitManpagesFailsLoudly covers the cases that must stop the build.
// Each one was silent before: the change that made two man roots mergeable
// also made five kinds of broken input succeed with exit 0.
func TestSplitManpagesFailsLoudly(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	tests := []struct {
		name     string
		with     map[string]string
		tree     splitTree
		links    []splitLink
		wantMsg  string
		wantKept []string // must still be in the parent package afterwards
	}{
		{
			// Directories merge, files collide. Without this the second
			// root's page silently replaced the first one's.
			name: "the same page in two roots",
			tree: splitTree{
				"usr/share/man/man1/foo.1":       "A",
				"usr/local/share/man/man1/foo.1": "B",
			},
			wantMsg: "is present in more than one man root",
		},
		{
			// Reproduces the hard-linked alias corruption: a copy-based
			// merge writes through the destination inode, so moving a.1 in
			// also rewrote alias.1.
			name: "a colliding page that is a hard-linked alias",
			tree: splitTree{
				"usr/share/man/man1/a.1":       "ORIGINAL",
				"usr/local/share/man/man1/a.1": "REPLACED",
			},
			links: []splitLink{
				{from: "usr/share/man/man1/alias.1", to: "usr/share/man/man1/a.1", hard: true},
			},
			wantMsg: "is present in more than one man root",
		},
		{
			// And the symlinked-alias version: a copy through dest/a.1 -> b.1
			// replaced b.1's contents.
			name: "a colliding page that is a symlinked alias",
			tree: splitTree{
				"usr/share/man/man1/b.1":       "BTARGET",
				"usr/local/share/man/man1/a.1": "NEWA",
			},
			links: []splitLink{
				{from: "usr/share/man/man1/a.1", to: "b.1"},
			},
			wantMsg: "is present in more than one man root",
		},
		{
			// `mv "$root"/*` failed on the unmatched glob, which is how a
			// broken install step got noticed. melange will otherwise emit
			// an apk of directory entries with no files in it.
			name:    "a man root that exists but is empty",
			tree:    splitTree{"usr/man/": ""},
			wantMsg: "contains no files",
		},
		{
			// -d follows the link, so the pages would be taken out of the
			// target while the cleanup removed only the link: the originals
			// stay in the parent and ship again in the subpackage.
			name: "a man root that is a symlink to a directory",
			tree: splitTree{"opt/real/man/man1/a.1": "A"},
			links: []splitLink{
				{from: "usr/man", to: "../opt/real/man"},
			},
			wantMsg:  "is a symlink to a directory",
			wantKept: []string{"opt/real/man/man1/a.1"},
		},
		{
			// $PACKAGE_DIR/../<name> is a sibling package's output directory,
			// and this pipeline ends in rm/rmdir. Before the fix this copied
			// the sibling into the subpackage and then deleted it, exit 0.
			name:    "a paths entry containing ..",
			with:    map[string]string{"paths": "../bar"},
			tree:    splitTree{"usr/share/man/man1/a.1": "A"},
			wantMsg: `must not contain ".."`,
		},
		{
			name:    "an absolute paths entry",
			with:    map[string]string{"paths": "/etc"},
			tree:    splitTree{"usr/share/man/man1/a.1": "A"},
			wantMsg: "must be relative to the package root",
		},
		{
			// A glob expands against the build directory, not the package
			// root, so it matched nothing and the versioned root was left
			// unsplit with exit 0.
			name:    "a glob in a paths entry",
			with:    map[string]string{"paths": "usr/lib/llvm-*/share/man"},
			tree:    splitTree{"usr/lib/llvm-99/share/man/man1/v.1": "V"},
			wantMsg: "must not contain a glob pattern",
		},
		{
			// Absent is `continue` for the standard roots, but a typo in an
			// explicitly named one produced an empty -doc subpackage.
			name:    "a paths entry that does not exist",
			with:    map[string]string{"paths": "usr/lib/lvm-99/share/man"},
			tree:    splitTree{"usr/lib/llvm-99/share/man/man1/v.1": "V"},
			wantMsg: "does not exist in the package",
		},
		{
			name:    "a preserve-path value that is not true or false",
			with:    map[string]string{"preserve-path": "yes"},
			tree:    splitTree{"usr/share/man/man1/a.1": "A"},
			wantMsg: `preserve-path must be "true" or "false"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			script, pkgDir, _ := compileSplitPipeline(t, "manpages", tt.with, tmp)
			writeSplitTree(t, pkgDir, tt.tree, tt.links)

			// A sibling package directory, for the traversal case to reach.
			sibling := filepath.Join(tmp, "melange-out", "bar", "secret")
			if err := os.MkdirAll(sibling, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(sibling, "keep.txt"), []byte("keep"), 0o644); err != nil {
				t.Fatal(err)
			}

			cwd := filepath.Join(tmp, "src")
			if err := os.MkdirAll(cwd, 0o755); err != nil {
				t.Fatal(err)
			}

			out, err := runSplitPipeline(t, script, cwd)
			if err == nil {
				t.Fatalf("script succeeded but should have failed\nOutput: %s", out)
			}
			if !strings.Contains(out, tt.wantMsg) {
				t.Errorf("error message %q not found in output:\n%s", tt.wantMsg, out)
			}

			// A failed split must not have taken the sibling with it.
			if _, err := os.Stat(filepath.Join(sibling, "keep.txt")); err != nil {
				t.Errorf("sibling package output was destroyed: %v", err)
			}

			pkg := relPaths(t, pkgDir)
			for _, want := range tt.wantKept {
				if !hasPath(pkg, want) {
					t.Errorf("parent package lost %q; has %v", want, pkg)
				}
			}
		})
	}
}

// TestSplitAllDocsMergesRoots covers the same two-root merge in split/alldocs,
// which carried an identical `mv "$root"/*` loop for man pages and another for
// usr/share/doc.
func TestSplitAllDocsMergesRoots(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	tests := []struct {
		name    string
		tree    splitTree
		wantDoc []string
		wantMsg string
	}{
		{
			name: "two man roots both with man1 are merged",
			tree: splitTree{
				"usr/share/man/man1/a.1":       "A",
				"usr/local/share/man/man1/b.1": "B",
			},
			wantDoc: []string{"usr/share/man/man1/a.1", "usr/share/man/man1/b.1"},
		},
		{
			name: "two doc roots sharing a package directory are merged",
			tree: splitTree{
				"usr/share/doc/foo/README":        "R",
				"usr/local/share/doc/foo/CHANGES": "C",
			},
			wantDoc: []string{"usr/share/doc/foo/README", "usr/share/doc/foo/CHANGES"},
		},
		{
			name: "info pages are still split",
			tree: splitTree{
				"usr/share/info/foo.info": "I",
				"usr/share/info/dir":      "index",
			},
			wantDoc: []string{"usr/share/info/foo.info"},
		},
		{
			name: "the same doc file in two roots fails",
			tree: splitTree{
				"usr/share/doc/foo/README":       "A",
				"usr/local/share/doc/foo/README": "B",
			},
			wantMsg: "is present in more than one root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			script, pkgDir, ctxDir := compileSplitPipeline(t, "alldocs", nil, tmp)
			writeSplitTree(t, pkgDir, tt.tree, nil)

			cwd := filepath.Join(tmp, "src")
			if err := os.MkdirAll(cwd, 0o755); err != nil {
				t.Fatal(err)
			}

			out, err := runSplitPipeline(t, script, cwd)
			if tt.wantMsg != "" {
				if err == nil {
					t.Fatalf("script succeeded but should have failed\nOutput: %s", out)
				}
				if !strings.Contains(out, tt.wantMsg) {
					t.Errorf("error message %q not found in output:\n%s", tt.wantMsg, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("script failed: %v\nOutput: %s", err, out)
			}
			doc := relPaths(t, ctxDir)
			for _, want := range tt.wantDoc {
				if !hasPath(doc, want) {
					t.Errorf("subpackage is missing %q; has %v", want, doc)
				}
			}
			// `dir` is the generated info index and must not ship.
			if hasPath(doc, "usr/share/info/dir") {
				t.Errorf("the generated info index was shipped; has %v", doc)
			}
		})
	}
}
