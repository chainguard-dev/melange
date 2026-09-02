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

package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecureJoin(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	if err := os.MkdirAll(filepath.Join(root, "sub", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Symlinks of the kind an earlier pipeline step could have created in the
	// workspace: one leaving the root, one unresolvable, one staying inside.
	if err := os.Symlink(outside, filepath.Join(root, "outward-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "does-not-exist"), filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "sub"), filepath.Join(root, "inside-link")); err != nil {
		t.Fatal(err)
	}

	// realRoot is what secureJoin returns paths relative to, since it resolves
	// the root itself (t.TempDir() sits behind /private on macOS).
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}

	allowed := map[string]string{
		"":                     realRoot,
		".":                    realRoot,
		"sub":                  filepath.Join(realRoot, "sub"),
		"sub/nested":           filepath.Join(realRoot, "sub", "nested"),
		"sub/../sub":           filepath.Join(realRoot, "sub"),
		"does/not/exist/yet":   filepath.Join(realRoot, "does", "not", "exist", "yet"),
		"inside-link":          filepath.Join(realRoot, "sub"),
		"inside-link/nested":   filepath.Join(realRoot, "sub", "nested"),
		"./sub/./nested/../..": realRoot,
	}
	for in, want := range allowed {
		t.Run("allow/"+in, func(t *testing.T) {
			got, err := secureJoin(root, in, "test")
			if err != nil {
				t.Fatalf("secureJoin(%q) = error %v, want %q", in, err, want)
			}
			if got != want {
				t.Errorf("secureJoin(%q) = %q, want %q", in, got, want)
			}
		})
	}

	rejected := []string{
		outside,                             // absolute
		"/etc",                              // absolute
		"..",                                // traversal
		"../..",                             // traversal
		"sub/../../elsewhere",               // traversal after cleaning
		"outward-link",                      // symlink leaving the root
		"outward-link/file",                 // path under a symlink leaving the root
		"inside-link/../outward-link",       // traversal onto a symlink leaving the root
		"dangling",                          // symlink with an unresolvable target
		filepath.Join(outside, "no-such-x"), // absolute, nonexistent
	}
	for _, in := range rejected {
		t.Run("reject/"+in, func(t *testing.T) {
			got, err := secureJoin(root, in, "test")
			if err == nil {
				t.Fatalf("secureJoin(%q) = %q, want an error", in, got)
			}
			if !strings.Contains(err.Error(), "test") {
				t.Errorf("error %q does not name the input kind", err)
			}
		})
	}
}
