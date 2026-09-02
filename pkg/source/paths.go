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
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// secureJoin resolves a path from a pipeline input against the workspace root
// and returns the absolute location it names. Source steps operate on the
// workspace, so absolute paths and `../` traversal are rejected and the result
// is always inside root.
//
// Pipeline steps run in sequence against the same workspace, which means a
// relative path may name a symlink an earlier step created. Symlinks along the
// path are therefore resolved before the containment check, rather than
// comparing lexically.
//
// The named path need not exist; only the components that do exist are
// resolved. A symlink whose target cannot be resolved is an error, since there
// is nothing to compare against root.
func secureJoin(root, p, what string) (string, error) {
	if filepath.IsAbs(p) {
		return "", fmt.Errorf("absolute %s paths are not allowed: %q", what, p)
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolving workspace directory %q: %w", root, err)
	}
	// The workspace root itself may legitimately sit behind a symlink (macOS
	// puts /tmp behind /private/tmp), so resolve it before comparing.
	if resolved, err := filepath.EvalSymlinks(absRoot); err == nil {
		absRoot = resolved
	}

	joined := filepath.Join(absRoot, p)
	if !within(absRoot, joined) {
		return "", fmt.Errorf("%s path %q escapes the workspace directory", what, p)
	}

	resolved, err := evalExistingPrefix(joined)
	if err != nil {
		return "", fmt.Errorf("resolving %s path %q: %w", what, p, err)
	}
	if !within(absRoot, resolved) {
		return "", fmt.Errorf("%s path %q escapes the workspace directory via a symlink", what, p)
	}

	return resolved, nil
}

// within reports whether path is root itself or lies underneath it. Both
// arguments must already be absolute and lexically clean.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// evalExistingPrefix resolves symlinks over the longest prefix of p that
// exists, then re-appends the components that do not exist yet. A component
// that exists but cannot be resolved (a dangling symlink) is an error: its
// target is unknown, so there is nothing to check.
func evalExistingPrefix(p string) (string, error) {
	cur, rest := p, ""
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(resolved, rest), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		// EvalSymlinks reports ENOENT both for "does not exist" and for a
		// symlink whose target does not exist. Lstat tells the two apart.
		if _, lerr := os.Lstat(cur); lerr == nil {
			return "", fmt.Errorf("%q is a symlink that cannot be resolved", cur)
		}

		parent := filepath.Dir(cur)
		if parent == cur {
			return "", fmt.Errorf("%q could not be resolved", p)
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}
