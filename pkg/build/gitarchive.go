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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/chainguard-dev/clog"
)

// gitArchiveOptions configures gitArchive.
type gitArchiveOptions struct {
	// RepositoryDir is any path inside the local git repository to archive
	// from; git discovers the enclosing repository root from it.
	RepositoryDir string
	// Ref is the git ref (tag, branch, or commit) to archive.
	Ref string
	// Path is the path within the repository (relative to the repository root)
	// to extract.
	Path string
	// ExpectedCommit, if set, is the commit Ref must resolve to. A mismatch is
	// a fatal error.
	ExpectedCommit string
	// Destination is the directory into which the archived subtree is
	// extracted. Extracted files retain their Path prefix beneath it.
	Destination string
}

// gitArchive populates Destination from a subtree of a local git repository at
// a specific ref, host-side, without cloning over the network and without
// touching the repository's working tree. It resolves the ref to a commit,
// optionally verifies it against ExpectedCommit, then streams `git archive` of
// Path into Destination. It returns the resolved commit.
//
// Path prefixes are preserved: archiving "charts/foo" extracts to
// Destination/charts/foo/..., matching the layout of the source repository.
//
// Because this uses `git archive`, the repository's .gitattributes are honored:
// paths marked `export-ignore` are omitted and `export-subst` placeholders are
// expanded. The output is therefore the committed tree as filtered by those
// export rules, not necessarily a byte-for-byte copy. Requires `git` and `tar`
// on the host.
func gitArchive(ctx context.Context, opts *gitArchiveOptions) (resolvedCommit string, err error) {
	log := clog.FromContext(ctx)

	if opts.Ref == "" {
		return "", fmt.Errorf("ref is required")
	}
	if opts.Path == "" {
		return "", fmt.Errorf("path is required")
	}
	if opts.Destination == "" {
		return "", fmt.Errorf("destination is required")
	}

	repoDir := opts.RepositoryDir
	if repoDir == "" {
		repoDir = "."
	}

	// Anchor at the repository toplevel. git archive interprets its pathspec
	// relative to the current directory prefix, so running from a subdirectory
	// would mis-resolve Path; from the toplevel, Path is repository-root
	// relative and unambiguous.
	topOut, err := exec.CommandContext(ctx, "git", "-C", repoDir, "rev-parse", "--show-toplevel").Output() // #nosec G204 - git arguments come from trusted melange build configuration
	if err != nil {
		return "", fmt.Errorf("locating git repository from %s: %w", repoDir, err)
	}
	topLevel := strings.TrimSpace(string(topOut))

	// Resolve the ref to a concrete commit so the archive (and the
	// expected-commit check) operate on an immutable target.
	resolved, err := gitRevParse(ctx, topLevel, opts.Ref+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("resolving ref %q in %s: %w", opts.Ref, topLevel, err)
	}

	if opts.ExpectedCommit != "" && resolved != opts.ExpectedCommit {
		return "", fmt.Errorf("ref %q resolved to commit %s, expected %s", opts.Ref, resolved, opts.ExpectedCommit)
	}
	if opts.ExpectedCommit == "" {
		// Only reached when the caller passed a tag/branch with no
		// expected-commit (genuinely unpinned). The default-ref path in
		// maybeGitArchiveSource backfills ExpectedCommit with the build commit,
		// so it does not trigger this warning.
		log.Warnf("git archive: no expected-commit; ref %q resolved to %s", opts.Ref, resolved)
	}

	if err := os.MkdirAll(opts.Destination, 0o755); err != nil {
		return "", fmt.Errorf("creating destination %s: %w", opts.Destination, err)
	}

	log.Infof("archiving %s at %s from %s into %s", opts.Path, resolved, topLevel, opts.Destination)

	// `git archive <commit> <path> | tar -x -C dest`. We pipe a tar stream so
	// extraction is direct and independent of tar's format autodetection.
	archive := exec.CommandContext(ctx, "git", "-C", topLevel, "archive", "--format=tar", resolved, opts.Path) // #nosec G204 - git arguments come from trusted melange build configuration
	extract := exec.CommandContext(ctx, "tar", "-x", "-C", opts.Destination)                                   // #nosec G204 - destination is a melange-created temp dir

	pipe, err := archive.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("creating archive pipe: %w", err)
	}
	archive.Stderr = os.Stderr
	extract.Stdin = pipe
	extract.Stdout = os.Stdout
	extract.Stderr = os.Stderr

	if err := extract.Start(); err != nil {
		return "", fmt.Errorf("starting tar: %w", err)
	}

	// Always wait on both commands so the tar child is reaped even when git
	// archive fails, and join their errors so a failure in either is surfaced.
	// Reporting only one would mask the real cause: if tar dies first, git
	// archive sees EPIPE; if git archive dies first, tar sees EOF.
	archiveErr := archive.Run()
	extractErr := extract.Wait()
	if archiveErr != nil || extractErr != nil {
		return "", fmt.Errorf("git archive %s %s: %w", resolved, opts.Path,
			errors.Join(archiveErr, extractErr))
	}

	return resolved, nil
}

// gitRevParse resolves rev to a commit hash in the repository containing dir.
func gitRevParse(ctx context.Context, dir, rev string) (string, error) {
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--verify", rev).Output() // #nosec G204 - git arguments come from trusted melange build configuration
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
