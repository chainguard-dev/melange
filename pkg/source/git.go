// Copyright 2025 Chainguard, Inc.
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
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

type GitCheckoutOptions struct {
	Repository     string
	Destination    string
	ExpectedCommit string
	CherryPicks    string
	Patches        string
	WorkspaceDir   string // Directory where patch files are located (usually config dir)
}

func GitCheckout(ctx context.Context, opts *GitCheckoutOptions) error {
	log := clog.FromContext(ctx)

	if opts.Repository == "" {
		return fmt.Errorf("repository is required")
	}

	if opts.Destination == "" {
		return fmt.Errorf("destination is required")
	}

	log.Infof("Cloning %s to %s", opts.Repository, opts.Destination)

	cloneOpts := &git.CloneOptions{
		URL:      opts.Repository,
		Progress: os.Stdout,
	}

	repo, err := git.PlainClone(opts.Destination, false, cloneOpts)
	if err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}

	if opts.ExpectedCommit != "" {
		log.Infof("Checking out commit %s", opts.ExpectedCommit)

		wt, err := repo.Worktree()
		if err != nil {
			return fmt.Errorf("failed to get worktree: %w", err)
		}

		err = wt.Checkout(&git.CheckoutOptions{
			Hash: plumbing.NewHash(opts.ExpectedCommit),
		})
		if err != nil {
			return fmt.Errorf("failed to checkout commit %s: %w", opts.ExpectedCommit, err)
		}
	}

	// Show what we checked out
	head, err := repo.Head()
	if err != nil {
		return fmt.Errorf("failed to get HEAD: %w", err)
	}

	log.Infof("Checked out commit %s", head.Hash().String())

	// Apply cherry-picks if specified
	if opts.CherryPicks != "" {
		log.Infof("Applying cherry-picks")
		picks, err := parseCherryPicks(opts.CherryPicks)
		if err != nil {
			return fmt.Errorf("failed to parse cherry-picks: %w", err)
		}

		if err := applyCherryPicks(ctx, opts.Destination, picks); err != nil {
			return fmt.Errorf("failed to apply cherry-picks: %w", err)
		}
	}

	// Apply patches if specified
	if opts.Patches != "" {
		log.Infof("Applying patches")
		patches := parsePatchList(opts.Patches)

		if err := applyPatches(ctx, opts.Destination, opts.WorkspaceDir, patches); err != nil {
			return fmt.Errorf("failed to apply patches: %w", err)
		}
	}

	return nil
}

func parseCherryPicks(input string) ([]string, error) {
	commits := make([]string, 0)

	for line := range strings.SplitSeq(input, "\n") {
		// Trim whitespace
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse format: [branch/]commit: comment
		// We only care about the commit hash
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid cherry-pick format (expected '[branch/]commit: comment'): %s", line)
		}

		pickSpec := strings.TrimSpace(parts[0])

		// Strip optional branch prefix (we don't need it with full clone)
		commit := path.Base(pickSpec)

		commits = append(commits, commit)
	}

	return commits, nil
}

func applyCherryPicks(ctx context.Context, repoPath string, commits []string) error {
	log := clog.FromContext(ctx)

	for _, commit := range commits {
		log.Infof("Cherry-picking %s", commit)

		cmd := exec.CommandContext(ctx, "git", "cherry-pick", "-x", commit)
		cmd.Dir = repoPath
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to cherry-pick %s: %w", commit, err)
		}
	}

	return nil
}

func parsePatchList(input string) []string {
	// Parse whitespace-delimited patch list
	return strings.Fields(input)
}

func applyPatches(ctx context.Context, repoPath string, workspaceDir string, patches []string) error {
	log := clog.FromContext(ctx)

	for _, patch := range patches {
		// Resolve patch path relative to workspace directory
		patchPath := patch
		if workspaceDir != "" && !strings.HasPrefix(patch, "/") {
			patchPath = fmt.Sprintf("%s/%s", workspaceDir, patch)
		}

		log.Infof("Applying patch %s", patchPath)

		// Try git am first (preserves commit metadata if present)
		amCmd := exec.CommandContext(ctx, "git", "am", patchPath)
		amCmd.Dir = repoPath
		amCmd.Stdout = os.Stdout
		amCmd.Stderr = os.Stderr

		if err := amCmd.Run(); err != nil {
			// git am failed, abort to clean up
			log.Infof("git am failed, aborting to clean up")
			abortCmd := exec.CommandContext(ctx, "git", "am", "--abort")
			abortCmd.Dir = repoPath
			_ = abortCmd.Run() // Ignore error, may not be in am session

			// Try git apply --check to see if patch is valid
			log.Infof("Checking if patch can be applied with git apply")
			checkCmd := exec.CommandContext(ctx, "git", "apply", "--check", patchPath)
			checkCmd.Dir = repoPath
			checkCmd.Stderr = os.Stderr

			if err := checkCmd.Run(); err != nil {
				return fmt.Errorf("patch %s cannot be applied: %w", patchPath, err)
			}

			// Apply the patch
			applyCmd := exec.CommandContext(ctx, "git", "apply", patchPath)
			applyCmd.Dir = repoPath
			applyCmd.Stdout = os.Stdout
			applyCmd.Stderr = os.Stderr
			if err := applyCmd.Run(); err != nil {
				return fmt.Errorf("failed to apply patch %s: %w", patchPath, err)
			}

			// Stage all changes
			addCmd := exec.CommandContext(ctx, "git", "add", "-A")
			addCmd.Dir = repoPath
			if err := addCmd.Run(); err != nil {
				return fmt.Errorf("failed to stage changes for patch %s: %w", patchPath, err)
			}

			// Commit with patch filename
			commitMsg := fmt.Sprintf("Apply patch: %s", patch)
			commitCmd := exec.CommandContext(ctx, "git", "commit", "-m", commitMsg)
			commitCmd.Dir = repoPath
			commitCmd.Stdout = os.Stdout
			commitCmd.Stderr = os.Stderr
			if err := commitCmd.Run(); err != nil {
				return fmt.Errorf("failed to commit patch %s: %w", patchPath, err)
			}

			log.Infof("Applied patch %s using git apply + commit", patchPath)
		}
	}

	return nil
}
