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

	"github.com/chainguard-dev/clog"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

type GitCheckoutOptions struct {
	Repository     string
	Destination    string
	ExpectedCommit string
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

	return nil
}
