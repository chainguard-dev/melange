// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package container

import (
	apko_build "chainguard.dev/apko/pkg/build"
	"chainguard.dev/melange/pkg/build"
	"fmt"
	"os"
)

type AKOGuest struct {
	Guest
}

// Build builds the base system inside the runner.
// For apko, it will install the requested environment from the
// configuration.
func (receiver *AKOGuest) Build(ctx *build.Context) error {
	// Prepare workspace directory
	if err := os.MkdirAll(ctx.WorkspaceDir, 0755); err != nil {
		return fmt.Errorf("mkdir -p %s: %w", ctx.WorkspaceDir, err)
	}

	// Prepare guest directory
	if err := os.MkdirAll(ctx.GuestDir, 0755); err != nil {
		return fmt.Errorf("mkdir -p %s: %w", ctx.GuestDir, err)
	}

	ctx.Logger.Printf("building workspace in '%s' with apko", ctx.GuestDir)

	bc, err := apko_build.New(ctx.GuestDir,
		apko_build.WithImageConfiguration(ctx.Configuration.Environment),
		apko_build.WithProot(ctx.UseProot),
		apko_build.WithArch(ctx.Arch),
		apko_build.WithExtraKeys(ctx.ExtraKeys),
		apko_build.WithExtraRepos(ctx.ExtraRepos),
		apko_build.WithDebugLogging(true),
		apko_build.WithLocal(true),
	)
	if err != nil {
		return fmt.Errorf("unable to create build context: %w", err)
	}

	if err := bc.Refresh(); err != nil {
		return fmt.Errorf("unable to refresh build context: %w", err)
	}

	bc.Summarize()

	if !ctx.Runner.NeedsImage() {
		if err := bc.BuildImage(); err != nil {
			return fmt.Errorf("unable to generate image: %w", err)
		}
	} else {
		if err := ctx.BuildAndPushLocalImage(bc); err != nil {
			return fmt.Errorf("unable to generate image: %w", err)
		}
	}

	ctx.Logger.Printf("successfully built workspace with apko")
	return nil
}

// ApkoGuest returns an apko Guest implementation.
func ApkoGuest() Guest {
	return &AKOGuest{}
}
