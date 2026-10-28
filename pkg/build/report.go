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
	"slices"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"

	"chainguard.dev/melange/pkg/report"
)

// recordGuestPackages records the packages of a freshly built guest into the
// report stage in ctx, if there is one.
func recordGuestPackages(ctx context.Context, bc *apko_build.Context, contents apko_types.ImageContents, extraRepos []string) {
	stage := report.StageFromContext(ctx)
	if stage == nil {
		return
	}

	installed, err := bc.InstalledPackages()
	if err != nil {
		clog.FromContext(ctx).Warnf("unable to list guest packages for the report: %v", err)
	}
	pkgs := make([]report.Package, 0, len(installed))
	for _, p := range installed {
		pkgs = append(pkgs, report.Package{Name: p.Name, Version: p.Version})
	}

	// The locked build config already includes the extra repos, so dedupe.
	repos := slices.Concat(contents.BuildRepositories, contents.Repositories, extraRepos)
	slices.Sort(repos)
	repos = slices.Compact(repos)
	stage.SetPackages(contents.Packages, pkgs, repos)
}
