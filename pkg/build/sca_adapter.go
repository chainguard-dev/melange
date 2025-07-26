// Copyright 2023 Chainguard, Inc.
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
	"chainguard.dev/apko/pkg/apk/apk"
	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/melange/pkg/config"
)

// packageBuildAdapter wraps PackageBuild to implement sca.PackageBuildAdapter
type packageBuildAdapter struct{ pb *PackageBuild }

func (a *packageBuildAdapter) GetPackageName() string               { return a.pb.PackageName }
func (a *packageBuildAdapter) GetOriginName() string                { return a.pb.Origin.Name }
func (a *packageBuildAdapter) GetOriginVersion() string             { return a.pb.Origin.Version }
func (a *packageBuildAdapter) GetOriginEpoch() uint64               { return a.pb.Origin.Epoch }
func (a *packageBuildAdapter) GetWorkspaceDirFS() apkofs.FullFS     { return a.pb.Build.WorkspaceDirFS }
func (a *packageBuildAdapter) GetPkgResolver() *apk.PkgResolver     { return a.pb.Build.PkgResolver }
func (a *packageBuildAdapter) GetOptions() *config.PackageOption    { return a.pb.Options }
func (a *packageBuildAdapter) GetDependencies() config.Dependencies { return a.pb.Dependencies }
func (a *packageBuildAdapter) GetConfiguration() *config.Configuration {
	return a.pb.Build.Configuration
}
