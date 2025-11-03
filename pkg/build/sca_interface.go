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
	"fmt"
	"path/filepath"
	"strings"

	"chainguard.dev/apko/pkg/apk/apk"
	apkofs "chainguard.dev/apko/pkg/apk/fs"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/sca"
)

// SCABuildInterface provides an implementation of SCAHandle which maps to
// a package build object.
type SCABuildInterface struct {
	// PackageBuild represents the underlying package build object.
	PackageBuild *PackageBuild
}

// PackageName returns the currently built package name.
func (scabi *SCABuildInterface) PackageName() string {
	return scabi.PackageBuild.PackageName
}

// RelativeNames returns all the package names relating to the package being
// built.
func (scabi *SCABuildInterface) RelativeNames() []string {
	targets := []string{scabi.PackageBuild.Origin.Name}

	for _, target := range scabi.PackageBuild.Build.Configuration.Subpackages {
		targets = append(targets, target.Name)
	}

	return targets
}

// Version returns the version of the package being built including epoch.
func (scabi *SCABuildInterface) Version() string {
	return fmt.Sprintf("%s-r%d", scabi.PackageBuild.Origin.Version, scabi.PackageBuild.Origin.Epoch)
}

// FilesystemForRelative implements an abstract filesystem for any of the packages being
// built.
func (scabi *SCABuildInterface) FilesystemForRelative(pkgName string) (sca.SCAFS, error) {
	rlFS, err := apkofs.Sub(scabi.PackageBuild.Build.WorkspaceDirFS, filepath.Join(melangeOutputDirName, pkgName))
	if err != nil {
		return nil, fmt.Errorf("package build subFS: %w", err)
	}
	scaFS, ok := rlFS.(sca.SCAFS)
	if !ok {
		return nil, fmt.Errorf("SCAFS not implemented")
	}

	return scaFS, nil
}

// Filesystem implements an abstract filesystem providing access to a package filesystem.
func (scabi *SCABuildInterface) Filesystem() (sca.SCAFS, error) {
	return scabi.FilesystemForRelative(scabi.PackageName())
}

// Options returns the configured SCA engine options for the package being built.
func (scabi *SCABuildInterface) Options() config.PackageOption {
	if scabi.PackageBuild.Options == nil {
		return config.PackageOption{}
	}
	return *scabi.PackageBuild.Options
}

// BaseDependencies returns the base dependencies for the package being built.
func (scabi *SCABuildInterface) BaseDependencies() config.Dependencies {
	return scabi.PackageBuild.Dependencies
}

// InstalledPackages returns a map [package name] => [package version]
// of the packages installed during build.
func (scabi *SCABuildInterface) InstalledPackages() map[string]string {
	pkgVersionMap := make(map[string]string)

	for _, fullpkg := range scabi.PackageBuild.Build.Configuration.Environment.Contents.Packages {
		pkg, version, _ := strings.Cut(fullpkg, "=")
		pkgVersionMap[pkg] = version
	}

	// We also include the packages being built.  They have the
	// special version string "@CURRENT@" to make it easier for
	// the SCA to identify them.
	for _, pkg := range scabi.RelativeNames() {
		pkgVersionMap[pkg] = "@CURRENT@"
	}

	return pkgVersionMap
}

// PkgResolver returns the package resolver for the package/build being analyzed.
func (scabi *SCABuildInterface) PkgResolver() *apk.PkgResolver {
	return scabi.PackageBuild.Build.PkgResolver
}
