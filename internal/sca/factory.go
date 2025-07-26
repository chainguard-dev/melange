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

package sca

import (
	"fmt"
	"path/filepath"
	"strings"

	"chainguard.dev/apko/pkg/apk/apk"
	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/melange/pkg/config"
)

// PackageBuildAdapter is an interface that package builds must implement to work with SCA
type PackageBuildAdapter interface {
	GetPackageName() string
	GetOriginName() string
	GetOriginVersion() string
	GetOriginEpoch() uint64
	GetConfiguration() *config.Configuration
	GetWorkspaceDirFS() apkofs.FullFS
	GetPkgResolver() *apk.PkgResolver
	GetOptions() *config.PackageOption
	GetDependencies() config.Dependencies
}

// buildInterface provides an implementation of SCAHandle which maps to
// a package build object.
type buildInterface struct {
	packageBuild PackageBuildAdapter
}

// NewBuildInterface creates a new SCAHandle for a package build
func NewBuildInterface(pb PackageBuildAdapter) SCAHandle {
	return &buildInterface{
		packageBuild: pb,
	}
}

// PackageName returns the currently built package name.
func (bi *buildInterface) PackageName() string {
	return bi.packageBuild.GetPackageName()
}

// RelativeNames returns all the package names relating to the package being
// built.
func (bi *buildInterface) RelativeNames() []string {
	targets := []string{bi.packageBuild.GetOriginName()}

	for _, target := range bi.packageBuild.GetConfiguration().Subpackages {
		targets = append(targets, target.Name)
	}

	return targets
}

// Version returns the version of the package being built including epoch.
func (bi *buildInterface) Version() string {
	return fmt.Sprintf("%s-r%d", bi.packageBuild.GetOriginVersion(), bi.packageBuild.GetOriginEpoch())
}

// FilesystemForRelative implements an abstract filesystem for any of the packages being
// built.
func (bi *buildInterface) FilesystemForRelative(pkgName string) (SCAFS, error) {
	rlFS, err := apkofs.Sub(bi.packageBuild.GetWorkspaceDirFS(), filepath.Join("melange-out", pkgName))
	if err != nil {
		return nil, fmt.Errorf("package build subFS: %w", err)
	}
	scaFS, ok := rlFS.(SCAFS)
	if !ok {
		return nil, fmt.Errorf("SCAFS not implemented")
	}

	return scaFS, nil
}

// Filesystem implements an abstract filesystem providing access to a package filesystem.
func (bi *buildInterface) Filesystem() (SCAFS, error) {
	return bi.FilesystemForRelative(bi.PackageName())
}

// Options returns the configured SCA engine options for the package being built.
func (bi *buildInterface) Options() config.PackageOption {
	if bi.packageBuild.GetOptions() == nil {
		return config.PackageOption{}
	}
	return *bi.packageBuild.GetOptions()
}

// BaseDependencies returns the base dependencies for the package being built.
func (bi *buildInterface) BaseDependencies() config.Dependencies {
	return bi.packageBuild.GetDependencies()
}

// InstalledPackages returns a map [package name] => [package version]
// of the packages installed during build.
func (bi *buildInterface) InstalledPackages() map[string]string {
	pkgVersionMap := make(map[string]string)

	for _, fullpkg := range bi.packageBuild.GetConfiguration().Environment.Contents.Packages {
		pkg, version, _ := strings.Cut(fullpkg, "=")
		pkgVersionMap[pkg] = version
	}

	// We also include the packages being built.  They have the
	// special version string "@CURRENT@" to make it easier for
	// the SCA to identify them.
	for _, pkg := range bi.RelativeNames() {
		pkgVersionMap[pkg] = "@CURRENT@"
	}

	return pkgVersionMap
}

// PkgResolver returns the package resolver for the package/build being analyzed.
func (bi *buildInterface) PkgResolver() *apk.PkgResolver {
	return bi.packageBuild.GetPkgResolver()
}
