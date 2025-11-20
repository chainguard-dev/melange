// Copyright 2022 Chainguard, Inc.
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

// Package sbom defines build-time SBOM structures and utilities.
package sbom

import (
	"context"
	"time"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	apko_build "chainguard.dev/apko/pkg/build"
	purl "github.com/package-url/packageurl-go"

	"chainguard.dev/melange/pkg/config"
)

const (
	SBOMDir = "/var/lib/db/sbom"
)

// GeneratorContext contains all the information needed to generate SBOMs
// after the build completes.
type GeneratorContext struct {
	// The build configuration containing package and subpackage information
	Configuration *config.Configuration

	// The workspace directory path
	WorkspaceDir string

	// The filesystem pointing to the output destination directory where SBOMs should be written.
	// This filesystem is rooted at the base SBOM directory.
	OutputFS apkofs.FullFS

	// The timestamp to use for SBOM creation time
	SourceDateEpoch time.Time

	// The namespace for PackageURLs
	Namespace string

	// The target architecture
	Arch string

	// Information about the build configuration file
	ConfigFile *ConfigFile

	// OS release data from the build container
	ReleaseData *apko_build.ReleaseData
}

type ConfigFile struct {
	Path          string
	RepositoryURL string
	Commit        string
	License       string
	PURL          *purl.PackageURL
}

// Generator is an interface for generating SBOMs post-build.
// Implementations can customize SBOM generation logic and how SBOMs are written.
type Generator interface {
	// GenerateSBOM creates SBOMs for all packages and writes them to disk.
	// The generator has access to the full build context including workspace
	// filesystem for persisting SBOMs.
	GenerateSBOM(ctx context.Context, genCtx *GeneratorContext) error
}
