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

// Package syft provides integration with Syft for scanning package contents
// to enrich SBOMs with detected components.
package syft

import (
	"context"
	"fmt"
	"strings"

	"chainguard.dev/melange/pkg/sbom"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/chainguard-dev/clog"
	purl "github.com/package-url/packageurl-go"
)

// Scanner wraps Syft functionality for scanning package contents
type Scanner struct {
	// Path to scan
	path string
}

// NewScanner creates a new Syft scanner for the given path
func NewScanner(path string) *Scanner {
	return &Scanner{
		path: path,
	}
}

// Scan performs a Syft scan on the configured path and returns detected packages
func (s *Scanner) Scan(ctx context.Context) ([]sbom.Package, error) {
	log := clog.FromContext(ctx)
	log.Infof("scanning package contents with Syft: %s", s.path)

	// Create a Syft source from the directory
	// In Melange, we're always scanning directories containing package contents
	src, err := directorysource.NewFromPath(s.path)
	if err != nil {
		return nil, fmt.Errorf("failed to create Syft source from path %s: %w", s.path, err)
	}
	defer func() {
		if err := src.Close(); err != nil {
			log.Warnf("failed to close Syft source: %v", err)
		}
	}()

	// Configure Syft to scan for all package types
	// For directory sources, we want to use directory-specific catalogers
	// that can find language-specific package manifests and installed software
	cfg := syft.DefaultCreateSBOMConfig().WithCatalogerSelection(
		pkgcataloging.NewSelectionRequest().WithDefaults(
			filecataloging.FileTag,
			pkgcataloging.ImageTag,
		).WithRemovals(
			"elf-package", // Don't consider ELF notes, which may report as being "apks"
			"sbom",        // If we find an SBOM (e.g., scanning whole APKs in golden_test), don't use it to catalog.
		)).WithParallelism(4)

	// Create SBOM with Syft
	syftSBOM, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create SBOM with Syft: %w", err)
	}

	// Convert Syft packages to Melange SBOM packages
	packageCount := syftSBOM.Artifacts.Packages.PackageCount()
	melangePackages := make([]sbom.Package, 0, packageCount)

	for _, syftPkg := range syftSBOM.Artifacts.Packages.Sorted() {
		// Skip APK packages to avoid duplication - the APK package itself
		// is already represented in the SBOM by Melange
		if syftPkg.Type == pkg.ApkPkg {
			log.Debugf("Skipping APK package %s to avoid duplication", syftPkg.Name)
			continue
		}

		melangePkg := convertSyftPackage(syftPkg)
		melangePackages = append(melangePackages, melangePkg)
	}

	log.Infof("Syft scan found %d packages", len(melangePackages))
	return melangePackages, nil
}

// convertSyftPackage converts a Syft package to a Melange SBOM package
func convertSyftPackage(syftPkg pkg.Package) sbom.Package {
	// Build the package name with type prefix for clarity
	name := syftPkg.Name
	if syftPkg.Type != "" {
		name = fmt.Sprintf("%s:%s", syftPkg.Type, syftPkg.Name)
	}

	// Convert Syft checksums to our format
	checksums := make(map[string]string)
	// Syft packages don't typically have checksums at this level

	// Build Package URL if available
	var packageURL *purl.PackageURL
	if syftPkg.PURL != "" {
		parsedPURL, err := purl.FromString(syftPkg.PURL)
		if err == nil {
			packageURL = &parsedPURL
		}
		// If parsing fails, we'll just skip the PURL
	}
	// Don't try to construct PURLs ourselves - rely on Syft's detection

	// Extract license information
	var licenseDeclared, licenseConcluded string
	syftLicenses := syftPkg.Licenses.ToSlice()
	if len(syftLicenses) > 0 {
		declaredLicenses := make([]string, 0)
		concludedLicenses := make([]string, 0)

		for _, l := range syftLicenses {
			if l.Value != "" {
				switch l.Type {
				case license.Declared:
					declaredLicenses = append(declaredLicenses, l.Value)
				case license.Concluded:
					concludedLicenses = append(concludedLicenses, l.Value)
				default:
					// If type is not specified, treat as declared for backward compatibility
					declaredLicenses = append(declaredLicenses, l.Value)
				}
			}
		}

		if len(declaredLicenses) > 0 {
			licenseDeclared = strings.Join(declaredLicenses, " AND ")
		}
		if len(concludedLicenses) > 0 {
			licenseConcluded = strings.Join(concludedLicenses, " AND ")
		}
	}

	return sbom.Package{
		Name:             name,
		Version:          syftPkg.Version,
		LicenseDeclared:  licenseDeclared,
		LicenseConcluded: licenseConcluded,
		Checksums:        checksums,
		PURL:             packageURL,
		// Add type info as a component to ensure uniqueness
		IDComponents: []string{string(syftPkg.Type), syftPkg.Name, syftPkg.Version},
	}
}
