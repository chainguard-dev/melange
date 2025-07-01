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
	defer src.Close()

	// Configure Syft to scan for all package types with default settings
	cfg := syft.DefaultCreateSBOMConfig().
		WithParallelism(4)

	// Create SBOM with Syft
	syftSBOM, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create SBOM with Syft: %w", err)
	}

	// Convert Syft packages to Melange SBOM packages
	melangePackages := make([]sbom.Package, 0, len(syftSBOM.Artifacts.Packages.Sorted()))
	
	for _, syftPkg := range syftSBOM.Artifacts.Packages.Sorted() {
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
	} else {
		// Try to construct a PURL based on package type
		packageURL = constructPURL(syftPkg)
	}

	// Extract license information
	var licenseDeclared string
	syftLicenses := syftPkg.Licenses.ToSlice()
	if len(syftLicenses) > 0 {
		licenses := make([]string, 0, len(syftLicenses))
		for _, l := range syftLicenses {
			if l.Value != "" {
				licenses = append(licenses, l.Value)
			}
		}
		if len(licenses) > 0 {
			licenseDeclared = strings.Join(licenses, " AND ")
		}
	}

	return sbom.Package{
		Name:            name,
		Version:         syftPkg.Version,
		LicenseDeclared: licenseDeclared,
		Checksums:       checksums,
		PURL:            packageURL,
		// Add type info as a component to ensure uniqueness
		IDComponents: []string{string(syftPkg.Type), syftPkg.Name, syftPkg.Version},
	}
}

// constructPURL attempts to construct a Package URL for packages that don't have one
func constructPURL(p pkg.Package) *purl.PackageURL {
	var purlType string
	var namespace string
	
	switch p.Type {
	case pkg.GoModulePkg:
		purlType = purl.TypeGolang
		// For Go modules, the name is usually the full import path
		if strings.Contains(p.Name, "/") {
			parts := strings.SplitN(p.Name, "/", 2)
			if len(parts) == 2 {
				namespace = parts[0]
				name := parts[1]
				return &purl.PackageURL{
					Type:      purlType,
					Namespace: namespace,
					Name:      name,
					Version:   p.Version,
				}
			}
		}
	case pkg.PythonPkg:
		purlType = purl.TypePyPi
	case pkg.NpmPkg:
		purlType = purl.TypeNPM
	case pkg.GemPkg:
		purlType = purl.TypeGem
	case pkg.JavaPkg:
		purlType = purl.TypeMaven
	default:
		// For unknown types, return nil
		return nil
	}

	if purlType != "" {
		return &purl.PackageURL{
			Type:      purlType,
			Namespace: namespace,
			Name:      p.Name,
			Version:   p.Version,
		}
	}
	
	return nil
}