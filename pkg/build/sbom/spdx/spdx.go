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

// Package spdx implements an SPDX SBOM generator for Melange builds.
package spdx

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"chainguard.dev/apko/pkg/sbom/generator/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"

	build "chainguard.dev/melange/pkg/build/sbom"
	"chainguard.dev/melange/pkg/sbom"
)

// An SBOMGroup stores SBOMs corresponding to each package (or subpackage)
// within a build group. Its purpose is to let the build process easily manage
// SBOMs for the 1-N number of packages it ends up emitting.
type SBOMGroup struct {
	set map[string]*sbom.Document
}

// NewSBOMGroup creates a new SBOMGroup, initializing SBOMs for each package and
// subpackage name provided.
func NewSBOMGroup(pkgNames ...string) *SBOMGroup {
	sg := &SBOMGroup{
		set: make(map[string]*sbom.Document),
	}

	for _, n := range pkgNames {
		doc := sbom.NewDocument()
		sg.set[n] = doc
	}

	return sg
}

// SetCreatedTime sets the creation time for all SBOMs in the group.
func (sg *SBOMGroup) SetCreatedTime(t time.Time) {
	for _, doc := range sg.set {
		doc.CreatedTime = t
	}
}

// SetLicensingInfos sets the licensing information for all SBOMs in the group.
func (sg *SBOMGroup) SetLicensingInfos(li map[string]string) {
	for _, doc := range sg.set {
		doc.LicensingInfos = li
	}
}

// Document retrieves the SBOM for the given package or subpackage name.
func (sg *SBOMGroup) Document(name string) *sbom.Document {
	return sg.set[name]
}

// AddBuildConfigurationPackage adds a package serving as the "build
// configuration package" to all SBOMs in the group.
func (sg *SBOMGroup) AddBuildConfigurationPackage(p *sbom.Package) {
	for _, doc := range sg.set {
		doc.AddPackage(p)
		doc.AddRelationship(doc.Describes, p, common.TypeRelationshipDescribeBy)
	}
}

// AddUpstreamSourcePackage adds a package serving as an "upstream source
// package" to all SBOMs in the group.
func (sg *SBOMGroup) AddUpstreamSourcePackage(p *sbom.Package) {
	for _, doc := range sg.set {
		doc.AddPackage(p)
		doc.AddRelationship(doc.Describes, p, common.TypeRelationshipGeneratedFrom)
	}
}

// Generator is the standard implementation of Generator.
// It creates a basic SBOMGroup with one SBOM document per package and populates
// it with all the standard SBOM information.
type Generator struct{}

// GenerateSPDX creates an SPDX SBOM document containing all packages based on the build context.
// It returns a map of package names to their corresponding SPDX documents.
func (g *Generator) GenerateSPDX(ctx context.Context, gc *build.GeneratorContext) (map[string]spdx.Document, error) {
	// Collect all package names
	pkgNames := []string{gc.Configuration.Package.Name}
	for _, sp := range gc.Configuration.Subpackages {
		pkgNames = append(pkgNames, sp.Name)
	}

	// Create the SBOM group
	sg := NewSBOMGroup(pkgNames...)
	sg.SetCreatedTime(gc.SourceDateEpoch)

	pkg := &gc.Configuration.Package
	arch := gc.Arch

	// Add APK packages to their respective SBOMs
	for _, sp := range gc.Configuration.Subpackages {
		spSBOM := sg.Document(sp.Name)

		apkSubPkg := &sbom.Package{
			Name:            sp.Name,
			Version:         pkg.FullVersion(),
			Copyright:       pkg.FullCopyright(),
			LicenseDeclared: pkg.LicenseExpression(),
			Namespace:       gc.Namespace,
			Arch:            arch,
			PURL:            pkg.PackageURLForSubpackage(gc.Namespace, arch, sp.Name),
		}
		spSBOM.AddPackageAndSetDescribed(apkSubPkg)

		// Add upstream source packages from subpackage pipelines
		for i, p := range sp.Pipeline {
			uniqueID := strconv.Itoa(i)
			upstreamPkg, err := p.SBOMPackageForUpstreamSource(pkg.LicenseExpression(), gc.Namespace, uniqueID)
			if err != nil {
				return nil, fmt.Errorf("creating SBOM package for upstream source in subpackage %s: %w", sp.Name, err)
			}

			if upstreamPkg == nil {
				// This particular pipeline step doesn't tell us about the upstream source code.
				continue
			}

			spSBOM.AddUpstreamSourcePackage(upstreamPkg)
		}
	}

	pSBOM := sg.Document(pkg.Name)
	apkPkg := &sbom.Package{
		Name:            pkg.Name,
		Version:         pkg.FullVersion(),
		Copyright:       pkg.FullCopyright(),
		LicenseDeclared: pkg.LicenseExpression(),
		Namespace:       gc.Namespace,
		Arch:            arch,
		PURL:            pkg.PackageURL(gc.Namespace, arch),
	}
	pSBOM.AddPackageAndSetDescribed(apkPkg)

	// Add build configuration package
	if gc.ConfigFile != nil {
		sg.AddBuildConfigurationPackage(&sbom.Package{
			Name:            gc.ConfigFile.Path,
			Version:         gc.ConfigFile.Commit,
			LicenseDeclared: gc.ConfigFile.License,
			Namespace:       gc.Namespace,
			Arch:            "", // This field doesn't make sense in this context
			PURL:            gc.ConfigFile.PURL,
		})
	}

	// Add upstream source packages from main package pipelines to main package SBOM
	// and to all subpackage SBOMs (since subpackages are derived from the main source)
	for i, p := range gc.Configuration.Pipeline {
		uniqueID := strconv.Itoa(i)
		upstreamPkg, err := p.SBOMPackageForUpstreamSource(gc.Configuration.Package.LicenseExpression(), gc.Namespace, uniqueID)
		if err != nil {
			return nil, fmt.Errorf("creating SBOM package for upstream source: %w", err)
		}

		if upstreamPkg == nil {
			// This particular pipeline step doesn't tell us about the upstream source code.
			continue
		}

		// Add to main package SBOM
		pSBOM.AddUpstreamSourcePackage(upstreamPkg)

		// Add to all subpackage SBOMs as well
		for _, sp := range gc.Configuration.Subpackages {
			sg.Document(sp.Name).AddUpstreamSourcePackage(upstreamPkg)
		}
	}

	// Add licensing information
	li, err := gc.Configuration.Package.LicensingInfos(gc.WorkspaceDir)
	if err != nil {
		return nil, fmt.Errorf("gathering licensing infos: %w", err)
	}
	sg.SetLicensingInfos(li)

	out := make(map[string]spdx.Document)

	// Convert the SBOMs to SPDX and write them
	for _, sp := range gc.Configuration.Subpackages {
		out[sp.Name] = sg.Document(sp.Name).ToSPDX(ctx, gc.ReleaseData)
	}

	out[pkg.Name] = pSBOM.ToSPDX(ctx, gc.ReleaseData)
	return out, nil
}

// GenerateSBOM generates and writes SPDX SBOM documents for the main package and
// all subpackages based on the build context.
func (g *Generator) GenerateSBOM(ctx context.Context, gc *build.GeneratorContext) error {
	sboms, err := g.GenerateSPDX(ctx, gc)
	if err != nil {
		return fmt.Errorf("generating SPDX SBOMs: %w", err)
	}

	for name, sbom := range sboms {
		if err := writeSBOM(gc, name, &sbom); err != nil {
			return fmt.Errorf("writing SBOM for %s: %w", name, err)
		}
	}

	return nil
}

// writeSPDXSBOM writes an SBOM document to the SBOM filesystem.
func writeSBOM(gc *build.GeneratorContext, pkgName string, doc *spdx.Document) error {
	// Create the SBOM directory for this package: {pkgName}/var/lib/db/sbom
	sbomDirPath := filepath.Join(pkgName, build.SBOMDir)
	if err := gc.OutputFS.MkdirAll(sbomDirPath, os.FileMode(0o755)); err != nil {
		return fmt.Errorf("creating SBOM directory: %w", err)
	}

	// Write the SBOM file: {pkgName}/var/lib/db/sbom/{pkgName}-{version}.spdx.json
	pkgVersion := gc.Configuration.Package.FullVersion()
	sbomPath := filepath.Join(sbomDirPath, fmt.Sprintf("%s-%s.spdx.json", pkgName, pkgVersion))
	f, err := gc.OutputFS.OpenFile(sbomPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("creating SBOM file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")

	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding SPDX SBOM: %w", err)
	}

	return nil
}
