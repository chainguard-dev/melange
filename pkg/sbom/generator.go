// Copyright 2022 Chainguard, Inc.
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

package sbom

import (
	"fmt"
	"log"
	"os"
)

func NewGenerator() (*Generator, error) {
	return &Generator{
		impl:    &defaultGeneratorImplementation{},
		logger:  log.New(log.Writer(), "melange-sbom: ", log.LstdFlags|log.Lmsgprefix),
		Options: defaultOptions,
	}, nil
}

var defaultOptions = Options{
	ScanLicenses: true,
	ScanFiles:    true,
}

type Options struct {
	ScanLicenses bool
	ScanFiles    bool
}

type Spec struct {
	Path           string
	PackageName    string
	PackageVersion string
	License        string // Full SPDX license expression
	Copyright      string
	Namespace      string
	Arch           string
	logger         *log.Logger
	GuestDir       string // Path to the apko build environment fs
	WorkspaceDir   string
	Subpackages    []string
	Languages      []string
}

type Generator struct {
	Options Options
	logger  *log.Logger
	impl    generatorImplementation
}

// GenerateBuildEnvSBOM creates the SBOM that describes the
// guest environment where melange ran its build
func (g *Generator) GenerateBuildEnvSBOM(spec *Spec) error {
	pkgs, err := g.impl.ReadPackageIndex(spec)
	if err != nil {
		return fmt.Errorf("while reading apk index: %w", err)
	}

	fmt.Fprintf(os.Stderr, "There are %d packages in the build SBOM", len(pkgs))

	pkg, err := g.impl.GenerateBuildPackage(spec, pkgs)
	if err != nil {
		return fmt.Errorf("generating build environment package: %w", err)
	}

	doc, err := g.impl.GenerateDocument(spec)
	if err != nil {
		return fmt.Errorf("generating bom document: %w", err)
	}

	doc.Packages = append(doc.Packages, pkg)

	for _, name := range append([]string{spec.PackageName}, spec.Subpackages...) {
		if err := g.impl.WriteSBOM(
			spec, doc, name, fmt.Sprintf("%s-build-%s.spdx.json", spec.PackageName, spec.PackageVersion),
		); err != nil {
			return fmt.Errorf("writing sbom to disk: %w", err)
		}
	}
	return nil
}

// GenerateSBOM runs the main SBOM generation process
func (g *Generator) GenerateSBOM(spec *Spec) error {
	spec.logger = g.logger
	shouldRun, err := g.impl.CheckEnvironment(spec)
	if err != nil {
		return fmt.Errorf("checking SBOM environment: %w", err)
	}

	if !shouldRun {
		// log "Not generating SBOM"
		return nil
	}

	sbomDoc, err := g.impl.GenerateDocument(spec)
	if err != nil {
		return fmt.Errorf("initializing new SBOM: %w", err)
	}

	pkg, err := g.impl.GenerateAPKPackage(spec)
	if err != nil {
		return fmt.Errorf("generating main package: %w", err)
	}

	// Add file inventory to packages
	if g.Options.ScanFiles {
		if err := g.impl.ScanFiles(spec, &pkg); err != nil {
			return fmt.Errorf("reading SBOM file inventory: %w", err)
		}
	}

	sbomDoc.Packages = append(sbomDoc.Packages, pkg)

	// Scan files for licensing data
	if g.Options.ScanLicenses {
		if err := g.impl.ScanLicenses(spec, sbomDoc); err != nil {
			return fmt.Errorf("reading SBOM file inventory: %w", err)
		}
	}

	// Generate dependency data from each language specified in the opts
	for _, lang := range spec.Languages {
		if err := g.impl.ReadDependencyData(spec, sbomDoc, lang); err != nil {
			return fmt.Errorf("reading %s dependecy data: %w", lang, err)
		}
	}

	// Finally, write the SBOM data to disk
	if err := g.impl.WriteSBOM(
		spec, sbomDoc, spec.PackageName,
		fmt.Sprintf("%s-%s.spdx.json", spec.PackageName, spec.PackageVersion),
	); err != nil {
		return fmt.Errorf("writing sbom to disk: %w", err)
	}

	return nil
}
