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

import "fmt"

func NewGenerator() (*Generator, error) {
	return &Generator{
		impl:    &defaultGeneratorImplementation{},
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
	Languages      []string
}

type Generator struct {
	Options Options
	impl    generatorImplementation
}

// GenerateSBOM runs the main SBOM generation process
func (g *Generator) GenerateSBOM(spec *Spec) error {
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
	if err := g.impl.WriteSBOM(spec, sbomDoc); err != nil {
		return fmt.Errorf("writing sbom to disk: %w", err)
	}

	return nil
}
