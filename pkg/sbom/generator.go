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
	"context"
	"fmt"
	"time"

	"github.com/chainguard-dev/clog"
	purl "github.com/package-url/packageurl-go"
	"go.opentelemetry.io/otel"
)

func NewGenerator() *Generator {
	return &Generator{}
}

type Spec struct {
	Path            string
	PackageName     string
	PackageVersion  string
	License         string // Full SPDX license expression
	LicensingInfos  map[string]string
	ExternalRefs    []purl.PackageURL
	Copyright       string
	Namespace       string
	Arch            string
	SourceDateEpoch time.Time
}

type Generator struct{}

// GenerateSBOM runs the main SBOM generation process
func (g *Generator) GenerateSBOM(ctx context.Context, spec *Spec) error {
	_, span := otel.Tracer("melange").Start(ctx, "GenerateSBOM")
	defer span.End()
	log := clog.FromContext(ctx)

	shouldRun, err := checkEnvironment(spec)
	if err != nil {
		return fmt.Errorf("checking SBOM environment: %w", err)
	}

	if !shouldRun {
		log.Infof("Warning: Working directory not found, probably apk is empty")
		return nil
	}

	sbomDoc := &bom{
		Packages: []pkg{},
	}

	pkg, err := generateAPKPackage(spec)
	if err != nil {
		return fmt.Errorf("generating main package: %w", err)
	}

	sbomDoc.Packages = append(sbomDoc.Packages, pkg)

	// Finally, write the SBOM data to disk
	if err := writeSBOM(ctx, spec, sbomDoc); err != nil {
		return fmt.Errorf("writing sbom to disk: %w", err)
	}

	return nil
}
