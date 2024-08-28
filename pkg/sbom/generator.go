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

	"chainguard.dev/apko/pkg/sbom/generator/spdx"
	"github.com/chainguard-dev/clog"
	purl "github.com/package-url/packageurl-go"
	"go.opentelemetry.io/otel"
)

// Spec describes the metadata of an APK package for which an SBOM should be
// created.
type Spec struct {
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

// GenerateAndWrite creates an SBOM for the APK package described by the given
// Spec and writes the SBOM to the APK's filesystem.
func GenerateAndWrite(ctx context.Context, apkFSPath string, spec *Spec) error {
	_, span := otel.Tracer("melange").Start(ctx, "GenerateSBOM")
	defer span.End()
	log := clog.FromContext(ctx)

	if shouldRun, err := checkEnvironment(apkFSPath); err != nil {
		return fmt.Errorf("checking SBOM environment: %w", err)
	} else if !shouldRun {
		log.Warnf("working directory not found, apk is empty")
		return nil
	}

	document, err := GenerateSPDX(ctx, spec)
	if err != nil {
		return fmt.Errorf("generating SPDX document: %w", err)
	}

	if err := writeSBOM(apkFSPath, spec.PackageName, spec.PackageVersion, document); err != nil {
		return fmt.Errorf("writing sbom to disk: %w", err)
	}

	return nil
}

// GenerateSPDX creates an SPDX 2.3 document from the given Spec.
func GenerateSPDX(ctx context.Context, spec *Spec) (*spdx.Document, error) {
	p, err := generateAPKPackage(spec)
	if err != nil {
		return nil, fmt.Errorf("generating main APK package: %w", err)
	}

	doc, err := newSPDXDocument(ctx, spec, p)
	if err != nil {
		return nil, fmt.Errorf("creating SPDX document: %w", err)
	}

	return doc, nil
}
