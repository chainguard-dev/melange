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

package spdx

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	apko_build "chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/sbom/generator/spdx"
	"github.com/google/go-cmp/cmp"
	purl "github.com/package-url/packageurl-go"

	build "chainguard.dev/melange/pkg/build/sbom"
	"chainguard.dev/melange/pkg/config"
)

func TestSBOMGeneration(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()
	outputFS := apkofs.DirFS(ctx, tmpDir)

	// Build configuration with subpackages
	cfg := &config.Configuration{
		Package: config.Package{
			Name:        "test-pkg",
			Version:     "1.2.3",
			Epoch:       2,
			Description: "Test package",
			Copyright: []config.Copyright{
				{License: "MIT"},
			},
		},
		Subpackages: []config.Subpackage{
			{
				Name:        "test-pkg-dev",
				Description: "Development files",
			},
		},
	}

	testTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	testPURL, err := purl.FromString("pkg:generic/test-pkg.yaml@commit123")
	if err != nil {
		t.Fatalf("failed to parse PURL: %v", err)
	}

	genCtx := &build.GeneratorContext{
		Configuration:   cfg,
		WorkspaceDir:    tmpDir,
		OutputFS:        outputFS,
		SourceDateEpoch: testTime,
		Namespace:       "test-ns",
		Arch:            "x86_64",
		ConfigFile: &build.ConfigFile{
			Path:    "test-pkg.yaml",
			Commit:  "commit123",
			License: "Apache-2.0",
			PURL:    &testPURL,
		},
		ReleaseData: &apko_build.ReleaseData{
			ID:        "test-os",
			VersionID: "1.0",
		},
	}

	gen := &Generator{}
	if err := gen.GenerateSBOM(ctx, genCtx); err != nil {
		t.Fatalf("GenerateSBOMs failed: %v", err)
	}

	// Define expected SBOM documents
	expectedSBOMs := map[string]*spdx.Document{
		"test-pkg": {
			ID:      "SPDXRef-DOCUMENT",
			Name:    "apk-test-pkg-1.2.3-r2",
			Version: "SPDX-2.3",
			CreationInfo: spdx.CreationInfo{
				Created:            "2023-01-01T00:00:00Z",
				Creators:           []string{"Tool: melange (devel)", "Organization: Chainguard, Inc"},
				LicenseListVersion: "3.22",
			},
			DataLicense:       "CC0-1.0",
			Namespace:         "https://spdx.org/spdxdocs/chainguard/melange/e43c05eed89f57b011808279db234a08",
			DocumentDescribes: []string{"SPDXRef-Package-test-pkg-1.2.3-r2"},
			Packages: []spdx.Package{
				{
					ID:               "SPDXRef-OperatingSystem",
					Name:             "test-os",
					Version:          "1.0",
					FilesAnalyzed:    false,
					LicenseConcluded: "NOASSERTION",
					LicenseDeclared:  "NOASSERTION",
					Description:      "Operating System",
					DownloadLocation: "NOASSERTION",
					Originator:       "Organization: Test-Ns",
					Supplier:         "Organization: Test-Ns",
					PrimaryPurpose:   "OPERATING-SYSTEM",
				},
				{
					ID:               "SPDXRef-Package-test-pkg-1.2.3-r2",
					Name:             "test-pkg",
					Version:          "1.2.3-r2",
					FilesAnalyzed:    false,
					LicenseConcluded: "NOASSERTION",
					LicenseDeclared:  "MIT",
					DownloadLocation: "NOASSERTION",
					Originator:       "Organization: Test-Ns",
					Supplier:         "Organization: Test-Ns",
					CopyrightText:    "NOASSERTION",
					ExternalRefs: []spdx.ExternalRef{
						{
							Category: "PACKAGE-MANAGER",
							Locator:  "pkg:apk/test-ns/test-pkg@1.2.3-r2?arch=x86_64&distro=test-ns",
							Type:     "purl",
						},
					},
				},
				{
					ID:               "SPDXRef-Package-test-pkg.yaml-commit123",
					Name:             "test-pkg.yaml",
					Version:          "commit123",
					FilesAnalyzed:    false,
					LicenseConcluded: "NOASSERTION",
					LicenseDeclared:  "Apache-2.0",
					DownloadLocation: "NOASSERTION",
					Originator:       "Organization: Test-Ns",
					Supplier:         "Organization: Test-Ns",
					ExternalRefs: []spdx.ExternalRef{
						{
							Category: "PACKAGE-MANAGER",
							Locator:  "pkg:generic/test-pkg.yaml@commit123",
							Type:     "purl",
						},
					},
				},
			},
			Relationships: []spdx.Relationship{
				{
					Element: "SPDXRef-Package-test-pkg-1.2.3-r2",
					Related: "SPDXRef-Package-test-pkg.yaml-commit123",
					Type:    "DESCRIBED_BY",
				},
			},
		},
		"test-pkg-dev": {
			ID:      "SPDXRef-DOCUMENT",
			Name:    "apk-test-pkg-dev-1.2.3-r2",
			Version: "SPDX-2.3",
			CreationInfo: spdx.CreationInfo{
				Created:            "2023-01-01T00:00:00Z",
				Creators:           []string{"Tool: melange (devel)", "Organization: Chainguard, Inc"},
				LicenseListVersion: "3.22",
			},
			DataLicense:       "CC0-1.0",
			Namespace:         "https://spdx.org/spdxdocs/chainguard/melange/e43c05eed89f57b011808279db234a08",
			DocumentDescribes: []string{"SPDXRef-Package-test-pkg-dev-1.2.3-r2"},
			Packages: []spdx.Package{
				{
					ID:               "SPDXRef-OperatingSystem",
					Name:             "test-os",
					Version:          "1.0",
					FilesAnalyzed:    false,
					LicenseConcluded: "NOASSERTION",
					LicenseDeclared:  "NOASSERTION",
					Description:      "Operating System",
					DownloadLocation: "NOASSERTION",
					Originator:       "Organization: Test-Ns",
					Supplier:         "Organization: Test-Ns",
					PrimaryPurpose:   "OPERATING-SYSTEM",
				},
				{
					ID:               "SPDXRef-Package-test-pkg-dev-1.2.3-r2",
					Name:             "test-pkg-dev",
					Version:          "1.2.3-r2",
					FilesAnalyzed:    false,
					LicenseConcluded: "NOASSERTION",
					LicenseDeclared:  "MIT",
					DownloadLocation: "NOASSERTION",
					Originator:       "Organization: Test-Ns",
					Supplier:         "Organization: Test-Ns",
					CopyrightText:    "NOASSERTION",
					ExternalRefs: []spdx.ExternalRef{
						{
							Category: "PACKAGE-MANAGER",
							Locator:  "pkg:apk/test-ns/test-pkg-dev@1.2.3-r2?arch=x86_64&distro=test-ns",
							Type:     "purl",
						},
					},
				},
				{
					ID:               "SPDXRef-Package-test-pkg.yaml-commit123",
					Name:             "test-pkg.yaml",
					Version:          "commit123",
					FilesAnalyzed:    false,
					LicenseConcluded: "NOASSERTION",
					LicenseDeclared:  "Apache-2.0",
					DownloadLocation: "NOASSERTION",
					Originator:       "Organization: Test-Ns",
					Supplier:         "Organization: Test-Ns",
					ExternalRefs: []spdx.ExternalRef{
						{
							Category: "PACKAGE-MANAGER",
							Locator:  "pkg:generic/test-pkg.yaml@commit123",
							Type:     "purl",
						},
					},
				},
			},
			Relationships: []spdx.Relationship{
				{
					Element: "SPDXRef-Package-test-pkg-dev-1.2.3-r2",
					Related: "SPDXRef-Package-test-pkg.yaml-commit123",
					Type:    "DESCRIBED_BY",
				},
			},
		},
	}

	// Verify each SBOM
	for pkgName, expected := range expectedSBOMs {
		sbomPath := filepath.Join(tmpDir, pkgName, build.SBOMDir,
			fmt.Sprintf("%s-%s.spdx.json", pkgName, cfg.Package.FullVersion()))

		// Verify file exists
		if _, err := os.Stat(sbomPath); err != nil {
			t.Fatalf("SBOM not created for %s: %v", pkgName, err)
		}

		// Read SBOM
		var actual spdx.Document
		data, err := os.ReadFile(sbomPath)
		if err != nil {
			t.Fatalf("failed to read SBOM for %s: %v", pkgName, err)
		}
		if err := json.Unmarshal(data, &actual); err != nil {
			t.Fatalf("failed to unmarshal SBOM for %s: %v", pkgName, err)
		}

		// Compare entire document
		diff := cmp.Diff(expected, &actual)
		if diff != "" {
			t.Errorf("%s: SBOM mismatch (-want +got):\n%s", pkgName, diff)
		}
	}
}
