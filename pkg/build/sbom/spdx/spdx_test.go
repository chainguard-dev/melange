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

func TestSBOMGenerationWithSubpackageGitCheckout(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()
	outputFS := apkofs.DirFS(ctx, tmpDir)

	// Build configuration with subpackage that has a git-checkout pipeline
	cfg := &config.Configuration{
		Package: config.Package{
			Name:        "main-pkg",
			Version:     "1.0.0",
			Epoch:       0,
			Description: "Main package",
			Copyright: []config.Copyright{
				{License: "MIT"},
			},
		},
		Pipeline: []config.Pipeline{
			{
				Uses: "git-checkout",
				With: map[string]string{
					"repository":      "https://github.com/main/repo.git",
					"tag":             "v1.0.0",
					"expected-commit": "abc123def456",
				},
			},
		},
		Subpackages: []config.Subpackage{
			{
				Name:        "sub-pkg",
				Description: "Subpackage with git-checkout",
				Pipeline: []config.Pipeline{
					{
						Uses: "git-checkout",
						With: map[string]string{
							"repository":      "https://github.com/sub/repo.git",
							"tag":             "v2.0.0",
							"expected-commit": "xyz789abc012",
						},
					},
				},
			},
			{
				Name:        "sub-pkg-no-git",
				Description: "Subpackage without git-checkout",
				Pipeline: []config.Pipeline{
					{
						Runs: "echo 'no git checkout'",
					},
				},
			},
		},
	}

	testTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	genCtx := &build.GeneratorContext{
		Configuration:   cfg,
		WorkspaceDir:    tmpDir,
		OutputFS:        outputFS,
		SourceDateEpoch: testTime,
		Namespace:       "test-ns",
		Arch:            "x86_64",
		ReleaseData: &apko_build.ReleaseData{
			ID:        "test-os",
			VersionID: "1.0",
		},
	}

	gen := &Generator{}
	if err := gen.GenerateSBOM(ctx, genCtx); err != nil {
		t.Fatalf("GenerateSBOM failed: %v", err)
	}

	// Read actual SBOMs to get the dynamic namespace
	var actualMainDoc spdx.Document
	mainSBOMPath := filepath.Join(tmpDir, "main-pkg", build.SBOMDir,
		fmt.Sprintf("main-pkg-%s.spdx.json", cfg.Package.FullVersion()))
	data, err := os.ReadFile(mainSBOMPath)
	if err != nil {
		t.Fatalf("failed to read main package SBOM: %v", err)
	}
	if err := json.Unmarshal(data, &actualMainDoc); err != nil {
		t.Fatalf("failed to unmarshal main package SBOM: %v", err)
	}

	// Expected SBOM documents
	expectedSBOMs := map[string]*spdx.Document{
		"main-pkg": {
			ID:      "SPDXRef-DOCUMENT",
			Name:    "apk-main-pkg-1.0.0-r0",
			Version: "SPDX-2.3",
			CreationInfo: spdx.CreationInfo{
				Created:            "2024-01-01T00:00:00Z",
				Creators:           []string{"Tool: melange (devel)", "Organization: Chainguard, Inc"},
				LicenseListVersion: "3.22",
			},
			DataLicense:       "CC0-1.0",
			Namespace:         actualMainDoc.Namespace, // Use the dynamically generated namespace
			DocumentDescribes: []string{"SPDXRef-Package-main-pkg-1.0.0-r0"},
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
					ID:               "SPDXRef-Package-main-pkg-1.0.0-r0",
					Name:             "main-pkg",
					Version:          "1.0.0-r0",
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
							Locator:  "pkg:apk/test-ns/main-pkg@1.0.0-r0?arch=x86_64&distro=test-ns",
							Type:     "purl",
						},
					},
				},
				{
					ID:               "SPDXRef-Package-github.com-main-repo.git-v1.0.0-abc123def456-0",
					Name:             "repo",
					Version:          "v1.0.0",
					FilesAnalyzed:    false,
					LicenseConcluded: "NOASSERTION",
					LicenseDeclared:  "MIT",
					DownloadLocation: "https://github.com/main/repo/archive/abc123def456.tar.gz",
					Originator:       "Organization: Main",
					Supplier:         "Organization: Main",
					ExternalRefs: []spdx.ExternalRef{
						{
							Category: "PACKAGE-MANAGER",
							Locator:  "pkg:github/main/repo@v1.0.0",
							Type:     "purl",
						},
					},
				},
			},
			Relationships: []spdx.Relationship{
				{
					Element: "SPDXRef-Package-main-pkg-1.0.0-r0",
					Related: "SPDXRef-Package-github.com-main-repo.git-v1.0.0-abc123def456-0",
					Type:    "GENERATED_FROM",
				},
			},
		},
		"sub-pkg": {
			ID:      "SPDXRef-DOCUMENT",
			Name:    "apk-sub-pkg-1.0.0-r0",
			Version: "SPDX-2.3",
			CreationInfo: spdx.CreationInfo{
				Created:            "2024-01-01T00:00:00Z",
				Creators:           []string{"Tool: melange (devel)", "Organization: Chainguard, Inc"},
				LicenseListVersion: "3.22",
			},
			DataLicense:       "CC0-1.0",
			Namespace:         actualMainDoc.Namespace, // Use the same dynamically generated namespace
			DocumentDescribes: []string{"SPDXRef-Package-sub-pkg-1.0.0-r0"},
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
					ID:               "SPDXRef-Package-sub-pkg-1.0.0-r0",
					Name:             "sub-pkg",
					Version:          "1.0.0-r0",
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
							Locator:  "pkg:apk/test-ns/sub-pkg@1.0.0-r0?arch=x86_64&distro=test-ns",
							Type:     "purl",
						},
					},
				},
				{
					ID:               "SPDXRef-Package-github.com-sub-repo.git-v2.0.0-xyz789abc012-0",
					Name:             "repo",
					Version:          "v2.0.0",
					FilesAnalyzed:    false,
					LicenseConcluded: "NOASSERTION",
					LicenseDeclared:  "MIT",
					DownloadLocation: "https://github.com/sub/repo/archive/xyz789abc012.tar.gz",
					Originator:       "Organization: Sub",
					Supplier:         "Organization: Sub",
					ExternalRefs: []spdx.ExternalRef{
						{
							Category: "PACKAGE-MANAGER",
							Locator:  "pkg:github/sub/repo@v2.0.0",
							Type:     "purl",
						},
					},
				},
				{
					ID:               "SPDXRef-Package-github.com-main-repo.git-v1.0.0-abc123def456-0",
					Name:             "repo",
					Version:          "v1.0.0",
					FilesAnalyzed:    false,
					LicenseConcluded: "NOASSERTION",
					LicenseDeclared:  "MIT",
					DownloadLocation: "https://github.com/main/repo/archive/abc123def456.tar.gz",
					Originator:       "Organization: Main",
					Supplier:         "Organization: Main",
					ExternalRefs: []spdx.ExternalRef{
						{
							Category: "PACKAGE-MANAGER",
							Locator:  "pkg:github/main/repo@v1.0.0",
							Type:     "purl",
						},
					},
				},
			},
			Relationships: []spdx.Relationship{
				{
					Element: "SPDXRef-Package-sub-pkg-1.0.0-r0",
					Related: "SPDXRef-Package-github.com-sub-repo.git-v2.0.0-xyz789abc012-0",
					Type:    "GENERATED_FROM",
				},
				{
					Element: "SPDXRef-Package-sub-pkg-1.0.0-r0",
					Related: "SPDXRef-Package-github.com-main-repo.git-v1.0.0-abc123def456-0",
					Type:    "GENERATED_FROM",
				},
			},
		},
		"sub-pkg-no-git": {
			ID:      "SPDXRef-DOCUMENT",
			Name:    "apk-sub-pkg-no-git-1.0.0-r0",
			Version: "SPDX-2.3",
			CreationInfo: spdx.CreationInfo{
				Created:            "2024-01-01T00:00:00Z",
				Creators:           []string{"Tool: melange (devel)", "Organization: Chainguard, Inc"},
				LicenseListVersion: "3.22",
			},
			DataLicense:       "CC0-1.0",
			Namespace:         actualMainDoc.Namespace, // Use the same dynamically generated namespace
			DocumentDescribes: []string{"SPDXRef-Package-sub-pkg-no-git-1.0.0-r0"},
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
					ID:               "SPDXRef-Package-sub-pkg-no-git-1.0.0-r0",
					Name:             "sub-pkg-no-git",
					Version:          "1.0.0-r0",
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
							Locator:  "pkg:apk/test-ns/sub-pkg-no-git@1.0.0-r0?arch=x86_64&distro=test-ns",
							Type:     "purl",
						},
					},
				},
				{
					ID:               "SPDXRef-Package-github.com-main-repo.git-v1.0.0-abc123def456-0",
					Name:             "repo",
					Version:          "v1.0.0",
					FilesAnalyzed:    false,
					LicenseConcluded: "NOASSERTION",
					LicenseDeclared:  "MIT",
					DownloadLocation: "https://github.com/main/repo/archive/abc123def456.tar.gz",
					Originator:       "Organization: Main",
					Supplier:         "Organization: Main",
					ExternalRefs: []spdx.ExternalRef{
						{
							Category: "PACKAGE-MANAGER",
							Locator:  "pkg:github/main/repo@v1.0.0",
							Type:     "purl",
						},
					},
				},
			},
			Relationships: []spdx.Relationship{
				{
					Element: "SPDXRef-Package-sub-pkg-no-git-1.0.0-r0",
					Related: "SPDXRef-Package-github.com-main-repo.git-v1.0.0-abc123def456-0",
					Type:    "GENERATED_FROM",
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
