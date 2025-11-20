package build

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	purl "github.com/package-url/packageurl-go"

	"chainguard.dev/melange/pkg/sbom"
)

func TestSBOMGroup_SubpackageUpstreamSource(t *testing.T) {
	// Create a mock SBOM group with a main package and a subpackage
	sg := NewSBOMGroup("main-pkg", "sub-pkg")
	if sg == nil {
		t.Fatal("expected SBOMGroup to be created")
	}

	mainDoc := sg.Document("main-pkg")
	subDoc := sg.Document("sub-pkg")

	// Set up the described packages for each document
	mainPkg := sbom.Package{
		Name:      "main-pkg",
		Version:   "1.0.0",
		Namespace: "test",
	}
	mainDoc.AddPackageAndSetDescribed(&mainPkg)

	subPkg := sbom.Package{
		Name:      "sub-pkg",
		Version:   "1.0.0",
		Namespace: "test",
	}
	subDoc.AddPackageAndSetDescribed(&subPkg)

	// Create an upstream source package for the main package
	mainPURL := purl.PackageURL{
		Type:      purl.TypeGithub,
		Namespace: "chainguard-dev",
		Name:      "melange",
		Version:   "abc123",
	}
	mainUpstream := sbom.Package{
		Name:             "melange",
		Version:          "abc123",
		LicenseDeclared:  "Apache-2.0",
		Namespace:        "chainguard-dev",
		PURL:             &mainPURL,
		DownloadLocation: "https://github.com/chainguard-dev/melange/archive/abc123.tar.gz",
	}

	// Add upstream source to ALL documents (old behavior)
	sg.AddUpstreamSourcePackage(&mainUpstream)

	// Create a subpackage-specific upstream source package
	subPURL := purl.PackageURL{
		Type:      purl.TypeGithub,
		Namespace: "wolfi-dev",
		Name:      "os",
		Version:   "def456",
	}
	subUpstream := sbom.Package{
		Name:             "os",
		Version:          "def456",
		LicenseDeclared:  "Apache-2.0",
		Namespace:        "wolfi-dev",
		PURL:             &subPURL,
		DownloadLocation: "https://github.com/wolfi-dev/os/archive/def456.tar.gz",
	}

	// Add to the subpackage SBOM only (new behavior)
	subDoc.AddUpstreamSourcePackage(&subUpstream)

	// Table-driven verification of final state
	tests := []struct {
		name        string
		doc         *sbom.Document
		expectedDoc *sbom.Document
	}{
		{
			name: "main doc has only main upstream source",
			doc:  mainDoc,
			expectedDoc: &sbom.Document{
				Describes: &mainPkg,
				Packages: []sbom.Package{
					mainPkg,
					mainUpstream,
				},
				Relationships: mainDoc.Relationships,
			},
		},
		{
			name: "sub doc has both upstream sources",
			doc:  subDoc,
			expectedDoc: &sbom.Document{
				Describes: &subPkg,
				Packages: []sbom.Package{
					subPkg,
					mainUpstream,
					subUpstream,
				},
				Relationships: subDoc.Relationships,
			},
		},
	}

	sortPackages := cmpopts.SortSlices(func(a, b sbom.Package) bool {
		return a.Name < b.Name
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.expectedDoc, tt.doc, sortPackages); diff != "" {
				t.Errorf("document mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSBOMGroup_NewGroup(t *testing.T) {
	tests := []struct {
		name     string
		pkgNames []string
	}{
		{
			name:     "single package",
			pkgNames: []string{"test-pkg"},
		},
		{
			name:     "multiple packages",
			pkgNames: []string{"main-pkg", "sub1-pkg", "sub2-pkg"},
		},
		{
			name:     "no packages",
			pkgNames: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sg := NewSBOMGroup(tt.pkgNames...)
			if sg == nil {
				t.Fatal("expected SBOMGroup to be created")
			}

			for _, name := range tt.pkgNames {
				doc := sg.Document(name)
				if doc == nil {
					t.Errorf("document for package %s should not be nil", name)
				}
			}
		})
	}
}

func TestSBOMGroup_AddBuildConfigurationPackage(t *testing.T) {
	sg := NewSBOMGroup("main-pkg", "sub-pkg")

	// Set up the described packages for each document
	mainDoc := sg.Document("main-pkg")
	subDoc := sg.Document("sub-pkg")

	mainPkg := sbom.Package{
		Name:      "main-pkg",
		Version:   "1.0.0",
		Namespace: "test",
	}
	mainDoc.AddPackageAndSetDescribed(&mainPkg)

	subPkg := sbom.Package{
		Name:      "sub-pkg",
		Version:   "1.0.0",
		Namespace: "test",
	}
	subDoc.AddPackageAndSetDescribed(&subPkg)

	buildCfgPURL := purl.PackageURL{
		Type:      purl.TypeGithub,
		Namespace: "wolfi-dev",
		Name:      "os",
		Version:   "c0ffee",
		Subpath:   "test.yaml",
	}
	buildCfgPkg := sbom.Package{
		Name:            "test.yaml",
		Version:         "c0ffee",
		LicenseDeclared: "Apache-2.0",
		Namespace:       "wolfi-dev",
		PURL:            &buildCfgPURL,
	}

	// Add build config package to all SBOMs
	sg.AddBuildConfigurationPackage(&buildCfgPkg)

	// Table-driven verification
	tests := []struct {
		name     string
		doc      *sbom.Document
		expected *sbom.Document
	}{
		{
			name: "main doc has build config",
			doc:  mainDoc,
			expected: &sbom.Document{
				Describes: &mainPkg,
				Packages: []sbom.Package{
					mainPkg,
					buildCfgPkg,
				},
				Relationships: mainDoc.Relationships,
			},
		},
		{
			name: "sub doc has build config",
			doc:  subDoc,
			expected: &sbom.Document{
				Describes: &subPkg,
				Packages: []sbom.Package{
					subPkg,
					buildCfgPkg,
				},
				Relationships: subDoc.Relationships,
			},
		},
	}

	sortPackages := cmpopts.SortSlices(func(a, b sbom.Package) bool {
		return a.Name < b.Name
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.expected, tt.doc, sortPackages); diff != "" {
				t.Errorf("document mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
