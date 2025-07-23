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

package syft

import (
	"testing"

	"chainguard.dev/melange/pkg/sbom"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/require"
)

func TestMergeIntoDocument_EmptyPackages(t *testing.T) {
	ctx := slogtest.Context(t)

	doc := sbom.NewDocument()
	doc.Packages = []sbom.Package{
		{
			Name:    "test-apk",
			Version: "1.0.0",
		},
	}

	err := MergeIntoDocument(ctx, doc, []sbom.Package{}, "test-apk")
	require.NoError(t, err)

	// Should still have only the original package
	require.Len(t, doc.Packages, 1)
	require.Empty(t, doc.Relationships)
}

func TestMergeIntoDocument_WithSyftPackages(t *testing.T) {
	ctx := slogtest.Context(t)

	doc := sbom.NewDocument()
	apkPkg := sbom.Package{
		Name:    "test-apk",
		Version: "1.0.0",
	}
	doc.Packages = []sbom.Package{apkPkg}

	syftPackages := []sbom.Package{
		{
			Name:    "github.com/stretchr/testify",
			Version: "v1.8.0",
		},
		{
			Name:    "numpy",
			Version: "1.24.0",
		},
	}

	err := MergeIntoDocument(ctx, doc, syftPackages, "test-apk")
	require.NoError(t, err)

	// Should have original + Syft packages
	require.Len(t, doc.Packages, 3)

	// Should have relationships for each Syft package
	require.Len(t, doc.Relationships, 2)

	// Check that relationships are correct
	for _, rel := range doc.Relationships {
		require.Equal(t, apkPkg.ID(), rel.Element)
		require.Equal(t, "CONTAINS", rel.Type)
		// Related should be one of the Syft package IDs
		foundRelated := false
		for _, syftPkg := range syftPackages {
			if rel.Related == syftPkg.ID() {
				foundRelated = true
				break
			}
		}
		require.True(t, foundRelated, "relationship should point to a Syft package")
	}
}

func TestMergeIntoDocument_PackageNotFound(t *testing.T) {
	ctx := slogtest.Context(t)

	doc := sbom.NewDocument()
	doc.Packages = []sbom.Package{
		{
			Name:    "other-apk",
			Version: "1.0.0",
		},
	}

	syftPackages := []sbom.Package{
		{
			Name:    "github.com/stretchr/testify",
			Version: "v1.8.0",
		},
	}

	err := MergeIntoDocument(ctx, doc, syftPackages, "test-apk")
	require.Error(t, err)
	require.Contains(t, err.Error(), "could not find APK package")
}

func TestMergeIntoDocument_PreservesExistingRelationships(t *testing.T) {
	ctx := slogtest.Context(t)

	doc := sbom.NewDocument()
	apkPkg := sbom.Package{
		Name:    "test-apk",
		Version: "1.0.0",
	}
	configPkg := sbom.Package{
		Name:    "config",
		Version: "1.0.0",
	}
	doc.Packages = []sbom.Package{apkPkg, configPkg}

	// Add an existing relationship
	doc.AddRelationship(&apkPkg, &configPkg, "DESCRIBED_BY")

	syftPackages := []sbom.Package{
		{
			Name:    "github.com/stretchr/testify",
			Version: "v1.8.0",
		},
	}

	err := MergeIntoDocument(ctx, doc, syftPackages, "test-apk")
	require.NoError(t, err)

	// Should have original + new relationships
	require.Len(t, doc.Relationships, 2)

	// Check that original relationship is preserved
	foundOriginal := false
	for _, rel := range doc.Relationships {
		if rel.Type == "DESCRIBED_BY" {
			foundOriginal = true
			require.Equal(t, apkPkg.ID(), rel.Element)
			require.Equal(t, configPkg.ID(), rel.Related)
		}
	}
	require.True(t, foundOriginal, "original relationship should be preserved")
}
