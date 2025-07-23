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
	"context"
	"fmt"

	"chainguard.dev/apko/pkg/sbom/generator/spdx"
	"chainguard.dev/melange/pkg/sbom"
	"github.com/chainguard-dev/clog"
)

// MergeIntoDocument merges Syft-detected packages into an existing SBOM document
func MergeIntoDocument(ctx context.Context, doc *sbom.Document, syftPackages []sbom.Package, apkPackageName string) error {
	log := clog.FromContext(ctx)

	if len(syftPackages) == 0 {
		log.Debug("no Syft packages to merge")
		return nil
	}

	// Find the APK package in the document to establish relationships
	var apkPackage *sbom.Package
	for i, pkg := range doc.Packages {
		if pkg.Name == apkPackageName {
			apkPackage = &doc.Packages[i]
			break
		}
	}

	if apkPackage == nil {
		return fmt.Errorf("could not find APK package %q in SBOM document", apkPackageName)
	}

	// Add all Syft-detected packages to the document
	for _, syftPkg := range syftPackages {
		doc.Packages = append(doc.Packages, syftPkg)

		// Create a CONTAINS relationship from the APK package to the Syft-detected package
		rel := spdx.Relationship{
			Element: apkPackage.ID(),
			Related: syftPkg.ID(),
			Type:    "CONTAINS",
		}
		doc.Relationships = append(doc.Relationships, rel)
	}

	log.Infof("merged %d Syft-detected packages into SBOM", len(syftPackages))
	return nil
}
