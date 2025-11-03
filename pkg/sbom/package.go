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

// Package sbom captures the internal data model of the SBOMs melange produces
// into a private, generalized bill of materials model (with relationship data)
// designed to be converted to specific formats — for now, just SPDX.
package sbom

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"chainguard.dev/apko/pkg/sbom/generator/spdx"
	"github.com/chainguard-dev/clog"
	"github.com/github/go-spdx/v2/spdxexp"
	purl "github.com/package-url/packageurl-go"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Package is a representation of an SBOM package specified by the build
// process. It is later converted to an SPDX package, but it doesn't expose
// fields that are invariant in the SPDX output.
type Package struct {
	// IDComponents lets the consumer specify additional bits of data that should be
	// included in the generation of the eventual SBOM package ID. By default, this
	// slice has a length of zero, in which case only the package's name and version
	// will be used. But sometimes it's necessary to include more bits of data to
	// ensure package IDs remain unique. If this slice's length is non-zero, only
	// these values will be used when producing the ID (via calling the ID method)
	// (i.e. name and version would need to be added explicitly to this slice).
	IDComponents []string

	// The name of the origin package, a subpackage, or any other kind of (e.g.
	// non-APK) package for inclusion in the SBOM.
	Name string

	// The version of the package. For APK packages, this should be the "full
	// version" (including the epoch).
	Version string

	// This is the copyright text in the SPDX package. It's usually left blank.
	Copyright string

	// SPDX license expression. Leaving this empty will result in NOASSERTION being
	// used as its value.
	LicenseDeclared string

	// Name of the distro/organization that produced the package. E.g. "wolfi".
	//
	// TODO: consider renaming this to avoid confusion from our other uses of
	//  "namespace", perhaps to "supplier" or "originator" (or have both), and signal
	//  that it's safe to leave this blank.
	Namespace string

	// The architecture of the package. E.g. "aarch64". This field isn't always
	// relevant, especially when describing material upstream of the built APK
	// package (e.g. source code or language ecosystem dependencies).
	Arch string

	// Checksums of the package. The keys are the checksum algorithms (e.g. "SHA-256"),
	// and the values are the checksums.
	Checksums map[string]string

	// The Package URL for this package, if any. If set, it will be added as the
	// only ExternalRef of type "purl" to the SPDX package. (A package
	// should have only one PURL external ref.)
	PURL *purl.PackageURL

	// The Download Location for this package, if any; It set this is generated
	// alongside the PackageURL from fetch/git-checkout pipelines for upstream
	// source locations; Leaving this empty will result in NOASSERTION being
	// used as its value.
	DownloadLocation string
}

// ToSPDX returns the Package converted to its SPDX representation.
func (p Package) ToSPDX(ctx context.Context) spdx.Package {
	log := clog.FromContext(ctx)

	if p.LicenseDeclared == "" {
		log.Warnf("%s: no license specified, defaulting to %s", p.ID(), spdx.NOASSERTION)
		p.LicenseDeclared = spdx.NOASSERTION
	} else {
		valid, bad := spdxexp.ValidateLicenses([]string{p.LicenseDeclared})
		if !valid {
			log.Warnf("invalid license: %s", strings.Join(bad, ", "))
		}
	}

	if p.DownloadLocation == "" {
		p.DownloadLocation = spdx.NOASSERTION
	}

	sp := spdx.Package{
		ID:               p.ID(),
		Name:             p.Name,
		Version:          p.Version,
		FilesAnalyzed:    false,
		LicenseConcluded: spdx.NOASSERTION,
		LicenseDeclared:  p.LicenseDeclared,
		DownloadLocation: p.DownloadLocation,
		CopyrightText:    p.Copyright,
		Checksums:        p.getChecksums(),
		ExternalRefs:     p.getExternalRefs(),
		Originator:       p.getSupplier(), // yes, we use this value for both fields (for now)
		Supplier:         p.getSupplier(),
	}

	return sp
}

// ID returns the unique identifier for this package. It implements the Element
// interface.
func (p Package) ID() string {
	if len(p.IDComponents) == 0 {
		return stringToIdentifier(
			fmt.Sprintf("SPDXRef-Package-%s-%s", p.Name, p.Version),
		)
	}

	var id strings.Builder
	id.WriteString("SPDXRef-Package")
	for _, component := range p.IDComponents {
		id.WriteString("-" + component)
	}
	return stringToIdentifier(id.String())
}

func (p Package) getChecksums() []spdx.Checksum {
	algos := make([]string, 0, len(p.Checksums))
	for algo := range p.Checksums {
		algos = append(algos, algo)
	}
	sort.Strings(algos)

	result := make([]spdx.Checksum, 0, len(p.Checksums))
	for _, algo := range algos {
		result = append(result, spdx.Checksum{
			Algorithm: algo,
			Value:     p.Checksums[algo],
		})
	}

	// For JSON, we'll want an empty array, not `null`.
	if len(result) == 0 {
		return []spdx.Checksum{}
	}

	return result
}

func (p Package) getSupplier() string {
	return "Organization: " + cases.Title(language.English).String(p.Namespace)
}

func (p Package) getExternalRefs() []spdx.ExternalRef {
	var result []spdx.ExternalRef

	if p.PURL != nil {
		result = append(result, spdx.ExternalRef{
			Category: spdx.ExtRefPackageManager,
			Locator:  p.PURL.ToString(),
			Type:     spdx.ExtRefTypePurl,
		})
	}

	return result
}

// stringToIdentifier converts a string to a valid SPDX identifier by replacing
// invalid characters. Colons and slashes are replaced by dashes, and all other
// invalid characters are replaced by their Unicode code point prefixed with
// "C".
//
// Examples:
//
//	"foo:bar" -> "foo-bar"
//	"foo/bar" -> "foo-bar"
//	"foo bar" -> "fooC32bar"
func stringToIdentifier(in string) string {
	var sb strings.Builder
	sb.Grow(len(in))

	for _, r := range in {
		switch {
		case r == ':' || r == '/':
			sb.WriteRune('-')
		case r == '-' || r == '.' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			sb.WriteRune(r)
		default:
			sb.WriteString(encodeInvalidRune(r))
		}
	}
	return sb.String()
}

func encodeInvalidRune(r rune) string {
	return "C" + strconv.Itoa(int(r))
}
