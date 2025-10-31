package sbom

import (
	"context"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"time"

	apko_build "chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/sbom/generator/spdx"
	"github.com/chainguard-dev/clog"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"sigs.k8s.io/release-utils/version"
)

// Document is a representation of an SBOM information provided by the build
// process. It is later converted to an SPDX document.
type Document struct {
	CreatedTime time.Time
	Describes   *Package
	Packages    []Package

	// Relationships is a list of relationships between elements in the SBOM.
	//
	// We're using the SPDX relationship type for now out of convenience, but we can
	// decouple this from our internal SBOM types later if it becomes valuable.
	Relationships []spdx.Relationship

	// LicensingInfos is a map of instances of the `Copyright.License` field in the
	// described package's build configuration to the string content of the file
	// from its corresponding `Copyright.LicensePath` field. It should be set by the
	// consumer, using the value from calling `(config.Package).LicensingInfos` on
	// the package being set as this document's described package.
	LicensingInfos map[string]string
}

// NewDocument creates a new Document.
func NewDocument() *Document {
	return &Document{}
}

// ToSPDX returns the Document converted to its SPDX representation.
func (d Document) ToSPDX(ctx context.Context, releaseData *apko_build.ReleaseData) spdx.Document {
	spdxPkgs := make([]spdx.Package, 0, len(d.Packages))

	// Start off by adding the OperatingSystem package to the list of packages.
	if releaseData != nil {
		spdxPkgs = append(spdxPkgs, d.createOperatingSystemPackage(releaseData))
	} else {
		log := clog.FromContext(ctx)
		log.Warn("No release data provided, not adding OperatingSystem package to SPDX document")
	}

	for _, p := range d.Packages {
		spdxPkgs = append(spdxPkgs, p.ToSPDX(ctx))
	}

	licensingInfos := make([]spdx.LicensingInfo, 0, len(d.LicensingInfos))
	for licenseID, extractedText := range d.LicensingInfos {
		licensingInfos = append(licensingInfos,
			spdx.LicensingInfo{
				LicenseID:     licenseID,
				ExtractedText: extractedText,
			},
		)
	}

	doc := spdx.Document{
		ID:      "SPDXRef-DOCUMENT",
		Name:    d.getSPDXName(),
		Version: "SPDX-2.3",
		CreationInfo: spdx.CreationInfo{
			Created: d.CreatedTime.Format(time.RFC3339),
			Creators: []string{
				fmt.Sprintf("Tool: melange (%s)", version.GetVersionInfo().GitVersion),
				"Organization: Chainguard, Inc",
			},
			LicenseListVersion: "3.22", // https://spdx.org/licenses/
		},
		DataLicense: "CC0-1.0",
		Namespace:   d.getSPDXNamespace(),
		DocumentDescribes: []string{
			d.Describes.ID(),
		},
		Packages:             spdxPkgs,
		Relationships:        d.Relationships,
		ExternalDocumentRefs: []spdx.ExternalDocumentRef{},
		LicensingInfos:       licensingInfos,
	}

	return doc
}

func (d Document) getSPDXName() string {
	return fmt.Sprintf("apk-%s-%s", d.Describes.Name, d.Describes.Version)
}

func (d Document) getSPDXNamespace() string {
	h := fnv.New128a()
	fmt.Fprintf(h, "apk-%s-%s", d.Describes.Namespace, d.Describes.Version)
	hexHash := hex.EncodeToString(h.Sum(nil))

	return "https://spdx.org/spdxdocs/chainguard/melange/" + hexHash
}

func (d Document) createOperatingSystemPackage(os *apko_build.ReleaseData) spdx.Package {
	return spdx.Package{
		ID:               "SPDXRef-OperatingSystem",
		Name:             os.ID,
		Version:          os.VersionID,
		FilesAnalyzed:    false,
		Description:      "Operating System",
		LicenseConcluded: spdx.NOASSERTION,
		LicenseDeclared:  spdx.NOASSERTION,
		DownloadLocation: spdx.NOASSERTION,
		PrimaryPurpose:   "OPERATING-SYSTEM",
		Originator:       d.Describes.getSupplier(),
		Supplier:         d.Describes.getSupplier(),
	}
}

// AddPackageAndSetDescribed adds a package to the document and sets it as the
// document's described package.
func (d *Document) AddPackageAndSetDescribed(p *Package) {
	d.AddPackage(p)
	d.Describes = p
}

// AddPackage adds a package to the document.
func (d *Document) AddPackage(p *Package) {
	if p == nil {
		return
	}
	d.Packages = append(d.Packages, *p)
}

// AddRelationship adds a relationship between two elements in the SBOM.
func (d *Document) AddRelationship(a, b Element, typ string) {
	d.Relationships = append(d.Relationships, spdx.Relationship{
		Element: a.ID(),
		Related: b.ID(),
		Type:    typ,
	})
}

func (d *Document) AddUpstreamSourcePackage(p *Package) {
	d.AddPackage(p)
	d.AddRelationship(d.Describes, p, common.TypeRelationshipGeneratedFrom)
}
