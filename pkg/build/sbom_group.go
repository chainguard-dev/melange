package build

import (
	"time"

	"chainguard.dev/melange/internal/sbom"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

// An SBOMGroup stores SBOMs corresponding to each package (or subpackage)
// within a build group. Its purpose is to let the build process easily manage
// SBOMs for the 1-N number of packages it ends up emitting.
type SBOMGroup struct {
	set map[string]*sbom.Document
}

// newSBOMGroup creates a new SBOMGroup, initializing SBOMs for each package and
// subpackage name provided.
func newSBOMGroup(pkgNames ...string) *SBOMGroup {
	sg := &SBOMGroup{
		set: make(map[string]*sbom.Document),
	}

	for _, n := range pkgNames {
		doc := sbom.NewDocument()
		sg.set[n] = doc
	}

	return sg
}

// setCreatedTime sets the creation time for all SBOMs in the group.
func (sg *SBOMGroup) setCreatedTime(t time.Time) {
	for _, doc := range sg.set {
		doc.CreatedTime = t
	}
}

// setLicensingInfos sets the licensing information for all SBOMs in the group.
func (sg *SBOMGroup) setLicensingInfos(li map[string]string) {
	for _, doc := range sg.set {
		doc.LicensingInfos = li
	}
}

// Document retrieves the SBOM for the given package or subpackage name.
func (sg *SBOMGroup) Document(name string) *sbom.Document {
	return sg.set[name]
}

// addBuildConfigurationPackage adds a package serving as the "build
// configuration package" to all SBOMs in the group.
func (sg *SBOMGroup) addBuildConfigurationPackage(p *sbom.Package) {
	for _, doc := range sg.set {
		doc.AddPackage(p)
		doc.AddRelationship(doc.Describes, p, common.TypeRelationshipDescribeBy)
	}
}

// addUpstreamSourcePackage adds a package serving as an "upstream source
// package" to all SBOMs in the group.
func (sg *SBOMGroup) addUpstreamSourcePackage(p *sbom.Package) {
	for _, doc := range sg.set {
		doc.AddPackage(p)
		doc.AddRelationship(doc.Describes, p, common.TypeRelationshipGeneratedFrom)
	}
}
