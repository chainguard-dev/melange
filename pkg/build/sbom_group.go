package build

import (
	"chainguard.dev/melange/pkg/build/sbom/spdx"
)

// An SBOMGroup stores SBOMs corresponding to each package (or subpackage)
// within a build group. Its purpose is to let the build process easily manage
// SBOMs for the 1-N number of packages it ends up emitting.
//
// Deprecated: use sbom/spdx.SBOMGroup instead.
type SBOMGroup = spdx.SBOMGroup

// NewSBOMGroup creates a new SBOMGroup, initializing SBOMs for each package and
// subpackage name provided.
func NewSBOMGroup(pkgNames ...string) *SBOMGroup {
	return spdx.NewSBOMGroup(pkgNames...)
}
