package sbom

// Element represents any referenceable entity in an SBOM.
type Element interface {
	// ID returns the unique identifier for this element.
	ID() string
}
