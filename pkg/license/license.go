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

// Package license checks a package's declared licensing against the license
// files its source tree actually ships.
//
// Discovery, classification and SPDX expression handling come from
// chainguard.dev/license, which melange shares with Chainguard's other license
// tooling so that the same tree yields the same answer everywhere. What stays
// here is melange's own: reading declarations out of a melange configuration,
// deciding which parts of a tree belong to the package, ranking a license by
// restrictiveness, and deciding what disagreement is worth warning about.
package license

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"chainguard.dev/license/detect"
	"chainguard.dev/license/spdx"
	"github.com/chainguard-dev/clog"
	golicenses "github.com/google/go-licenses/v2/licenses"

	"chainguard.dev/melange/pkg/config"
)

// License represents a software license, as detected by the classifier.
type License struct {
	Name       string
	Type       golicenses.Type
	Confidence float64
	Source     string
	Overrides  string
}

// LicenseFile represents a license file, with its name, path, and relevance score.
type LicenseFile struct {
	Name   string
	Path   string
	Weight float64
}

// LicenseDiff represents a difference between the detected license and the expected license.
type LicenseDiff struct {
	Path     string
	Is       string
	Should   string
	Override string
	NewType  golicenses.Type
}

// scopeFor maps melange's shallow/deep choice onto a discovery scope.
// A shallow scan reads the root and one directory below it, which is where a
// package keeps its own license, and skips the directories the module
// attributes to other components, vendor/ and third_party/ among them. A deep
// scan reads the whole tree.
func scopeFor(deep bool) detect.Scope {
	if deep {
		return detect.ScopeTree
	}
	return detect.ScopeProject
}

// installedTrees are the directories a build installs into rather than builds
// from: a virtualenv, node_modules, a Rust standard library. The licenses
// there belong to what was installed, not to the package.
//
// Vendored source under vendor/, third_party/ and the like is deliberately
// absent. It is built into the package, so its terms are obligations the
// package carries and a deep scan reports them. The module classifies both
// kinds as ExclusionVendored, which is why melange keeps this list itself.
var installedTrees = map[string]struct{}{
	".virtualenv":  {},
	"env":          {},
	"node_modules": {},
	"rust-src":     {},
	"rustc-src":    {},
	"venv":         {},
}

// embeddedVersionRe collapses a version embedded in a directory name, so that
// rust-1.86.0-src matches rust-src.
var embeddedVersionRe = regexp.MustCompile(`-\d+\.\d+\.\d+-`)

func inInstalledTree(p string) bool {
	for seg := range strings.SplitSeq(p, "/") {
		if _, ok := installedTrees[embeddedVersionRe.ReplaceAllString(seg, "-")]; ok {
			return true
		}
	}
	return false
}

// describesPackage reports whether a discovered path describes the package
// being built rather than something installed beside it. Build output is
// refused too: melange stages each subpackage under melange-out/ in the same
// workspace, and a license there is a copy of the answer this check is
// producing.
func describesPackage(p string) bool {
	if inInstalledTree(p) {
		return false
	}
	// One segment at a time: for a whole path the module reports only the
	// first dependency or build-output directory, so a vendored directory
	// above melange-out/ would hide it.
	for seg := range strings.SplitSeq(p, "/") {
		if detect.ClassifyDirExclusion(seg) == detect.ExclusionBuildOutput {
			return false
		}
	}
	return true
}

// IsLicenseFile checks if a file is a license file based on its name.
// Returns true/false if the file is a license file, and the weight value
// associated with the match, as some matches are potentially more relevant.
// A file under a directory a build installs into, such as node_modules or a
// virtualenv, is not counted unless overrideIgnore is set, which lets a linter
// ask about the name alone (e.g., to avoid listing each instance of a given
// LICENSE file as a duplicate).
func IsLicenseFile(filename string, overrideIgnore bool) (bool, float64) {
	if !overrideIgnore && inInstalledTree(filename) {
		return false, 0.0
	}
	return detect.IsLicenseFile(filename)
}

// requireReadable fails a scan that could not read all of its tree. A tree read
// only in part has no trustworthy answer, so the scan reports none rather than
// whatever it reached.
func requireReadable(unreadable []string) error {
	if len(unreadable) == 0 {
		return nil
	}
	return fmt.Errorf("finding license files: cannot read %q", unreadable)
}

// FindLicenseFiles returns a list of license files in a directory, sorted by their relevance score.
// If deep is true, the entire tree is scanned. If deep is false, only the top directory and one level down are scanned,
// returning the list of most likely licenses of the project itself (not vendored dependencies)
func FindLicenseFiles(fsys fs.FS, deep bool) ([]LicenseFile, error) {
	found, err := detect.Find(fsys, scopeFor(deep))
	if err != nil {
		return nil, fmt.Errorf("finding license files: %w", err)
	}
	if err := requireReadable(found.Unreadable); err != nil {
		return nil, err
	}

	licenseFiles := make([]LicenseFile, 0, len(found.Candidates))
	for _, c := range found.Candidates {
		if !describesPackage(c.Path) {
			continue
		}
		licenseFiles = append(licenseFiles, LicenseFile{
			Name:   path.Base(c.Path),
			Path:   c.Path,
			Weight: c.Weight,
		})
	}
	return licenseFiles, nil
}

// declarationsFrom reads the licenses a melange configuration declares.
//
// A declaration naming a path is what lets a package whose license lives in an
// unconventionally named file say so: discovery does not select such a file by
// name, and the declaration makes it read and classified anyway.
func declarationsFrom(cfg *config.Configuration) []detect.Declaration {
	if cfg == nil {
		return nil
	}
	decls := make([]detect.Declaration, 0, len(cfg.Package.Copyright))
	for _, cp := range cfg.Package.Copyright {
		decls = append(decls, detect.Declaration{
			License:  cp.License,
			Path:     cp.LicensePath,
			Override: cp.DetectionOverride,
		})
	}
	return decls
}

// CollectLicenseInfo collects license information from the given filesystem.
// If deep is true, the entire tree is scanned. If deep is false, only the top directory and one level down are scanned.
func CollectLicenseInfo(ctx context.Context, fsys fs.FS, deep bool, cfg *config.Configuration) ([]License, error) {
	log := clog.FromContext(ctx)

	decls := declarationsFrom(cfg)
	res, err := detect.Detect(ctx, detect.Request{
		FS:       fsys,
		Scope:    scopeFor(deep),
		Declared: decls,
	})
	if err != nil {
		return nil, fmt.Errorf("detecting licenses: %w", err)
	}
	if err := requireReadable(res.Unreadable); err != nil {
		return nil, err
	}

	// A declared file is read wherever it sits: naming it is the package's own
	// statement about its licensing, and skipping it would leave that
	// statement unchecked.
	declared := make(map[string]struct{}, len(decls))
	for _, d := range decls {
		if d.Path != "" {
			declared[path.Clean(d.Path)] = struct{}{}
		}
	}

	detectedLicenses := []License{}
	for _, f := range res.Files {
		if _, ok := declared[f.Path]; !ok && !describesPackage(f.Path) {
			continue
		}
		if f.Err != "" {
			return nil, fmt.Errorf("reading license file %q: %s", f.Path, f.Err)
		}
		// The classifier reads no more than detect.MaxTextBytes of a file.
		if f.SizeBytes > detect.MaxTextBytes {
			log.Warnf("only the first %d bytes of %q are classified; a license past that point is not detected", detect.MaxTextBytes, f.Path)
		}

		// A file can carry more than one license text, and they are separate
		// licenses: a LICENSE that appends a bundled dependency's terms is the
		// common shape. Reporting only the strongest would hide the other.
		detectedLicenses = append(detectedLicenses, licenseFor(f.License, f.Confidence, f.Path))
		for _, m := range f.AdditionalLicenses {
			detectedLicenses = append(detectedLicenses, licenseFor(m.Name, m.Confidence, f.Path))
		}
		log.Debugf("detected license %s in %s", f.License, f.Path)
	}

	if len(detectedLicenses) == 0 {
		// No license files detected, no linting performed.
		log.Debugf("no license files detected")
		return nil, nil
	}
	return detectedLicenses, nil
}

// licenseFor describes one classified license text. A file nothing recognized
// carries no license type, since there is no license to rank.
func licenseFor(name string, confidence float64, source string) License {
	l := License{Name: name, Confidence: confidence, Source: source}
	if name != detect.NoAssertion {
		l.Type = golicenses.LicenseType(name)
	}
	return l
}

// IsLicenseMatchConfident checks if the license match is confident enough to be considered valid.
func IsLicenseMatchConfident(dl License) bool {
	// This is heuristics, but we want to ignore licenses with a confidence lower than a threshold
	return dl.Confidence >= detect.ConfidenceThreshold
}

// LicenseCheck checks the licenses of the files in the given filesystem against the melange configuration.
// If deep is true, the entire tree is scanned. If deep is false, only the top directory and one level down are scanned.
func LicenseCheck(ctx context.Context, cfg *config.Configuration, fsys fs.FS, deep bool) ([]License, []LicenseDiff, error) {
	log := clog.FromContext(ctx)
	log.Infof("checking license information")

	detectedLicenses, err := CollectLicenseInfo(ctx, fsys, deep, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("collecting license info: %w", err)
	}

	if detectedLicenses == nil {
		log.Infof("no license files detected")
		return nil, nil, nil
	}

	// Print out all the gathered licenses and record low-confidence ones
	lowConfidence := []License{}
	for _, dl := range detectedLicenses {
		s := ""
		// This is heuristics, but we want to ignore licenses with a confidence lower than a threshold
		if !IsLicenseMatchConfident(dl) {
			s = " low-confidence"
			lowConfidence = append(lowConfidence, dl)
		}
		log.Infof("  %s: %s (%f%s) (%s)", dl.Source, dl.Name, dl.Confidence, s, dl.Type)
	}

	// TODO: Handle low-confidence licenses, possibly by printing out info about those separately!

	var diffs []LicenseDiff
	if cfg != nil {
		log.Infof("checking gathered license information against the configuration")

		// Turn the melange licensing information into a coherent licensing list, similar to what detection returns
		melangeLicenses := gatherMelangeLicenses(ctx, cfg)

		// Now let's check if the detected licenses are in the configuration
		diffs = getLicenseDifferences(detectedLicenses, melangeLicenses)

		// Print out the license differences
		if len(diffs) > 0 {
			log.Warnf("detected license differences:")
			for _, diff := range diffs {
				switch {
				case diff.Is == "":
					log.Warnf("  %s: %s not found", diff.Path, diff.Should)
				case diff.Override != "":
					log.Warnf("  %s: requested override from %s to %s, but now detecting as %s", diff.Path, diff.Override, diff.Is, diff.Should)
				default:
					log.Warnf("  %s: %s != %s", diff.Path, diff.Should, diff.Is)
				}

				if diff.NewType != "unencumbered" && diff.NewType != "notice" {
					log.Warnf("  NOTE! %s: %s might be a restrictive license, please proceed with caution", diff.Path, diff.Should)
				}
			}
			log.Warnf("detected license differences, please check the configuration")
		} else {
			log.Warnf("no license differences detected")
		}
	}

	if len(lowConfidence) > 0 {
		log.Warnf("following license files could not be confidently assessed:")
		for _, dl := range lowConfidence {
			log.Warnf("  %s: %s (%f) (%s)", dl.Source, dl.Name, dl.Confidence, dl.Type)
		}
		log.Warnf("could not identify some licenses, please check the configuration")
	}

	log.Infof("license information check complete")

	return detectedLicenses, diffs, nil
}

// gatherMelangeLicenses gathers the licenses from the melange configuration and
// splits them into separate entries.
//
// A declaration is an SPDX expression, so the identifiers it exposes a consumer
// to are read by parsing it rather than by splitting on the operators. That
// keeps a parenthesised or WITH-qualified expression readable, and it takes
// every branch of an OR, because the declaration does not say which branch the
// package was taken under.
func gatherMelangeLicenses(ctx context.Context, cfg *config.Configuration) []License {
	log := clog.FromContext(ctx)

	mls := []License{}
	for _, ml := range cfg.Package.Copyright {
		ids := []string{ml.License}
		if expr, err := spdx.Parse(ml.License); err == nil {
			ids = expr.Identifiers()
		} else if ml.License != "" {
			// An unparseable declaration is still reported as declared, so the
			// disagreement is attributed to what was written rather than
			// disappearing.
			log.Warnf("could not parse declared license %q: %v", ml.License, err)
		}

		// Detection reports a declared file under its cleaned path, so the
		// declaration is compared under the same one. An empty path stays
		// empty: it marks a declaration for the whole package, and path.Clean
		// would make it ".".
		source := ml.LicensePath
		if source != "" {
			source = path.Clean(source)
		}
		for _, id := range ids {
			mls = append(mls, License{
				Name:      id,
				Source:    source,
				Overrides: ml.DetectionOverride,
			})
		}
	}
	return mls
}

// getLicenseDifferences compares the detected licenses with the melange licenses and returns the differences.
func getLicenseDifferences(detectedLicenses []License, melangeLicenses []License) []LicenseDiff {
	diffs := []LicenseDiff{}
	for _, dl := range detectedLicenses {
		// This is heuristics, but we want to ignore licenses with a confidence lower than a threshold
		if !IsLicenseMatchConfident(dl) {
			continue
		}

		found := false
		for _, ml := range melangeLicenses {
			if dl.Source == ml.Source {
				// Check if the license matches the license path
				if dl.Name == ml.Name {
					found = true
				} else {
					// Check if we consciously know about the difference and just override it
					if ml.Overrides == "" || ml.Overrides != dl.Name {
						// If not, then it is a mismatch: add it to license differences
						diffs = append(diffs, LicenseDiff{
							dl.Source,
							ml.Name,
							dl.Name,
							ml.Overrides,
							dl.Type,
						})
					}
					// We already added the diff, so we can break out of the loop
					found = true
					break
				}
			} else if ml.Source == "" {
				// Check if the license matches the license path
				if dl.Name == ml.Name {
					found = true
				}
			}
		}

		if !found {
			// We didn't find a match, add it to license differences
			diffs = append(diffs, LicenseDiff{
				dl.Source,
				"",
				dl.Name,
				"",
				dl.Type,
			})
		}
	}
	return diffs
}
