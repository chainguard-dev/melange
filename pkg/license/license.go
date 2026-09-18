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
// ranking a license by restrictiveness, and deciding what disagreement is worth
// warning about.
package license

import (
	"context"
	"fmt"
	"io/fs"
	"path"
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
// package keeps its own license; a deep scan reads the whole tree.
func scopeFor(deep bool) detect.Scope {
	if deep {
		return detect.ScopeTree
	}
	return detect.ScopeProject
}

// vendoredIntoBuild is the one dependency directory melange counts as part of
// the package. Vendoring copies a dependency's source into the build, so its
// terms are obligations the package carries and a deep scan reports them. A
// shallow scan still skips the directory, because it looks no deeper than one
// level below the root.
const vendoredIntoBuild = "vendor"

// describesPackage reports whether a discovered path describes the package
// being built rather than something sitting beside it.
//
// The dependency directories are the module's list rather than a copy of it,
// asked one segment at a time so that vendoring can be admitted without
// admitting the trees a build installed: a virtualenv, node_modules or a Rust
// standard library carries terms that are not this package's. Build output is
// refused outright, since melange stages each subpackage under melange-out/ in
// the same workspace and a license there is a copy of the answer this check is
// producing.
func describesPackage(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == vendoredIntoBuild {
			continue
		}
		if detect.ClassifyDirExclusion(seg) == detect.ExclusionVendored {
			return false
		}
	}
	return detect.ClassifyExclusion(p) != detect.ExclusionBuildOutput
}

// IsLicenseFile checks if a file is a license file based on its name.
// Returns true/false if the file is a license file, and the weight value
// associated with the match, as some matches are potentially more relevant.
// overrideIgnore considers the name alone, so that a caller asking "is this a
// license file" about a path outside the package's own source gets an answer
// about the name rather than about the location.
func IsLicenseFile(filename string, overrideIgnore bool) (bool, float64) {
	is, weight := detect.IsLicenseFile(filename)
	if !is {
		return false, 0.0
	}
	if !overrideIgnore && detect.ClassifyExclusion(filename) != detect.ExclusionNone {
		return false, 0.0
	}
	return true, weight
}

// FindLicenseFiles returns a list of license files in a directory, sorted by their relevance score.
// If deep is true, the entire tree is scanned. If deep is false, only the top directory and one level down are scanned,
// returning the list of most likely licenses of the project itself (not vendored dependencies)
func FindLicenseFiles(fsys fs.FS, deep bool) ([]LicenseFile, error) {
	found, err := detect.Find(fsys, scopeFor(deep))
	if err != nil {
		return nil, fmt.Errorf("finding license files: %w", err)
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

	res, err := detect.Detect(ctx, detect.Request{
		FS:       fsys,
		Scope:    scopeFor(deep),
		Declared: declarationsFrom(cfg),
	})
	if err != nil {
		return nil, fmt.Errorf("detecting licenses: %w", err)
	}

	for _, p := range res.Unreadable {
		log.Warnf("could not read %s while looking for license files", p)
	}

	detectedLicenses := []License{}
	for _, f := range res.Files {
		if !describesPackage(f.Path) {
			continue
		}
		// One unreadable file is not a reason to discard what the others carry,
		// so the failure is reported and the scan continues.
		if f.Err != "" {
			log.Warnf("could not classify %s: %s", f.Path, f.Err)
			continue
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

		for _, id := range ids {
			mls = append(mls, License{
				Name:      id,
				Source:    ml.LicensePath,
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
