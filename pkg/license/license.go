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

package license

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/chainguard-dev/clog"
	golicenses "github.com/google/go-licenses/v2/licenses"
	licenseclassifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"

	"chainguard.dev/melange/pkg/config"
)

// NOTE: the detection logic is done via a Classifier type as this is how it was
// implemented, for instance, in the go-licenses project (also using licenseclassifier).

// Classifier can detect the type of a software license.
type Classifier interface {
	Identify(fsys fs.FS, licensePath string) ([]License, error)
}

type melangeClassifier struct {
	classifier *licenseclassifier.Classifier
}

// NewClassifier creates a license classifier.
func NewClassifier() (Classifier, error) {
	c, err := assets.DefaultClassifier()
	if err != nil {
		return nil, err
	}
	return &melangeClassifier{classifier: c}, nil
}

// License represents a software license, as detected by licenseclassifier.
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

// Identify identifies the license of a file on a filesystem using the licenseclassifier.
func (c *melangeClassifier) Identify(fsys fs.FS, licensePath string) ([]License, error) {
	file, err := fsys.Open(licensePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	matches, err := c.classifier.MatchFrom(file)
	if err != nil {
		return nil, err
	}

	// Go through all the matches and filter out the ones that are not licenses
	// and also filter out duplicates
	foundLicenseNames := map[string]struct{}{}
	licenses := []License{}
	for _, match := range matches.Matches {
		if match.MatchType != "License" {
			continue
		}

		// Skip duplicate licenses
		if _, ok := foundLicenseNames[match.Name]; ok {
			continue
		}
		foundLicenseNames[match.Name] = struct{}{}

		licenses = append(licenses, License{
			Name:       match.Name,
			Type:       golicenses.LicenseType(match.Name),
			Confidence: match.Confidence,
			Source:     licensePath,
			Overrides:  "",
		})
	}

	// No license found, append a no-assertion entry
	if len(licenses) == 0 {
		licenses = append(licenses, License{
			Name:       "NOASSERTION",
			Confidence: 0.0,
			Source:     licensePath,
		})
	}

	return licenses, nil
}

// FindLicenseFiles returns a list of license files in a directory, sorted by their relevance score.
func FindLicenseFiles(fsys fs.FS) ([]LicenseFile, error) {
	// This file is using regular expressions defined in the regexp.go file
	var licenseFiles []LicenseFile
	err := fs.WalkDir(fsys, ".", func(filePath string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip directories and non-regular files, like symlinks
		if !info.Type().IsRegular() {
			return nil
		}
		// Let's ignore all files in the melange-out/ directory, as it's not part of the source
		if strings.Contains(filePath, "melange-out") {
			return nil
		}

		is, weight := IsLicenseFile(filePath, false)
		if is {
			// Licenses in the top level directory have a higher weight so that they
			// always appear first
			if filepath.Dir(filePath) == "." {
				weight += 0.5
			}
			licenseFiles = append(licenseFiles, LicenseFile{
				Name:   info.Name(),
				Path:   filePath,
				Weight: weight,
			})
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sort the license files by their 'score' (weight)
	// The order isn't necesasrily important, but we want to have the most relevant files first
	sort.SliceStable(licenseFiles, func(i, j int) bool {
		return licenseFiles[i].Weight > licenseFiles[j].Weight
	})

	return licenseFiles, nil
}

// IsLicenseFile checks if a file is a license file based on its name.
// Returns true/fals if the file is a license file, and the weight value
// associated with the match, as some matches are potentially more relevant.
// overrideIgnore skips over ignored paths to allow linters
// to correctly determine whether a path is a valid license file
// (e.g., to avoid listing each instance of a given LICENSE file as a duplicate)
func IsLicenseFile(filename string, overrideIgnore bool) (bool, float64) {
	// Ignore files in these paths

	// Packages like Rust embed the semver in certain paths, so replace the segment with `-`
	// rust-1.86.0-src -> rust-src
	re := regexp.MustCompile(`\-\d+\.\d+\.\d+\-`)
	filename = re.ReplaceAllString(filename, "-")

	ignoredPaths := []string{
		".virtualenv",
		"env",
		"node_modules",
		"rust-src",
		"rustc-src",
		"venv",
	}
	if !overrideIgnore {
		for _, i := range ignoredPaths {
			if slices.Contains(strings.Split(filename, string(filepath.Separator)), i) {
				return false, 0.0
			}
		}
	}

	// normalize to file name only
	filename = filepath.Base(filename)

	filenameExt := filepath.Ext(filename)
	// Check if the file matches any of the license-related regex patterns
	for regex, weight := range filenameRegexes {
		if !regex.MatchString(filename) {
			continue
		}
		// licensee does this check as part of the regex, but in go we don't have
		// the same regex capabilities
		if slices.Contains(ignoredExt, filenameExt) {
			continue
		}
		return true, weight
	}
	return false, 0.0
}

// CollectLicenseInfo collects license information from the given filesystem.
func CollectLicenseInfo(ctx context.Context, fsys fs.FS) ([]License, error) {
	log := clog.FromContext(ctx)

	// Find all license-text files
	licenseFiles, err := FindLicenseFiles(fsys)
	if err != nil {
		return nil, fmt.Errorf("finding license files: %w", err)
	}

	if len(licenseFiles) == 0 {
		// No license files detected, no linting performed.
		log.Debugf("no license files detected")
		return nil, nil
	}

	classifier, err := NewClassifier()
	if err != nil {
		return nil, fmt.Errorf("creating classifier: %w", err)
	}

	melangeClassifier := classifier.(*melangeClassifier)
	detectedLicenses := []License{}
	for _, lf := range licenseFiles {
		dl, err := melangeClassifier.Identify(fsys, lf.Path)
		if err != nil {
			return nil, fmt.Errorf("identifying license: %w", err)
		}

		log.Debugf("detected licenses %v in %s", dl, lf.Path)
		detectedLicenses = append(detectedLicenses, dl...)
	}

	return detectedLicenses, nil
}

// IsLicenseMatchConfident checks if the license match is confident enough to be considered valid.
func IsLicenseMatchConfident(dl License) bool {
	// This is heuristics, but we want to ignore licenses with a confidence lower than a threshold
	// We'll make this configurable in the future
	return dl.Confidence >= 0.9
}

// LicenseCheck checks the licenses of the files in the given filesystem against the melange configuration.
func LicenseCheck(ctx context.Context, cfg *config.Configuration, fsys fs.FS) ([]License, []LicenseDiff, error) {
	log := clog.FromContext(ctx)
	log.Infof("checking license information")

	detectedLicenses, err := CollectLicenseInfo(ctx, fsys)
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

		// Let's first turn the melange licensing information into a coherent licensing list, similar to what Identify returns
		// We first start off by splitting license information that has OR and AND into separate license entries
		// Every entry can have multiple AND or ORs
		melangeLicenses := gatherMelangeLicenses(cfg)

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

// gatherMelangeLicenses gathers the licenses from the melange configuration and splits them into separate entries.
func gatherMelangeLicenses(cfg *config.Configuration) []License {
	mls := []License{}
	for _, ml := range cfg.Package.Copyright {
		if strings.Contains(ml.License, " OR ") || strings.Contains(ml.License, " AND ") {
			// Split the license into separate entries using regexp
			sls := regexp.MustCompile(`\s+(AND|OR)\s+`).Split(ml.License, -1)
			for _, sl := range sls {
				mls = append(mls,
					License{
						Name:      sl,
						Source:    ml.LicensePath,
						Overrides: ml.DetectionOverride,
					})
			}
		} else {
			mls = append(mls,
				License{
					Name:      ml.License,
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
