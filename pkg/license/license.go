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
	"sort"
	"strings"

	"chainguard.dev/melange/pkg/config"
	"github.com/chainguard-dev/clog"
	golicenses "github.com/google/go-licenses/v2/licenses"
	licenseclassifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
)

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
}

// LicenseFile represents a license file, with its name, path, and relevance score.
type LicenseFile struct {
	Name   string
	Path   string
	Weight float64
}

// LicenseDiff represents a difference between the detected license and the expected license.
type LicenseDiff struct {
	Path   string
	Is     string
	Should string
}

// Identify identifies the license of a file on a filesystem using the licenseclassifier.
func (c *melangeClassifier) Identify(fsys fs.FS, licensePath string) ([]License, error) {
	if licensePath == "" {
		return nil, nil
	}

	file, err := fsys.Open(licensePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	matches, err := c.classifier.MatchFrom(file)
	if err != nil {
		return nil, err
	}

	foundLicenseNames := map[string]struct{}{}

	licenses := []License{}
	for _, match := range matches.Matches {
		if match.MatchType != "License" {
			continue
		}

		// Skip duplicate licenses.
		if _, ok := foundLicenseNames[match.Name]; ok {
			continue
		}
		foundLicenseNames[match.Name] = struct{}{}

		licenses = append(licenses, License{
			Name:       match.Name,
			Type:       golicenses.LicenseType(match.Name),
			Confidence: match.Confidence,
			Source:     licensePath,
		})
	}

	return licenses, nil
}

// FindLicenseFiles returns a list of license files in a directory, sorted by their relevance score.
func FindLicenseFiles(fsys fs.FS) ([]LicenseFile, error) {
	// Copied and adjusted from Ruby to Go from the "licensee" project
	var (
		preferredExt      = []string{"md", "markdown", "txt", "html"}
		ignoredExt        = []string{"xml", "go", "gemspec", "spdx", "header"}
		preferredExtRegex = regexp.MustCompile(`\.(?:` + regexp.QuoteMeta(preferredExt[0]) + `|` + regexp.QuoteMeta(preferredExt[1]) + `|` + regexp.QuoteMeta(preferredExt[2]) + `|` + regexp.QuoteMeta(preferredExt[3]) + `)$`)
		anyExtRegex       = regexp.MustCompile(`(\.[^./]+$)`)
		licenseRegex      = regexp.MustCompile(`(?i)(un)?licen[sc]e`)
		copyingRegex      = regexp.MustCompile(`(?i)copy(ing|right)`)
		oflRegex          = regexp.MustCompile(`(?i)ofl`)
		patentsRegex      = regexp.MustCompile(`(?i)patents`)
		filenameRegexes   = map[*regexp.Regexp]float64{
			regexp.MustCompile(`(?i)^` + licenseRegex.String() + `$`):                                          1.00, // LICENSE
			regexp.MustCompile(`(?i)^` + licenseRegex.String() + preferredExtRegex.String() + `$`):             0.95, // LICENSE.md
			regexp.MustCompile(`(?i)^` + copyingRegex.String() + `$`):                                          0.90, // COPYING
			regexp.MustCompile(`(?i)^` + copyingRegex.String() + preferredExtRegex.String() + `$`):             0.85, // COPYING.md
			regexp.MustCompile(`(?i)^` + licenseRegex.String() + anyExtRegex.String() + `$`):                   0.80, // LICENSE.textile
			regexp.MustCompile(`(?i)^` + copyingRegex.String() + anyExtRegex.String() + `$`):                   0.75, // COPYING.textile
			regexp.MustCompile(`(?i)^` + licenseRegex.String() + `[-_][^.]*` + anyExtRegex.String() + `?$`):    0.70, // LICENSE-MIT
			regexp.MustCompile(`(?i)^` + copyingRegex.String() + `[-_][^.]*` + anyExtRegex.String() + `?$`):    0.65, // COPYING-MIT
			regexp.MustCompile(`(?i)^\w+[-_]` + licenseRegex.String() + `[^.]*` + anyExtRegex.String() + `?$`): 0.60, // MIT-LICENSE-MIT
			regexp.MustCompile(`(?i)^\w+[-_]` + copyingRegex.String() + `[^.]*` + anyExtRegex.String() + `?$`): 0.55, // MIT-COPYING
			regexp.MustCompile(`(?i)^` + oflRegex.String() + preferredExtRegex.String()):                       0.50, // OFL.md
			regexp.MustCompile(`(?i)^` + oflRegex.String() + anyExtRegex.String()):                             0.45, // OFL.textile
			regexp.MustCompile(`(?i)^` + oflRegex.String() + `$`):                                              0.40, // OFL
			regexp.MustCompile(`(?i)^` + patentsRegex.String() + `$`):                                          0.35, // PATENTS
			regexp.MustCompile(`(?i)^` + patentsRegex.String() + anyExtRegex.String() + `$`):                   0.30, // PATENTS.txt
		}
	)

	var licenseFiles []LicenseFile
	var ignore bool

	err := fs.WalkDir(fsys, ".", func(filePath string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Let's ignore all files in the melange-out/ directory, as it's not part of the source
		if strings.Contains(filePath, "melange-out") {
			return nil
		}

		// Check if the file matches any of the license-related regex patterns
		for regex, weight := range filenameRegexes {
			if regex.MatchString(info.Name()) {
				for _, ext := range ignoredExt {
					if ignore = strings.HasSuffix(info.Name(), ext); ignore {
						break
					}
				}
				if ignore {
					continue
				}

				// Licenses in the top level directory have a higher weight
				if filepath.Dir(filePath) == "." {
					weight += 0.5
				}

				licenseFiles = append(licenseFiles, LicenseFile{
					Name:   info.Name(),
					Path:   filePath,
					Weight: weight,
				})
				break
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sort the license files by their 'score' (weight)
	sort.Slice(licenseFiles, func(i, j int) bool {
		return licenseFiles[i].Weight > licenseFiles[j].Weight
	})

	return licenseFiles, nil
}

// melangeLicenseToLicense is a helper that converts a melange license info to a License struct.
func melangeLicenseToLicense(license string, licensePath string) License {
	return License{
		Name:       license,
		Type:       "",
		Confidence: 0.0,
		Source:     licensePath,
	}
}

// LicenseCheck checks the licenses of the files in the given filesystem against the melange configuration.
func LicenseCheck(ctx context.Context, cfg *config.Configuration, fsys fs.FS) ([]LicenseDiff, error) {
	log := clog.FromContext(ctx)

	// Find all license-text files
	licenseFiles, err := FindLicenseFiles(fsys)
	if err != nil {
		return nil, fmt.Errorf("finding license files: %w", err)
	}

	if len(licenseFiles) == 0 {
		// No license files detected, no linting performed.
		return nil, nil
	}

	classifier, err := NewClassifier()
	if err != nil {
		return nil, fmt.Errorf("creating classifier: %w", err)
	}

	melangeClassifier := classifier.(*melangeClassifier)

	log.Infof("detected the following licenses in the source code:")
	detectedLicenses := []License{}
	for _, lf := range licenseFiles {
		dl, err := melangeClassifier.Identify(fsys, lf.Path)
		if err != nil {
			return nil, fmt.Errorf("identifying license: %w", err)
		}

		// Print out the licensing information
		for _, l := range dl {
			s := ""
			// This is heuristics, but we want to ignore licenses with a confidence lower than a threshold
			if l.Confidence < 0.9 {
				s = " ignored"
			}
			log.Infof("  %s: %s (%f%s)", l.Source, l.Name, l.Confidence, s)

			if s == "" {
				detectedLicenses = append(detectedLicenses, l)
			}
		}
	}

	log.Infof("checking gathered license information against the configuration")

	// Let's first turn the melange licensing information into a coherent licensing list, similar to what Identify returns
	// We first start off by splitting license information that has OR and AND into separate license entries
	// Every entry can have multiple AND or ORs
	melangeLicenses := []License{}
	for _, ml := range cfg.Package.Copyright {
		if strings.Contains(ml.License, " OR ") || strings.Contains(ml.License, " AND ") {
			// Split the license into separate entries using regexp
			splitLicenses := regexp.MustCompile(`\s+( AND | OR )\s+`).Split(ml.License, -1)
			for _, sl := range splitLicenses {
				melangeLicenses = append(melangeLicenses, melangeLicenseToLicense(sl, ml.LicensePath))
			}
		} else {
			melangeLicenses = append(melangeLicenses, melangeLicenseToLicense(ml.License, ml.LicensePath))
		}
	}

	// Now let's check if the detected licenses are in the configuration
	diffs := []LicenseDiff{}
	for _, dl := range detectedLicenses {
		found := false
		for _, ml := range melangeLicenses {
			if dl.Source == ml.Source {
				// Check if the license matches the license path
				if dl.Name == ml.Name {
					found = true
				} else {
					// A mismatch, add it to license differences
					diffs = append(diffs, LicenseDiff{
						dl.Source,
						ml.Name,
						dl.Name,
					})
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
			})
		}
	}

	// Print out the license differences
	if len(diffs) > 0 {
		log.Warnf("detected license differences:")
		for _, diff := range diffs {
			if diff.Is == "" {
				log.Warnf("  %s: %s not found", diff.Path, diff.Should)
			} else {
				log.Warnf("  %s: %s != %s", diff.Path, diff.Should, diff.Is)
			}
		}
		log.Warnf("detected license differences, please check the configuration")
	} else {
		log.Infof("no license differences detected")
	}

	return diffs, nil
}
