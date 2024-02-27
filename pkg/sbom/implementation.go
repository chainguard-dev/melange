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

// Some of this code is based on the bom tool scan code originally
// found at https://github.com/kubernetes-sigs/bom/blob/main/pkg/spdx/implementation.go

package sbom

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chainguard-dev/clog"
	"github.com/github/go-spdx/v2/spdxexp"
	purl "github.com/package-url/packageurl-go"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"sigs.k8s.io/release-utils/hash"
	"sigs.k8s.io/release-utils/version"

	"chainguard.dev/apko/pkg/sbom/generator/spdx"
)

var validIDCharsRe = regexp.MustCompile(`[^a-zA-Z0-9-.]+`)

func stringToIdentifier(in string) (out string) {
	in = strings.ReplaceAll(in, ":", "-")
	in = strings.ReplaceAll(in, "/", "-")
	return validIDCharsRe.ReplaceAllStringFunc(in, func(s string) string {
		r := ""
		for i := 0; i < len(s); i++ {
			uc, _ := utf8.DecodeRuneInString(string(s[i]))
			r = fmt.Sprintf("%sC%d", r, uc)
		}
		return r
	})
}

func checkEnvironment(spec *Spec) (bool, error) {
	dirPath, err := filepath.Abs(spec.Path)
	if err != nil {
		return false, fmt.Errorf("getting absolute directory path: %w", err)
	}

	// Check if directory exists
	if _, err := os.Stat(dirPath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("checking if working directory exists: %w", err)
	}

	return true, nil
}

// generateAPKPackage generates the sbom package representing the apk
func generateAPKPackage(spec *Spec) (pkg, error) {
	if spec.PackageName == "" {
		return pkg{}, errors.New("unable to generate package, name not specified")
	}

	newPackage := pkg{
		id:               stringToIdentifier(fmt.Sprintf("%s-%s", spec.PackageName, spec.PackageVersion)),
		FilesAnalyzed:    false,
		Name:             spec.PackageName,
		Version:          spec.PackageVersion,
		Relationships:    []relationship{},
		LicenseDeclared:  spdx.NOASSERTION,
		LicenseConcluded: spdx.NOASSERTION, // remove when omitted upstream
		Copyright:        spec.Copyright,
		Namespace:        spec.Namespace,
		Arch:             spec.Arch,
		Originator:       "Organization: " + cases.Title(language.English).String(spec.Namespace),
	}

	if spec.License != "" {
		newPackage.LicenseDeclared = spec.License
	}

	return newPackage, nil
}

// scanFiles reads the files to be packaged in the apk and
// extracts the required data for the SBOM.
func scanFiles(spec *Spec, dirPackage *pkg) error {
	dirPath, err := filepath.Abs(spec.Path)
	if err != nil {
		return fmt.Errorf("getting absolute directory path: %w", err)
	}
	fileList, err := getDirectoryTree(dirPath)
	if err != nil {
		return fmt.Errorf("building directory tree: %w", err)
	}

	dirPackage.FilesAnalyzed = true

	var g errgroup.Group
	g.SetLimit(4)

	files := make([]file, len(fileList))
	for i, path := range fileList {
		i, path := i, path

		g.Go(func() error {
			f := file{
				id:            stringToIdentifier(path),
				Name:          strings.TrimPrefix(path, "/"),
				Checksums:     map[string]string{},
				Relationships: []relationship{},
			}

			// Hash the file contents
			for algo, fn := range map[string]func(string) (string, error){
				"SHA1":   hash.SHA1ForFile,
				"SHA256": hash.SHA256ForFile,
				"SHA512": hash.SHA512ForFile,
			} {
				csum, err := fn(filepath.Join(dirPath, path))
				if err != nil {
					return fmt.Errorf("hashing %s file %s: %w", algo, path, err)
				}
				f.Checksums[algo] = csum
			}

			files[i] = f
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	// Sort the resulting dataset to ensure deterministic order
	// to ensure builds are reproducible.
	slices.SortFunc(files, func(a, b file) int {
		return strings.Compare(a.Name, b.Name)
	})

	// Add files into the package
	for _, f := range files {
		// TODO: Remove me when loopvar stuff lands.
		target := f

		rel := relationship{
			Source: dirPackage,
			Type:   "CONTAINS",
		}

		rel.Target = &target

		dirPackage.Relationships = append(dirPackage.Relationships, rel)
	}
	return nil
}

func computeVerificationCode(hashList []string) string {
	// Sort the strings:
	sort.Strings(hashList)
	h := sha1.New()
	if _, err := h.Write([]byte(strings.Join(hashList, ""))); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// addPackage adds a package to the document
func addPackage(doc *spdx.Document, p *pkg) {
	spdxPkg := spdx.Package{
		ID:                   p.ID(),
		Name:                 p.Name,
		Version:              p.Version,
		FilesAnalyzed:        false,
		HasFiles:             []string{},
		LicenseConcluded:     p.LicenseConcluded,
		LicenseDeclared:      p.LicenseDeclared,
		DownloadLocation:     spdx.NOASSERTION,
		LicenseInfoFromFiles: []string{},
		CopyrightText:        p.Copyright,
		Checksums:            []spdx.Checksum{},
		ExternalRefs:         []spdx.ExternalRef{},
		Originator:           p.Originator,
	}

	algos := []string{}
	for algo := range p.Checksums {
		algos = append(algos, algo)
	}
	sort.Strings(algos)
	for _, algo := range algos {
		spdxPkg.Checksums = append(spdxPkg.Checksums, spdx.Checksum{
			Algorithm: algo,
			Value:     p.Checksums[algo],
		})
	}

	// We need to cycle all files to add them to the package
	// regardless if they are related else where in the doc.
	// We also need to capture their hashes to produce the
	// verification code
	hashList := []string{}
	excluded := []string{}
	for _, rel := range p.Relationships {
		if f, ok := rel.Target.(*file); ok {
			spdxPkg.HasFiles = append(spdxPkg.HasFiles, f.ID())
			if h, ok := f.Checksums["SHA1"]; ok {
				hashList = append(hashList, h)
			} else {
				excluded = append(excluded, f.ID())
			}
		}
	}

	verificationCode := computeVerificationCode(hashList)
	if verificationCode != "" {
		spdxPkg.VerificationCode = &spdx.PackageVerificationCode{
			Value: verificationCode,
		}
		spdxPkg.FilesAnalyzed = true
		if len(excluded) > 0 {
			spdxPkg.VerificationCode.ExcludedFiles = excluded
		}
	}

	// Add the purl to the package
	if p.Namespace != "" {
		var q purl.Qualifiers
		if p.Arch != "" {
			q = purl.QualifiersFromMap(
				map[string]string{"arch": p.Arch},
			)
		}
		spdxPkg.ExternalRefs = append(spdxPkg.ExternalRefs, spdx.ExternalRef{
			Category: "PACKAGE_MANAGER",
			Locator: purl.NewPackageURL(
				"apk", p.Namespace, p.Name, p.Version, q, "",
			).ToString(),
			Type: "purl",
		})
	}

	doc.Packages = append(doc.Packages, spdxPkg)

	// Cycle the related objects and add them
	for _, rel := range p.Relationships {
		if sbomHasRelationship(doc, rel) {
			continue
		}
		switch v := rel.Target.(type) {
		case *file:
			addFile(doc, v)
		case *pkg:
			addPackage(doc, v)
		}
		doc.Relationships = append(doc.Relationships, spdx.Relationship{
			Element: rel.Source.ID(),
			Type:    rel.Type,
			Related: rel.Target.ID(),
		})
	}
}

func addFile(doc *spdx.Document, f *file) {
	spdxFile := spdx.File{
		ID:                f.ID(),
		Name:              f.Name,
		LicenseConcluded:  spdx.NOASSERTION,
		FileTypes:         []string{},
		LicenseInfoInFile: []string{},
		Checksums:         []spdx.Checksum{},
	}

	algos := []string{}
	for algo := range f.Checksums {
		algos = append(algos, algo)
	}
	sort.Strings(algos)
	for _, algo := range algos {
		spdxFile.Checksums = append(spdxFile.Checksums, spdx.Checksum{
			Algorithm: algo,
			Value:     f.Checksums[algo],
		})
	}

	doc.Files = append(doc.Files, spdxFile)

	// Cycle the related objects and add them
	for _, rel := range f.Relationships {
		if sbomHasRelationship(doc, rel) {
			continue
		}
		switch v := rel.Target.(type) {
		case *file:
			addFile(doc, v)
		case *pkg:
			addPackage(doc, v)
		}
	}
}

// sbomHasRelationship takes a relationship and an SPDX sbom and heck if
// it already has it in its rel catalog
func sbomHasRelationship(spdxDoc *spdx.Document, bomRel relationship) bool {
	for _, spdxRel := range spdxDoc.Relationships {
		if spdxRel.Element == bomRel.Source.ID() && spdxRel.Related == bomRel.Target.ID() && spdxRel.Type == bomRel.Type {
			return true
		}
	}
	return false
}

// buildDocumentSPDX creates an SPDX 2.3 document from our generic representation
func buildDocumentSPDX(ctx context.Context, spec *Spec, doc *bom) (*spdx.Document, error) {
	log := clog.FromContext(ctx)

	h := sha1.New()
	h.Write([]byte(fmt.Sprintf("apk-%s-%s", spec.PackageName, spec.PackageVersion)))

	spdxDoc := spdx.Document{
		ID:      "SPDXRef-DOCUMENT",
		Name:    fmt.Sprintf("apk-%s-%s", spec.PackageName, spec.PackageVersion),
		Version: "SPDX-2.3",
		CreationInfo: spdx.CreationInfo{
			Created: spec.SourceDateEpoch.Format(time.RFC3339),
			Creators: []string{
				fmt.Sprintf("Tool: melange (%s)", version.GetVersionInfo().GitVersion),
				"Organization: Chainguard, Inc",
			},
			LicenseListVersion: "3.22", // https://spdx.org/licenses/
		},
		DataLicense:          "CC0-1.0",
		Namespace:            "https://spdx.org/spdxdocs/chainguard/melange/" + hex.EncodeToString(h.Sum(nil)),
		DocumentDescribes:    []string{},
		Files:                []spdx.File{},
		Packages:             []spdx.Package{},
		Relationships:        []spdx.Relationship{},
		ExternalDocumentRefs: []spdx.ExternalDocumentRef{},
	}

	if spec.License == "" {
		log.Warnf("no license specified, defaulting to %s", spdx.NOASSERTION)
	} else {
		valid, bad := spdxexp.ValidateLicenses([]string{spec.License})
		if !valid {
			log.Warnf("invalid license: %s", strings.Join(bad, ", "))
		}
	}

	for _, p := range doc.Packages {
		spdxDoc.DocumentDescribes = append(spdxDoc.DocumentDescribes, stringToIdentifier(p.ID()))
		addPackage(&spdxDoc, &p)
	}

	for _, f := range doc.Files {
		spdxDoc.DocumentDescribes = append(spdxDoc.DocumentDescribes, stringToIdentifier(f.ID()))
		addFile(&spdxDoc, &f)
	}
	return &spdxDoc, nil
}

// writeSBOM writes the SBOM to the apk filesystem
func writeSBOM(ctx context.Context, spec *Spec, doc *bom) error {
	spdxDoc, err := buildDocumentSPDX(ctx, spec, doc)
	if err != nil {
		return fmt.Errorf("building SPDX document: %w", err)
	}

	dirPath, err := filepath.Abs(spec.Path)
	if err != nil {
		return fmt.Errorf("getting absolute directory path: %w", err)
	}

	apkSBOMdir := "/var/lib/db/sbom"
	if err := os.MkdirAll(filepath.Join(dirPath, apkSBOMdir), os.FileMode(0755)); err != nil {
		return fmt.Errorf("creating SBOM directory in apk filesystem: %w", err)
	}

	apkSBOMpath := filepath.Join(
		dirPath, apkSBOMdir,
		fmt.Sprintf("%s-%s.spdx.json", spec.PackageName, spec.PackageVersion),
	)
	f, err := os.Create(apkSBOMpath)
	if err != nil {
		return fmt.Errorf("opening SBOM file for writing: %w", err)
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(true)

	if err := enc.Encode(spdxDoc); err != nil {
		return fmt.Errorf("encoding spdx sbom: %w", err)
	}

	return nil
}

// getDirectoryTree reads a directory and returns a list of strings of all files init
func getDirectoryTree(dirPath string) ([]string, error) {
	fileList := []string{}

	if err := fs.WalkDir(os.DirFS(dirPath), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		if d.Type() == os.ModeSymlink {
			return nil
		}

		fileList = append(fileList, filepath.Join(string(filepath.Separator), path))
		return nil
	}); err != nil {
		return nil, fmt.Errorf("buiding directory tree: %w", err)
	}
	sort.Strings(fileList)
	return fileList, nil
}
