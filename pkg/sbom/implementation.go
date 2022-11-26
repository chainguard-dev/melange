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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"chainguard.dev/apko/pkg/sbom/generator/spdx"
	"golang.org/x/sync/errgroup"
	"sigs.k8s.io/release-utils/hash"
	"sigs.k8s.io/release-utils/version"
)

type generatorImplementation interface {
	GenerateDocument(*Spec) (*bom, error)
	GenerateAPKPackage(*Spec) (pkg, error)
	ScanFiles(*Spec, *pkg) error
	ScanLicenses(*Spec, *bom) error
	ReadDependencyData(*Spec, *bom, string) error
	WriteSBOM(*Spec, *bom) error
}

type defaultGeneratorImplementation struct{}

func (di *defaultGeneratorImplementation) GenerateDocument(spec *Spec) (*bom, error) {
	return &bom{
		Packages: []pkg{},
		Files:    []file{},
	}, nil
}

// GenerateAPKPackage generates the sbom package representing the apk
func (di *defaultGeneratorImplementation) GenerateAPKPackage(spec *Spec) (pkg, error) {
	if spec.PackageName == "" {
		return pkg{}, errors.New("unable to generate package, name not specified")
	}
	newPackage := pkg{
		FilesAnalyzed:    false,
		Name:             spec.PackageName,
		Version:          spec.PackageVersion,
		Relationships:    []relationship{},
		LicenseDeclared:  spdx.NOASSERTION,
		LicenseConcluded: spdx.NOASSERTION, // remove when omitted upstream
		Copyright:        spec.Copyright,
	}

	if spec.License != "" {
		newPackage.LicenseDeclared = spec.License
	}

	return newPackage, nil
}

// ScanFiles reads the files to be packaged in the apk and
// extracts the required data for the SBOM.
func (di *defaultGeneratorImplementation) ScanFiles(spec *Spec, dirPackage *pkg) error {
	dirPath, err := filepath.Abs(spec.Path)
	if err != nil {
		return fmt.Errorf("getting absolute directory path: %w", err)
	}
	fileList, err := getDirectoryTree(dirPath)
	if err != nil {
		return fmt.Errorf("building directory tree: %w", err)
	}

	// logrus.Debugf("Scanning %d files and adding them to the SPDX package", len(fileList))

	dirPackage.FilesAnalyzed = true

	g, _ := errgroup.WithContext(context.Background())
	files := sync.Map{}
	for _, path := range fileList {
		path := path
		g.Go(func() error {
			f := file{
				Name:          path,
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

			files.Store(path, f)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	// Add files into the package
	files.Range(func(key, f any) bool {

		rel := relationship{
			Source: dirPackage,
			Type:   "CONTAINS",
		}

		switch v := f.(type) {
		case file:
			rel.Target = &v
		case pkg:
			rel.Target = &v
		}

		dirPackage.Relationships = append(dirPackage.Relationships, rel)
		return true
	})
	return nil
}

func (di *defaultGeneratorImplementation) ScanLicenses(spec *Spec, doc *bom) error {
	return nil
}

func (di *defaultGeneratorImplementation) ReadDependencyData(spec *Spec, doc *bom, language string) error {
	return nil
}

func computeVerificationCode(hashList []string) string {
	// Sort the strings:
	sort.Strings(hashList)
	h := sha1.New()
	if _, err := h.Write([]byte(strings.Join(hashList, ""))); err != nil {
		// logrus.Error("getting SHA1 verification of files: %w", err)
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// addPackage adds a package to the document
func addPackage(doc *spdx.Document, p *pkg) {
	spdxPkg := spdx.Package{
		ID:            p.ID(),
		Name:          p.Name,
		Version:       p.Version,
		FilesAnalyzed: false,
		HasFiles:      []string{},
		// LicenseInfoFromFiles: []string{},
		LicenseConcluded: p.LicenseConcluded,
		LicenseDeclared:  p.LicenseDeclared,
		// Description:          "",
		// DownloadLocation:     "",
		// Originator:           "",
		// SourceInfo:           "",
		CopyrightText: p.Copyright,
		// PrimaryPurpose:       "",
		Checksums:    []spdx.Checksum{},
		ExternalRefs: []spdx.ExternalRef{},
		// VerificationCode: spdx.PackageVerificationCode{},
	}

	for algo, c := range p.Checksums {
		spdxPkg.Checksums = append(spdxPkg.Checksums, spdx.Checksum{
			Algorithm: algo,
			Value:     c,
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
		spdxPkg.VerificationCode.Value = verificationCode
		if len(excluded) > 0 {
			spdxPkg.VerificationCode.ExcludedFiles = excluded
		}
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
		ID:   f.ID(),
		Name: f.Name,
		//CopyrightText:     f.Copyright,
		// NoticeText:        "",
		//LicenseConcluded:  "",
		//Description:       "",
		FileTypes:         []string{},
		LicenseInfoInFile: []string{},
		Checksums:         []spdx.Checksum{},
	}

	for algo, c := range f.Checksums {
		spdxFile.Checksums = append(spdxFile.Checksums, spdx.Checksum{
			Algorithm: algo,
			Value:     c,
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

func (di *defaultGeneratorImplementation) WriteSBOM(spec *Spec, doc *bom) error {
	// Build the SBOM time, but respect SOURCE_DATE_EPOCH
	sbomTime := time.Now().UTC().Format(time.RFC3339)
	if v, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok {
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse SOURCE_DATE_EPOCH: %w", err)
		}

		t := time.Unix(sec, 0)
		sbomTime = t.UTC().Format(time.RFC3339)
	}

	spdxDoc := spdx.Document{
		ID:      fmt.Sprintf("SPDXRef-DOCUMENT-%s", fmt.Sprintf("apk-%s-%s", spec.PackageName, spec.PackageVersion)),
		Name:    fmt.Sprintf("apk-%s-%s", spec.PackageName, spec.PackageVersion),
		Version: "SPDX-2.3",
		CreationInfo: spdx.CreationInfo{
			Created: sbomTime,
			Creators: []string{
				fmt.Sprintf("Tool: melange (%s)", version.GetVersionInfo().GitVersion),
				"Organization: Chainguard, Inc",
			},
			LicenseListVersion: "3.18",
		},
		DataLicense:          "CC0-1.0",
		Namespace:            "https://spdx.org/spdxdocs/chainguard/melange/",
		DocumentDescribes:    []string{},
		Files:                []spdx.File{},
		Packages:             []spdx.Package{},
		Relationships:        []spdx.Relationship{},
		ExternalDocumentRefs: []spdx.ExternalDocumentRef{},
	}

	for _, p := range doc.Packages {
		spdxDoc.DocumentDescribes = append(spdxDoc.DocumentDescribes, p.ID())
		addPackage(&spdxDoc, &p)
	}

	for _, f := range doc.Files {
		spdxDoc.DocumentDescribes = append(spdxDoc.DocumentDescribes, f.ID())
		addFile(&spdxDoc, &f)
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

	mwriter := io.MultiWriter(os.Stderr, f)

	enc := json.NewEncoder(mwriter)
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

		fileList = append(fileList, path)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("buiding directory tree: %w", err)
	}
	return fileList, nil
}
