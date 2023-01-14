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
	"bufio"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/korovkin/limiter"
	purl "github.com/package-url/packageurl-go"
	"gitlab.alpinelinux.org/alpine/go/repository"
	"sigs.k8s.io/release-utils/hash"
	"sigs.k8s.io/release-utils/version"

	"chainguard.dev/apko/pkg/sbom/generator/spdx"
)

const apkSBOMdir = "/var/lib/db/sbom"

type generatorImplementation interface {
	CheckEnvironment(*Spec) (bool, error)
	GenerateDocument(*Spec) (*bom, error)
	GenerateAPKPackage(*Spec) (pkg, error)
	ScanFiles(*Spec, *pkg) error
	ScanLicenses(*Spec, *bom) error
	ReadDependencyData(*Spec, *bom, string) error
	WriteSBOM(*Spec, *bom, string, string) error
	ReadPackageIndex(spec *Spec) ([]*pkg, error)
	ReadDistroID(spec *Spec) (string, error)
	GenerateBuildPackage(spec *Spec, packages []*pkg) (pkg, error)
}

type defaultGeneratorImplementation struct{}

func (di *defaultGeneratorImplementation) CheckEnvironment(spec *Spec) (bool, error) {
	dirPath, err := filepath.Abs(spec.Path)
	if err != nil {
		return false, fmt.Errorf("getting absolute directory path: %w", err)
	}

	// Check if directory exists
	if _, err := os.Stat(dirPath); err != nil {
		if os.IsNotExist(err) {
			// log "Working directory not found, probably apk is empty"
			return false, nil
		}
		return false, fmt.Errorf("checking if workind directory exists: %w", err)
	}

	return true, nil
}

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
		Namespace:        spec.Namespace,
		Arch:             spec.Arch,
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

	g := limiter.NewConcurrencyLimiterForIO(limiter.DefaultConcurrencyLimitIO)
	files := sync.Map{}
	for _, path := range fileList {
		path := path

		// nolint:errcheck
		g.Execute(func() {
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
					// nolint:errcheck
					g.FirstErrorStore(fmt.Errorf("hashing %s file %s: %w", algo, path, err))
				}
				f.Checksums[algo] = csum
			}

			files.Store(path, f)
		})
	}

	if err := g.WaitAndClose(); err != nil {
		return fmt.Errorf("waiting for limiter to finish: %w", err)
	}

	if err := g.FirstErrorGet(); err != nil {
		return err
	}

	// Sort the resulting dataset to ensure deterministic order
	// to ensure builds are reproducible.
	pathList := []string{}
	files.Range(func(key, _ any) bool {
		pathList = append(pathList, key.(string))
		return true
	})

	sort.Strings(pathList)

	// Add files into the package
	for _, path := range pathList {
		rel := relationship{
			Source: dirPackage,
			Type:   "CONTAINS",
		}

		f, ok := files.Load(path)
		if !ok {
			continue
		}

		switch v := f.(type) {
		case file:
			rel.Target = &v
		case pkg:
			rel.Target = &v
		}

		dirPackage.Relationships = append(dirPackage.Relationships, rel)
	}
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
func buildDocumentSPDX(spec *Spec, doc *bom) (*spdx.Document, error) {
	// Build the SBOM time, but respect SOURCE_DATE_EPOCH
	sbomTime := time.Now().UTC().Format(time.RFC3339)
	if v, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok {
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SOURCE_DATE_EPOCH: %w", err)
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
	return &spdxDoc, nil
}

// WriteSBOM writes the SBOM to the apk filesystem
func (di *defaultGeneratorImplementation) WriteSBOM(spec *Spec, doc *bom, packageName, fileName string) error {
	spdxDoc, err := buildDocumentSPDX(spec, doc)
	if err != nil {
		return fmt.Errorf("building SPDX document: %w", err)
	}

	dirPath, err := filepath.Abs(filepath.Join(spec.WorkspaceDir, "melange-out", packageName))
	if err != nil {
		return fmt.Errorf("getting absolute directory path: %w", err)
	}

	if err := os.MkdirAll(filepath.Join(dirPath, apkSBOMdir), os.FileMode(0755)); err != nil {
		return fmt.Errorf("creating SBOM directory in apk filesystem: %w", err)
	}

	apkSBOMpath := filepath.Join(dirPath, apkSBOMdir, fmt.Sprintf(fileName, packageName, spec.PackageVersion))
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

func (di *defaultGeneratorImplementation) ReadDistroID(spec *Spec) (string, error) {
	f, err := os.Open(filepath.Join(spec.GuestDir, "/etc/os-release"))
	if err != nil {
		return "", fmt.Errorf("opening os-release file: %w", err)
	}
	fileScanner := bufio.NewScanner(f)

	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		l := strings.TrimSpace(fileScanner.Text())
		if strings.HasPrefix(l, "ID=") {
			return strings.TrimPrefix("ID=", l), nil
		}
	}
	return "unknown", nil
}

// ReadPackageIndex reads the apk index and returns the installed packages
func (di *defaultGeneratorImplementation) ReadPackageIndex(spec *Spec) ([]*pkg, error) {
	distroid, err := di.ReadDistroID(spec)
	if err != nil {
		return nil, fmt.Errorf("getting distro id")
	}

	installedDB, err := os.Open(spec.GuestDir)
	if err != nil {
		return nil, fmt.Errorf("opening APK installed db: %w", err)
	}
	defer installedDB.Close()

	// repository.ParsePackageIndex closes the file itself
	packages, err := repository.ParsePackageIndex(installedDB)
	if err != nil {
		return nil, fmt.Errorf("parsing apk index: %w", err)
	}
	ret := []*pkg{}
	for _, p := range packages {
		ret = append(ret, &pkg{
			FilesAnalyzed: false,
			id:            "",
			Name:          p.Name,
			Version:       p.Version,
			HomePage:      p.URL,
			Supplier:      p.Maintainer,
			// Originator:    "",
			// Copyright:       p.,
			LicenseDeclared: p.License,
			//LicenseConcluded: "",
			Namespace: distroid,
			Arch:      p.Arch,
			Checksums: map[string]string{
				"SHA1": p.ChecksumString(),
			},
			Relationships: []relationship{},
		})
	}
	return ret, nil
}

// GenerateBuildPackage generates the package representing the build environment
func (di *defaultGeneratorImplementation) GenerateBuildPackage(spec *Spec, packages []*pkg) (pkg, error) {
	return pkg{}, nil
}
