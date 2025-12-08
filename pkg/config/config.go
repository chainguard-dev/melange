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

package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	apko_types "chainguard.dev/apko/pkg/build/types"
	purl "github.com/package-url/packageurl-go"

	"chainguard.dev/melange/pkg/sbom"

	"github.com/chainguard-dev/clog"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/util"
)

const (
	buildUser   = "build"
	purlTypeAPK = "apk"
)

type Trigger struct {
	// Optional: The script to run
	Script string `json:"script,omitempty"`
	// Optional: The list of paths to monitor to trigger the script
	Paths []string `json:"paths,omitempty"`
}

type Scriptlets struct {
	// Optional: A script to run on a custom trigger
	Trigger Trigger `json:"trigger" yaml:"trigger,omitempty"`
	// Optional: The script to run pre install. The script should contain the
	// shebang interpreter.
	PreInstall string `json:"pre-install,omitempty" yaml:"pre-install,omitempty"`
	// Optional: The script to run post install. The script should contain the
	// shebang interpreter.
	PostInstall string `json:"post-install,omitempty" yaml:"post-install,omitempty"`
	// Optional: The script to run before uninstalling. The script should contain
	// the shebang interpreter.
	PreDeinstall string `json:"pre-deinstall,omitempty" yaml:"pre-deinstall,omitempty"`
	// Optional: The script to run after uninstalling. The script should contain
	// the shebang interpreter.
	PostDeinstall string `json:"post-deinstall,omitempty" yaml:"post-deinstall,omitempty"`
	// Optional: The script to run before upgrading. The script should contain
	// the shebang interpreter.
	PreUpgrade string `json:"pre-upgrade,omitempty" yaml:"pre-upgrade,omitempty"`
	// Optional: The script to run after upgrading. The script should contain the
	// shebang interpreter.
	PostUpgrade string `json:"post-upgrade,omitempty" yaml:"post-upgrade,omitempty"`
}

type PackageOption struct {
	// Optional: Signify this package as a virtual package which does not provide
	// any files, executables, libraries, etc... and is otherwise empty
	NoProvides bool `json:"no-provides,omitempty" yaml:"no-provides,omitempty"`
	// Optional: Mark this package as a self contained package that does not
	// depend on any other package
	NoDepends bool `json:"no-depends,omitempty" yaml:"no-depends,omitempty"`
	// Optional: Mark this package as not providing any executables
	NoCommands bool `json:"no-commands,omitempty" yaml:"no-commands,omitempty"`
	// Optional: Don't generate versioned depends for shared libraries
	NoVersionedShlibDeps bool `json:"no-versioned-shlib-deps,omitempty" yaml:"no-versioned-shlib-deps,omitempty"`
}

type Checks struct {
	// Optional: disable these linters that are not enabled by default.
	Disabled []string `json:"disabled,omitempty" yaml:"disabled,omitempty"`
}

type Package struct {
	// The name of the package
	Name string `json:"name" yaml:"name"`
	// The version of the package
	Version string `json:"version" yaml:"version"`
	// The monotone increasing epoch of the package
	Epoch uint64 `json:"epoch" yaml:"epoch"`
	// A human-readable description of the package
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Annotations for this package
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	// The URL to the package's homepage
	URL string `json:"url,omitempty" yaml:"url,omitempty"`
	// Optional: The git commit of the package build configuration
	Commit string `json:"commit,omitempty" yaml:"commit,omitempty"`
	// List of target architectures for which this package should be build for
	TargetArchitecture []string `json:"target-architecture,omitempty" yaml:"target-architecture,omitempty"`
	// The list of copyrights for this package
	Copyright []Copyright `json:"copyright,omitempty" yaml:"copyright,omitempty"`
	// List of packages to depends on
	Dependencies Dependencies `json:"dependencies" yaml:"dependencies,omitempty"`
	// Optional: Options that alter the packages behavior
	Options *PackageOption `json:"options,omitempty" yaml:"options,omitempty"`
	// Optional: Executable scripts that run at various stages of the package
	// lifecycle, triggered by configurable events
	Scriptlets *Scriptlets `json:"scriptlets,omitempty" yaml:"scriptlets,omitempty"`
	// Optional: enabling, disabling, and configuration of build checks
	Checks Checks `json:"checks" yaml:"checks,omitempty"`
	// The CPE field values to be used for matching against NVD vulnerability
	// records, if known.
	CPE CPE `json:"cpe" yaml:"cpe,omitempty"`
	// Capabilities to set after the pipeline completes.
	SetCap []Capability `json:"setcap,omitempty" yaml:"setcap,omitempty"`

	// Optional: The amount of time to allow this build to take before timing out.
	Timeout time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	// Optional: Resources to allocate to the build.
	Resources *Resources `json:"resources,omitempty" yaml:"resources,omitempty"`
	// Optional: Resources to allocate for test execution.
	// Used by external schedulers (like elastic build) to provision
	// appropriately-sized test pods/VMs. If not specified, falls back
	// to Resources.
	TestResources *Resources `json:"test-resources,omitempty" yaml:"test-resources,omitempty"`
}

// CPE stores values used to produce a CPE to describe the package, suitable for
// matching against NVD records.
//
// Based on the spec found at
// https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf.
//
// For Melange, the "part" attribute should always be interpreted as "a" (for
// "application") unless otherwise specified.
//
// The "Version" and "Update" fields have been intentionally left out of the CPE
// struct to avoid confusion with the version information of the package itself.
type CPE struct {
	Part      string `json:"part,omitempty" yaml:"part,omitempty"`
	Vendor    string `json:"vendor,omitempty" yaml:"vendor,omitempty"`
	Product   string `json:"product,omitempty" yaml:"product,omitempty"`
	Edition   string `json:"edition,omitempty" yaml:"edition,omitempty"`
	Language  string `json:"language,omitempty" yaml:"language,omitempty"`
	SWEdition string `json:"sw_edition,omitempty" yaml:"sw_edition,omitempty"`
	TargetSW  string `json:"target_sw,omitempty" yaml:"target_sw,omitempty"`
	TargetHW  string `json:"target_hw,omitempty" yaml:"target_hw,omitempty"`
	Other     string `json:"other,omitempty" yaml:"other,omitempty"`
}

// Capability stores paths and an associated map of capabilities and justification to include in a package.
// These capabilities will be set after pipelines run to avoid permissions issues with `setcap`.
// Empty justifications will result in an error.
type Capability struct {
	Path   string            `json:"path,omitempty" yaml:"path,omitempty"`
	Add    map[string]string `json:"add,omitempty" yaml:"add,omitempty"`
	Reason string            `json:"reason,omitempty" yaml:"reason,omitempty"`
}

func (cpe CPE) IsZero() bool {
	return cpe == CPE{}
}

type Resources struct {
	CPU      string `json:"cpu,omitempty" yaml:"cpu,omitempty"`
	CPUModel string `json:"cpumodel,omitempty" yaml:"cpumodel,omitempty"`
	Memory   string `json:"memory,omitempty" yaml:"memory,omitempty"`
	Disk     string `json:"disk,omitempty" yaml:"disk,omitempty"`
}

// CPEString returns the CPE string for the package, suitable for matching
// against NVD records.
func (p Package) CPEString() (string, error) {
	const anyValue = "*"

	part := anyValue
	if p.CPE.Part != "" {
		part = p.CPE.Part
	}
	vendor := anyValue
	if p.CPE.Vendor != "" {
		vendor = p.CPE.Vendor
	}
	product := anyValue
	if p.CPE.Product != "" {
		product = p.CPE.Product
	}
	edition := anyValue
	if p.CPE.Edition != "" {
		edition = p.CPE.Edition
	}
	language := anyValue
	if p.CPE.Language != "" {
		language = p.CPE.Language
	}
	swEdition := anyValue
	if p.CPE.SWEdition != "" {
		swEdition = p.CPE.SWEdition
	}
	targetSW := anyValue
	if p.CPE.TargetSW != "" {
		targetSW = p.CPE.TargetSW
	}
	targetHW := anyValue
	if p.CPE.TargetHW != "" {
		targetHW = p.CPE.TargetHW
	}
	other := anyValue
	if p.CPE.Other != "" {
		other = p.CPE.Other
	}

	// Last-mile validation to avoid headaches downstream of this.
	if vendor == anyValue {
		return "", fmt.Errorf("vendor value must be exactly specified")
	}
	if product == anyValue {
		return "", fmt.Errorf("product value must be exactly specified")
	}

	return fmt.Sprintf(
		"cpe:2.3:%s:%s:%s:%s:*:%s:%s:%s:%s:%s:%s",
		part,
		vendor,
		product,
		p.Version,
		edition,
		language,
		swEdition,
		targetSW,
		targetHW,
		other,
	), nil
}

// PackageURL returns the package URL ("purl") for the APK (origin) package.
func (p Package) PackageURL(distro, arch string) *purl.PackageURL {
	return newAPKPackageURL(distro, p.Name, p.FullVersion(), arch)
}

// PackageURLForSubpackage returns the package URL ("purl") for the APK
// subpackage.
func (p Package) PackageURLForSubpackage(distro, arch, subpackage string) *purl.PackageURL {
	return newAPKPackageURL(distro, subpackage, p.FullVersion(), arch)
}

func newAPKPackageURL(distro, name, version, arch string) *purl.PackageURL {
	u := &purl.PackageURL{
		Type:      purlTypeAPK,
		Namespace: distro,
		Name:      name,
		Version:   version,
	}

	if distro != "unknown" {
		u.Qualifiers = append(u.Qualifiers, purl.Qualifier{
			Key:   "distro",
			Value: distro,
		})
	}

	if arch != "" {
		u.Qualifiers = append(u.Qualifiers, purl.Qualifier{
			Key:   "arch",
			Value: arch,
		})
	}

	return u
}

// FullVersion returns the full version of the APK package produced by the
// build, including the epoch.
func (p Package) FullVersion() string {
	return fmt.Sprintf("%s-r%d", p.Version, p.Epoch)
}

func (cfg *Configuration) applySubstitutionsForProvides() error {
	nw := buildConfigMap(cfg)
	if err := cfg.PerformVarSubstitutions(nw); err != nil {
		return fmt.Errorf("applying variable substitutions for provides: %w", err)
	}
	for i, prov := range cfg.Package.Dependencies.Provides {
		var err error
		cfg.Package.Dependencies.Provides[i], err = util.MutateStringFromMap(nw, prov)
		if err != nil {
			return fmt.Errorf("failed to apply replacement to provides %q: %w", prov, err)
		}
	}
	for _, sp := range cfg.Subpackages {
		for i, prov := range sp.Dependencies.Provides {
			var err error
			sp.Dependencies.Provides[i], err = util.MutateStringFromMap(nw, prov)
			if err != nil {
				return fmt.Errorf("failed to apply replacement to %q provides %q: %w", sp.Name, prov, err)
			}
		}
	}
	return nil
}

func (cfg *Configuration) applySubstitutionsForPriorities() error {
	nw := buildConfigMap(cfg)
	var err error
	cfg.Package.Dependencies.ProviderPriority, err = util.MutateStringFromMap(nw, cfg.Package.Dependencies.ProviderPriority)
	if err != nil {
		return fmt.Errorf("failed to apply replacement to provider priority %q: %w", cfg.Package.Dependencies.ProviderPriority, err)
	}
	cfg.Package.Dependencies.ReplacesPriority, err = util.MutateStringFromMap(nw, cfg.Package.Dependencies.ReplacesPriority)
	if err != nil {
		return fmt.Errorf("failed to apply replacement to replaces priority %q: %w", cfg.Package.Dependencies.ReplacesPriority, err)
	}
	for _, sp := range cfg.Subpackages {
		sp.Dependencies.ProviderPriority, err = util.MutateStringFromMap(nw, sp.Dependencies.ProviderPriority)
		if err != nil {
			return fmt.Errorf("failed to apply replacement to %q provider priority %q: %w", sp.Name, sp.Dependencies.ProviderPriority, err)
		}
		sp.Dependencies.ReplacesPriority, err = util.MutateStringFromMap(nw, sp.Dependencies.ReplacesPriority)
		if err != nil {
			return fmt.Errorf("failed to apply replacement to %q replaces priority %q: %w", sp.Name, sp.Dependencies.ReplacesPriority, err)
		}
	}
	return nil
}

func (cfg *Configuration) applySubstitutionsForRuntime() error {
	nw := buildConfigMap(cfg)
	if err := cfg.PerformVarSubstitutions(nw); err != nil {
		return fmt.Errorf("applying variable substitutions for runtime: %w", err)
	}
	for i, runtime := range cfg.Package.Dependencies.Runtime {
		var err error
		cfg.Package.Dependencies.Runtime[i], err = util.MutateStringFromMap(nw, runtime)
		if err != nil {
			return fmt.Errorf("failed to apply replacement to runtime dependency %q: %w", runtime, err)
		}
	}
	for _, sp := range cfg.Subpackages {
		for i, runtime := range sp.Dependencies.Runtime {
			var err error
			sp.Dependencies.Runtime[i], err = util.MutateStringFromMap(nw, runtime)
			if err != nil {
				return fmt.Errorf("failed to apply replacement to %q runtime dependency %q: %w", sp.Name, runtime, err)
			}
		}
	}
	return nil
}

func (cfg *Configuration) applySubstitutionsForReplaces() error {
	nw := buildConfigMap(cfg)
	for i, replaces := range cfg.Package.Dependencies.Replaces {
		var err error
		cfg.Package.Dependencies.Replaces[i], err = util.MutateStringFromMap(nw, replaces)
		if err != nil {
			return fmt.Errorf("failed to apply replacement to replaces %q: %w", replaces, err)
		}
	}
	for _, sp := range cfg.Subpackages {
		for i, replaces := range sp.Dependencies.Replaces {
			var err error
			sp.Dependencies.Replaces[i], err = util.MutateStringFromMap(nw, replaces)
			if err != nil {
				return fmt.Errorf("failed to apply replacement to %q replaces %q: %w", sp.Name, replaces, err)
			}
		}
	}
	return nil
}

func (cfg *Configuration) applySubstitutionsForPackages() error {
	nw := buildConfigMap(cfg)
	if err := cfg.PerformVarSubstitutions(nw); err != nil {
		return fmt.Errorf("applying variable substitutions for packages: %w", err)
	}
	for i, runtime := range cfg.Environment.Contents.Packages {
		var err error
		cfg.Environment.Contents.Packages[i], err = util.MutateStringFromMap(nw, runtime)
		if err != nil {
			return fmt.Errorf("failed to apply replacement to package %q: %w", runtime, err)
		}
	}
	if cfg.Test != nil {
		for i, runtime := range cfg.Test.Environment.Contents.Packages {
			var err error
			cfg.Test.Environment.Contents.Packages[i], err = util.MutateStringFromMap(nw, runtime)
			if err != nil {
				return fmt.Errorf("failed to apply replacement to test package %q: %w", runtime, err)
			}
		}
	}
	for _, sp := range cfg.Subpackages {
		if sp.Test != nil {
			for i, runtime := range sp.Test.Environment.Contents.Packages {
				var err error
				sp.Test.Environment.Contents.Packages[i], err = util.MutateStringFromMap(nw, runtime)
				if err != nil {
					return fmt.Errorf("failed to apply replacement to subpackage %q test %q: %w", sp.Name, runtime, err)
				}
			}
		}
	}
	return nil
}

type Copyright struct {
	// Optional: The license paths, typically '*'
	Paths []string `json:"paths,omitempty" yaml:"paths,omitempty"`
	// Optional: Attestations of the license
	Attestation string `json:"attestation,omitempty" yaml:"attestation,omitempty"`
	// Required: The license for this package
	License string `json:"license" yaml:"license"`
	// Optional: Path to text of the custom License Ref
	LicensePath string `json:"license-path,omitempty" yaml:"license-path,omitempty"`
	// Optional: License override
	DetectionOverride string `json:"detection-override,omitempty" yaml:"detection-override,omitempty"`
}

// LicenseExpression returns an SPDX license expression formed from the data in
// the copyright structs found in the conf. It's a simple OR for now.
func (p Package) LicenseExpression() string {
	licenseExpression := ""
	if p.Copyright == nil {
		return licenseExpression
	}
	for _, cp := range p.Copyright {
		if licenseExpression != "" {
			licenseExpression += " AND "
		}
		licenseExpression += cp.License
	}
	return licenseExpression
}

// LicensingInfos looks at the `Package.Copyright[].LicensePath` fields of the
// parsed build configuration for the package. If this value has been set,
// LicensingInfos opens the file at this path from the build's workspace
// directory, and reads in the license content. LicensingInfos then returns a
// map of the `Copyright.License` field to the string content of the file from
// `.LicensePath`.
func (p Package) LicensingInfos(workspaceDir string) (map[string]string, error) {
	licenseInfos := make(map[string]string)
	for _, cp := range p.Copyright {
		if cp.LicensePath != "" {
			content, err := os.ReadFile(filepath.Join(workspaceDir, cp.LicensePath)) // #nosec G304 - Reading license file from build workspace
			if err != nil {
				return nil, fmt.Errorf("failed to read licensepath %q: %w", cp.LicensePath, err)
			}
			licenseInfos[cp.License] = string(content)
		}
	}
	return licenseInfos, nil
}

// FullCopyright returns the concatenated copyright expressions defined
// in the configuration file.
func (p Package) FullCopyright() string {
	copyright := ""
	for _, cp := range p.Copyright {
		if cp.Attestation != "" {
			copyright += cp.Attestation + "\n"
		}
	}
	// No copyright found, instead of omitting the field declare
	// that no determination was attempted, which is better than a
	// whitespace (which should also be interpreted as
	// NOASSERTION)
	if copyright == "" {
		copyright = "NOASSERTION"
	}
	return copyright
}

type Needs struct {
	// A list of packages needed by this pipeline
	Packages []string
}

type PipelineAssertions struct {
	// The number (an int) of required steps that must complete successfully
	// within the asserted pipeline.
	RequiredSteps int `json:"required-steps,omitempty" yaml:"required-steps,omitempty"`
}

type Pipeline struct {
	// Optional: A condition to evaluate before running the pipeline
	If string `json:"if,omitempty" yaml:"if,omitempty"`
	// Optional: A user defined name for the pipeline
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Optional: A named reusable pipeline to run
	//
	// This can be either a pipeline builtin to melange, or a user defined named pipeline.
	// For example, to use a builtin melange pipeline:
	// 		uses: autoconf/make
	Uses string `json:"uses,omitempty" yaml:"uses,omitempty"`
	// Optional: Arguments passed to the reusable pipelines defined in `uses`
	With map[string]string `json:"with,omitempty" yaml:"with,omitempty"`
	// Optional: The command to run using the builder's shell (/bin/sh)
	Runs string `json:"runs,omitempty" yaml:"runs,omitempty"`
	// Optional: The list of pipelines to run.
	//
	// Each pipeline runs in its own context that is not shared between other
	// pipelines. To share context between pipelines, nest a pipeline within an
	// existing pipeline. This can be useful when you wish to share common
	// configuration, such as an alternative `working-directory`.
	Pipeline []Pipeline `json:"pipeline,omitempty" yaml:"pipeline,omitempty"`
	// Optional: A map of inputs to the pipeline
	Inputs map[string]Input `json:"inputs,omitempty" yaml:"inputs,omitempty"`
	// Optional: Configuration to determine any explicit dependencies this pipeline may have
	Needs *Needs `json:"needs,omitempty" yaml:"needs,omitempty"`
	// Optional: Labels to apply to the pipeline
	Label string `json:"label,omitempty" yaml:"label,omitempty"`
	// Optional: Assertions to evaluate whether the pipeline was successful
	Assertions *PipelineAssertions `json:"assertions,omitempty" yaml:"assertions,omitempty"`
	// Optional: The working directory of the pipeline
	//
	// This defaults to the guests' build workspace (/home/build)
	WorkDir string `json:"working-directory,omitempty" yaml:"working-directory,omitempty"`
	// Optional: environment variables to override apko
	Environment map[string]string `json:"environment,omitempty" yaml:"environment,omitempty"`
}

// SHA256 generates a digest based on the text provided
// Returns a hex encoded string
func SHA256(text string) string {
	algorithm := sha256.New()
	algorithm.Write([]byte(text))
	return hex.EncodeToString(algorithm.Sum(nil))
}

// getGitSBOMPackage creates an SBOM package for Git based repositories.
// Returns nil package and nil error if the repository is not from a supported platform or
// if neither a tag of expectedCommit is not provided
func getGitSBOMPackage(repo, tag, expectedCommit string, idComponents []string, licenseDeclared, hint, supplier string) (*sbom.Package, error) {
	var repoType, namespace, name, ref string
	var downloadLocation string

	repoURL, err := url.Parse(repo)
	if err != nil {
		return nil, err
	}

	switch {
	case expectedCommit != "":
		ref = expectedCommit
	case tag != "":
		ref = tag
	default:
		return nil, nil
	}

	trimmedPath := strings.TrimPrefix(repoURL.Path, "/")
	namespace, name, _ = strings.Cut(trimmedPath, "/")
	name = strings.TrimSuffix(name, ".git")

	switch {
	case repoURL.Host == "github.com":
		repoType = purl.TypeGithub
		downloadLocation = fmt.Sprintf("%s://github.com/%s/%s/archive/%s.tar.gz", repoURL.Scheme, namespace, name, ref)

	case repoURL.Host == "gitlab.com":
		repoType = purl.TypeGitlab
		downloadLocation = fmt.Sprintf("%s://gitlab.com/%s/%s/-/archive/%s/%s.tar.gz", repoURL.Scheme, namespace, name, ref, ref)

	case strings.HasPrefix(repoURL.Host, "gitlab") || hint == "gitlab":
		repoType = purl.TypeGeneric
		downloadLocation = fmt.Sprintf("%s://%s/%s/%s/-/archive/%s/%s.tar.gz", repoURL.Scheme, repoURL.Host, namespace, name, ref, ref)

	default:
		repoType = purl.TypeGeneric
		// We can't determine the namespace so use the supplier passed instead.
		namespace = supplier
		name = strings.TrimSuffix(trimmedPath, ".git")
		// Use first letter of name as a directory to avoid a single huge bucket of tarballs
		downloadLocation = fmt.Sprintf("https://tarballs.cgr.dev/%s/%s-%s.tar.gz", name[:1], SHA256(name), ref)
	}

	// Prefer tag to commit, but use only ONE of these.
	versions := []string{
		tag,
		expectedCommit,
	}

	// Encode vcs_url with git+ prefix and @commit suffix
	var vcsUrl string
	if !strings.HasPrefix(repo, "git") {
		vcsUrl = "git+" + repo
	} else {
		vcsUrl = repo
	}

	if expectedCommit != "" {
		vcsUrl += "@" + expectedCommit
	}

	for _, v := range versions {
		if v == "" {
			continue
		}

		var pu *purl.PackageURL

		switch repoType {
		case purl.TypeGithub, purl.TypeGitlab:
			pu = &purl.PackageURL{
				Type:      repoType,
				Namespace: namespace,
				Name:      name,
				Version:   v,
			}
		case purl.TypeGeneric:
			pu = &purl.PackageURL{
				Type:       "generic",
				Name:       name,
				Version:    v,
				Qualifiers: purl.QualifiersFromMap(map[string]string{"vcs_url": vcsUrl}),
			}
		}

		if err := pu.Normalize(); err != nil {
			return nil, err
		}

		return &sbom.Package{
			IDComponents:     idComponents,
			Name:             name,
			Version:          v,
			LicenseDeclared:  licenseDeclared,
			Namespace:        namespace,
			PURL:             pu,
			DownloadLocation: downloadLocation,
		}, nil
	}

	// If we get here, we have a repo but no tag or commit. Without version
	// information, we can't create a sensible SBOM package.
	return nil, nil
}

// SBOMPackageForUpstreamSource returns an SBOM package for the upstream source
// of the package, if this Pipeline step was used to bring source code from an
// upstream project into the build. This function helps with generating SBOMs
// for the package being built. If the pipeline step is not a fetch or
// git-checkout step, this function returns nil and no error.
func (p Pipeline) SBOMPackageForUpstreamSource(licenseDeclared, supplier string, uniqueID string) (*sbom.Package, error) {
	// TODO: It'd be great to detect the license from the source code itself. Such a
	//  feature could even eliminate the need for the package's license field in the
	//  build configuration.

	uses, with := p.Uses, p.With

	switch uses {
	case "fetch":
		args := make(map[string]string)
		args["download_url"] = with["uri"]
		checksums := make(map[string]string)

		expectedSHA256 := with["expected-sha256"]
		if len(expectedSHA256) > 0 {
			args["checksum"] = "sha256:" + expectedSHA256
			checksums["SHA256"] = expectedSHA256
		}
		expectedSHA512 := with["expected-sha512"]
		if len(expectedSHA512) > 0 {
			args["checksum"] = "sha512:" + expectedSHA512
			checksums["SHA512"] = expectedSHA512
		}

		// These get defaulted correctly from within the fetch pipeline definition
		// (YAML) itself.
		pkgName := with["purl-name"]
		pkgVersion := with["purl-version"]

		pu := &purl.PackageURL{
			Type:       "generic",
			Name:       pkgName,
			Version:    pkgVersion,
			Qualifiers: purl.QualifiersFromMap(args),
		}
		if err := pu.Normalize(); err != nil {
			return nil, err
		}

		idComponents := []string{pkgName, pkgVersion}
		if uniqueID != "" {
			idComponents = append(idComponents, uniqueID)
		}

		return &sbom.Package{
			IDComponents:     idComponents,
			Name:             pkgName,
			Version:          pkgVersion,
			Namespace:        supplier,
			Checksums:        checksums,
			PURL:             pu,
			DownloadLocation: args["download_url"],
		}, nil

	case "git-checkout":
		repo := with["repository"]
		branch := with["branch"]
		tag := with["tag"]
		expectedCommit := with["expected-commit"]
		hint := with["type-hint"]

		// We'll use all available data to ensure our SBOM's package ID is unique, even
		// when the same repo is git-checked out multiple times.
		var idComponents []string
		repoCleaned := func() string {
			s := strings.TrimPrefix(repo, "https://")
			s = strings.TrimPrefix(s, "http://")
			return s
		}()
		for _, component := range []string{repoCleaned, branch, tag, expectedCommit} {
			if component != "" {
				idComponents = append(idComponents, component)
			}
		}
		if uniqueID != "" {
			idComponents = append(idComponents, uniqueID)
		}

		gitPackage, err := getGitSBOMPackage(repo, tag, expectedCommit, idComponents, licenseDeclared, hint, supplier)
		if err != nil {
			return nil, err
		} else if gitPackage != nil {
			return gitPackage, nil
		}
	}

	// This is not a fetch or git-checkout step.

	return nil, nil
}

type Subpackage struct {
	// Optional: A conditional statement to evaluate for the subpackage
	If string `json:"if,omitempty" yaml:"if,omitempty"`
	// Optional: The iterable used to generate multiple subpackages
	Range string `json:"range,omitempty" yaml:"range,omitempty"`
	// Required: Name of the subpackage
	Name string `json:"name" yaml:"name"`
	// Optional: The list of pipelines that produce subpackage.
	Pipeline []Pipeline `json:"pipeline,omitempty" yaml:"pipeline,omitempty"`
	// Optional: List of packages to depend on
	Dependencies Dependencies `json:"dependencies" yaml:"dependencies,omitempty"`
	// Optional: Options that alter the packages behavior
	Options    *PackageOption `json:"options,omitempty" yaml:"options,omitempty"`
	Scriptlets *Scriptlets    `json:"scriptlets,omitempty" yaml:"scriptlets,omitempty"`
	// Optional: The human readable description of the subpackage
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Optional: The URL to the package's homepage
	URL string `json:"url,omitempty" yaml:"url,omitempty"`
	// Optional: The git commit of the subpackage build configuration
	Commit string `json:"commit,omitempty" yaml:"commit,omitempty"`
	// Optional: enabling, disabling, and configuration of build checks
	Checks Checks `json:"checks" yaml:"checks,omitempty"`
	// Test section for the subpackage.
	Test *Test `json:"test,omitempty" yaml:"test,omitempty"`
	// Capabilities to set after the pipeline completes.
	SetCap []Capability `json:"setcap,omitempty" yaml:"setcap,omitempty"`
}

type Input struct {
	// Optional: The human-readable description of the input
	Description string `json:"description,omitempty"`
	// Optional: The default value of the input. Required when the input is.
	Default string `json:"default,omitempty"`
	// Optional: A toggle denoting whether the input is required or not
	Required bool `json:"required,omitempty"`
}

// Capabilities is the configuration for Linux capabilities for the runner.
type Capabilities struct {
	// Linux process capabilities to add to the pipeline container.
	Add []string `json:"add,omitempty" yaml:"add,omitempty"`
	// Linux process capabilities to drop from the pipeline container.
	Drop []string `json:"drop,omitempty" yaml:"drop,omitempty"`
}

// Configuration is the root melange configuration.
type Configuration struct {
	// Package metadata
	Package Package `json:"package" yaml:"package"`
	// The specification for the packages build environment
	// Optional: environment variables to override apko
	Environment apko_types.ImageConfiguration `json:"environment" yaml:"environment,omitempty"`
	// Optional: Linux capabilities configuration to apply to the melange runner.
	Capabilities Capabilities `json:"capabilities" yaml:"capabilities,omitempty"`

	// Required: The list of pipelines that produce the package.
	Pipeline []Pipeline `json:"pipeline,omitempty" yaml:"pipeline,omitempty"`
	// Optional: The list of subpackages that this package also produces.
	Subpackages []Subpackage `json:"subpackages,omitempty" yaml:"subpackages,omitempty"`
	// Optional: An arbitrary list of data that can be used via templating in the
	// pipeline
	Data []RangeData `json:"data,omitempty" yaml:"data,omitempty"`
	// Optional: The update block determining how this package is auto updated
	Update Update `json:"update" yaml:"update,omitempty"`
	// Optional: A map of arbitrary variables that can be used via templating in
	// the pipeline
	Vars map[string]string `json:"vars,omitempty" yaml:"vars,omitempty"`
	// Optional: A list of transformations to create for the builtin template
	// variables
	VarTransforms []VarTransforms `json:"var-transforms,omitempty" yaml:"var-transforms,omitempty"`
	// Optional: Deviations to the build
	Options map[string]BuildOption `json:"options,omitempty" yaml:"options,omitempty"`

	// Test section for the main package.
	Test *Test `json:"test,omitempty" yaml:"test,omitempty"`

	// Parsed AST for this configuration
	root *yaml.Node
}

// AllPackageNames returns a sequence of all package names in the configuration,
// i.e. the origin package name and the names of all subpackages.
func (cfg Configuration) AllPackageNames() iter.Seq[string] {
	return func(yield func(string) bool) {
		if !yield(cfg.Package.Name) {
			return
		}

		for _, sp := range cfg.Subpackages {
			if !yield(sp.Name) {
				return
			}
		}
	}
}

type Test struct {
	// Additional Environment necessary for test.
	// Environment.Contents.Packages automatically get
	// package.dependencies.runtime added to it. So, if your test needs
	// no additional packages, you can leave it blank.
	// Optional: Additional Environment the test needs to run
	Environment apko_types.ImageConfiguration `json:"environment" yaml:"environment,omitempty"`

	// Required: The list of pipelines that test the produced package.
	Pipeline []Pipeline `json:"pipeline" yaml:"pipeline"`
}

// Name returns a name for the configuration, using the package name. This
// implements the configs.Configuration interface in wolfictl and is important
// to keep as long as that package is in use.
func (cfg Configuration) Name() string {
	return cfg.Package.Name
}

type VarTransforms struct {
	// Required: The original template variable.
	//
	// Example: ${{package.version}}
	From string `json:"from" yaml:"from"`
	// Required: The regular expression to match against the `from` variable
	Match string `json:"match" yaml:"match"`
	// Required: The repl to replace on all `match` matches
	Replace string `json:"replace" yaml:"replace"`
	// Required: The name of the new variable to create
	//
	// Example: mangeled-package-version
	To string `json:"to" yaml:"to"`
}

// Update provides information used to describe how to keep the package up to date
type Update struct {
	// Toggle if updates should occur
	Enabled bool `json:"enabled" yaml:"enabled"`
	// Indicates that this package should be manually updated, usually taking
	// care over special version numbers
	Manual bool `json:"manual,omitempty" yaml:"manual"`
	// Indicates that automated pull requests should be merged in order rather than superseding and closing previous unmerged PRs
	RequireSequential bool `json:"require-sequential,omitempty" yaml:"require-sequential"`
	// Indicate that an update to this package requires an epoch bump of
	// downstream dependencies, e.g. golang, java
	Shared bool `json:"shared,omitempty" yaml:"shared,omitempty"`
	// Override the version separator if it is nonstandard
	VersionSeparator string `json:"version-separator,omitempty" yaml:"version-separator,omitempty"`
	// A slice of regex patterns to match an upstream version and ignore
	IgnoreRegexPatterns []string `json:"ignore-regex-patterns,omitempty" yaml:"ignore-regex-patterns,omitempty"`
	// The configuration block for updates tracked via release-monitoring.org
	ReleaseMonitor *ReleaseMonitor `json:"release-monitor,omitempty" yaml:"release-monitor,omitempty"`
	// The configuration block for updates tracked via the Github API
	GitHubMonitor *GitHubMonitor `json:"github,omitempty" yaml:"github,omitempty"`
	// The configuration block for updates tracked via Git
	GitMonitor *GitMonitor `json:"git,omitempty" yaml:"git,omitempty"`
	// The configuration block for transforming the `package.version` into an APK version
	VersionTransform []VersionTransform `json:"version-transform,omitempty" yaml:"version-transform,omitempty"`
	// ExcludeReason is required if enabled=false, to explain why updates are disabled.
	ExcludeReason string `json:"exclude-reason,omitempty" yaml:"exclude-reason,omitempty"`
	// Schedule defines the schedule for the update check to run
	Schedule *Schedule `json:"schedule,omitempty" yaml:"schedule,omitempty"`
	// Optional: Disables filtering of common pre-release tags
	EnablePreReleaseTags bool `json:"enable-prerelease-tags,omitempty" yaml:"enable-prerelease-tags,omitempty"`
}

// ReleaseMonitor indicates using the API for https://release-monitoring.org/
type ReleaseMonitor struct {
	// Required: ID number for release monitor
	Identifier int `json:"identifier" yaml:"identifier"`
	// If the version in release monitor contains a prefix which should be ignored
	StripPrefix string `json:"strip-prefix,omitempty" yaml:"strip-prefix,omitempty"`
	// If the version in release monitor contains a suffix which should be ignored
	StripSuffix string `json:"strip-suffix,omitempty" yaml:"strip-suffix,omitempty"`
	// Filter to apply when searching version on a Release Monitoring
	VersionFilterContains string `json:"version-filter-contains,omitempty" yaml:"version-filter-contains,omitempty"`
	// Filter to apply when searching version Release Monitoring
	VersionFilterPrefix string `json:"version-filter-prefix,omitempty" yaml:"version-filter-prefix,omitempty"`
}

// VersionHandler is an interface that defines methods for retrieving version filtering and stripping parameters.
// It is used to provide a common interface for handling version-related operations for different types of version monitors.
type VersionHandler interface {
	GetStripPrefix() string
	GetStripSuffix() string
	GetFilterPrefix() string
	GetFilterContains() string
}

// GitHubMonitor indicates using the GitHub API
type GitHubMonitor struct {
	// Org/repo for GitHub
	Identifier string `json:"identifier" yaml:"identifier"`
	// If the version in GitHub contains a prefix which should be ignored
	StripPrefix string `json:"strip-prefix,omitempty" yaml:"strip-prefix,omitempty"`
	// If the version in GitHub contains a suffix which should be ignored
	StripSuffix string `json:"strip-suffix,omitempty" yaml:"strip-suffix,omitempty"`
	// Filter to apply when searching tags on a GitHub repository
	//
	// Deprecated: Use TagFilterPrefix instead
	TagFilter string `json:"tag-filter,omitempty" yaml:"tag-filter,omitempty"`
	// Prefix filter to apply when searching tags on a GitHub repository
	TagFilterPrefix string `json:"tag-filter-prefix,omitempty" yaml:"tag-filter-prefix,omitempty"`
	// Filter to apply when searching tags on a GitHub repository
	TagFilterContains string `json:"tag-filter-contains,omitempty" yaml:"tag-filter-contains,omitempty"`
	// Override the default of using a GitHub release to identify related tag to
	// fetch.  Not all projects use GitHub releases but just use tags
	UseTags bool `json:"use-tag,omitempty" yaml:"use-tag,omitempty"`
}

// GitMonitor indicates using Git
type GitMonitor struct {
	// StripPrefix is the prefix to strip from the version
	StripPrefix string `json:"strip-prefix,omitempty" yaml:"strip-prefix,omitempty"`
	// If the version in GitHub contains a suffix which should be ignored
	StripSuffix string `json:"strip-suffix,omitempty" yaml:"strip-suffix,omitempty"`
	// Prefix filter to apply when searching tags on a GitHub repository
	TagFilterPrefix string `json:"tag-filter-prefix,omitempty" yaml:"tag-filter-prefix,omitempty"`
	// Filter to apply when searching tags on a GitHub repository
	TagFilterContains string `json:"tag-filter-contains,omitempty" yaml:"tag-filter-contains,omitempty"`
}

// GetStripPrefix returns the prefix that should be stripped from the GitMonitor version.
func (gm *GitMonitor) GetStripPrefix() string {
	return gm.StripPrefix
}

// GetStripSuffix returns the suffix that should be stripped from the GitMonitor version.
func (gm *GitMonitor) GetStripSuffix() string {
	return gm.StripSuffix
}

// GetFilterPrefix returns the prefix filter to apply when searching tags in GitMonitor.
func (gm *GitMonitor) GetFilterPrefix() string {
	return gm.TagFilterPrefix
}

// GetFilterContains returns the substring filter to apply when searching tags in GitMonitor.
func (gm *GitMonitor) GetFilterContains() string {
	return gm.TagFilterContains
}

// GetStripPrefix returns the prefix that should be stripped from the GitHubMonitor version.
func (ghm *GitHubMonitor) GetStripPrefix() string {
	return ghm.StripPrefix
}

// GetStripSuffix returns the suffix that should be stripped from the GitHubMonitor version.
func (ghm *GitHubMonitor) GetStripSuffix() string {
	return ghm.StripSuffix
}

// GetFilterPrefix returns the prefix filter to apply when searching tags in GitHubMonitor.
func (ghm *GitHubMonitor) GetFilterPrefix() string {
	return ghm.TagFilterPrefix
}

// GetFilterContains returns the substring filter to apply when searching tags in GitHubMonitor.
func (ghm *GitHubMonitor) GetFilterContains() string {
	return ghm.TagFilterContains
}

// GetStripPrefix returns the prefix that should be stripped from the ReleaseMonitor version.
func (rm *ReleaseMonitor) GetStripPrefix() string {
	return rm.StripPrefix
}

// GetStripSuffix returns the suffix that should be stripped from the ReleaseMonitor version.
func (rm *ReleaseMonitor) GetStripSuffix() string {
	return rm.StripSuffix
}

// GetFilterPrefix returns the prefix filter to apply when searching versions in ReleaseMonitor.
func (rm *ReleaseMonitor) GetFilterPrefix() string {
	return rm.VersionFilterPrefix
}

// GetFilterContains returns the substring filter to apply when searching versions in ReleaseMonitor.
func (rm *ReleaseMonitor) GetFilterContains() string {
	return rm.VersionFilterContains
}

// VersionTransform allows mapping the package version to an APK version
type VersionTransform struct {
	// Required: The regular expression to match against the `package.version` variable
	Match string `json:"match" yaml:"match"`
	// Required: The repl to replace on all `match` matches
	Replace string `json:"replace" yaml:"replace"`
}

// Period represents the update check period
type Period string

const (
	Daily   Period = "daily"
	Weekly  Period = "weekly"
	Monthly Period = "monthly"
)

// Schedule defines the schedule for the update check to run
type Schedule struct {
	// The reason scheduling is being used
	Reason string `json:"reason,omitempty" yaml:"reason,omitempty"`
	Period Period `json:"period,omitempty" yaml:"period,omitempty"`
}

func (schedule Schedule) GetScheduleMessage() (string, error) {
	switch schedule.Period {
	case Daily:
		return "Scheduled daily update check", nil
	case Weekly:
		return "Scheduled weekly update check", nil
	case Monthly:
		return "Scheduled monthly update check", nil
	default:
		return "", fmt.Errorf("unsupported period: %s", schedule.Period)
	}
}

type RangeData struct {
	Name  string    `json:"name" yaml:"name"`
	Items DataItems `json:"items" yaml:"items"`
}

type DataItems map[string]string

type Dependencies struct {
	// Optional: List of runtime dependencies
	Runtime []string `json:"runtime,omitempty" yaml:"runtime,omitempty"`
	// Optional: List of packages provided
	Provides []string `json:"provides,omitempty" yaml:"provides,omitempty"`
	// Optional: List of replace objectives
	Replaces []string `json:"replaces,omitempty" yaml:"replaces,omitempty"`
	// Optional: An integer string compared against other equal package provides used to
	// determine priority of provides
	ProviderPriority string `json:"provider-priority,omitempty" yaml:"provider-priority,omitempty"`
	// Optional: An integer string compared against other equal package provides used to
	// determine priority of file replacements
	ReplacesPriority string `json:"replaces-priority,omitempty" yaml:"replaces-priority,omitempty"`

	// List of self-provided dependencies found outside of lib directories
	// ("lib", "usr/lib", "lib64", or "usr/lib64").
	Vendored []string `json:"-" yaml:"-"`
}

type ConfigurationParsingOption func(*configOptions)

type configOptions struct {
	filesystem                  fs.FS
	envFilePath                 string
	cpu, cpumodel, memory, disk string
	timeout                     time.Duration
	commit                      string

	varsFilePath string
}

// include reconciles all given opts into the receiver variable, such that it is
// ready to use for config parsing.
func (options *configOptions) include(opts ...ConfigurationParsingOption) {
	for _, fn := range opts {
		fn(options)
	}
}

func WithDefaultTimeout(timeout time.Duration) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.timeout = timeout
	}
}

func WithDefaultCPU(cpu string) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.cpu = cpu
	}
}

func WithDefaultCPUModel(cpumodel string) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.cpumodel = cpumodel
	}
}

func WithDefaultDisk(disk string) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.disk = disk
	}
}

func WithDefaultMemory(memory string) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.memory = memory
	}
}

// WithFS sets the fs.FS implementation to use. So far this FS is used only for
// reading the configuration file. If not provided, the default FS will be an
// os.DirFS created from the configuration file's containing directory.
func WithFS(filesystem fs.FS) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.filesystem = filesystem
	}
}

func WithCommit(hash string) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.commit = hash
	}
}

// WithEnvFileForParsing set the paths from which to read an environment file.
func WithEnvFileForParsing(path string) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.envFilePath = path
	}
}

// WithVarsFileForParsing sets the path to the vars file to use if the user wishes to
// populate the variables block from an external file.
func WithVarsFileForParsing(path string) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.varsFilePath = path
	}
}

// buildConfigMap builds a map used to prepare a replacer for variable substitution.
func buildConfigMap(cfg *Configuration) map[string]string {
	out := map[string]string{
		SubstitutionPackageName:        cfg.Package.Name,
		SubstitutionPackageVersion:     cfg.Package.Version,
		SubstitutionPackageDescription: cfg.Package.Description,
		SubstitutionPackageEpoch:       strconv.FormatUint(cfg.Package.Epoch, 10),
		SubstitutionPackageFullVersion: fmt.Sprintf("%s-r%d", cfg.Package.Version, cfg.Package.Epoch),
	}

	for k, v := range cfg.Vars {
		nk := fmt.Sprintf("${{vars.%s}}", k)
		out[nk] = v
	}

	return out
}

func replacerFromMap(with map[string]string) *strings.Replacer {
	replacements := []string{}
	for k, v := range with {
		replacements = append(replacements, k, v)
	}
	return strings.NewReplacer(replacements...)
}

func replaceAll(r *strings.Replacer, in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = r.Replace(s)
	}
	return out
}

func replaceNeeds(r *strings.Replacer, in *Needs) *Needs {
	if in == nil {
		return nil
	}
	return &Needs{
		Packages: replaceAll(r, in.Packages),
	}
}

func replaceMap(r *strings.Replacer, in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}

	replacedWith := make(map[string]string, len(in))
	for key, value := range in {
		replacedWith[key] = r.Replace(value)
	}
	return replacedWith
}

func replaceEntrypoint(r *strings.Replacer, in apko_types.ImageEntrypoint) apko_types.ImageEntrypoint {
	return apko_types.ImageEntrypoint{
		Type:          in.Type,
		Command:       r.Replace(in.Command),
		ShellFragment: r.Replace(in.ShellFragment),
		Services:      replaceMap(r, in.Services),
	}
}

func replaceImageContents(r *strings.Replacer, in apko_types.ImageContents) apko_types.ImageContents {
	return apko_types.ImageContents{
		BuildRepositories: replaceAll(r, in.BuildRepositories),
		Repositories:      replaceAll(r, in.Repositories),
		Keyring:           replaceAll(r, in.Keyring),
		Packages:          replaceAll(r, in.Packages),
		BaseImage:         in.BaseImage, // TODO
	}
}

func replaceImageConfig(r *strings.Replacer, in apko_types.ImageConfiguration) apko_types.ImageConfiguration {
	return apko_types.ImageConfiguration{
		Contents:    replaceImageContents(r, in.Contents),
		Entrypoint:  replaceEntrypoint(r, in.Entrypoint),
		Cmd:         r.Replace(in.Cmd),
		StopSignal:  r.Replace(in.StopSignal),
		WorkDir:     r.Replace(in.WorkDir),
		Accounts:    in.Accounts, // TODO
		Archs:       in.Archs,    // TODO
		Environment: replaceMap(r, in.Environment),
		Paths:       in.Paths, // TODO
		VCSUrl:      r.Replace(in.VCSUrl),
		Annotations: replaceMap(r, in.Annotations),
		Include:     in.Include, //nolint:staticcheck // TODO
		Volumes:     replaceAll(r, in.Volumes),
	}
}

func replacePipeline(r *strings.Replacer, in Pipeline) Pipeline {
	return Pipeline{
		Name:        r.Replace(in.Name),
		Uses:        in.Uses,
		With:        replaceMap(r, in.With),
		Runs:        r.Replace(in.Runs),
		Pipeline:    replacePipelines(r, in.Pipeline),
		Inputs:      in.Inputs,
		Needs:       replaceNeeds(r, in.Needs),
		Label:       in.Label,
		If:          r.Replace(in.If),
		Assertions:  in.Assertions,
		WorkDir:     r.Replace(in.WorkDir),
		Environment: replaceMap(r, in.Environment),
	}
}

func replacePipelines(r *strings.Replacer, in []Pipeline) []Pipeline {
	if in == nil {
		return nil
	}

	out := make([]Pipeline, 0, len(in))
	for _, p := range in {
		out = append(out, replacePipeline(r, p))
	}
	return out
}

func replaceTest(r *strings.Replacer, in *Test) *Test {
	if in == nil {
		return nil
	}
	return &Test{
		Environment: replaceImageConfig(r, in.Environment),
		Pipeline:    replacePipelines(r, in.Pipeline),
	}
}

func replaceScriptlets(r *strings.Replacer, in *Scriptlets) *Scriptlets {
	if in == nil {
		return nil
	}

	return &Scriptlets{
		Trigger: Trigger{
			Script: r.Replace(in.Trigger.Script),
			Paths:  replaceAll(r, in.Trigger.Paths),
		},
		PreInstall:    r.Replace(in.PreInstall),
		PostInstall:   r.Replace(in.PostInstall),
		PreDeinstall:  r.Replace(in.PreDeinstall),
		PostDeinstall: r.Replace(in.PostDeinstall),
		PreUpgrade:    r.Replace(in.PreUpgrade),
		PostUpgrade:   r.Replace(in.PostUpgrade),
	}
}

// default to value of in parameter unless commit is explicitly specified.
func replaceCommit(commit string, in string) string {
	if in == "" {
		return commit
	}
	return in
}

func replaceDependencies(r *strings.Replacer, in Dependencies) Dependencies {
	return Dependencies{
		Runtime:          replaceAll(r, in.Runtime),
		Provides:         replaceAll(r, in.Provides),
		Replaces:         replaceAll(r, in.Replaces),
		ProviderPriority: r.Replace(in.ProviderPriority),
		ReplacesPriority: r.Replace(in.ReplacesPriority),
	}
}

func replacePackage(r *strings.Replacer, commit string, in Package) Package {
	return Package{
		Name:               r.Replace(in.Name),
		Version:            r.Replace(in.Version),
		Epoch:              in.Epoch,
		Description:        r.Replace(in.Description),
		Annotations:        replaceMap(r, in.Annotations),
		URL:                r.Replace(in.URL),
		Commit:             replaceCommit(commit, in.Commit),
		TargetArchitecture: replaceAll(r, in.TargetArchitecture),
		Copyright:          in.Copyright,
		Dependencies:       replaceDependencies(r, in.Dependencies),
		Options:            in.Options,
		Scriptlets:         replaceScriptlets(r, in.Scriptlets),
		Checks:             in.Checks,
		CPE:                in.CPE,
		Timeout:            in.Timeout,
		Resources:          in.Resources,
		TestResources:      in.TestResources,
		SetCap:             in.SetCap,
	}
}

func replaceSubpackage(r *strings.Replacer, detectedCommit string, in Subpackage) Subpackage {
	return Subpackage{
		If:           r.Replace(in.If),
		Name:         r.Replace(in.Name),
		Pipeline:     replacePipelines(r, in.Pipeline),
		Dependencies: replaceDependencies(r, in.Dependencies),
		Options:      in.Options,
		Scriptlets:   replaceScriptlets(r, in.Scriptlets),
		Description:  r.Replace(in.Description),
		URL:          r.Replace(in.URL),
		Commit:       replaceCommit(detectedCommit, in.Commit),
		Checks:       in.Checks,
		Test:         replaceTest(r, in.Test),
	}
}

func replaceSubpackages(r *strings.Replacer, datas map[string]DataItems, cfg Configuration, in []Subpackage) ([]Subpackage, error) {
	out := make([]Subpackage, 0, len(in))

	for i, sp := range in {
		if sp.Commit == "" {
			sp.Commit = cfg.Package.Commit
		}

		if sp.Range == "" {
			out = append(out, replaceSubpackage(r, cfg.Package.Commit, sp))
			continue
		}

		items, ok := datas[sp.Range]
		if !ok {
			return nil, fmt.Errorf("subpackages[%d] (%q) specified undefined range: %q", i, sp.Name, sp.Range)
		}

		// Ensure iterating over items is deterministic by sorting keys alphabetically
		keys := make([]string, 0, len(items))
		for k := range items {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		configMap := buildConfigMap(&cfg)
		if err := cfg.PerformVarSubstitutions(configMap); err != nil {
			return nil, fmt.Errorf("applying variable substitutions: %w", err)
		}

		for _, k := range keys {
			v := items[k]
			configMap["${{range.key}}"] = k
			configMap["${{range.value}}"] = v
			r := replacerFromMap(configMap)

			thingToAdd := replaceSubpackage(r, cfg.Package.Commit, sp)

			out = append(out, thingToAdd)
		}
	}

	return out, nil
}

// propagateChildPipelines performs downward propagation of configuration values.
func (p *Pipeline) propagateChildPipelines() {
	for idx := range p.Pipeline {
		if p.Pipeline[idx].WorkDir == "" {
			p.Pipeline[idx].WorkDir = p.WorkDir
		}

		m := maps.Clone(p.Environment)
		maps.Copy(m, p.Pipeline[idx].Environment)
		p.Pipeline[idx].Environment = m

		p.Pipeline[idx].propagateChildPipelines()
	}
}

// propagatePipelines performs downward propagation of all pipelines in the config.
func (cfg *Configuration) propagatePipelines() {
	for _, sp := range cfg.Pipeline {
		sp.propagateChildPipelines()
	}

	// Also propagate subpackages
	for _, sp := range cfg.Subpackages {
		for _, spp := range sp.Pipeline {
			spp.propagateChildPipelines()
		}
	}
}

// ParseConfiguration returns a decoded build Configuration using the parsing options provided.
func ParseConfiguration(ctx context.Context, configurationFilePath string, opts ...ConfigurationParsingOption) (*Configuration, error) {
	options := &configOptions{}
	configurationDirPath := filepath.Dir(configurationFilePath)
	options.include(opts...)

	if options.filesystem == nil {
		// TODO: this is an abstraction leak, and we can remove this `if statement` once
		//  ParseConfiguration relies solely on an abstract fs.FS.

		options.filesystem = os.DirFS(configurationDirPath)
		configurationFilePath = filepath.Base(configurationFilePath)
	}

	if configurationFilePath == "" {
		return nil, errors.New("no configuration file path provided")
	}

	f, err := options.filesystem.Open(configurationFilePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	root := yaml.Node{}

	cfg := Configuration{root: &root}

	// Unmarshal into a node first
	decoderNode := yaml.NewDecoder(f)
	err = decoderNode.Decode(&root)
	if err != nil {
		return nil, fmt.Errorf("unable to decode configuration file %q: %w", configurationFilePath, err)
	}

	// XXX(Elizafox) - Node.Decode doesn't allow setting of KnownFields, so we do this cheesy hack below
	data, err := yaml.Marshal(&root)
	if err != nil {
		return nil, fmt.Errorf("unable to decode configuration file %q: %w", configurationFilePath, err)
	}

	// Now unmarshal it into the struct, part of said cheesy hack
	reader := bytes.NewReader(data)
	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("unable to decode configuration file %q: %w", configurationFilePath, err)
	}

	// If a variables file was defined, merge it into the variables block.
	if varsFile := options.varsFilePath; varsFile != "" {
		f, err := os.Open(varsFile) // #nosec G304 - User-specified variables file from configuration
		if err != nil {
			return nil, fmt.Errorf("loading variables file: %w", err)
		}
		defer f.Close()

		vars := map[string]string{}
		err = yaml.NewDecoder(f).Decode(&vars)
		if err != nil {
			return nil, fmt.Errorf("loading variables file: %w", err)
		}

		maps.Copy(cfg.Vars, vars)
	}

	// Mutate config properties with substitutions.
	configMap := buildConfigMap(&cfg)
	if err := cfg.PerformVarSubstitutions(configMap); err != nil {
		return nil, fmt.Errorf("applying variable substitutions: %w", err)
	}

	replacer := replacerFromMap(configMap)

	cfg.Package = replacePackage(replacer, options.commit, cfg.Package)

	cfg.Pipeline = replacePipelines(replacer, cfg.Pipeline)

	datas := make(map[string]DataItems, len(cfg.Data))
	for _, d := range cfg.Data {
		datas[d.Name] = d.Items
	}

	cfg.Subpackages, err = replaceSubpackages(replacer, datas, cfg, cfg.Subpackages)
	if err != nil {
		return nil, fmt.Errorf("unable to decode configuration file %q: %w", configurationFilePath, err)
	}

	cfg.Environment = replaceImageConfig(replacer, cfg.Environment)

	cfg.Test = replaceTest(replacer, cfg.Test)

	cfg.Data = nil // TODO: zero this out or not?

	// TODO: validate that subpackage ranges have been consumed and applied
	grpName := buildUser
	grp := apko_types.Group{
		GroupName: grpName,
		GID:       1000,
		Members:   []string{buildUser},
	}

	usr := apko_types.User{
		UserName: buildUser,
		UID:      1000,
		GID:      apko_types.GID(&grp.GID),
	}

	sameGroup := func(g apko_types.Group) bool { return g.GroupName == grpName }
	if !slices.ContainsFunc(cfg.Environment.Accounts.Groups, sameGroup) {
		cfg.Environment.Accounts.Groups = append(cfg.Environment.Accounts.Groups, grp)
	}
	if cfg.Test != nil && !slices.ContainsFunc(cfg.Test.Environment.Accounts.Groups, sameGroup) {
		cfg.Test.Environment.Accounts.Groups = append(cfg.Test.Environment.Accounts.Groups, grp)
	}
	for _, sub := range cfg.Subpackages {
		if sub.Test == nil || len(sub.Test.Pipeline) == 0 {
			continue
		}
		if !slices.ContainsFunc(sub.Test.Environment.Accounts.Groups, sameGroup) {
			sub.Test.Environment.Accounts.Groups = append(sub.Test.Environment.Accounts.Groups, grp)
		}
	}

	sameUser := func(u apko_types.User) bool { return u.UserName == buildUser }
	if !slices.ContainsFunc(cfg.Environment.Accounts.Users, sameUser) {
		cfg.Environment.Accounts.Users = append(cfg.Environment.Accounts.Users, usr)
	}
	if cfg.Test != nil && !slices.ContainsFunc(cfg.Test.Environment.Accounts.Users, sameUser) {
		cfg.Test.Environment.Accounts.Users = append(cfg.Test.Environment.Accounts.Users, usr)
	}
	for _, sub := range cfg.Subpackages {
		if sub.Test == nil || len(sub.Test.Pipeline) == 0 {
			continue
		}
		if !slices.ContainsFunc(sub.Test.Environment.Accounts.Users, sameUser) {
			sub.Test.Environment.Accounts.Users = append(sub.Test.Environment.Accounts.Users, usr)
		}
	}

	// Merge environment file if needed.
	if envFile := options.envFilePath; envFile != "" {
		envMap, err := godotenv.Read(envFile)
		if err != nil {
			return nil, fmt.Errorf("loading environment file: %w", err)
		}

		curEnv := cfg.Environment.Environment
		cfg.Environment.Environment = envMap

		// Overlay the environment in the YAML on top as override.
		maps.Copy(cfg.Environment.Environment, curEnv)
	}

	// Set up some useful environment variables.
	if cfg.Environment.Environment == nil {
		cfg.Environment.Environment = make(map[string]string)
	}

	const (
		defaultEnvVarHOME       = "/home/build"
		defaultEnvVarGOPATH     = "/home/build/.cache/go"
		defaultEnvVarGOMODCACHE = "/var/cache/melange/gomodcache"
	)

	setIfEmpty := func(key, value string) {
		if cfg.Environment.Environment[key] == "" {
			cfg.Environment.Environment[key] = value
		}
	}

	setIfEmpty("HOME", defaultEnvVarHOME)
	setIfEmpty("GOPATH", defaultEnvVarGOPATH)
	setIfEmpty("GOMODCACHE", defaultEnvVarGOMODCACHE)

	if err := cfg.applySubstitutionsForProvides(); err != nil {
		return nil, err
	}
	if err := cfg.applySubstitutionsForRuntime(); err != nil {
		return nil, err
	}
	if err := cfg.applySubstitutionsForReplaces(); err != nil {
		return nil, err
	}
	if err := cfg.applySubstitutionsForPackages(); err != nil {
		return nil, err
	}
	if err := cfg.applySubstitutionsForPriorities(); err != nil {
		return nil, err
	}

	// Propagate all child pipelines
	cfg.propagatePipelines()

	if cfg.Package.Resources == nil {
		cfg.Package.Resources = &Resources{}
	}
	if options.timeout != 0 {
		cfg.Package.Timeout = options.timeout
	}
	if options.cpu != "" {
		cfg.Package.Resources.CPU = options.cpu
	}
	if options.cpumodel != "" {
		cfg.Package.Resources.CPUModel = options.cpumodel
	}
	if options.memory != "" {
		cfg.Package.Resources.Memory = options.memory
	}
	if options.disk != "" {
		cfg.Package.Resources.Disk = options.disk
	}

	// Finally, validate the configuration we ended up with before returning it for use downstream.
	if err = cfg.validate(ctx); err != nil {
		return nil, fmt.Errorf("validating configuration %q: %w", cfg.Package.Name, err)
	}

	return &cfg, nil
}

func (cfg Configuration) Root() *yaml.Node {
	return cfg.root
}

type ErrInvalidConfiguration struct {
	Problem error
}

func (e ErrInvalidConfiguration) Error() string {
	return fmt.Sprintf("build configuration is invalid: %v", e.Problem)
}

func (e ErrInvalidConfiguration) Unwrap() error {
	return e.Problem
}

var packageNameRegex = regexp.MustCompile(`^[a-zA-Z\d][a-zA-Z\d+_.-]*$`)

func (cfg Configuration) validate(ctx context.Context) error {
	if !packageNameRegex.MatchString(cfg.Package.Name) {
		return ErrInvalidConfiguration{Problem: fmt.Errorf("package name must match regex %q", packageNameRegex)}
	}

	if cfg.Package.Version == "" {
		return ErrInvalidConfiguration{Problem: errors.New("package version must not be empty")}
	}

	// TODO: try to validate value of .package.version

	if err := validateDependenciesPriorities(cfg.Package.Dependencies); err != nil {
		return ErrInvalidConfiguration{Problem: errors.New("priority must convert to integer")}
	}
	if err := validatePipelines(ctx, cfg.Pipeline); err != nil {
		return ErrInvalidConfiguration{Problem: err}
	}
	if err := validateCapabilities(cfg.Package.SetCap); err != nil {
		return ErrInvalidConfiguration{Problem: err}
	}

	saw := map[string]int{cfg.Package.Name: -1}
	for i, sp := range cfg.Subpackages {
		if extant, ok := saw[sp.Name]; ok {
			if extant == -1 {
				return ErrInvalidConfiguration{
					Problem: fmt.Errorf("subpackage[%d] has same name as main package: %q", i, sp.Name),
				}
			} else {
				return ErrInvalidConfiguration{
					Problem: fmt.Errorf("saw duplicate subpackage name %q (subpackages index: %d and %d)", sp.Name, extant, i),
				}
			}
		}

		saw[sp.Name] = i

		if !packageNameRegex.MatchString(sp.Name) {
			return ErrInvalidConfiguration{Problem: fmt.Errorf("subpackage name %q (subpackages index: %d) must match regex %q", sp.Name, i, packageNameRegex)}
		}
		if err := validateDependenciesPriorities(sp.Dependencies); err != nil {
			return ErrInvalidConfiguration{Problem: errors.New("priority must convert to integer")}
		}
		if err := validatePipelines(ctx, sp.Pipeline); err != nil {
			return ErrInvalidConfiguration{Problem: err}
		}
		if err := validateCapabilities(sp.SetCap); err != nil {
			return ErrInvalidConfiguration{Problem: err}
		}
	}

	if err := validateCPE(cfg.Package.CPE); err != nil {
		return ErrInvalidConfiguration{Problem: fmt.Errorf("CPE validation: %w", err)}
	}

	return nil
}

func pipelineName(p Pipeline, i int) string {
	if p.Name != "" {
		return strconv.Quote(p.Name)
	}

	if p.Uses != "" {
		return strconv.Quote(p.Uses)
	}

	return fmt.Sprintf("[%d]", i)
}

func validatePipelines(ctx context.Context, ps []Pipeline) error {
	log := clog.FromContext(ctx)
	for i, p := range ps {
		if p.With != nil && p.Uses == "" {
			return fmt.Errorf("pipeline contains with but no uses")
		}

		if p.Uses != "" && p.Runs != "" {
			return fmt.Errorf("pipeline cannot contain both uses %q and runs", p.Uses)
		}

		if p.Uses != "" && len(p.Pipeline) > 0 {
			log.Warnf("pipeline %s contains both uses and a pipeline", pipelineName(p, i))
		}

		if len(p.With) > 0 && p.Runs != "" {
			return fmt.Errorf("pipeline cannot contain both with and runs")
		}

		if err := validatePipelines(ctx, p.Pipeline); err != nil {
			return fmt.Errorf("validating pipeline %s children: %w", pipelineName(p, i), err)
		}
	}
	return nil
}

func validateDependenciesPriorities(deps Dependencies) error {
	priorities := []string{deps.ProviderPriority, deps.ReplacesPriority}
	for _, priority := range priorities {
		if priority == "" {
			continue
		}
		_, err := strconv.Atoi(priority)
		if err != nil {
			return err
		}
	}
	return nil
}

func validateCPE(cpe CPE) error {
	if cpe.Part != "" && cpe.Part != "a" {
		return fmt.Errorf("invalid CPE part (must be 'a' for application, if specified): %q", cpe.Part)
	}

	if (cpe.Vendor == "") != (cpe.Product == "") {
		return errors.New("vendor and product must each be set if the other is set")
	}

	const all = "*"
	if cpe.Vendor == all {
		return fmt.Errorf("invalid CPE vendor: %q", cpe.Vendor)
	}
	if cpe.Product == all {
		return fmt.Errorf("invalid CPE product: %q", cpe.Product)
	}

	if err := validateCPEField(cpe.Vendor); err != nil {
		return fmt.Errorf("invalid vendor: %w", err)
	}
	if err := validateCPEField(cpe.Product); err != nil {
		return fmt.Errorf("invalid product: %w", err)
	}
	if err := validateCPEField(cpe.Edition); err != nil {
		return fmt.Errorf("invalid edition: %w", err)
	}
	if err := validateCPEField(cpe.Language); err != nil {
		return fmt.Errorf("invalid language: %w", err)
	}
	if err := validateCPEField(cpe.SWEdition); err != nil {
		return fmt.Errorf("invalid software edition: %w", err)
	}
	if err := validateCPEField(cpe.TargetSW); err != nil {
		return fmt.Errorf("invalid target software: %w", err)
	}
	if err := validateCPEField(cpe.TargetHW); err != nil {
		return fmt.Errorf("invalid target hardware: %w", err)
	}
	if err := validateCPEField(cpe.Other); err != nil {
		return fmt.Errorf("invalid other field: %w", err)
	}

	return nil
}

var cpeFieldRegex = regexp.MustCompile(`^[a-z\d][a-z\d+_.-]*$`)

func validateCPEField(val string) error {
	if val == "" {
		return nil
	}

	if !cpeFieldRegex.MatchString(val) {
		return fmt.Errorf("invalid CPE field value %q, must match regex %q", val, cpeFieldRegex.String())
	}

	return nil
}

// Summarize lists the dependencies that are configured in a dependency set.
func (dep *Dependencies) Summarize(ctx context.Context) {
	log := clog.FromContext(ctx)
	if len(dep.Runtime) > 0 {
		log.Info("  runtime:")

		for _, dep := range dep.Runtime {
			log.Info("    " + dep)
		}
	}

	if len(dep.Provides) > 0 {
		log.Info("  provides:")

		for _, dep := range dep.Provides {
			log.Info("    " + dep)
		}
	}
}

// validCapabilities contains a list of _in-use_ capabilities and their respective bits from existing package specs.
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/capability.h#L106-L422
var validCapabilities = map[string]uint32{
	"cap_net_bind_service": 10,
	"cap_net_admin":        12,
	"cap_net_raw":          13,
	"cap_ipc_lock":         14,
	"cap_sys_admin":        21,
}

func getCapabilityValue(attr string) uint32 {
	if value, ok := validCapabilities[attr]; ok {
		return 1 << value
	}
	return 0
}

func validateCapabilities(setcap []Capability) error {
	var errs []error

	for _, cap := range setcap {
		for add := range cap.Add {
			// Allow for multiple capabilities per addition
			// e.g., cap_net_raw,cap_net_admin,cap_net_bind_service+eip
			for p := range strings.SplitSeq(add, ",") {
				if _, ok := validCapabilities[p]; !ok {
					errs = append(errs, fmt.Errorf("invalid capability %q for path %q", p, cap.Path))
				}
			}
		}
		if cap.Reason == "" {
			errs = append(errs, fmt.Errorf("unjustified reason for capability %q", cap.Add))
		}
	}

	if len(errs) == 0 {
		return nil
	}

	return errors.Join(errs...)
}

type capabilityData struct {
	Effective   uint32
	Permitted   uint32
	Inheritable uint32
}

// ParseCapabilities processes all capabilities for a given path.
func ParseCapabilities(caps []Capability) (map[string]capabilityData, error) {
	pathCapabilities := map[string]capabilityData{}

	for _, c := range caps {
		for attrs, data := range c.Add {
			for attr := range strings.SplitSeq(attrs, ",") {
				capValues := getCapabilityValue(attr)
				effective, permitted, inheritable := parseCapability(data)

				caps, ok := pathCapabilities[c.Path]
				if !ok {
					caps = struct {
						Effective   uint32
						Permitted   uint32
						Inheritable uint32
					}{}
				}

				if effective {
					caps.Effective |= capValues
				}
				if permitted {
					caps.Permitted |= capValues
				}
				if inheritable {
					caps.Inheritable |= capValues
				}

				pathCapabilities[c.Path] = caps
			}
		}
	}

	return pathCapabilities, nil
}

// parseCapability determines which bits are set for a given capability.
func parseCapability(capFlag string) (effective, permitted, inheritable bool) {
	for _, c := range capFlag {
		switch c {
		case 'e':
			effective = true
		case 'p':
			permitted = true
		case 'i':
			inheritable = true
		}
	}
	return effective, permitted, inheritable
}

// EncodeCapability returns the byte slice necessary to set the final capability xattr.
func EncodeCapability(effectiveBits, permittedBits, inheritableBits uint32) []byte {
	revision := uint32(0x03000000)

	var flags uint32 = 0
	if effectiveBits != 0 {
		flags = 0x01
	}
	magic := revision | flags

	data := make([]byte, 24)

	binary.LittleEndian.PutUint32(data[0:4], magic)
	binary.LittleEndian.PutUint32(data[4:8], permittedBits)
	binary.LittleEndian.PutUint32(data[8:12], inheritableBits)

	binary.LittleEndian.PutUint32(data[12:16], 0)
	binary.LittleEndian.PutUint32(data[16:20], 0)
	binary.LittleEndian.PutUint32(data[20:24], 0)

	return data
}
