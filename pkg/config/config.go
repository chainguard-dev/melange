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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	apko_types "chainguard.dev/apko/pkg/build/types"

	"github.com/chainguard-dev/clog"
	"github.com/go-git/go-git/v5"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/util"
)

type Trigger struct {
	// Optional: The script to run
	Script string `json:"script,omitempty"`
	// Optional: The list of paths to monitor to trigger the script
	Paths []string `json:"paths,omitempty"`
}

type Scriptlets struct {
	// Optional: A script to run on a custom trigger
	Trigger Trigger `json:"trigger,omitempty" yaml:"trigger,omitempty"`
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
	NoProvides bool `json:"no-provides" yaml:"no-provides"`
	// Optional: Mark this package as a self contained package that does not
	// depend on any other package
	NoDepends bool `json:"no-depends" yaml:"no-depends"`
	// Optional: Mark this package as not providing any executables
	NoCommands bool `json:"no-commands" yaml:"no-commands"`
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
	// A human readable description of the package
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// The URL to the package's homepage
	URL string `json:"url,omitempty" yaml:"url,omitempty"`
	// Optional: The git commit of the package build configuration
	Commit string `json:"commit,omitempty" yaml:"commit,omitempty"`
	// List of target architectures for which this package should be build for
	TargetArchitecture []string `json:"target-architecture,omitempty" yaml:"target-architecture,omitempty"`
	// The list of copyrights for this package
	Copyright []Copyright `json:"copyright,omitempty" yaml:"copyright,omitempty"`
	// List of packages to depends on
	Dependencies Dependencies `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	// Optional: Options that alter the packages behavior
	Options *PackageOption `json:"options,omitempty" yaml:"options,omitempty"`
	// Optional: Executable scripts that run at various stages of the package
	// lifecycle, triggered by configurable events
	Scriptlets *Scriptlets `json:"scriptlets,omitempty" yaml:"scriptlets,omitempty"`
	// Optional: enabling, disabling, and configuration of build checks
	Checks Checks `json:"checks,omitempty" yaml:"checks,omitempty"`

	// Optional: The amount of time to allow this build to take before timing out.
	Timeout time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	// Optional: Resources to allocate to the build.
	Resources *Resources `json:"resources,omitempty" yaml:"resources,omitempty"`
}

type Resources struct {
	CPU    string `json:"cpu,omitempty" yaml:"cpu,omitempty"`
	Memory string `json:"memory,omitempty" yaml:"memory,omitempty"`
	Disk   string `json:"memory,omitempty" yaml:"disk,omitempty"`
}

// PackageURL returns the package URL ("purl") for the package. For more
// information, see https://github.com/package-url/purl-spec#purl.
func (p Package) PackageURL(distro string) string {
	const typ = "apk"
	version := fmt.Sprintf("%s-r%d", p.Version, p.Epoch)

	return fmt.Sprintf("pkg:%s/%s/%s@%s",
		typ,
		distro,
		p.Name,
		version,
	)
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
				return fmt.Errorf("failed to apply replacement to provides %q: %w", prov, err)
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
		return fmt.Errorf("failed to apply replacement to provides %q: %w", cfg.Package.Dependencies.ProviderPriority, err)
	}
	cfg.Package.Dependencies.ReplacesPriority, err = util.MutateStringFromMap(nw, cfg.Package.Dependencies.ReplacesPriority)
	if err != nil {
		return fmt.Errorf("failed to apply replacement to provides %q: %w", cfg.Package.Dependencies.ReplacesPriority, err)
	}
	for _, sp := range cfg.Subpackages {
		sp.Dependencies.ProviderPriority, err = util.MutateStringFromMap(nw, sp.Dependencies.ProviderPriority)
		if err != nil {
			return fmt.Errorf("failed to apply replacement to provides %q: %w", sp.Dependencies.ProviderPriority, err)
		}
		sp.Dependencies.ReplacesPriority, err = util.MutateStringFromMap(nw, sp.Dependencies.ReplacesPriority)
		if err != nil {
			return fmt.Errorf("failed to apply replacement to provides %q: %w", sp.Dependencies.ReplacesPriority, err)
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
			return fmt.Errorf("failed to apply replacement to runtime %q: %w", runtime, err)
		}
	}
	for _, srt := range cfg.Subpackages {
		for i, runtime := range srt.Dependencies.Runtime {
			var err error
			srt.Dependencies.Runtime[i], err = util.MutateStringFromMap(nw, runtime)
			if err != nil {
				return fmt.Errorf("failed to apply replacement to runtime %q: %w", runtime, err)
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
	for _, srt := range cfg.Subpackages {
		for i, replaces := range srt.Dependencies.Replaces {
			var err error
			srt.Dependencies.Replaces[i], err = util.MutateStringFromMap(nw, replaces)
			if err != nil {
				return fmt.Errorf("failed to apply replacement to replaces %q: %w", replaces, err)
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
}

// LicenseExpression returns an SPDX license expression formed from the
// data in the copyright structs found in the conf. Its a simple OR for now.
func (p *Package) LicenseExpression() string {
	licenseExpression := ""
	if p.Copyright == nil {
		return licenseExpression
	}
	for _, cp := range p.Copyright {
		if licenseExpression != "" {
			licenseExpression += " OR "
		}
		licenseExpression += cp.License
	}
	return licenseExpression
}

// Returns array of ExtractedLicensingInfos formed from the data in
// the copyright structs found in the conf.
func (p *Package) LicensingInfos(WorkspaceDir string) (map[string]string, error) {
	licenseInfos := make(map[string]string)
	for _, cp := range p.Copyright {
		if cp.LicensePath != "" {
			content, err := os.ReadFile(filepath.Join(WorkspaceDir, cp.LicensePath))
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
func (p *Package) FullCopyright() string {
	copyright := ""
	for _, cp := range p.Copyright {
		copyright += cp.Attestation + "\n"
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
	// Each pipeline runs in it's own context that is not shared between other
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
	// Optional: A condition to evaluate before running the pipeline
	If string `json:"if,omitempty" yaml:"if,omitempty"`
	// Optional: Assertions to evaluate whether the pipeline was successful
	Assertions *PipelineAssertions `json:"assertions,omitempty" yaml:"assertions,omitempty"`
	// Optional: The working directory of the pipeline
	//
	// This defaults to the guests' build workspace (/home/build)
	WorkDir string `json:"working-directory,omitempty" yaml:"working-directory,omitempty"`
	// Optional: environment variables to override the apko environment
	Environment map[string]string `json:"environment,omitempty" yaml:"environment,omitempty"`
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
	Dependencies Dependencies `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
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
	Checks Checks `json:"checks,omitempty" yaml:"checks,omitempty"`
	// Test section for the subpackage.
	Test *Test `json:"test,omitempty" yaml:"test,omitempty"`
}

// PackageURL returns the package URL ("purl") for the subpackage. For more
// information, see https://github.com/package-url/purl-spec#purl.
func (spkg Subpackage) PackageURL(distro, packageVersionWithRelease string) string {
	const typ = "apk"

	return fmt.Sprintf("pkg:%s/%s/%s@%s",
		typ,
		distro,
		spkg.Name,
		packageVersionWithRelease,
	)
}

type SBOM struct {
	// Optional: The language of the generated SBOM
	Language string `json:"language" yaml:"language"`
}

type Input struct {
	// Optional: The human readable description of the input
	Description string `json:"description,omitempty"`
	// Optional: The default value of the input. Required when the input is.
	Default string `json:"default,omitempty"`
	// Optional: A toggle denoting whether the input is required or not
	Required bool `json:"required,omitempty"`
}

// The root melange configuration
type Configuration struct {
	// Package metadata
	Package Package `json:"package" yaml:"package"`
	// The specification for the packages build environment
	Environment apko_types.ImageConfiguration `json:"environment" yaml:"environment"`
	// Required: The list of pipelines that produce the package.
	Pipeline []Pipeline `json:"pipeline,omitempty" yaml:"pipeline,omitempty"`
	// Optional: The list of subpackages that this package also produces.
	Subpackages []Subpackage `json:"subpackages,omitempty" yaml:"subpackages,omitempty"`
	// Optional: An arbitrary list of data that can be used via templating in the
	// pipeline
	Data []RangeData `json:"data,omitempty" yaml:"data,omitempty"`
	// Optional: The update block determining how this package is auto updated
	Update Update `json:"update,omitempty" yaml:"update,omitempty"`
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

type Test struct {
	// Additional Environment necessary for test.
	// Environment.Contents.Packages automatically get
	// package.dependencies.runtime added to it. So, if your test needs
	// no additional packages, you can leave it blank.
	Environment apko_types.ImageConfiguration `json:"environment" yaml:"environment"`

	// Required: The list of pipelines that test the produced package.
	Pipeline []Pipeline `json:"pipeline" yaml:"pipeline"`
}

// Name returns a name for the configuration, using the package name.
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
	// The configuration block for transforming the `package.version` into an APK version
	VersionTransform []VersionTransform `json:"version-transform,omitempty" yaml:"version-transform,omitempty"`
	// ExcludeReason is required if enabled=false, to explain why updates are disabled.
	ExcludeReason string `json:"exclude-reason,omitempty" yaml:"exclude-reason,omitempty"`
}

// ReleaseMonitor indicates using the API for https://release-monitoring.org/
type ReleaseMonitor struct {
	// Required: ID number for release monitor
	Identifier int `json:"identifier" yaml:"identifier"`
	// If the version in release monitor contains a prefix which should be ignored
	StripPrefix string `json:"strip-prefix,omitempty" yaml:"strip-prefix,omitempty"`
	// If the version in release monitor contains a suffix which should be ignored
	StripSuffix string `json:"strip-suffix,omitempty" yaml:"strip-suffix,omitempty"`
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

// VersionTransform allows mapping the package version to an APK version
type VersionTransform struct {
	// Required: The regular expression to match against the `package.version` variable
	Match string `json:"match" yaml:"match"`
	// Required: The repl to replace on all `match` matches
	Replace string `json:"replace" yaml:"replace"`
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
	filesystem        fs.FS
	envFilePath       string
	cpu, memory, disk string
	timeout           time.Duration

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

func detectCommit(ctx context.Context, dirPath string) string {
	log := clog.FromContext(ctx)
	// Best-effort detection of current commit, to be used when not specified in the config file

	// TODO: figure out how to use an abstract FS
	repo, err := git.PlainOpen(dirPath)
	if err != nil {
		log.Debugf("unable to detect git commit for build configuration: %v", err)
		return ""
	}

	head, err := repo.Head()
	if err != nil {
		return ""
	}

	commit := head.Hash().String()
	return commit
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

// propagateChildPipelines performs downward propagation of configuration values.
func (p *Pipeline) propagateChildPipelines() {
	for idx := range p.Pipeline {
		if p.Pipeline[idx].WorkDir == "" {
			p.Pipeline[idx].WorkDir = p.WorkDir
		}

		p.Pipeline[idx].Environment = util.RightJoinMap(p.Environment, p.Pipeline[idx].Environment)

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
	err = decoder.Decode(&cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to decode configuration file %q: %w", configurationFilePath, err)
	}

	detectedCommit := detectCommit(ctx, configurationDirPath)
	if cfg.Package.Commit == "" {
		cfg.Package.Commit = detectedCommit
	}

	datas := make(map[string]DataItems)
	for _, d := range cfg.Data {
		datas[d.Name] = d.Items
	}
	subpackages := []Subpackage{}
	for _, sp := range cfg.Subpackages {
		if sp.Commit == "" {
			sp.Commit = detectedCommit
		}

		if sp.Range == "" {
			subpackages = append(subpackages, sp)
			continue
		}
		items, ok := datas[sp.Range]
		if !ok {
			return nil, fmt.Errorf("unable to parse configuration file %q: subpackage %q specified undefined range: %q", configurationFilePath, sp.Name, sp.Range)
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
			replacer := replacerFromMap(configMap)

			thingToAdd := Subpackage{
				Name:        replacer.Replace(sp.Name),
				Description: replacer.Replace(sp.Description),
				Commit:      detectedCommit,
				Dependencies: Dependencies{
					Runtime:          replaceAll(replacer, sp.Dependencies.Runtime),
					Provides:         replaceAll(replacer, sp.Dependencies.Provides),
					Replaces:         replaceAll(replacer, sp.Dependencies.Replaces),
					ProviderPriority: replacer.Replace(sp.Dependencies.ProviderPriority),
					ReplacesPriority: replacer.Replace(sp.Dependencies.ReplacesPriority),
				},
				Options: sp.Options,
				URL:     replacer.Replace(sp.URL),
				If:      replacer.Replace(sp.If),
			}

			if script := sp.Scriptlets; script != nil {
				thingToAdd.Scriptlets = &Scriptlets{
					Trigger: Trigger{
						Script: replacer.Replace(sp.Scriptlets.Trigger.Script),
						Paths:  replaceAll(replacer, sp.Scriptlets.Trigger.Paths),
					},
					PreInstall:    replacer.Replace(sp.Scriptlets.PreInstall),
					PostInstall:   replacer.Replace(sp.Scriptlets.PostInstall),
					PreDeinstall:  replacer.Replace(sp.Scriptlets.PreDeinstall),
					PostDeinstall: replacer.Replace(sp.Scriptlets.PostDeinstall),
					PreUpgrade:    replacer.Replace(sp.Scriptlets.PreUpgrade),
					PostUpgrade:   replacer.Replace(sp.Scriptlets.PostUpgrade),
				}
			}

			for _, p := range sp.Pipeline {
				// take a copy of the with map, so we can replace the values
				replacedWith := make(map[string]string)
				for key, value := range p.With {
					replacedWith[key] = replacer.Replace(value)
				}

				// if the map is empty, set it to nil to avoid serializing an empty map
				if len(replacedWith) == 0 {
					replacedWith = nil
				}

				thingToAdd.Pipeline = append(thingToAdd.Pipeline, Pipeline{
					Name:    p.Name,
					Uses:    p.Uses,
					With:    replacedWith,
					Inputs:  p.Inputs,
					Needs:   p.Needs,
					Label:   p.Label,
					Runs:    replacer.Replace(p.Runs),
					WorkDir: replacer.Replace(p.WorkDir),
					// TODO: p.Pipeline?
				})
			}
			if sp.Test != nil {
				thingToAdd.Test = &Test{}
				for _, p := range sp.Test.Pipeline {
					// take a copy of the with map, so we can replace the values
					replacedWith := make(map[string]string)
					for key, value := range p.With {
						replacedWith[key] = replacer.Replace(value)
					}

					// if the map is empty, set it to nil to avoid serializing an empty map
					if len(replacedWith) == 0 {
						replacedWith = nil
					}

					thingToAdd.Test.Pipeline = append(thingToAdd.Test.Pipeline, Pipeline{
						Name:    p.Name,
						Uses:    p.Uses,
						With:    replacedWith,
						Inputs:  p.Inputs,
						Needs:   p.Needs,
						Label:   p.Label,
						Runs:    replacer.Replace(p.Runs),
						WorkDir: replacer.Replace(p.WorkDir),
						// TODO: p.Pipeline?
					})
				}
			}
			subpackages = append(subpackages, thingToAdd)
		}
	}
	cfg.Data = nil // TODO: zero this out or not?
	cfg.Subpackages = subpackages

	// TODO: validate that subpackage ranges have been consumed and applied

	grp := apko_types.Group{
		GroupName: "build",
		GID:       1000,
		Members:   []string{"build"},
	}
	cfg.Environment.Accounts.Groups = append(cfg.Environment.Accounts.Groups, grp)

	usr := apko_types.User{
		UserName: "build",
		UID:      1000,
		GID:      1000,
	}
	cfg.Environment.Accounts.Users = append(cfg.Environment.Accounts.Users, usr)

	// Merge environment file if needed.
	if envFile := options.envFilePath; envFile != "" {
		envMap, err := godotenv.Read(envFile)
		if err != nil {
			return nil, fmt.Errorf("loading environment file: %w", err)
		}

		curEnv := cfg.Environment.Environment
		cfg.Environment.Environment = envMap

		// Overlay the environment in the YAML on top as override.
		for k, v := range curEnv {
			cfg.Environment.Environment[k] = v
		}
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

	// If a variables file was defined, merge it into the variables block.
	if varsFile := options.varsFilePath; varsFile != "" {
		f, err := os.Open(varsFile)
		if err != nil {
			return nil, fmt.Errorf("loading variables file: %w", err)
		}
		defer f.Close()

		vars := map[string]string{}
		err = yaml.NewDecoder(f).Decode(&vars)
		if err != nil {
			return nil, fmt.Errorf("loading variables file: %w", err)
		}

		for k, v := range vars {
			cfg.Vars[k] = v
		}
	}

	// Mutate config properties with substitutions.
	configMap := buildConfigMap(&cfg)
	if err := cfg.PerformVarSubstitutions(configMap); err != nil {
		return nil, fmt.Errorf("applying variable substitutions: %w", err)
	}

	replacer := replacerFromMap(configMap)

	cfg.Package.Name = replacer.Replace(cfg.Package.Name)
	cfg.Package.Version = replacer.Replace(cfg.Package.Version)
	cfg.Package.Description = replacer.Replace(cfg.Package.Description)

	subpackages = []Subpackage{}

	for _, sp := range cfg.Subpackages {
		sp.Name = replacer.Replace(sp.Name)
		sp.Description = replacer.Replace(sp.Description)

		subpackages = append(subpackages, sp)
	}

	cfg.Subpackages = subpackages

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
	if options.memory != "" {
		cfg.Package.Resources.Memory = options.memory
	}
	if options.disk != "" {
		cfg.Package.Resources.Disk = options.disk
	}

	// Finally, validate the configuration we ended up with before returning it for use downstream.
	if err = cfg.validate(); err != nil {
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

func (cfg Configuration) validate() error {
	if !packageNameRegex.MatchString(cfg.Package.Name) {
		return ErrInvalidConfiguration{Problem: fmt.Errorf("package name must match regex %q", packageNameRegex)}
	}

	if cfg.Package.Version == "" {
		return ErrInvalidConfiguration{Problem: errors.New("package version must not be empty")}
	}

	// TODO: try to validate value of .package.version

	if err := validateDependenciesPriorities(cfg.Package.Dependencies); err != nil {
		return ErrInvalidConfiguration{Problem: errors.New("prioritiy must convert to integer")}
	}
	if err := validatePipelines(cfg.Pipeline); err != nil {
		return ErrInvalidConfiguration{Problem: err}
	}

	saw := map[string]int{}
	for i, sp := range cfg.Subpackages {
		if extant, ok := saw[sp.Name]; ok {
			return fmt.Errorf("saw duplicate subpackage name %q (subpackages index: %d and %d)", sp.Name, extant, i)
		}
		saw[sp.Name] = i

		if !packageNameRegex.MatchString(sp.Name) {
			return ErrInvalidConfiguration{Problem: fmt.Errorf("subpackage name %q (subpackages index: %d) must match regex %q", sp.Name, i, packageNameRegex)}
		}
		if err := validateDependenciesPriorities(sp.Dependencies); err != nil {
			return ErrInvalidConfiguration{Problem: errors.New("prioritiy must convert to integer")}
		}
		if err := validatePipelines(sp.Pipeline); err != nil {
			return ErrInvalidConfiguration{Problem: err}
		}
	}

	return nil
}

func validatePipelines(ps []Pipeline) error {
	for _, p := range ps {
		if p.With != nil && p.Uses == "" {
			return fmt.Errorf("pipeline contains with but no uses")
		}

		if p.Uses != "" && p.Runs != "" {
			return fmt.Errorf("pipeline cannot contain both uses %q and runs", p.Uses)
		}

		if len(p.With) > 0 && p.Runs != "" {
			return fmt.Errorf("pipeline cannot contain both with and runs")
		}

		if err := validatePipelines(p.Pipeline); err != nil {
			return err
		}
	}
	return nil
}

func validateDependenciesPriorities(deps Dependencies) error {
	priorities := []string{deps.ProviderPriority, deps.ProviderPriority}
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

// PackageURLs returns a list of package URLs ("purls") for the given
// configuration. The first PURL is always the origin package, and any subsequent
// items are the PURLs for the Configuration's subpackages. For more information
// on PURLs, see https://github.com/package-url/purl-spec#purl.
func (cfg Configuration) PackageURLs(distro string) []string {
	var purls []string

	p := cfg.Package
	purls = append(purls, p.PackageURL(distro))

	for _, subpackage := range cfg.Subpackages {
		version := fmt.Sprintf("%s-r%d", p.Version, p.Epoch)
		purls = append(purls, subpackage.PackageURL(distro, version))
	}

	return purls
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
