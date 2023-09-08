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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	apko_types "chainguard.dev/apko/pkg/build/types"
	apko_log "chainguard.dev/apko/pkg/log"

	"github.com/go-git/go-git/v5"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/logger"
	"chainguard.dev/melange/pkg/util"
)

type Scriptlets struct {
	// Optional: A script to run on a custom trigger
	Trigger struct {
		// Optional: The script to run
		Script string
		// Optional: The list of paths to monitor to trigger the script
		Paths []string
	} `yaml:"trigger,omitempty"`

	// Optional: The script to run pre install. The script should contain the
	// shebang interpreter.
	PreInstall string `yaml:"pre-install,omitempty"`
	// Optional: The script to run post install. The script should contain the
	// shebang interpreter.
	PostInstall string `yaml:"post-install,omitempty"`
	// Optional: The script to run before uninstalling. The script should contain
	// the shebang interpreter.
	PreDeinstall string `yaml:"pre-deinstall,omitempty"`
	// Optional: The script to run after uninstalling. The script should contain
	// the shebang interpreter.
	PostDeinstall string `yaml:"post-deinstall,omitempty"`
	// Optional: The script to run before upgrading. The script should contain
	// the shebang interpreter.
	PreUpgrade string `yaml:"pre-upgrade,omitempty"`
	// Optional: The script to run after upgrading. The script should contain the
	// shebang interpreter.
	PostUpgrade string `yaml:"post-upgrade,omitempty"`
}

type PackageOption struct {
	// Optional: Signify this package as a virtual package which does not provide
	// any files, executables, librariries, etc... and is otherwise empty
	NoProvides bool `yaml:"no-provides"`
	// Optional: Mark this package as a self contained package that does not
	// depend on any other package
	NoDepends bool `yaml:"no-depends"`
	// Optional: Mark this package as not providing any executables
	NoCommands bool `yaml:"no-commands"`
}

type Package struct {
	// The name of the package
	Name string `yaml:"name"`
	// The version of the package
	Version string `yaml:"version"`
	// The monotone increasing epoch of the package
	Epoch uint64 `yaml:"epoch"`
	// A human readable description of the package
	Description string `yaml:"description,omitempty"`
	// The URL to the package's homepage
	URL string `yaml:"url,omitempty"`
	// Optional: The git commit of the package build configuration
	Commit string `yaml:"commit,omitempty"`
	// List of target architectures for which this package should be build for
	TargetArchitecture []string `yaml:"target-architecture,omitempty"`
	// The list of copyrights for this package
	Copyright []Copyright `yaml:"copyright,omitempty"`
	// List of packages to depends on
	Dependencies Dependencies `yaml:"dependencies,omitempty"`
	// Optional: Options that alter the packages behavior
	Options PackageOption `yaml:"options,omitempty"`
	// Optional: Executable scripts that run at various stages of the package
	// lifecycle, triggered by configurable events
	Scriptlets Scriptlets `yaml:"scriptlets,omitempty"`
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

type Copyright struct {
	// Optional: The license paths, typically '*'
	Paths []string `yaml:"paths,omitempty"`
	// Optional: Attestations of the license
	Attestation string `yaml:"attestation,omitempty"`
	// Required: The license for this package
	License string `yaml:"license"`
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
	RequiredSteps int `yaml:"required-steps,omitempty"`
}

type Pipeline struct {
	// Optional: A user defined name for the pipeline
	Name string `yaml:"name,omitempty"`
	// Optional: A named reusable pipeline to run
	//
	// This can be either a pipeline builtin to melange, or a user defined named pipeline.
	// For example, to use a builtin melange pipeline:
	// 		uses: autoconf/make
	Uses string `yaml:"uses,omitempty"`
	// Optional: Arguments passed to the reusable pipelines defined in `uses`
	With map[string]string `yaml:"with,omitempty"`
	// Optional: The command to run using the builder's shell (/bin/sh)
	Runs string `yaml:"runs,omitempty"`
	// Optional: The list of pipelines to run.
	//
	// Each pipeline runs in it's own context that is not shared between other
	// pipelines. To share context between pipelines, nest a pipeline within an
	// existing pipeline. This can be useful when you wish to share common
	// configuration, such as an alternative `working-directory`.
	Pipeline []Pipeline `yaml:"pipeline,omitempty"`
	// Optional: A map of inputs to the pipeline
	Inputs map[string]Input `yaml:"inputs,omitempty"`
	// Optional: Configuration to determine any explicit dependencies this pipeline may have
	Needs Needs `yaml:"needs,omitempty"`
	// Optional: Labels to apply to the pipeline
	Label string `yaml:"label,omitempty"`
	// Optional: A condition to evaluate before running the pipeline
	If string `yaml:"if,omitempty"`
	// Optional: Assertions to evaluate whether the pipeline was successful
	Assertions PipelineAssertions `yaml:"assertions,omitempty"`
	// Optional: The working directory of the pipeline
	//
	// This defaults to the guests' build workspace (/home/build)
	WorkDir string `yaml:"working-directory,omitempty"`
	// Optional: Configuration for the generated SBOM
	SBOM SBOM `yaml:"sbom,omitempty"`
}

type Subpackage struct {
	// Optional: A conditional statement to evaluate for the subpackage
	If string `yaml:"if,omitempty"`
	// Optional: The iterable used to generate multiple subpackages
	Range string `yaml:"range,omitempty"`
	// Required: Name of the subpackage
	Name string `yaml:"name"`
	// Optional: The list of pipelines that produce subpackage.
	Pipeline []Pipeline `yaml:"pipeline,omitempty"`
	// Optional: List of packages to depend on
	Dependencies Dependencies `yaml:"dependencies,omitempty"`
	// Optional: Options that alter the packages behavior
	Options    PackageOption `yaml:"options,omitempty"`
	Scriptlets Scriptlets    `yaml:"scriptlets,omitempty"`
	// Optional: The human readable description of the subpackage
	Description string `yaml:"description,omitempty"`
	// Optional: The URL to the package's homepage
	URL string `yaml:"url,omitempty"`
	// Optional: The git commit of the subpackage build configuration
	Commit string `yaml:"commit,omitempty"`
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
	Language string `yaml:"language"`
}

type Input struct {
	// Optional: The human readable description of the input
	Description string
	// Optional: The default value of the input. Required when the input is.
	Default string
	// Optional: A toggle denoting whether the input is required or not
	Required bool
}

// The root melange configuration
type Configuration struct {
	// Package metadata
	Package Package `yaml:"package"`
	// The specification for the packages build environment
	Environment apko_types.ImageConfiguration
	// Required: The list of pipelines that produce the package.
	Pipeline []Pipeline `yaml:"pipeline,omitempty"`
	// Optional: The list of subpackages that this package also produces.
	Subpackages []Subpackage `yaml:"subpackages,omitempty"`
	// Optional: An arbitrary list of data that can be used via templating in the
	// pipeline
	Data []RangeData `yaml:"data,omitempty"`
	// Optional: The update block determining how this package is auto updated
	Update Update `yaml:"update,omitempty"`
	// Optional: A map of arbitrary variables that can be used via templating in
	// the pipeline
	Vars map[string]string `yaml:"vars,omitempty"`
	// Optional: A list of transformations to create for the builtin template
	// variables
	VarTransforms []VarTransforms `yaml:"var-transforms,omitempty"`
	// Optional: Deviations to the build
	Options map[string]BuildOption `yaml:"options,omitempty"`

	// Parsed AST for this configuration
	root *yaml.Node
}

// Name returns a name for the configuration, using the package name.
func (cfg Configuration) Name() string {
	return cfg.Package.Name
}

type VarTransforms struct {
	// Required: The original template variable.
	//
	// Example: ${{package.version}}
	From string `yaml:"from"`
	// Required: The regular expression to match against the `from` variable
	Match string `yaml:"match"`
	// Required: The repl to replace on all `match` matches
	Replace string `yaml:"replace"`
	// Required: The name of the new variable to create
	//
	// Example: mangeled-package-version
	To string `yaml:"to"`
}

// Update provides information used to describe how to keep the package up to date
type Update struct {
	// Toggle if updates should occur
	Enabled bool `yaml:"enabled"`
	// Indicates that this package should be manually updated, usually taking
	// care over special version numbers
	Manual bool `yaml:"manual"`
	// Indicate that an update to this package requires an epoch bump of
	// downstream dependencies, e.g. golang, java
	Shared bool `yaml:"shared,omitempty"`
	// Override the version separator if it is nonstandard
	VersionSeparator string `yaml:"version-separator,omitempty"`
	// A slice of regex patterns to match an upstream version and ignore
	IgnoreRegexPatterns []string `yaml:"ignore-regex-patterns,omitempty"`
	// The configuration block for updates tracked via release-monitoring.org
	ReleaseMonitor *ReleaseMonitor `yaml:"release-monitor,omitempty"`
	// The configuration block for updates tracked via the Github API
	GitHubMonitor *GitHubMonitor `yaml:"github,omitempty"`
	// The configuration block for transforming the `package.version` into an APK version
	VersionTransform []VersionTransform `yaml:"version-transform,omitempty"`
}

// ReleaseMonitor indicates using the API for https://release-monitoring.org/
type ReleaseMonitor struct {
	// Required: ID number for release monitor
	Identifier int `yaml:"identifier"`
	// If the version in release monitor contains a prefix which should be ignored
	StripPrefix string `yaml:"strip-prefix,omitempty"`
	// If the version in release monitor contains a suffix which should be ignored
	StripSuffix string `yaml:"strip-suffix,omitempty"`
}

// GitHubMonitor indicates using the GitHub API
type GitHubMonitor struct {
	// Org/repo for GitHub
	Identifier string `yaml:"identifier"`
	// If the version in GitHub contains a prefix which should be ignored
	StripPrefix string `yaml:"strip-prefix,omitempty"`
	// If the version in GitHub contains a suffix which should be ignored
	StripSuffix string `yaml:"strip-suffix,omitempty"`
	// Filter to apply when searching tags on a GitHub repository
	TagFilter string `yaml:"tag-filter,omitempty"`
	// Override the default of using a GitHub release to identify related tag to
	// fetch.  Not all projects use GitHub releases but just use tags
	UseTags bool `yaml:"use-tag,omitempty"`
}

// VersionTransform allows mapping the package version to an APK version
type VersionTransform struct {
	// Required: The regular expression to match against the `package.version` variable
	Match string `yaml:"match"`
	// Required: The repl to replace on all `match` matches
	Replace string `yaml:"replace"`
}

type RangeData struct {
	Name  string    `yaml:"name"`
	Items DataItems `yaml:"items"`
}

type DataItems map[string]string

type Dependencies struct {
	// Optional: List of runtime dependencies
	Runtime []string `yaml:"runtime,omitempty"`
	// Optional: List of packages provided
	Provides []string `yaml:"provides,omitempty"`
	// Optional: List of replace objectives
	Replaces []string `yaml:"replaces,omitempty"`
	// Optional: An integer compared against other equal package provides used to
	// determine priority
	ProviderPriority int `yaml:"provider-priority,omitempty"`
}

type ConfigurationParsingOption func(*configOptions)

type configOptions struct {
	filesystem  fs.FS
	envFilePath string
	logger      apko_log.Logger

	varsFilePath string
}

// include reconciles all given opts into the receiver variable, such that it is
// ready to use for config parsing.
func (options *configOptions) include(opts ...ConfigurationParsingOption) {
	for _, fn := range opts {
		fn(options)
	}

	if options.logger == nil {
		options.logger = logger.NopLogger{}
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

// WithLogger sets the logger to use during configuration parsing. This is
// optional, and if not supplied, a no-op logger will be used.
func WithLogger(logger apko_log.Logger) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.logger = logger
	}
}

// WithVarsFileForParsing sets the path to the vars file to use if the user wishes to
// populate the variables block from an external file.
func WithVarsFileForParsing(path string) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.varsFilePath = path
	}
}

func detectCommit(dirPath string, logger apko_log.Logger) string {
	// Best-effort detection of current commit, to be used when not specified in the config file

	// TODO: figure out how to use an abstract FS
	repo, err := git.PlainOpen(dirPath)
	if err != nil {
		logger.Printf("unable to detect git commit for build configuration: %v", err)
		return ""
	}

	head, err := repo.Head()
	if err != nil {
		return ""
	}

	commit := head.Hash().String()
	logger.Printf("detected git commit for build configuration: %s", commit)
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

// ParseConfiguration returns a decoded build Configuration using the parsing options provided.
func ParseConfiguration(configurationFilePath string, opts ...ConfigurationParsingOption) (*Configuration, error) {
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

	detectedCommit := detectCommit(configurationDirPath, options.logger)
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

		for _, k := range keys {
			v := items[k]
			replacer := replacerFromMap(map[string]string{
				"${{range.key}}":   k,
				"${{range.value}}": v,
			})
			thingToAdd := Subpackage{
				Name:        replacer.Replace(sp.Name),
				Description: replacer.Replace(sp.Description),
				Dependencies: Dependencies{
					Runtime:          replaceAll(replacer, sp.Dependencies.Runtime),
					Provides:         replaceAll(replacer, sp.Dependencies.Provides),
					Replaces:         replaceAll(replacer, sp.Dependencies.Replaces),
					ProviderPriority: sp.Dependencies.ProviderPriority,
				},
				Options: sp.Options,
				URL:     replacer.Replace(sp.URL),
				If:      replacer.Replace(sp.If),
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
					Name:   p.Name,
					Uses:   p.Uses,
					With:   replacedWith,
					Inputs: p.Inputs,
					Needs:  p.Needs,
					Label:  p.Label,
					Runs:   replacer.Replace(p.Runs),
					// TODO: p.Pipeline?
				})
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
		defaultEnvVarHOME   = "/home/build"
		defaultEnvVarGOPATH = "/home/build/.cache/go"
	)

	if cfg.Environment.Environment["HOME"] == "" {
		cfg.Environment.Environment["HOME"] = defaultEnvVarHOME
	}
	if cfg.Environment.Environment["GOPATH"] == "" {
		cfg.Environment.Environment["GOPATH"] = defaultEnvVarGOPATH
	}

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

	// Finally, validate the configuration we ended up with before returning it for use downstream.
	if err = cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating configuration: %w", err)
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

var packageNameRegex = regexp.MustCompile(`^[a-zA-Z\d][a-zA-Z\d+_.-]*$`)

func (cfg Configuration) validate() error {
	if !packageNameRegex.MatchString(cfg.Package.Name) {
		return ErrInvalidConfiguration{Problem: fmt.Errorf("package name must match regex %q", packageNameRegex)}
	}

	if cfg.Package.Version == "" {
		return ErrInvalidConfiguration{Problem: errors.New("package version must not be empty")}
	}

	// TODO: try to validate value of .package.version

	for i, sp := range cfg.Subpackages {
		if !packageNameRegex.MatchString(sp.Name) {
			return ErrInvalidConfiguration{Problem: fmt.Errorf("subpackage name %q (subpackages index: %d) must match regex %q", sp.Name, i, packageNameRegex)}
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
func (dep *Dependencies) Summarize(logger apko_log.Logger) {
	if len(dep.Runtime) > 0 {
		logger.Printf("  runtime:")

		for _, dep := range dep.Runtime {
			logger.Printf("    %s", dep)
		}
	}

	if len(dep.Provides) > 0 {
		logger.Printf("  provides:")

		for _, dep := range dep.Provides {
			logger.Printf("    %s", dep)
		}
	}
}
