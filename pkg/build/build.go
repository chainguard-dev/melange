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

package build

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_oci "chainguard.dev/apko/pkg/build/oci"
	apko_types "chainguard.dev/apko/pkg/build/types"
	apkofs "chainguard.dev/apko/pkg/fs"
	"cloud.google.com/go/storage"
	"github.com/go-git/go-git/v5"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/joho/godotenv"
	"github.com/zealic/xignore"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/container"
	"chainguard.dev/melange/pkg/index"
	"chainguard.dev/melange/pkg/sbom"
)

type Scriptlets struct {
	Trigger struct {
		Script string
		Paths  []string
	} `yaml:"trigger,omitempty"`

	PreInstall    string `yaml:"pre-install,omitempty"`
	PostInstall   string `yaml:"post-install,omitempty"`
	PreDeinstall  string `yaml:"pre-deinstall,omitempty"`
	PostDeinstall string `yaml:"post-deinstall,omitempty"`
	PreUpgrade    string `yaml:"pre-upgrade,omitempty"`
	PostUpgrade   string `yaml:"post-upgrade,omitempty"`
}

type PackageOption struct {
	NoProvides bool `yaml:"no-provides"`
	NoDepends  bool `yaml:"no-depends"`
	NoCommands bool `yaml:"no-commands"`
}

type Package struct {
	Name               string        `yaml:"name"`
	Version            string        `yaml:"version"`
	Epoch              uint64        `yaml:"epoch"`
	Description        string        `yaml:"description,omitempty"`
	URL                string        `yaml:"url,omitempty"`
	Commit             string        `yaml:"commit,omitempty"`
	TargetArchitecture []string      `yaml:"target-architecture"`
	Copyright          []Copyright   `yaml:"copyright,omitempty"`
	Dependencies       Dependencies  `yaml:"dependencies,omitempty"`
	Options            PackageOption `yaml:"options,omitempty"`
	Scriptlets         Scriptlets    `yaml:"scriptlets,omitempty"`
}

type Copyright struct {
	Paths       []string `yaml:"paths"`
	Attestation string   `yaml:"attestation"`
	License     string   `yaml:"license"`
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
	Packages []string
}

type PipelineAssertions struct {
	RequiredSteps int `yaml:"required-steps,omitempty"`
}

type Pipeline struct {
	Name       string             `yaml:"name,omitempty"`
	Uses       string             `yaml:"uses,omitempty"`
	With       map[string]string  `yaml:"with,omitempty"`
	Runs       string             `yaml:"runs,omitempty"`
	Pipeline   []Pipeline         `yaml:"pipeline,omitempty"`
	Inputs     map[string]Input   `yaml:"inputs,omitempty"`
	Needs      Needs              `yaml:"needs,omitempty"`
	Label      string             `yaml:"label,omitempty"`
	If         string             `yaml:"if,omitempty"`
	Assertions PipelineAssertions `yaml:"assertions,omitempty"`
	logger     *log.Logger
	steps      int
	SBOM       SBOM `yaml:"sbom,omitempty"`
}

type Subpackage struct {
	Range        string        `yaml:"range,omitempty"`
	Name         string        `yaml:"name"`
	Pipeline     []Pipeline    `yaml:"pipeline,omitempty"`
	Dependencies Dependencies  `yaml:"dependencies,omitempty"`
	Options      PackageOption `yaml:"options,omitempty"`
	Scriptlets   Scriptlets    `yaml:"scriptlets,omitempty"`
	Description  string        `yaml:"description,omitempty"`
	URL          string        `yaml:"url,omitempty"`
	Commit       string        `yaml:"commit,omitempty"`
}

type SBOM struct {
	Language string `yaml:"language"`
}

type Input struct {
	Description string
	Default     string
	Required    bool
}

type Configuration struct {
	Package     Package
	Environment apko_types.ImageConfiguration
	Pipeline    []Pipeline   `yaml:"pipeline,omitempty"`
	Subpackages []Subpackage `yaml:"subpackages,omitempty"`
	Data        []RangeData  `yaml:"data,omitempty"`
}

type RangeData struct {
	Name  string       `yaml:"name"`
	Items DataItemList `yaml:"items"`
}

type DataItemList []DataItem

func (d *DataItemList) UnmarshalYAML(n *yaml.Node) error {
	if d == nil {
		return nil
	}
	var m map[string]string
	if err := n.Decode(&m); err != nil {
		return err
	}
	out := make([]DataItem, 0, len(*d))
	for k, v := range m {
		out = append(out, DataItem{Key: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	*d = out
	return nil
}

func (d *DataItemList) MarshalYAML() (interface{}, error) {
	if d == nil {
		return nil, nil
	}
	m := map[string]string{}
	for _, i := range *d {
		m[i.Key] = m[i.Value]
	}
	return m, nil
}

type DataItem struct {
	Key, Value string
}

type Context struct {
	Configuration      Configuration
	ConfigFile         string
	SourceDateEpoch    time.Time
	WorkspaceDir       string
	WorkspaceIgnore    string
	PipelineDir        string
	BuiltinPipelineDir string
	SourceDir          string
	GuestDir           string
	SigningKey         string
	SigningPassphrase  string
	GenerateIndex      bool
	UseProot           bool
	EmptyWorkspace     bool
	OutDir             string
	Logger             *log.Logger
	Arch               apko_types.Architecture
	ExtraKeys          []string
	ExtraRepos         []string
	DependencyLog      string
	BinShOverlay       string
	ignorePatterns     []*xignore.Pattern
	CacheDir           string
	BreakpointLabel    string
	ContinueLabel      string
	foundContinuation  bool
	StripOriginName    bool
	EnvFile            string
	Runner             container.Runner
	imgDigest          name.Digest
	containerConfig    *container.Config
}

type Dependencies struct {
	Runtime  []string `yaml:"runtime,omitempty"`
	Provides []string `yaml:"provides,omitempty"`
}

func New(opts ...Option) (*Context, error) {
	ctx := Context{
		WorkspaceIgnore: ".melangeignore",
		SourceDir:       ".",
		OutDir:          ".",
		CacheDir:        "/var/cache/melange",
		Logger:          log.New(log.Writer(), "melange: ", log.LstdFlags|log.Lmsgprefix),
		Arch:            apko_types.ParseArchitecture(runtime.GOARCH),
	}

	for _, opt := range opts {
		if err := opt(&ctx); err != nil {
			return nil, err
		}
	}

	// If no workspace directory is explicitly requested, create a
	// temporary directory for it.  Otherwise, ensure we are in a
	// subdir for this specific build context.
	if ctx.WorkspaceDir != "" {
		// If we are continuing the build, do not modify the workspace
		// directory path.
		// TODO(kaniini): Clean up the logic for this, perhaps by signalling
		// multi-arch builds to the build context.
		if ctx.ContinueLabel == "" {
			ctx.WorkspaceDir = filepath.Join(ctx.WorkspaceDir, ctx.Arch.ToAPK())
		}

		// Get the absolute path to the workspace dir, which is needed for bind
		// mounts.
		absdir, err := filepath.Abs(ctx.WorkspaceDir)
		if err != nil {
			return nil, fmt.Errorf("unable to resolve path %s: %w", ctx.WorkspaceDir, err)
		}

		ctx.WorkspaceDir = absdir
	} else {
		tmpdir, err := os.MkdirTemp("", "melange-workspace-*")
		if err != nil {
			return nil, fmt.Errorf("unable to create workspace dir: %w", err)
		}
		ctx.WorkspaceDir = tmpdir
	}

	// If no config file is explicitly requested for the build context
	// we check if .melange.yaml or melange.yaml exist.
	checks := []string{".melange.yaml", ".melange.yml", "melange.yaml", "melange.yml"}
	if ctx.ConfigFile == "" {
		for _, chk := range checks {
			if _, err := os.Stat(chk); err == nil {
				ctx.Logger.Printf("no configuration file provided -- using %s", chk)
				ctx.ConfigFile = chk
				break
			}
		}
	}

	// If no config file could be automatically detected, error.
	if ctx.ConfigFile == "" {
		return nil, fmt.Errorf("melange.yaml is missing")
	}

	if err := ctx.Configuration.Load(ctx); err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// SOURCE_DATE_EPOCH will always overwrite the build flag
	if v, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok {
		// The value MUST be an ASCII representation of an integer
		// with no fractional component, identical to the output
		// format of date +%s.
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			// If the value is malformed, the build process
			// SHOULD exit with a non-zero error code.
			return nil, fmt.Errorf("failed to parse SOURCE_DATE_EPOCH: %w", err)
		}

		ctx.SourceDateEpoch = time.Unix(sec, 0)
	}

	ctx.Logger.SetPrefix(fmt.Sprintf("melange (%s/%s): ", ctx.Configuration.Package.Name, ctx.Arch.ToAPK()))

	// Make sure there is actually a pipeline to run.
	if len(ctx.Configuration.Pipeline) == 0 {
		return nil, fmt.Errorf("no pipeline has been configured, check your config for indentation errors")
	}

	// Check that we actually can run things in containers.
	runner, err := container.GetRunner()
	if err != nil {
		return nil, err
	}
	ctx.Runner = runner

	return &ctx, nil
}

type Option func(*Context) error

// WithConfig sets the configuration file used for the package build context.
func WithConfig(configFile string) Option {
	return func(ctx *Context) error {
		ctx.ConfigFile = configFile
		return nil
	}
}

// WithBuildDate sets the timestamps for the build context.
// The string is parsed according to RFC3339.
// An empty string is a special case and will default to
// the unix epoch.
func WithBuildDate(s string) Option {
	return func(bc *Context) error {
		// default to 0 for reproducibility
		if s == "" {
			bc.SourceDateEpoch = time.Unix(0, 0)
			return nil
		}

		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return err
		}

		bc.SourceDateEpoch = t
		return nil
	}
}

// WithWorkspaceDir sets the workspace directory to use.
func WithWorkspaceDir(workspaceDir string) Option {
	return func(ctx *Context) error {
		ctx.WorkspaceDir = workspaceDir
		return nil
	}
}

// WithGuestDir sets the guest directory to use.
func WithGuestDir(guestDir string) Option {
	return func(ctx *Context) error {
		ctx.GuestDir = guestDir
		return nil
	}
}

// WithWorkspaceIgnore sets the workspace ignore rules file to use.
func WithWorkspaceIgnore(workspaceIgnore string) Option {
	return func(ctx *Context) error {
		ctx.WorkspaceIgnore = workspaceIgnore
		return nil
	}
}

// WithEmptyWorkspace sets whether the workspace should be empty.
func WithEmptyWorkspace(emptyWorkspace bool) Option {
	return func(ctx *Context) error {
		ctx.EmptyWorkspace = emptyWorkspace
		return nil
	}
}

// WithPipelineDir sets the pipeline directory to extend the built-in pipeline directory.
func WithPipelineDir(pipelineDir string) Option {
	return func(ctx *Context) error {
		ctx.PipelineDir = pipelineDir
		return nil
	}
}

// WithBuiltinPipelineDirectory sets the pipeline directory to use.
func WithBuiltinPipelineDirectory(builtinPipelineDir string) Option {
	return func(ctx *Context) error {
		ctx.BuiltinPipelineDir = builtinPipelineDir
		return nil
	}
}

// WithSourceDir sets the source directory to use.
func WithSourceDir(sourceDir string) Option {
	return func(ctx *Context) error {
		ctx.SourceDir = sourceDir
		return nil
	}
}

// WithCacheDir sets the cache directory to use.
func WithCacheDir(cacheDir string) Option {
	return func(ctx *Context) error {
		ctx.CacheDir = cacheDir
		return nil
	}
}

// WithSigningKey sets the signing key path to use.
func WithSigningKey(signingKey string) Option {
	return func(ctx *Context) error {
		ctx.SigningKey = signingKey
		return nil
	}
}

// WithGenerateIndex sets whether or not the apk index should be generated.
func WithGenerateIndex(generateIndex bool) Option {
	return func(ctx *Context) error {
		ctx.GenerateIndex = generateIndex
		return nil
	}
}

// WithUseProot sets whether or not proot should be used.
func WithUseProot(useProot bool) Option {
	return func(ctx *Context) error {
		ctx.UseProot = useProot
		return nil
	}
}

// WithOutDir sets the output directory to use for the packages.
func WithOutDir(outDir string) Option {
	return func(ctx *Context) error {
		ctx.OutDir = outDir
		return nil
	}
}

// WithArch sets the build architecture to use for this build context.
func WithArch(arch apko_types.Architecture) Option {
	return func(ctx *Context) error {
		ctx.Arch = arch
		return nil
	}
}

// WithExtraKeys adds a set of extra keys to the build context.
func WithExtraKeys(extraKeys []string) Option {
	return func(ctx *Context) error {
		ctx.ExtraKeys = extraKeys
		return nil
	}
}

// WithExtraRepos adds a set of extra repos to the build context.
func WithExtraRepos(extraRepos []string) Option {
	return func(ctx *Context) error {
		ctx.ExtraRepos = extraRepos
		return nil
	}
}

// WithDependencyLog sets a filename to use for dependency logging.
func WithDependencyLog(logFile string) Option {
	return func(ctx *Context) error {
		ctx.DependencyLog = logFile
		return nil
	}
}

// WithBinShOverlay sets a filename to copy from when installing /bin/sh
// into a build environment.
func WithBinShOverlay(binShOverlay string) Option {
	return func(ctx *Context) error {
		ctx.BinShOverlay = binShOverlay
		return nil
	}
}

// WithBreakpointLabel sets a label to stop build execution at.  The build
// environment and workspace are preserved.
func WithBreakpointLabel(breakpointLabel string) Option {
	return func(ctx *Context) error {
		ctx.BreakpointLabel = breakpointLabel
		return nil
	}
}

// WithContinueLabel sets a label to continue build execution from.  This
// requires a preserved build environment and workspace.
func WithContinueLabel(continueLabel string) Option {
	return func(ctx *Context) error {
		ctx.ContinueLabel = continueLabel
		return nil
	}
}

// WithStripOriginName determines whether the origin name should be stripped
// from generated packages.  The APK solver uses origin names to flatten
// possible dependency nodes when solving for a DAG, which means that they
// should be stripped when building "bootstrap" repositories, as the
// cross-sysroot packages will be preferred over the native ones otherwise.
func WithStripOriginName(stripOriginName bool) Option {
	return func(ctx *Context) error {
		ctx.StripOriginName = stripOriginName
		return nil
	}
}

// WithEnvFile specifies an environment file to use to preload the build
// environment.  It should contain the CFLAGS and LDFLAGS used by the C
// toolchain as well as any other desired environment settings for the
// build environment.
func WithEnvFile(envFile string) Option {
	return func(ctx *Context) error {
		ctx.EnvFile = envFile
		return nil
	}
}

type ConfigurationParsingOption func(*configOptions)

type configOptions struct {
	filesystem  fs.FS
	envFilePath string
	logger      Logger
}

// include reconciles all given opts into the receiver variable, such that it is
// ready to use for config parsing.
func (options *configOptions) include(dirPath string, opts ...ConfigurationParsingOption) {
	for _, fn := range opts {
		fn(options)
	}
	if options.logger == nil {
		options.logger = nopLogger{}
	}
	if options.filesystem == nil {
		options.filesystem = os.DirFS(dirPath)
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

// WithEnvFileForParsing set the paths from whcih to read an environment file.
func WithEnvFileForParsing(path string) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.envFilePath = path
	}
}

// WithLogger sets the logger to use during configuration parsing. This is
// optional, and if not supplied, a no-op logger will be used.
func WithLogger(logger Logger) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.logger = logger
	}
}

func detectCommit(dirPath string, logger Logger) string {
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

// ParseConfiguration returns a decoded build Configuration using the parsing options provided.
func ParseConfiguration(configurationFilePath string, opts ...ConfigurationParsingOption) (*Configuration, error) {
	options := &configOptions{}
	configurationDirPath := filepath.Dir(configurationFilePath)
	options.include(configurationDirPath, opts...)

	if configurationFilePath == "" {
		return nil, errors.New("no configuration file path provided")
	}

	f, err := options.filesystem.Open(filepath.Base(configurationFilePath))
	if err != nil {
		return nil, err
	}

	cfg := Configuration{}
	err = yaml.NewDecoder(f).Decode(&cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to decode configuration file: %w", err)
	}

	detectedCommit := detectCommit(configurationDirPath, options.logger)
	if cfg.Package.Commit == "" {
		cfg.Package.Commit = detectedCommit
	}

	datas := map[string][]DataItem{}
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
			return nil, fmt.Errorf("subpackage specified undefined range: %q", sp.Range)
		}

		for _, it := range items {
			k, v := it.Key, it.Value
			replacer := replacerFromMap(map[string]string{
				"${{range.key}}":   k,
				"${{range.value}}": v,
			})
			thingToAdd := Subpackage{
				Name:        replacer.Replace(sp.Name),
				Description: replacer.Replace(sp.Description),
			}
			for _, p := range sp.Pipeline {
				thingToAdd.Pipeline = append(thingToAdd.Pipeline, Pipeline{
					Name:   p.Name,
					Uses:   p.Uses,
					With:   p.With,
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
	cfg.Environment.Accounts.Groups = []apko_types.Group{grp}

	usr := apko_types.User{
		UserName: "build",
		UID:      1000,
		GID:      1000,
	}
	cfg.Environment.Accounts.Users = []apko_types.User{usr}

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

	cfg.Environment.Environment["HOME"] = "/home/build"
	cfg.Environment.Environment["GOPATH"] = "/home/build/.cache/go"

	return &cfg, nil
}

// Load the configuration data from the build context configuration file.
func (cfg *Configuration) Load(ctx Context) error {
	parsedCfg, err := ParseConfiguration(
		ctx.ConfigFile,
		WithEnvFileForParsing(ctx.EnvFile),
		WithLogger(ctx.Logger),
	)
	if err != nil {
		return err
	}

	*cfg = *parsedCfg
	return nil
}

// BuildGuest invokes apko to build the guest environment.
func (ctx *Context) BuildGuest() error {
	// Prepare workspace directory
	if err := os.MkdirAll(ctx.WorkspaceDir, 0755); err != nil {
		return fmt.Errorf("mkdir -p %s: %w", ctx.WorkspaceDir, err)
	}

	// Prepare guest directory
	if err := os.MkdirAll(ctx.GuestDir, 0755); err != nil {
		return fmt.Errorf("mkdir -p %s: %w", ctx.GuestDir, err)
	}

	ctx.Logger.Printf("building workspace in '%s' with apko", ctx.GuestDir)

	bc, err := apko_build.New(ctx.GuestDir,
		apko_build.WithImageConfiguration(ctx.Configuration.Environment),
		apko_build.WithProot(ctx.UseProot),
		apko_build.WithArch(ctx.Arch),
		apko_build.WithExtraKeys(ctx.ExtraKeys),
		apko_build.WithExtraRepos(ctx.ExtraRepos),
		apko_build.WithDebugLogging(true),
		apko_build.WithLocal(true),
	)
	if err != nil {
		return fmt.Errorf("unable to create build context: %w", err)
	}

	if err := bc.Refresh(); err != nil {
		return fmt.Errorf("unable to refresh build context: %w", err)
	}

	bc.Summarize()

	if !ctx.Runner.NeedsImage() {
		if err := bc.BuildImage(); err != nil {
			return fmt.Errorf("unable to generate image: %w", err)
		}
	} else {
		if err := ctx.BuildAndPushLocalImage(bc); err != nil {
			return fmt.Errorf("unable to generate image: %w", err)
		}
	}

	ctx.Logger.Printf("successfully built workspace with apko")

	return nil
}

// BuildAndPushLocalImage uses apko to build and push the image to the local
// Docker daemon.
func (ctx *Context) BuildAndPushLocalImage(bc *apko_build.Context) error {
	layerTarGZ, err := bc.BuildLayer()
	if err != nil {
		return err
	}
	defer os.Remove(layerTarGZ)

	ctx.Logger.Printf("using %s for image layer", layerTarGZ)

	imgDigest, _, err := apko_oci.PublishImageFromLayer(
		layerTarGZ, bc.ImageConfiguration, bc.Options.SourceDateEpoch, ctx.Arch,
		bc.Logger(), bc.Options.SBOMPath, bc.Options.SBOMFormats, true, "melange:latest")
	if err != nil {
		return err
	}

	ctx.Logger.Printf("pushed %s as %v", layerTarGZ, imgDigest.Name())
	ctx.imgDigest = imgDigest

	return nil
}

func copyFile(base, src, dest string, perm fs.FileMode) error {
	basePath := filepath.Join(base, src)
	destPath := filepath.Join(dest, src)
	destDir := filepath.Dir(destPath)

	inF, err := os.Open(basePath)
	if err != nil {
		return err
	}
	defer inF.Close()

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("mkdir -p %s: %w", destDir, err)
	}

	outF, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", destPath, err)
	}
	defer outF.Close()

	if _, err := io.Copy(outF, inF); err != nil {
		return err
	}

	if err := os.Chmod(destPath, perm); err != nil {
		return err
	}

	return nil
}

func (ctx *Context) LoadIgnoreRules() error {
	ignorePath := filepath.Join(ctx.SourceDir, ctx.WorkspaceIgnore)

	if _, err := os.Stat(ignorePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return err
	}

	ctx.Logger.Printf("loading ignore rules from %s", ignorePath)

	inF, err := os.Open(ignorePath)
	if err != nil {
		return err
	}
	defer inF.Close()

	ignF := xignore.Ignorefile{}
	if err := ignF.FromReader(inF); err != nil {
		return err
	}

	for _, rule := range ignF.Patterns {
		pattern := xignore.NewPattern(rule)

		if err := pattern.Prepare(); err != nil {
			return err
		}

		ctx.ignorePatterns = append(ctx.ignorePatterns, pattern)
	}

	return nil
}

func (ctx *Context) matchesIgnorePattern(path string) bool {
	for _, pat := range ctx.ignorePatterns {
		if pat.Match(path) {
			return true
		}
	}

	return false
}

func (ctx *Context) OverlayBinSh() error {
	if ctx.BinShOverlay == "" {
		return nil
	}

	targetPath := filepath.Join(ctx.GuestDir, "bin", "sh")

	inF, err := os.Open(ctx.BinShOverlay)
	if err != nil {
		return fmt.Errorf("copying overlay /bin/sh: %w", err)
	}
	defer inF.Close()

	// We unlink the target first because it might be a symlink.
	if err := os.Remove(targetPath); err != nil {
		return fmt.Errorf("copying overlay /bin/sh: %w", err)
	}

	outF, err := os.Create(targetPath)
	if err != nil {
		return fmt.Errorf("copying overlay /bin/sh: %w", err)
	}
	defer outF.Close()

	if _, err := io.Copy(outF, inF); err != nil {
		return fmt.Errorf("copying overlay /bin/sh: %w", err)
	}

	if err := os.Chmod(targetPath, 0o755); err != nil {
		return fmt.Errorf("setting overlay /bin/sh executable: %w", err)
	}

	return nil
}

func (ctx *Context) fetchBucket(cmm CacheMembershipMap) (string, error) {
	cctx := context.TODO()

	tmp, err := os.MkdirTemp("", "melange-cache")
	if err != nil {
		return "", err
	}
	bucket, prefix, _ := strings.Cut(strings.TrimPrefix(ctx.CacheDir, "gs://"), "/")

	client, err := storage.NewClient(cctx)
	if err != nil {
		ctx.Logger.Printf("downgrading to anonymous mode: %s", err)

		client, err = storage.NewClient(cctx, option.WithoutAuthentication())
		if err != nil {
			return "", fmt.Errorf("failed to get storage client: %w", err)
		}
	}

	b := client.Bucket(bucket)
	it := b.Objects(cctx, &storage.Query{Prefix: prefix})
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		} else if err != nil {
			return tmp, fmt.Errorf("failed to get next remote cache object: %w", err)
		}
		on := attrs.Name
		if !cmm[on] {
			continue
		}
		rc, err := b.Object(on).NewReader(cctx)
		if err != nil {
			return tmp, fmt.Errorf("failed to get reader for next remote cache object %s: %w", on, err)
		}
		w, err := os.Create(filepath.Join(tmp, on))
		if err != nil {
			return tmp, err
		}
		if _, err := io.Copy(w, rc); err != nil {
			return tmp, fmt.Errorf("failed to copy remote cache object %s: %w", on, err)
		}
		if err := rc.Close(); err != nil {
			return tmp, fmt.Errorf("failed to close remote cache object %s: %w", on, err)
		}
		ctx.Logger.Printf("cached gs://%s/%s -> %s", bucket, on, w.Name())
	}

	return tmp, nil
}

func (ctx *Context) PopulateCache() error {
	cmm, err := cacheItemsForBuild(ctx.ConfigFile)
	if err != nil {
		return fmt.Errorf("while determining which objects to fetch: %w", err)
	}

	ctx.Logger.Printf("populating cache from %s", ctx.CacheDir)

	// --cache-dir=gs://bucket/path/to/cache first pulls all found objects to a
	// tmp dir which is subsequently used as the cache.
	if strings.HasPrefix(ctx.CacheDir, "gs://") {
		tmp, err := ctx.fetchBucket(cmm)
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		ctx.Logger.Printf("cache bucket copied to %s", tmp)

		fsys := apkofs.DirFS(tmp)

		// mkdir /var/cache/melange
		if err := os.MkdirAll(ctx.CacheDir, 0o755); err != nil {
			return err
		}

		// --cache-dir doesn't exist, nothing to do.
		if _, err := fs.Stat(fsys, "."); errors.Is(err, fs.ErrNotExist) {
			return nil
		}

		return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			fi, err := d.Info()
			if err != nil {
				return err
			}

			mode := fi.Mode()
			if !mode.IsRegular() {
				return nil
			}

			// Skip files in the cache that aren't named like sha256:... or sha512:...
			// This is likely a bug, and won't be matched by any fetch.
			base := filepath.Base(fi.Name())
			if !strings.HasPrefix(base, "sha256:") &&
				!strings.HasPrefix(base, "sha512:") {
				return nil
			}

			ctx.Logger.Printf("  -> %s", path)

			if err := copyFile(tmp, path, ctx.CacheDir, mode.Perm()); err != nil {
				return err
			}

			return nil
		})
	}

	return nil
}

func (ctx *Context) PopulateWorkspace() error {
	if ctx.EmptyWorkspace {
		ctx.Logger.Printf("empty workspace requested")
		return nil
	}

	if err := ctx.LoadIgnoreRules(); err != nil {
		return err
	}

	ctx.Logger.Printf("populating workspace %s from %s", ctx.WorkspaceDir, ctx.SourceDir)

	fsys := apkofs.DirFS(ctx.SourceDir)

	return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		fi, err := d.Info()
		if err != nil {
			return err
		}

		mode := fi.Mode()
		if !mode.IsRegular() {
			return nil
		}

		if ctx.matchesIgnorePattern(path) {
			return nil
		}

		ctx.Logger.Printf("  -> %s", path)

		if err := copyFile(ctx.SourceDir, path, ctx.WorkspaceDir, mode.Perm()); err != nil {
			return err
		}

		return nil
	})
}

func (ctx *Context) BuildPackage() error {
	ctx.Summarize()

	pctx := PipelineContext{
		Context: ctx,
		Package: &ctx.Configuration.Package,
	}

	if ctx.GuestDir == "" {
		guestDir, err := os.MkdirTemp("", "melange-guest-*")
		if err != nil {
			return fmt.Errorf("unable to make guest directory: %w", err)
		}
		ctx.GuestDir = guestDir
	}

	ctx.Logger.Printf("evaluating pipelines for package requirements")
	for _, p := range ctx.Configuration.Pipeline {
		if err := p.ApplyNeeds(&pctx); err != nil {
			return fmt.Errorf("unable to apply pipeline requirements: %w", err)
		}
	}

	if err := ctx.BuildGuest(); err != nil {
		return fmt.Errorf("unable to build guest: %w", err)
	}

	// TODO(kaniini): Make overlay-binsh work with Docker and Kubernetes.
	// Probably needs help from apko.
	if err := ctx.OverlayBinSh(); err != nil {
		return fmt.Errorf("unable to install overlay /bin/sh: %w", err)
	}

	if err := ctx.PopulateCache(); err != nil {
		return fmt.Errorf("unable to populate cache: %w", err)
	}

	if err := ctx.PopulateWorkspace(); err != nil {
		return fmt.Errorf("unable to populate workspace: %w", err)
	}

	cfg := ctx.WorkspaceConfig()
	if err := ctx.Runner.StartPod(cfg); err != nil {
		return fmt.Errorf("unable to start pod: %w", err)
	}

	// run the main pipeline
	ctx.Logger.Printf("running the main pipeline")
	for _, p := range ctx.Configuration.Pipeline {
		if _, err := p.Run(&pctx); err != nil {
			return fmt.Errorf("unable to run pipeline: %w", err)
		}
	}

	// Run the SBOM generator
	generator, err := sbom.NewGenerator()
	if err != nil {
		return fmt.Errorf("creating sbom generator: %w", err)
	}

	// Capture languages declared in pipelines
	langs := []string{}

	// run any pipelines for subpackages
	for _, sp := range ctx.Configuration.Subpackages {
		ctx.Logger.Printf("running pipeline for subpackage %s", sp.Name)
		pctx.Subpackage = &sp
		langs := []string{}

		for _, p := range sp.Pipeline {
			if _, err := p.Run(&pctx); err != nil {
				return fmt.Errorf("unable to run pipeline: %w", err)
			}
			langs = append(langs, p.SBOM.Language)
		}

		if err := generator.GenerateSBOM(&sbom.Spec{
			Path:           filepath.Join(ctx.WorkspaceDir, "melange-out", sp.Name),
			PackageName:    sp.Name,
			PackageVersion: fmt.Sprintf("%s-r%d", ctx.Configuration.Package.Version, ctx.Configuration.Package.Epoch),
			Languages:      langs,
			License:        ctx.Configuration.Package.LicenseExpression(),
			Copyright:      ctx.Configuration.Package.FullCopyright(),
		}); err != nil {
			return fmt.Errorf("writing SBOMs: %w", err)
		}
	}

	for i := range ctx.Configuration.Pipeline {
		langs = append(langs, ctx.Configuration.Pipeline[i].SBOM.Language)
	}
	if err := generator.GenerateSBOM(&sbom.Spec{
		Path:           filepath.Join(ctx.WorkspaceDir, "melange-out", ctx.Configuration.Package.Name),
		PackageName:    ctx.Configuration.Package.Name,
		PackageVersion: fmt.Sprintf("%s-r%d", ctx.Configuration.Package.Version, ctx.Configuration.Package.Epoch),
		Languages:      langs,
		License:        ctx.Configuration.Package.LicenseExpression(),
		Copyright:      ctx.Configuration.Package.FullCopyright(),
	}); err != nil {
		return fmt.Errorf("writing SBOMs: %w", err)
	}

	// emit main package
	pkg := pctx.Package
	if err := pkg.Emit(&pctx); err != nil {
		return fmt.Errorf("unable to emit package: %w", err)
	}

	// emit subpackages
	for _, sp := range ctx.Configuration.Subpackages {
		if err := sp.Emit(&pctx); err != nil {
			return fmt.Errorf("unable to emit package: %w", err)
		}
	}

	// terminate pod
	if err := ctx.Runner.TerminatePod(cfg); err != nil {
		ctx.Logger.Printf("WARNING: unable to terminate pod: %s", err)
	}

	// clean build guest container
	if err := os.RemoveAll(ctx.GuestDir); err != nil {
		ctx.Logger.Printf("WARNING: unable to clean guest container: %s", err)
	}

	// clean build environment
	if err := os.RemoveAll(ctx.WorkspaceDir); err != nil {
		ctx.Logger.Printf("WARNING: unable to clean workspace: %s", err)
	}

	// generate APKINDEX.tar.gz and sign it
	if ctx.GenerateIndex {
		packageDir := filepath.Join(pctx.Context.OutDir, pctx.Context.Arch.ToAPK())
		ctx.Logger.Printf("generating apk index from packages in %s", packageDir)

		opts := []index.Option{
			index.WithPackageDir(packageDir),
			index.WithSigningKey(ctx.SigningKey),
			index.WithIndexFile(filepath.Join(packageDir, "APKINDEX.tar.gz")),
		}

		if ctx, err := index.New(opts...); err != nil {
			return fmt.Errorf("unable to create index ctx: %w", err)
		} else {
			if err := ctx.GenerateIndex(); err != nil {
				return fmt.Errorf("unable to generate index: %w", err)
			}
		}
	}

	return nil
}

func (ctx *Context) SummarizePaths() {
	ctx.Logger.Printf("  workspace dir: %s", ctx.WorkspaceDir)

	if ctx.GuestDir != "" {
		ctx.Logger.Printf("  guest dir: %s", ctx.GuestDir)
	}
}

func (ctx *Context) Summarize() {
	ctx.Logger.Printf("melange is building:")
	ctx.Logger.Printf("  configuration file: %s", ctx.ConfigFile)
	ctx.SummarizePaths()
}

// BuildFlavor determines if a build context uses glibc or musl, it returns
// "gnu" for GNU systems, and "musl" for musl systems.
func (ctx *Context) BuildFlavor() string {
	matches, err := filepath.Glob(filepath.Join(ctx.GuestDir, "lib*", "libc.so.6"))
	if err != nil || len(matches) == 0 {
		return "musl"
	}

	return "gnu"
}

// BuildTripletGnu returns the GNU autoconf build triplet, for example
// `x86_64-pc-linux-gnu`.
func (ctx *Context) BuildTripletGnu() string {
	return ctx.Arch.ToTriplet(ctx.BuildFlavor())
}

// BuildTripletRust returns the Rust/Cargo build triplet, for example
// `x86_64-unknown-linux-gnu`.
func (ctx *Context) BuildTripletRust() string {
	return ctx.Arch.ToRustTriplet(ctx.BuildFlavor())
}

func (ctx *Context) buildWorkspaceConfig() *container.Config {
	mounts := []container.BindMount{}

	if !ctx.Runner.NeedsImage() {
		mounts = append(mounts, container.BindMount{Source: ctx.GuestDir, Destination: "/"})
	}

	builtinMounts := []container.BindMount{
		{Source: ctx.WorkspaceDir, Destination: "/home/build"},
		{Source: "/etc/resolv.conf", Destination: "/etc/resolv.conf"},
	}

	mounts = append(mounts, builtinMounts...)

	if ctx.CacheDir != "" {
		if fi, err := os.Stat(ctx.CacheDir); err == nil && fi.IsDir() {
			mounts = append(mounts, container.BindMount{Source: ctx.CacheDir, Destination: "/var/cache/melange"})
		} else {
			ctx.Logger.Printf("--cache-dir %s not a dir; skipping", ctx.CacheDir)
		}
	}

	// TODO(kaniini): Disable networking capability according to the pipeline requirements.
	caps := container.Capabilities{
		Networking: true,
	}

	cfg := container.Config{
		Mounts:       mounts,
		Capabilities: caps,
		Logger:       ctx.Logger,
		Environment: map[string]string{
			"SOURCE_DATE_EPOCH": fmt.Sprintf("%d", ctx.SourceDateEpoch.Unix()),
		},
	}

	for k, v := range ctx.Configuration.Environment.Environment {
		cfg.Environment[k] = v
	}

	if ctx.Runner.NeedsImage() {
		repoparts := strings.Split(ctx.imgDigest.Name(), "@")
		cfg.ImgDigest = fmt.Sprintf("%s:%s", repoparts[0], strings.Split(repoparts[1], ":")[1])
		ctx.Logger.Printf("ImgDigest = %s", cfg.ImgDigest)
	}

	return &cfg
}

func (ctx *Context) WorkspaceConfig() *container.Config {
	if ctx.containerConfig != nil {
		return ctx.containerConfig
	}

	ctx.containerConfig = ctx.buildWorkspaceConfig()
	return ctx.containerConfig
}
