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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/template"
	"time"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	apkofs "chainguard.dev/apko/pkg/fs"
	"github.com/zealic/xignore"
	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/internal/index"
	"chainguard.dev/melange/internal/sign"
)

type Scriptlets struct {
	Trigger struct {
		Script string
		Paths  []string
	}

	PreInstall    string `yaml:"pre-install"`
	PostInstall   string `yaml:"post-install"`
	PreDeinstall  string `yaml:"pre-deinstall"`
	PostDeinstall string `yaml:"post-deinstall"`
	PreUpgrade    string `yaml:"pre-upgrade"`
	PostUpgrade   string `yaml:"post-upgrade"`
}

type PackageOption struct {
	NoProvides bool `yaml:"no-provides"`
	NoDepends  bool `yaml:"no-depends"`
	NoCommands bool `yaml:"no-commands"`
}

type Package struct {
	Name               string
	Version            string
	Epoch              uint64
	Description        string
	TargetArchitecture []string `yaml:"target-architecture"`
	Copyright          []Copyright
	Dependencies       Dependencies
	Options            PackageOption
	Scriptlets         Scriptlets
}

type Copyright struct {
	Paths       []string
	Attestation string
	License     string
}

type Needs struct {
	Packages []string
}

type Pipeline struct {
	Name     string
	Uses     string
	With     map[string]string
	Runs     string
	Pipeline []Pipeline
	Inputs   map[string]Input
	Needs    Needs
	logger   *log.Logger
}

type Subpackage struct {
	Name         string
	Pipeline     []Pipeline
	Dependencies Dependencies
	Options      PackageOption
	Scriptlets   Scriptlets
	Description  string
}

type Input struct {
	Description string
	Default     string
	Required    bool
}

type Configuration struct {
	Package     Package
	Environment apko_types.ImageConfiguration
	Pipeline    []Pipeline
	Subpackages []Subpackage
}

type Context struct {
	Configuration     Configuration
	ConfigFile        string
	SourceDateEpoch   time.Time
	WorkspaceDir      string
	WorkspaceIgnore   string
	PipelineDir       string
	SourceDir         string
	GuestDir          string
	SigningKey        string
	SigningPassphrase string
	Template          string
	GenerateIndex     bool
	UseProot          bool
	EmptyWorkspace    bool
	OutDir            string
	Logger            *log.Logger
	Arch              apko_types.Architecture
	ExtraKeys         []string
	ExtraRepos        []string
	DependencyLog     string
	BinShOverlay      string
	ignorePatterns    []*xignore.Pattern
	DisableNetwork    bool
}

type Dependencies struct {
	Runtime  []string
	Provides []string
}

func New(opts ...Option) (*Context, error) {
	ctx := Context{
		WorkspaceIgnore: ".melangeignore",
		PipelineDir:     "/usr/share/melange/pipelines",
		SourceDir:       ".",
		OutDir:          ".",
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
		ctx.WorkspaceDir = filepath.Join(ctx.WorkspaceDir, ctx.Arch.ToAPK())
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

	if err := ctx.Configuration.Load(ctx.ConfigFile, ctx.Template); err != nil {
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

// WithPipelineDir sets the pipeline directory to use.
func WithPipelineDir(pipelineDir string) Option {
	return func(ctx *Context) error {
		ctx.PipelineDir = pipelineDir
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

func WithTemplate(template string) Option {
	return func(ctx *Context) error {
		ctx.Template = template
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

// WithDisableNetwork disables networking in the build environment.
var WithDisableNetwork Option = func(ctx *Context) error {
	ctx.DisableNetwork = true
	return nil
}

// Load the configuration data from the build context configuration file.
func (cfg *Configuration) Load(configFile, template string) error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("unable to load configuration file: %w", err)
	}
	templatized, err := applyTemplate(data, template)
	if err != nil {
		return fmt.Errorf("unable to apply template: %w", err)
	}

	if err := yaml.Unmarshal(templatized, cfg); err != nil {
		return fmt.Errorf("unable to parse configuration file: %w", err)
	}

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

	return nil
}

func applyTemplate(contents []byte, t string) ([]byte, error) {
	if t == "" {
		return contents, nil
	}

	var i map[string]interface{}
	if err := json.Unmarshal([]byte(t), &i); err != nil {
		return nil, err
	}

	// First, replace all protected pipeline templated vars temporarily
	// So that we can apply the Go template
	// We have to do this bc go templates doesn't support ignoring certain fields: https://github.com/golang/go/issues/31147

	sr := substitutionReplacements()

	protected := string(contents)
	for k, v := range sr {
		protected = strings.ReplaceAll(protected, k, v)
	}

	tmpl, err := template.New("").Parse(protected)
	if err != nil {
		return nil, err
	}
	tmpl = tmpl.Option("missingkey=error")
	buf := bytes.NewBuffer([]byte{})
	if err := tmpl.Execute(buf, i); err != nil {
		return nil, err
	}

	// Add the pipeline templating back in
	templateApplied := buf.String()
	for k, v := range sr {
		templateApplied = strings.ReplaceAll(templateApplied, v, k)
	}

	return []byte(templateApplied), nil
}

func substitutionReplacements() map[string]string {
	return map[string]string{
		substitutionPackageName:    "MELANGE_TEMP_REPLACEMENT_PACAKAGE_NAME",
		substitutionPackageVersion: "MELANGE_TEMP_REPLACEMENT_PACAKAGE_VERSION",
		substitutionPackageEpoch:   "MELANGE_TEMP_REPLACEMENT_PACAKAGE_EPOCH",
		substitutionTargetsDestdir: "MELANGE_TEMP_REPLACEMENT_DESTDIR",
		substitutionSubPkgDir:      "MELANGE_TEMP_REPLACEMENT_SUBPKGDIR",
	}
}

func (ctx *Context) BuildWorkspace(workspaceDir string) error {
	// Prepare workspace directory
	if err := os.MkdirAll(ctx.WorkspaceDir, 0755); err != nil {
		return err
	}

	ctx.Logger.Printf("building workspace in '%s' with apko", workspaceDir)

	bc, err := apko_build.New(workspaceDir,
		apko_build.WithImageConfiguration(ctx.Configuration.Environment),
		apko_build.WithProot(ctx.UseProot),
		apko_build.WithArch(ctx.Arch),
		apko_build.WithExtraKeys(ctx.ExtraKeys),
		apko_build.WithExtraRepos(ctx.ExtraRepos),
		apko_build.WithDebugLogging(true),
	)
	if err != nil {
		return fmt.Errorf("unable to create build context: %w", err)
	}

	if err := bc.Refresh(); err != nil {
		return fmt.Errorf("unable to refresh build context: %w", err)
	}

	bc.Summarize()

	if err := bc.BuildImage(); err != nil {
		return fmt.Errorf("unable to generate image: %w", err)
	}

	ctx.Logger.Printf("successfully built workspace with apko")

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
		return err
	}

	outF, err := os.Create(destPath)
	if err != nil {
		return err
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

	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
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
	}); err != nil {
		return err
	}

	return nil
}

func (ctx *Context) BuildPackage() error {
	ctx.Summarize()

	pctx := PipelineContext{
		Context: ctx,
		Package: &ctx.Configuration.Package,
	}

	guestDir, err := os.MkdirTemp("", "melange-guest-*")
	if err != nil {
		return fmt.Errorf("unable to make guest directory: %w", err)
	}
	ctx.GuestDir = guestDir

	ctx.Logger.Printf("evaluating pipelines for package requirements")
	for _, p := range ctx.Configuration.Pipeline {
		if err := p.ApplyNeeds(&pctx); err != nil {
			return fmt.Errorf("unable to apply pipeline requirements: %w", err)
		}
	}

	if err := ctx.BuildWorkspace(guestDir); err != nil {
		return fmt.Errorf("unable to build workspace: %w", err)
	}

	if err := ctx.OverlayBinSh(); err != nil {
		return fmt.Errorf("unable to install overlay /bin/sh: %w", err)
	}

	if err := ctx.PopulateWorkspace(); err != nil {
		return fmt.Errorf("unable to populate workspace: %w", err)
	}

	// run the main pipeline
	ctx.Logger.Printf("running the main pipeline")
	for _, p := range ctx.Configuration.Pipeline {
		if err := p.Run(&pctx); err != nil {
			return fmt.Errorf("unable to run pipeline: %w", err)
		}
	}

	// run any pipelines for subpackages
	for _, sp := range ctx.Configuration.Subpackages {
		ctx.Logger.Printf("running pipeline for subpackage %s", sp.Name)
		pctx.Subpackage = &sp

		for _, p := range sp.Pipeline {
			if err := p.Run(&pctx); err != nil {
				return fmt.Errorf("unable to run pipeline: %w", err)
			}
		}
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
		packagesDir := filepath.Join(pctx.Context.OutDir, pctx.Context.Arch.ToAPK())
		ctx.Logger.Printf("generating apk index from packages in %s", packagesDir)
		files, err := os.ReadDir(packagesDir)
		if err != nil {
			return fmt.Errorf("unable to list packages: %w", err)
		}
		apkFiles := []string{}
		for _, file := range files {
			n := filepath.Join(packagesDir, file.Name())
			if !file.IsDir() && strings.HasSuffix(n, ".apk") {
				apkFiles = append(apkFiles, n)
			}
		}
		apkIndexFilename := filepath.Join(packagesDir, "APKINDEX.tar.gz")
		if err := index.Index(ctx.Logger, apkIndexFilename, apkFiles); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}

		if ctx.SigningKey != "" {
			ctx.Logger.Printf("signing apk index at %s", apkIndexFilename)
			if err := sign.SignIndex(ctx.Logger, ctx.SigningKey, apkIndexFilename); err != nil {
				return fmt.Errorf("failed to sign apk index: %w", err)
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

func (ctx *Context) PrivilegedWorkspaceCmd(args ...string) (*exec.Cmd, error) {
	args = append([]string{"-S", ctx.GuestDir, "-i", "1000:1000", "-b", fmt.Sprintf("%s:/home/build", ctx.WorkspaceDir), "-w", "/home/build"}, args...)
	cmd := exec.Command("proot", args...)

	return cmd, nil
}

func (ctx *Context) WorkspaceCmd(args ...string) (*exec.Cmd, error) {
	baseargs := []string{
		"--bind", ctx.GuestDir, "/",
		"--bind", ctx.WorkspaceDir, "/home/build",
		"--bind", "/etc/resolv.conf", "/etc/resolv.conf",
		"--unshare-pid",
		"--dev", "/dev",
		"--proc", "/proc",
		"--chdir", "/home/build",
		"--setenv", "SOURCE_DATE_EPOCH", fmt.Sprintf("%d", ctx.SourceDateEpoch.Unix()),
	}

	if ctx.DisableNetwork {
		baseargs = append(baseargs, "--unshare-net")
	}

	// Add any user-provided env vars
	for k, v := range ctx.Configuration.Environment.Environment {
		baseargs = append(baseargs, "--setenv", k, v)
	}

	args = append(baseargs, args...)
	cmd := exec.Command("bwrap", args...)

	return cmd, nil
}
