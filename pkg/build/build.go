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
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"gopkg.in/yaml.v3"
)

type Package struct {
	Name               string
	Version            string
	Epoch              uint64
	Description        string
	TargetArchitecture []string `yaml:"target-architecture"`
	Copyright          []Copyright
	Dependencies       Dependencies
}

type Copyright struct {
	Paths       []string
	Attestation string
	License     string
}

type Pipeline struct {
	Name     string
	Uses     string
	With     map[string]string
	Runs     string
	Pipeline []Pipeline
	logger   *log.Logger
}

type Subpackage struct {
	Name     string
	Pipeline []Pipeline
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
	PipelineDir       string
	GuestDir          string
	SigningKey        string
	SigningPassphrase string
	UseProot          bool
	OutDir            string
	Logger            *log.Logger
	Arch              apko_types.Architecture
}

type Dependencies struct {
	Runtime []string
}

func New(opts ...Option) (*Context, error) {
	ctx := Context{
		ConfigFile:   ".melange.yaml",
		WorkspaceDir: ".",
		PipelineDir:  "/usr/share/melange/pipelines",
		OutDir:       ".",
		Logger:       log.New(log.Writer(), "melange: ", log.LstdFlags|log.Lmsgprefix),
		Arch:         apko_types.ParseArchitecture(runtime.GOARCH),
	}

	for _, opt := range opts {
		if err := opt(&ctx); err != nil {
			return nil, err
		}
	}

	if err := ctx.Configuration.Load(ctx.ConfigFile); err != nil {
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

// WithPipelineDir sets the pipeline directory to use.
func WithPipelineDir(pipelineDir string) Option {
	return func(ctx *Context) error {
		ctx.PipelineDir = pipelineDir
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

// Load the configuration data from the build context configuration file.
func (cfg *Configuration) Load(configFile string) error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("unable to load configuration file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
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

func (ctx *Context) BuildWorkspace(workspaceDir string) error {
	// Prepare workspace directory
	if err := os.MkdirAll(ctx.WorkspaceDir, 0755); err != nil {
		return err
	}

	ctx.Logger.Printf("building workspace in '%s' with apko", workspaceDir)

	// TODO(kaniini): update to apko 0.2 Build.New() when WithImageConfiguration
	// is merged.
	bc := apko_build.Context{
		ImageConfiguration: ctx.Configuration.Environment,
		WorkDir:            workspaceDir,
		UseProot:           ctx.UseProot,
		// TODO(kaniini): maybe support multiarch builds somehow
		Arch: ctx.Arch,
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

func (ctx *Context) BuildPackage() error {
	ctx.Summarize()

	guestDir, err := os.MkdirTemp("", "melange-guest-*")
	if err != nil {
		return fmt.Errorf("unable to make guest directory: %w", err)
	}
	ctx.GuestDir = guestDir

	if err := ctx.BuildWorkspace(guestDir); err != nil {
		return fmt.Errorf("unable to build workspace: %w", err)
	}

	// run the main pipeline
	ctx.Logger.Printf("running the main pipeline")
	pctx := PipelineContext{
		Context: ctx,
		Package: &ctx.Configuration.Package,
	}
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

	return nil
}

func (ctx *Context) Summarize() {
	ctx.Logger.Printf("melange is building:")
	ctx.Logger.Printf("  configuration file: %s", ctx.ConfigFile)
	ctx.Logger.Printf("  workspace dir: %s", ctx.WorkspaceDir)
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
	}
	args = append(baseargs, args...)
	cmd := exec.Command("bwrap", args...)

	return cmd, nil
}
