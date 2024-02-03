// Copyright 2023 Chainguard, Inc.
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
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
	apkofs "github.com/chainguard-dev/go-apk/pkg/fs"
	"github.com/yookoala/realpath"
	"go.opentelemetry.io/otel"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/container"
)

type Test struct {
	// Package to test.
	Package         string
	Configuration   config.Configuration
	ConfigFile      string
	WorkspaceDir    string
	WorkspaceIgnore string
	// Ordered directories where to find 'uses' pipelines.
	PipelineDirs      []string
	SourceDir         string
	GuestDir          string
	Arch              apko_types.Architecture
	ExtraKeys         []string
	ExtraRepos        []string
	ExtraTestPackages []string
	BinShOverlay      string
	CacheDir          string
	ApkCacheDir       string
	CacheSource       string
	Runner            container.Runner
	RunnerName        string
	Debug             bool
	DebugRunner       bool
	LogPolicy         []string
}

func NewTest(ctx context.Context, opts ...TestOption) (*Test, error) {
	t := Test{
		WorkspaceIgnore: ".melangeignore",
		Arch:            apko_types.ParseArchitecture(runtime.GOARCH),
		LogPolicy:       []string{"builtin:stderr"},
	}

	for _, opt := range opts {
		if err := opt(&t); err != nil {
			return nil, err
		}
	}

	log := clog.New(slog.Default().Handler()).With("arch", t.Arch)
	ctx = clog.WithLogger(ctx, log)

	// try to get the runner
	runner, err := container.GetRunner(ctx, t.RunnerName)
	if err != nil {
		return nil, fmt.Errorf("unable to get runner %s: %w", t.RunnerName, err)
	}
	t.Runner = runner

	// If no workspace directory is explicitly requested, create a
	// temporary directory for it.  Otherwise, ensure we are in a
	// subdir for this specific build context.
	if t.WorkspaceDir != "" {
		t.WorkspaceDir = filepath.Join(t.WorkspaceDir, t.Arch.ToAPK())

		// Get the absolute path to the workspace dir, which is needed for bind
		// mounts.
		absdir, err := filepath.Abs(t.WorkspaceDir)
		if err != nil {
			return nil, fmt.Errorf("unable to resolve path %s: %w", t.WorkspaceDir, err)
		}

		t.WorkspaceDir = absdir
	} else {
		tmpdir, err := os.MkdirTemp(t.Runner.TempDir(), "melange-workspace-*")
		if err != nil {
			return nil, fmt.Errorf("unable to create workspace dir: %w", err)
		}
		t.WorkspaceDir = tmpdir
	}

	parsedCfg, err := config.ParseConfiguration(ctx, t.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	t.Configuration = *parsedCfg

	// Check that we actually can run things in containers.
	if !runner.TestUsability(ctx) {
		return nil, fmt.Errorf("unable to run containers using %s, specify --runner and one of %s", runner.Name(), GetAllRunners())
	}

	return &t, nil
}

type TestOption func(*Test) error

// WithTestConfig sets the configuration file used for the package test context.
func WithTestConfig(configFile string) TestOption {
	return func(t *Test) error {
		t.ConfigFile = configFile
		return nil
	}
}

// WithWorkspaceDir sets the workspace directory to use.
func WithTestWorkspaceDir(workspaceDir string) TestOption {
	return func(t *Test) error {
		t.WorkspaceDir = workspaceDir
		return nil
	}
}

// WithGuestDir sets the guest directory to use.
func WithTestGuestDir(guestDir string) TestOption {
	return func(t *Test) error {
		t.GuestDir = guestDir
		return nil
	}
}

// WithWorkspaceIgnore sets the workspace ignore rules file to use.
func WithTestWorkspaceIgnore(workspaceIgnore string) TestOption {
	return func(t *Test) error {
		t.WorkspaceIgnore = workspaceIgnore
		return nil
	}
}

// WithPipelineDir sets the pipeline directory to extend the built-in pipeline directory.
func WithTestPipelineDir(pipelineDir string) TestOption {
	return func(t *Test) error {
		t.PipelineDirs = append(t.PipelineDirs, pipelineDir)
		return nil
	}
}

// WithSourceDir sets the source directory to use.
func WithTestSourceDir(sourceDir string) TestOption {
	return func(t *Test) error {
		t.SourceDir = sourceDir
		return nil
	}
}

// WithCacheDir sets the cache directory to use.
func WithTestCacheDir(cacheDir string) TestOption {
	return func(t *Test) error {
		t.CacheDir = cacheDir
		return nil
	}
}

// WithCacheSource sets the cache source directory to use.  The cache will be
// pre-populated from this source directory.
func WithTestCacheSource(sourceDir string) TestOption {
	return func(t *Test) error {
		t.CacheSource = sourceDir
		return nil
	}
}

// WithTestArch sets the build architecture to use for this test context.
func WithTestArch(arch apko_types.Architecture) TestOption {
	return func(t *Test) error {
		t.Arch = arch
		return nil
	}
}

// WithTestExtraKeys adds a set of extra keys to the test context.
func WithTestExtraKeys(extraKeys []string) TestOption {
	return func(t *Test) error {
		t.ExtraKeys = extraKeys
		return nil
	}
}

// WithTestDebug indicates whether debug logging of pipelines should be enabled.
func WithTestDebug(debug bool) TestOption {
	return func(t *Test) error {
		t.Debug = debug
		return nil
	}
}

func WithTestDebugRunner(debugRunner bool) TestOption {
	return func(t *Test) error {
		t.DebugRunner = debugRunner
		return nil
	}
}

// WithTestExtraRepos adds a set of extra repos to the test context.
func WithTestExtraRepos(extraRepos []string) TestOption {
	return func(t *Test) error {
		t.ExtraRepos = extraRepos
		return nil
	}
}

// WithTestBinShOverlay sets a filename to copy from when installing /bin/sh
// into a test environment.
func WithTestBinShOverlay(binShOverlay string) TestOption {
	return func(t *Test) error {
		t.BinShOverlay = binShOverlay
		return nil
	}
}

// WithTestLogPolicy sets the logging policy to use during tests.
func WithTestLogPolicy(policy []string) TestOption {
	return func(t *Test) error {
		t.LogPolicy = policy
		return nil
	}
}

// WithTestRunner specifies what runner to use to wrap
// the test environment.
func WithTestRunner(runner string) TestOption {
	return func(t *Test) error {
		t.RunnerName = runner
		return nil
	}
}

// WithTestPackage specifies the package to test.
func WithTestPackage(pkg string) TestOption {
	return func(t *Test) error {
		t.Package = pkg
		return nil
	}
}

func WithTestPackageCacheDir(apkCacheDir string) TestOption {
	return func(t *Test) error {
		t.ApkCacheDir = apkCacheDir
		return nil
	}
}

// WithExtraTestPackages specifies packages that are added to each test by
// default.
func WithExtraTestPackages(extraTestPackages []string) TestOption {
	return func(t *Test) error {
		t.ExtraTestPackages = extraTestPackages
		return nil
	}
}

// BuildGuest invokes apko to create the test image for the guest environment.
// imgConfig specifies the environment for the test to run (e.g. packages to
// install).
// Returns the imgRef for the created image, or error.
func (t *Test) BuildGuest(ctx context.Context, imgConfig apko_types.ImageConfiguration, guestFS apkofs.FullFS) (string, error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "BuildGuest")
	defer span.End()

	// Then add any extra packages specified by the command line.
	imgConfig.Contents.Packages = append(imgConfig.Contents.Packages, t.ExtraTestPackages...)

	bc, err := apko_build.New(ctx, guestFS,
		apko_build.WithImageConfiguration(imgConfig),
		apko_build.WithArch(t.Arch),
		apko_build.WithExtraKeys(t.ExtraKeys),
		apko_build.WithExtraRepos(t.ExtraRepos),
		apko_build.WithCacheDir(t.ApkCacheDir, false), // TODO: Replace with real offline plumbing
	)
	if err != nil {
		return "", fmt.Errorf("unable to create build context: %w", err)
	}

	bc.Summarize(ctx)

	// lay out the contents for the image in a directory.
	if err := bc.BuildImage(ctx); err != nil {
		return "", fmt.Errorf("unable to generate image: %w", err)
	}
	// if the runner needs an image, create an OCI image from the directory and load it.
	loader := t.Runner.OCIImageLoader()
	if loader == nil {
		return "", fmt.Errorf("runner %s does not support OCI image loading", t.Runner.Name())
	}
	layerTarGZ, layer, err := bc.ImageLayoutToLayer(ctx)
	if err != nil {
		return "", err
	}
	defer os.Remove(layerTarGZ)

	log.Infof("using %s for image layer", layerTarGZ)

	ref, err := loader.LoadImage(ctx, layer, t.Arch, bc)
	if err != nil {
		return "", err
	}

	log.Infof("pushed %s as %v", layerTarGZ, ref)
	log.Infof("successfully built workspace with apko")

	return ref, nil
}

func (t *Test) OverlayBinSh(suffix string) error {
	if t.BinShOverlay == "" {
		return nil
	}

	guestDir := fmt.Sprintf("%s-%s", t.GuestDir, suffix)

	targetPath := filepath.Join(guestDir, "bin", "sh")

	inF, err := os.Open(t.BinShOverlay)
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

// IsTestless returns true if the test context does not actually do any
// testing.
func (t *Test) IsTestless() bool {
	return len(t.Configuration.Test.Pipeline) == 0
}

func (t *Test) PopulateCache(ctx context.Context) error {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "PopulateCache")
	defer span.End()

	if t.CacheDir == "" {
		return nil
	}

	cmm, err := cacheItemsForBuild(t.ConfigFile)
	if err != nil {
		return fmt.Errorf("while determining which objects to fetch: %w", err)
	}

	log.Infof("populating cache from %s", t.CacheSource)

	// --cache-dir=gs://bucket/path/to/cache first pulls all found objects to a
	// tmp dir which is subsequently used as the cache.
	if strings.HasPrefix(t.CacheSource, "gs://") {
		tmp, err := fetchBucket(ctx, t.CacheSource, cmm)
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		log.Infof("cache bucket copied to %s", tmp)

		fsys := os.DirFS(tmp)

		// mkdir /var/cache/melange
		if err := os.MkdirAll(t.CacheDir, 0o755); err != nil {
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

			log.Debugf("  -> %s", path)

			return copyFile(tmp, path, t.CacheDir, mode.Perm())
		})
	}

	return nil
}

func (t *Test) PopulateWorkspace(ctx context.Context, src fs.FS) error {
	log := clog.FromContext(ctx)
	_, span := otel.Tracer("melange").Start(ctx, "PopulateWorkspace")
	defer span.End()

	if t.SourceDir == "" {
		log.Infof("No source directory specified, skipping workspace population")
		return nil
	}

	log.Infof("populating workspace %s from %s", t.WorkspaceDir, t.SourceDir)

	fsys := os.DirFS(t.SourceDir)

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

		log.Debugf("  -> %s", path)

		return copyFile(t.SourceDir, path, t.WorkspaceDir, mode.Perm())
	})
}

func (t *Test) TestPackage(ctx context.Context) error {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "testPackage")
	defer span.End()

	pkg := &t.Configuration.Package

	pb := PipelineBuild{
		Test:    t,
		Package: pkg,
	}

	if t.GuestDir == "" {
		guestDir, err := os.MkdirTemp(t.Runner.TempDir(), "melange-guest-*")
		if err != nil {
			return fmt.Errorf("unable to make guest directory: %w", err)
		}
		t.GuestDir = guestDir
	}

	log.Infof("evaluating main pipeline for package requirements")
	// Append the main test package to be installed unless explicitly specified
	// by the command line.
	if t.Package != "" {
		t.Configuration.Test.Environment.Contents.Packages = append(t.Configuration.Test.Environment.Contents.Packages, t.Package)
	} else {
		t.Configuration.Test.Environment.Contents.Packages = append(t.Configuration.Test.Environment.Contents.Packages, pkg.Name)
	}

	for i := range t.Configuration.Test.Pipeline {
		p := &t.Configuration.Test.Pipeline[i]
		// fine to pass nil for config, since not running in container.
		pctx := NewPipelineContext(p, &t.Configuration.Test.Environment, nil, t.PipelineDirs)

		if err := pctx.ApplyNeeds(ctx, &pb); err != nil {
			return fmt.Errorf("unable to apply pipeline requirements: %w", err)
		}
	}

	imgRef := ""
	var err error

	guestFS, err := t.guestFS(ctx, "main")
	if err != nil {
		return err
	}

	// If there are no 'main' test pipelines, we can skip building the guest.
	if !t.IsTestless() {
		imgRef, err = t.BuildGuest(ctx, t.Configuration.Test.Environment, guestFS)
		if err != nil {
			return fmt.Errorf("unable to build guest: %w", err)
		}

		// TODO(kaniini): Make overlay-binsh work with Docker and Kubernetes.
		// Probably needs help from apko.
		if err := t.OverlayBinSh(""); err != nil {
			return fmt.Errorf("unable to install overlay /bin/sh: %w", err)
		}

		if err := t.PopulateCache(ctx); err != nil {
			return fmt.Errorf("unable to populate cache: %w", err)
		}
	}

	if t.SourceDir == "" {
		log.Info("No source directory specified, skipping workspace population")
	} else {
		// Prepare workspace directory
		if err := os.MkdirAll(t.WorkspaceDir, 0755); err != nil {
			return fmt.Errorf("mkdir -p %s: %w", t.WorkspaceDir, err)
		}

		log.Infof("populating workspace %s from %s", t.WorkspaceDir, t.SourceDir)
		if err := t.PopulateWorkspace(ctx, os.DirFS(t.SourceDir)); err != nil {
			return fmt.Errorf("unable to populate workspace: %w", err)
		}
	}

	cfg, err := t.buildWorkspaceConfig(ctx, imgRef, pkg.Name, t.Configuration.Test.Environment.Environment)
	if err != nil {
		return fmt.Errorf("unable to build workspace config: %w", err)
	}

	if !t.IsTestless() {
		cfg.Arch = t.Arch
		if err := t.Runner.StartPod(ctx, cfg); err != nil {
			return fmt.Errorf("unable to start pod: %w", err)
		}
		if !t.DebugRunner {
			defer func() {
				if err := t.Runner.TerminatePod(ctx, cfg); err != nil {
					log.Warnf("unable to terminate pod: %s", err)
				}
			}()
		}

		// run the main test pipeline
		log.Infof("running the main test pipeline")
		for i := range t.Configuration.Test.Pipeline {
			p := &t.Configuration.Test.Pipeline[i]
			pctx := NewPipelineContext(p, &t.Configuration.Test.Environment, cfg, t.PipelineDirs)
			if _, err := pctx.Run(ctx, &pb); err != nil {
				return fmt.Errorf("unable to run pipeline: %w", err)
			}
		}
	}

	// Run any test pipelines for subpackages.
	// Note that we create a fresh container for each subpackage to ensure
	// that we don't keep adding packages to tests and hence mask any missing
	// dependencies.
	for i := range t.Configuration.Subpackages {
		sp := &t.Configuration.Subpackages[i]
		if len(sp.Test.Pipeline) > 0 {
			// Append the subpackage that we're testing to be installed.
			sp.Test.Environment.Contents.Packages = append(sp.Test.Environment.Contents.Packages, sp.Name)

			// See if there are any packages needed by the 'uses' pipelines, so
			// they get built into the container.
			for i := range sp.Test.Pipeline {
				p := &sp.Test.Pipeline[i]
				// fine to pass nil for config, since not running in container.
				pctx := NewPipelineContext(p, &sp.Test.Environment, nil, t.PipelineDirs)
				if err := pctx.ApplyNeeds(ctx, &pb); err != nil {
					return fmt.Errorf("unable to apply pipeline requirements: %w", err)
				}
			}

			log.Infof("running test pipeline for subpackage %s", sp.Name)
			pb.Subpackage = sp

			guestFS, err := t.guestFS(ctx, sp.Name)
			if err != nil {
				return err
			}

			spImgRef, err := t.BuildGuest(ctx, sp.Test.Environment, guestFS)
			if err != nil {
				return fmt.Errorf("unable to build guest: %w", err)
			}
			if err := t.OverlayBinSh(sp.Name); err != nil {
				return fmt.Errorf("unable to install overlay /bin/sh: %w", err)
			}
			subCfg, err := t.buildWorkspaceConfig(ctx, spImgRef, sp.Name, sp.Test.Environment.Environment)
			if err != nil {
				return fmt.Errorf("unable to build workspace config: %w", err)
			}
			subCfg.Arch = t.Arch
			if err := t.Runner.StartPod(ctx, subCfg); err != nil {
				return fmt.Errorf("unable to start subpackage test pod: %w", err)
			}
			if !t.DebugRunner {
				defer func() {
					if err := t.Runner.TerminatePod(ctx, subCfg); err != nil {
						log.Warnf("unable to terminate subpackage test pod: %s", err)
					}
				}()
			}

			result, err := pb.ShouldRun(*sp)
			if err != nil {
				return err
			}
			if !result {
				continue
			}

			for i := range sp.Test.Pipeline {
				p := &sp.Test.Pipeline[i]
				pctx := NewPipelineContext(p, &sp.Test.Environment, subCfg, t.PipelineDirs)
				if _, err := pctx.Run(ctx, &pb); err != nil {
					return fmt.Errorf("unable to run pipeline: %w", err)
				}
			}
		}
		pb.Subpackage = nil

		if err := os.MkdirAll(filepath.Join(t.WorkspaceDir, "melange-out", sp.Name), 0o755); err != nil {
			return err
		}
	}

	// clean workspace dir
	if err := os.RemoveAll(t.WorkspaceDir); err != nil {
		log.Infof("WARNING: unable to clean workspace: %s", err)
	}
	return nil
}

func (t *Test) SummarizePaths(ctx context.Context) {
	log := clog.FromContext(ctx)
	log.Infof("  workspace dir: %s", t.WorkspaceDir)

	if t.GuestDir != "" {
		log.Infof("  guest dir: %s", t.GuestDir)
	}
}

func (t *Test) Summarize(ctx context.Context) {
	log := clog.FromContext(ctx)
	log.Infof("melange is testing:")
	log.Infof("  configuration file: %s", t.ConfigFile)
	t.SummarizePaths(ctx)
}

func (t *Test) buildWorkspaceConfig(ctx context.Context, imgRef, pkgName string, env map[string]string) (*container.Config, error) {
	log := clog.FromContext(ctx)
	mounts := []container.BindMount{
		{Source: t.WorkspaceDir, Destination: container.DefaultWorkspaceDir},
		{Source: "/etc/resolv.conf", Destination: container.DefaultResolvConfPath},
	}

	if t.CacheDir != "" {
		if fi, err := os.Stat(t.CacheDir); err == nil && fi.IsDir() {
			mountSource, err := realpath.Realpath(t.CacheDir)
			if err != nil {
				return nil, fmt.Errorf("could not resolve path for --cache-dir: %s : %w", t.CacheDir, err)
			}

			mounts = append(mounts, container.BindMount{Source: mountSource, Destination: container.DefaultCacheDir})
		} else {
			return nil, fmt.Errorf("--cache-dir %s not a dir", t.CacheDir)
		}
	}

	// TODO(kaniini): Disable networking capability according to the pipeline requirements.
	caps := container.Capabilities{
		Networking: true,
	}

	cfg := container.Config{
		PackageName:  pkgName,
		Mounts:       mounts,
		Capabilities: caps,
		Environment:  map[string]string{},
	}

	for k, v := range env {
		cfg.Environment[k] = v
	}

	cfg.ImgRef = imgRef
	log.Infof("ImgRef = %s", cfg.ImgRef)

	return &cfg, nil
}

func (t *Test) guestFS(ctx context.Context, suffix string) (apkofs.FullFS, error) {
	log := clog.FromContext(ctx)
	// Prepare guest directory. Note that we customize this for each unique
	// Test by having a suffix, so we get a clean guest directory for each of
	// them.
	guestDir := fmt.Sprintf("%s-%s", t.GuestDir, suffix)
	if err := os.MkdirAll(guestDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir -p %s: %w", guestDir, err)
	}

	log.Infof("building test workspace in: '%s' with apko", guestDir)

	return apkofs.DirFS(guestDir, apkofs.WithCreateDir()), nil
}
