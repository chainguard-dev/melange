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
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	apkofs "chainguard.dev/apko/pkg/apk/fs"
	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
	"chainguard.dev/apko/pkg/tarfs"
	"github.com/chainguard-dev/clog"
	"github.com/yookoala/realpath"
	"go.opentelemetry.io/otel"
	"sigs.k8s.io/release-utils/version"

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
	Remove            bool
	Arch              apko_types.Architecture
	ExtraKeys         []string
	ExtraRepos        []string
	ExtraTestPackages []string
	BinShOverlay      string
	CacheDir          string
	ApkCacheDir       string
	CacheSource       string
	EnvFile           string
	Runner            container.Runner
	Debug             bool
	DebugRunner       bool
	Interactive       bool
	Auth              map[string]options.Auth
	IgnoreSignatures  bool
	DefaultCPU        string
	DefaultCPUModel   string
	DefaultDisk       string
	DefaultMemory     string
	DefaultTimeout    time.Duration
}

func NewTest(ctx context.Context, opts ...TestOption) (*Test, error) {
	t := Test{
		WorkspaceIgnore: ".melangeignore",
		Arch:            apko_types.ParseArchitecture(runtime.GOARCH),
	}

	for _, opt := range opts {
		if err := opt(&t); err != nil {
			return nil, err
		}
	}

	log := clog.FromContext(ctx).With("arch", t.Arch)
	ctx = clog.WithLogger(ctx, log)

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

	parsedCfg, err := config.ParseConfiguration(ctx, t.ConfigFile,
		config.WithEnvFileForParsing(t.EnvFile),
		config.WithDefaultCPU(t.DefaultCPU),
		config.WithDefaultCPUModel(t.DefaultCPUModel),
		config.WithDefaultDisk(t.DefaultDisk),
		config.WithDefaultMemory(t.DefaultMemory),
		config.WithDefaultTimeout(t.DefaultTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	t.Configuration = *parsedCfg

	// Check that we actually can run things in containers.
	if !t.Runner.TestUsability(ctx) {
		return nil, fmt.Errorf("unable to run containers using %s, specify --runner and one of %s", t.Runner.Name(), GetAllRunners())
	}

	return &t, nil
}

func (t *Test) Close() error {
	return t.Runner.Close()
}

// BuildGuest invokes apko to create the test image for the guest environment.
// imgConfig specifies the environment for the test to run (e.g. packages to
// install).
// Returns the imgRef for the created image, or error.
func (t *Test) BuildGuest(ctx context.Context, imgConfig apko_types.ImageConfiguration, guestFS apkofs.FullFS) (string, error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "buildGuest")
	defer span.End()

	tmp, err := os.MkdirTemp(os.TempDir(), "apko-temp-*")
	if err != nil {
		return "", fmt.Errorf("creating apko tempdir: %w", err)
	}
	defer os.RemoveAll(tmp)

	bc, err := apko_build.New(ctx, guestFS,
		apko_build.WithImageConfiguration(imgConfig),
		apko_build.WithArch(t.Arch),
		apko_build.WithExtraKeys(t.ExtraKeys),
		apko_build.WithExtraBuildRepos(t.ExtraRepos),
		apko_build.WithExtraPackages(t.ExtraTestPackages),
		apko_build.WithIgnoreSignatures(t.IgnoreSignatures),
		apko_build.WithCache(t.ApkCacheDir, false, apk.NewCache(true)),
		apko_build.WithTempDir(tmp))
	if err != nil {
		return "", fmt.Errorf("unable to create build context: %w", err)
	}

	t.Summarize(ctx)
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

	log.Debugf("using %s for image layer", layerTarGZ)

	ref, err := loader.LoadImage(ctx, layer, t.Arch, bc)
	if err != nil {
		return "", err
	}

	log.Debugf("pushed %s as %v", layerTarGZ, ref)
	log.Debug("successfully built workspace with apko")
	return ref, nil
}

// IsTestless returns true if the test context does not actually do any
// testing.
func (t *Test) IsTestless() bool {
	return t.Configuration.Test == nil || len(t.Configuration.Test.Pipeline) == 0
}

func (t *Test) PopulateWorkspace(ctx context.Context, src fs.FS) error {
	log := clog.FromContext(ctx)
	_, span := otel.Tracer("melange").Start(ctx, "populateWorkspace")
	defer span.End()

	if t.SourceDir == "" {
		log.Infof("No source directory specified, skipping workspace population")
		return nil
	}

	log.Infof("populating workspace %s from %s", t.WorkspaceDir, t.SourceDir)

	fsys := apkofs.DirFS(ctx, t.SourceDir, apkofs.WithCreateDir())

	if fsys == nil {
		return fmt.Errorf("unable to create/use directory %s", t.SourceDir)
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

		log.Debugf("  -> %s", path)

		return copyFile(t.SourceDir, path, t.WorkspaceDir, mode.Perm())
	})
}

func (t *Test) TestPackage(ctx context.Context) error {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "testPackage")
	defer span.End()

	pkg := &t.Configuration.Package

	log.Debugf("evaluating pipelines for package requirements")
	if err := t.Compile(ctx); err != nil {
		return fmt.Errorf("compiling %s tests: %w", t.ConfigFile, err)
	}

	// Filter out any subpackages with false If conditions.
	t.Configuration.Subpackages = slices.DeleteFunc(t.Configuration.Subpackages, func(sp config.Subpackage) bool {
		result, err := shouldRun(sp.If)
		if err != nil {
			// This shouldn't give an error because we evaluate it in Compile.
			panic(err)
		}
		if !result {
			log.Infof("skipping subpackage %s because %s == false", sp.Name, sp.If)
		}

		return !result
	})

	// Unless a specific architecture is requests, we run the test for all.
	inarchs := len(pkg.TargetArchitecture) == 0
	for _, ta := range pkg.TargetArchitecture {
		if apko_types.ParseArchitecture(ta) == t.Arch {
			inarchs = true
			break
		}
	}
	if !inarchs {
		log.Warnf("skipping test for %s on %s", pkg.Name, t.Arch)
		return nil
	}

	imgRef := ""
	var err error

	guestFS := t.guestFS(ctx)

	// If there are no 'main' test pipelines, we can skip building the guest.
	if !t.IsTestless() {
		imgRef, err = t.BuildGuest(ctx, t.Configuration.Test.Environment, guestFS)
		if err != nil {
			return fmt.Errorf("unable to build guest: %w", err)
		}
	}

	if t.SourceDir == "" {
		log.Info("No source directory specified, skipping workspace population")
	} else {
		// Prepare workspace directory
		if err := os.MkdirAll(t.WorkspaceDir, 0o755); err != nil {
			return fmt.Errorf("mkdir -p %s: %w", t.WorkspaceDir, err)
		}

		if err := t.PopulateWorkspace(ctx, apkofs.DirFS(ctx, t.SourceDir)); err != nil {
			return fmt.Errorf("unable to populate workspace: %w", err)
		}
	}

	env := apko_types.ImageConfiguration{}
	if t.Configuration.Test != nil {
		env = t.Configuration.Test.Environment
	}
	cfg, err := t.buildWorkspaceConfig(ctx, imgRef, pkg.Name, env)
	if err != nil {
		return fmt.Errorf("unable to build workspace config: %w", err)
	}

	pr := &pipelineRunner{
		interactive: t.Interactive,
		debug:       t.Debug,
		config:      cfg,
		runner:      t.Runner,
	}

	if !t.IsTestless() {
		// use anonymous function so that deferring will actually run
		// on this function's end
		err = func() error {
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

			log.Infof("running the main test pipeline")
			if err := pr.runPipelines(ctx, t.Configuration.Test.Pipeline); err != nil {
				return fmt.Errorf("unable to run pipeline: %w", err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}

	// Run any test pipelines for subpackages.
	// Note that we create a fresh container for each subpackage to ensure
	// that we don't keep adding packages to tests and hence mask any missing
	// dependencies.
	for i := range t.Configuration.Subpackages {
		// use anonymous function so that deferring will actually run
		// on this function's end
		err = func() error {
			sp := &t.Configuration.Subpackages[i]
			if sp.Test == nil || len(sp.Test.Pipeline) == 0 {
				return nil
			}
			log.Infof("running test pipeline for subpackage %s", sp.Name)

			guestFS := t.guestFS(ctx)

			spImgRef, err := t.BuildGuest(ctx, sp.Test.Environment, guestFS)
			if err != nil {
				return fmt.Errorf("unable to build guest: %w", err)
			}
			subCfg, err := t.buildWorkspaceConfig(ctx, spImgRef, sp.Name, sp.Test.Environment)
			if err != nil {
				return fmt.Errorf("unable to build workspace config: %w", err)
			}
			subCfg.Arch = t.Arch

			pr := &pipelineRunner{
				interactive: t.Interactive,
				debug:       t.Debug,
				config:      subCfg,
				runner:      t.Runner,
			}

			if err := t.Runner.StartPod(ctx, subCfg); err != nil {
				return fmt.Errorf("unable to start subpackage test pod for %s: %w", sp.Name, err)
			}
			if !t.DebugRunner {
				defer func() {
					if err := t.Runner.TerminatePod(ctx, subCfg); err != nil {
						log.Warnf("unable to terminate subpackage test pod: %s", err)
					}
				}()
			}

			if err := pr.runPipelines(ctx, sp.Test.Pipeline); err != nil {
				return fmt.Errorf("unable to run pipeline: %w", err)
			}

			return nil
		}()
		if err != nil {
			return err
		}
	}

	// clean workspace dir
	if err := os.RemoveAll(t.WorkspaceDir); err != nil {
		log.Warnf("unable to clean workspace: %s", err)
	}
	return nil
}

func (t *Test) SummarizePaths(ctx context.Context) {
	log := clog.FromContext(ctx)
	log.Debugf("  workspace dir: %s", t.WorkspaceDir)
}

func (t *Test) Summarize(ctx context.Context) {
	log := clog.FromContext(ctx)
	log.Infof("melange %s with runner %s is testing:", version.GetVersionInfo().GitVersion, t.Runner.Name())
	log.Debugf("  configuration file: %s", t.ConfigFile)
	t.SummarizePaths(ctx)
}

func (t *Test) buildWorkspaceConfig(ctx context.Context, imgRef, pkgName string, imgcfg apko_types.ImageConfiguration) (*container.Config, error) {
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
			log.Debugf("--cache-dir %s not a dir; skipping", t.CacheDir)
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
		WorkspaceDir: t.WorkspaceDir,
		CacheDir:     t.CacheDir,
		Environment:  map[string]string{},
		RunAsUID:     runAsUID(imgcfg.Accounts),
		RunAs:        runAs(imgcfg.Accounts),
		RunAsGID:     runAsGID(imgcfg.Accounts),
	}

	if t.Configuration.Package.Resources != nil {
		cfg.CPU = t.Configuration.Package.Resources.CPU
		cfg.CPUModel = t.Configuration.Package.Resources.CPUModel
		cfg.Memory = t.Configuration.Package.Resources.Memory
		cfg.Disk = t.Configuration.Package.Resources.Disk
	}
	if t.Configuration.Capabilities.Add != nil {
		cfg.Capabilities.Add = t.Configuration.Capabilities.Add
	}
	if t.Configuration.Capabilities.Drop != nil {
		cfg.Capabilities.Drop = t.Configuration.Capabilities.Drop
	}

	maps.Copy(cfg.Environment, t.Configuration.Environment.Environment)
	maps.Copy(cfg.Environment, imgcfg.Environment)

	if _, ok := cfg.Environment["HOME"]; !ok {
		cfg.Environment["HOME"] = "/root"
	}

	cfg.ImgRef = imgRef
	log.Debugf("ImgRef = %s", cfg.ImgRef)

	return &cfg, nil
}

func (t *Test) guestFS(_ context.Context) apkofs.FullFS {
	return tarfs.New()
}
