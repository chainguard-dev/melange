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
	"archive/tar"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	apkofs "chainguard.dev/apko/pkg/apk/fs"
	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
	"chainguard.dev/apko/pkg/tarfs"
	"github.com/chainguard-dev/clog"
	purl "github.com/package-url/packageurl-go"
	"github.com/yookoala/realpath"
	"github.com/zealic/xignore"
	"go.opentelemetry.io/otel"
	"golang.org/x/sys/unix"
	"sigs.k8s.io/release-utils/version"

	"chainguard.dev/melange/pkg/build/sbom"
	"chainguard.dev/melange/pkg/build/sbom/spdx"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/container"
	"chainguard.dev/melange/pkg/index"
	"chainguard.dev/melange/pkg/license"
	"chainguard.dev/melange/pkg/linter"
)

const melangeOutputDirName = "melange-out"

var shellEmptyDir = []string{
	"sh", "-c",
	`d="$1";
[ $# -eq 1 ] || { echo "must provide dir. got $# args."; exit 1; }
cd "$d" || { echo "failed cd '$d'"; exit 1; }
set --
for e in * .*; do
  [ "$e" = "." -o "$e" = ".." -o "$e" = "*" ] && continue
  set -- "$@" "$e"
done
[ $# -gt 0 ] || { echo "nothing to cleanup. $d was empty."; exit 0; }
echo "cleaning Workspace by removing $# file/directories in $d"
rm -Rf "$@"`,
	"shellEmptyDir",
}

var gccLinkTemplate = `*link:
+ --package-metadata={"type":"apk","os":"{{.Namespace}}","name":"{{.Configuration.Package.Name}}","version":"{{.Configuration.Package.FullVersion}}","architecture":"{{.Arch.ToAPK}}"}
`

var ErrSkipThisArch = errors.New("error: skip this arch")

type Build struct {
	Configuration *config.Configuration

	// The name of the build configuration file, e.g. "crane.yaml".
	ConfigFile string

	// The URL of the git repository where the build configuration file is stored,
	// e.g. "https://github.com/wolfi-dev/os".
	ConfigFileRepositoryURL string

	// The commit hash of the git repository corresponding to the current state of
	// the build configuration file.
	ConfigFileRepositoryCommit string

	// The SPDX license string to use for the build configuration file.
	ConfigFileLicense string

	SourceDateEpoch time.Time
	WorkspaceDir    string
	WorkspaceDirFS  apkofs.FullFS
	WorkspaceIgnore string
	GuestFS         apkofs.FullFS
	// Ordered directories where to find 'uses' pipelines.
	PipelineDirs          []string
	SourceDir             string
	SigningKey            string
	SigningPassphrase     string
	Namespace             string
	GenerateIndex         bool
	EmptyWorkspace        bool
	OutDir                string
	Arch                  apko_types.Architecture
	Libc                  string
	ExtraKeys             []string
	ExtraRepos            []string
	ExtraPackages         []string
	DependencyLog         string
	BinShOverlay          string
	CreateBuildLog        bool
	PersistLintResults    bool
	CacheDir              string
	ApkCacheDir           string
	CacheSource           string
	StripOriginName       bool
	EnvFile               string
	VarsFile              string
	Runner                container.Runner
	containerConfig       *container.Config
	Debug                 bool
	DebugRunner           bool
	Interactive           bool
	Remove                bool
	LintRequire, LintWarn []string
	DefaultCPU            string
	DefaultCPUModel       string
	DefaultDisk           string
	DefaultMemory         string
	DefaultTimeout        time.Duration
	Auth                  map[string]options.Auth
	IgnoreSignatures      bool

	EnabledBuildOptions []string

	// SBOMGenerator is the generator used to create SBOMs for this build.
	// If not set, defaults to DefaultSBOMGenerator.
	SBOMGenerator sbom.Generator

	// SBOMGroup stores SBOMs for the main package and all subpackages.
	SBOMGroup *SBOMGroup

	Start time.Time
	End   time.Time

	// Opt-in SLSA provenance generation for initial rollout/testing
	GenerateProvenance bool

	// The package resolver associated with this build.
	//
	// This is only applicable when there's a build context.  It
	// is filled by buildGuest.
	PkgResolver *apk.PkgResolver
}

func New(ctx context.Context, opts ...Option) (*Build, error) {
	b := Build{
		WorkspaceIgnore: ".melangeignore",
		SourceDir:       ".",
		OutDir:          ".",
		CacheDir:        "./melange-cache/",
		Arch:            apko_types.ParseArchitecture(runtime.GOARCH),
		GuestFS:         tarfs.New(),
		Start:           time.Now(),
		SBOMGenerator:   &spdx.Generator{},
	}

	for _, opt := range opts {
		if err := opt(&b); err != nil {
			return nil, err
		}
	}

	log := clog.FromContext(ctx).With("arch", b.Arch.ToAPK())
	ctx = clog.WithLogger(ctx, log)

	// If no workspace directory is explicitly requested, create a
	// temporary directory for it.  Otherwise, ensure we are in a
	// subdir for this specific build context.
	if b.WorkspaceDir != "" {
		b.WorkspaceDir = filepath.Join(b.WorkspaceDir, b.Arch.ToAPK())

		// Get the absolute path to the workspace dir, which is needed for bind
		// mounts.
		absdir, err := filepath.Abs(b.WorkspaceDir)
		if err != nil {
			return nil, fmt.Errorf("unable to resolve path %s: %w", b.WorkspaceDir, err)
		}

		b.WorkspaceDir = absdir
	} else if b.Runner != nil {
		tmpdir, err := os.MkdirTemp(b.Runner.TempDir(), "melange-workspace-*")
		if err != nil {
			return nil, fmt.Errorf("unable to create workspace dir: %w", err)
		}
		b.WorkspaceDir = tmpdir
	}

	// If no config file is explicitly requested for the build context
	// we check if .melange.yaml or melange.yaml exist.
	checks := []string{".melange.yaml", ".melange.yml", "melange.yaml", "melange.yml"}
	if b.ConfigFile == "" {
		for _, chk := range checks {
			if _, err := os.Stat(chk); err == nil {
				log.Infof("no configuration file provided -- using %s", chk)
				b.ConfigFile = chk
				break
			}
		}
	}

	// If no config file could be automatically detected, error.
	if b.ConfigFile == "" {
		return nil, fmt.Errorf("melange.yaml is missing")
	}
	if b.ConfigFileRepositoryURL == "" {
		return nil, fmt.Errorf("config file repository URL was not set")
	}
	if b.ConfigFileRepositoryCommit == "" {
		return nil, fmt.Errorf("config file repository commit was not set")
	}

	if b.Configuration == nil {
		parsedCfg, err := config.ParseConfiguration(ctx,
			b.ConfigFile,
			config.WithEnvFileForParsing(b.EnvFile),
			config.WithVarsFileForParsing(b.VarsFile),
			config.WithDefaultCPU(b.DefaultCPU),
			config.WithDefaultCPUModel(b.DefaultCPUModel),
			config.WithDefaultDisk(b.DefaultDisk),
			config.WithDefaultMemory(b.DefaultMemory),
			config.WithDefaultTimeout(b.DefaultTimeout),
			config.WithCommit(b.ConfigFileRepositoryCommit),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to load configuration: %w", err)
		}
		b.Configuration = parsedCfg
	}

	if len(b.Configuration.Package.TargetArchitecture) == 1 &&
		b.Configuration.Package.TargetArchitecture[0] == "all" {
		log.Warnf("target-architecture: ['all'] is deprecated and will become an error; remove this field to build for all available archs")
	} else if len(b.Configuration.Package.TargetArchitecture) != 0 &&
		!slices.Contains(b.Configuration.Package.TargetArchitecture, b.Arch.ToAPK()) {
		return nil, ErrSkipThisArch
	}

	// SOURCE_DATE_EPOCH will always overwrite the build flag
	if _, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok {
		t, err := sourceDateEpoch(b.SourceDateEpoch)
		if err != nil {
			return nil, err
		}
		b.SourceDateEpoch = t
	}

	// Check that we actually can run things in containers.
	if b.Runner != nil && !b.Runner.TestUsability(ctx) {
		return nil, fmt.Errorf("unable to run containers using %s, specify --runner and one of %s", b.Runner.Name(), GetAllRunners())
	}

	// Apply build options to the context.
	for _, optName := range b.EnabledBuildOptions {
		log.Infof("applying configuration patches for build option %s", optName)

		if opt, ok := b.Configuration.Options[optName]; ok {
			b.applyBuildOption(opt)
		}
	}

	return &b, nil
}

func (b *Build) Close(ctx context.Context) error {
	log := clog.FromContext(ctx)
	errs := []error{}
	if b.Remove {
		log.Debugf("deleting workspace dir %s", b.WorkspaceDir)
		errs = append(errs, os.RemoveAll(b.WorkspaceDir))
		if b.containerConfig != nil && b.containerConfig.ImgRef != "" {
			errs = append(errs, b.Runner.OCIImageLoader().RemoveImage(context.WithoutCancel(ctx), b.containerConfig.ImgRef))
		}
	}

	if b.Runner != nil {
		errs = append(errs, b.Runner.Close())
	}

	return errors.Join(errs...)
}

// buildGuest invokes apko to build the guest environment, returning a reference to the image
// loaded by the OCI Image loader.
//
// NB: This has side effects! This mutates Build by overwriting Configuration.Environment with
// a locked version (packages resolved to versions) so we can record which packages were used.
func (b *Build) buildGuest(ctx context.Context, imgConfig apko_types.ImageConfiguration, guestFS apkofs.FullFS) (string, error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "buildGuest")
	defer span.End()

	tmp, err := os.MkdirTemp(os.TempDir(), "apko-temp-*")
	if err != nil {
		return "", fmt.Errorf("creating apko tempdir: %w", err)
	}
	defer os.RemoveAll(tmp)

	// Work around LockImageConfiguration assuming multi-arch.
	imgConfig.Archs = []apko_types.Architecture{b.Arch}

	opts := []apko_build.Option{
		apko_build.WithImageConfiguration(imgConfig),
		apko_build.WithArch(b.Arch),
		apko_build.WithExtraKeys(b.ExtraKeys),
		apko_build.WithExtraBuildRepos(b.ExtraRepos),
		apko_build.WithExtraPackages(b.ExtraPackages),
		apko_build.WithCache(b.ApkCacheDir, false, apk.NewCache(true)),
		apko_build.WithTempDir(tmp),
		apko_build.WithIgnoreSignatures(b.IgnoreSignatures),
	}

	configs, warn, err := apko_build.LockImageConfiguration(ctx, imgConfig, opts...)
	if err != nil {
		return "", fmt.Errorf("unable to lock image configuration: %w", err)
	}

	for k, v := range warn {
		log.Warnf("Unable to lock package %s: %s", k, v)
	}

	locked, ok := configs["index"]
	if !ok {
		return "", errors.New("missing locked config")
	}

	// Overwrite the environment with the locked one.
	b.Configuration.Environment = *locked

	opts = append(opts, apko_build.WithImageConfiguration(*locked))

	bc, err := apko_build.New(ctx, guestFS, opts...)
	if err != nil {
		return "", fmt.Errorf("unable to create build context: %w", err)
	}

	// Get the APK associated with our build, and then get a Resolver
	namedIndexes, err := bc.APK().GetRepositoryIndexes(ctx, false)
	if err != nil {
		return "", fmt.Errorf("unable to obtain repository indexes: %w", err)
	}
	b.PkgResolver = apk.NewPkgResolver(ctx, namedIndexes)

	bc.Summarize(ctx)
	log.Infof("auth configured for: %v", maps.Keys(b.Auth)) // TODO: add this to summarize

	// lay out the contents for the image in a directory.
	if err := bc.BuildImage(ctx); err != nil {
		return "", fmt.Errorf("unable to generate image: %w", err)
	}
	// if the runner needs an image, create an OCI image from the directory and load it.
	loader := b.Runner.OCIImageLoader()
	if loader == nil {
		return "", fmt.Errorf("runner %s does not support OCI image loading", b.Runner.Name())
	}
	layerTarGZ, layer, err := bc.ImageLayoutToLayer(ctx)
	if err != nil {
		return "", err
	}
	defer os.Remove(layerTarGZ)

	log.Debugf("using %s for image layer", layerTarGZ)

	ref, err := loader.LoadImage(ctx, layer, b.Arch, bc)
	if err != nil {
		return "", err
	}

	log.Debugf("pushed %s as %v", layerTarGZ, ref)
	log.Debug("successfully built workspace with apko")
	return ref, nil
}

func copyFile(base, src, dest string, perm fs.FileMode) error {
	basePath := filepath.Join(base, src)
	destPath := filepath.Join(dest, src)
	destDir := filepath.Dir(destPath)

	inF, err := os.Open(basePath) // #nosec G304 - Internal build workspace file operation
	if err != nil {
		return err
	}
	defer inF.Close()

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("mkdir -p %s: %w", destDir, err)
	}

	outF, err := os.Create(destPath) // #nosec G304 - Internal build workspace file operation
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

// applyBuildOption applies a patch described by a BuildOption to a package build.
func (b *Build) applyBuildOption(bo config.BuildOption) {
	// Patch the variables block.
	if b.Configuration.Vars == nil {
		b.Configuration.Vars = make(map[string]string)
	}

	maps.Copy(b.Configuration.Vars, bo.Vars)

	// Patch the build environment configuration.
	lo := bo.Environment.Contents.Packages
	b.Configuration.Environment.Contents.Packages = append(b.Configuration.Environment.Contents.Packages, lo.Add...)

	for _, pkg := range lo.Remove {
		pkgList := b.Configuration.Environment.Contents.Packages

		for pos, ppkg := range pkgList {
			if pkg == ppkg {
				pkgList[pos] = pkgList[len(pkgList)-1]
				pkgList = pkgList[:len(pkgList)-1]
			}
		}

		b.Configuration.Environment.Contents.Packages = pkgList
	}
}

func (b *Build) loadIgnoreRules(ctx context.Context) ([]*xignore.Pattern, error) {
	log := clog.FromContext(ctx)
	ignorePath := filepath.Join(b.SourceDir, b.WorkspaceIgnore)

	ignorePatterns := []*xignore.Pattern{}

	if _, err := os.Stat(ignorePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ignorePatterns, nil
		}

		return nil, err
	}

	log.Infof("loading ignore rules from %s", ignorePath)

	inF, err := os.Open(ignorePath) // #nosec G304 - Reading workspace ignore file from build configuration
	if err != nil {
		return nil, err
	}
	defer inF.Close()

	ignF := xignore.Ignorefile{}
	if err := ignF.FromReader(inF); err != nil {
		return nil, err
	}

	for _, rule := range ignF.Patterns {
		pattern := xignore.NewPattern(rule)

		if err := pattern.Prepare(); err != nil {
			return nil, err
		}

		ignorePatterns = append(ignorePatterns, pattern)
	}

	return ignorePatterns, nil
}

// getBuildConfigPURL determines the package URL for the melange config file
// itself.
func (b Build) getBuildConfigPURL() (*purl.PackageURL, error) {
	namespace, name, found := strings.Cut(strings.TrimPrefix(b.ConfigFileRepositoryURL, "https://github.com/"), "/")
	if !found {
		return nil, fmt.Errorf("extracting namespace and name from %s", b.ConfigFileRepositoryURL)
	}

	u := &purl.PackageURL{
		Type:      purl.TypeGithub,
		Namespace: namespace,
		Name:      name,
		Version:   b.ConfigFileRepositoryCommit,
		Subpath:   b.ConfigFile,
	}
	if err := u.Normalize(); err != nil {
		return nil, fmt.Errorf("normalizing PURL: %w", err)
	}
	return u, nil
}

func (b *Build) populateWorkspace(ctx context.Context, src fs.FS) error {
	log := clog.FromContext(ctx)
	_, span := otel.Tracer("melange").Start(ctx, "populateWorkspace")
	defer span.End()

	ignorePatterns, err := b.loadIgnoreRules(ctx)
	if err != nil {
		return err
	}

	// Write out build settings into workspacedir
	// For now, just the gcc spec file and just link settings.
	// In the future can control debug symbol generation, march/mtune, etc.
	specFile, err := os.Create(filepath.Join(b.WorkspaceDir, ".melange.gcc.spec"))
	if err != nil {
		return err
	}
	specTemplate := template.New("gccSpecFile")
	if err := template.Must(specTemplate.Parse(gccLinkTemplate)).Execute(specFile, b); err != nil {
		return err
	}
	if err := specFile.Close(); err != nil {
		return err
	}
	return fs.WalkDir(src, ".", func(path string, d fs.DirEntry, err error) error {
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

		for _, pat := range ignorePatterns {
			if pat.Match(path) {
				return nil
			}
		}

		log.Debugf("  -> %s", path)

		if err := copyFile(b.SourceDir, path, b.WorkspaceDir, mode.Perm()); err != nil {
			return err
		}

		return nil
	})
}

type linterTarget struct {
	pkgName  string
	disabled []string // checks that are downgraded from required -> warn
}

func (b *Build) BuildPackage(ctx context.Context) error {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "BuildPackage")
	defer span.End()

	if b.Runner == nil {
		return fmt.Errorf("no runner was specified")
	}

	b.summarize(ctx)

	ver := b.Configuration.Package.Version
	if _, err := apk.ParseVersion(ver); err != nil {
		return fmt.Errorf("unable to parse version '%s' for %s: %w", ver, b.ConfigFile, err)
	}

	namespace := b.Namespace
	if namespace == "" {
		namespace = "unknown"
	}

	if to := b.Configuration.Package.Timeout; to > 0 {
		tctx, cancel := context.WithTimeoutCause(ctx, to,
			fmt.Errorf("build exceeded its timeout of %s", to))
		defer cancel()
		ctx = tctx
	}

	pkg := &b.Configuration.Package

	log.Debugf("evaluating pipelines for package requirements")
	if err := b.Compile(ctx); err != nil {
		return fmt.Errorf("compiling %s: %w", b.ConfigFile, err)
	}

	// Filter out any subpackages with false If conditions.
	b.Configuration.Subpackages = slices.DeleteFunc(b.Configuration.Subpackages, func(sp config.Subpackage) bool {
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

	// Initialize SBOMGroup for the main package and all subpackages
	pkgNames := []string{b.Configuration.Package.Name}
	for _, sp := range b.Configuration.Subpackages {
		pkgNames = append(pkgNames, sp.Name)
	}
	b.SBOMGroup = NewSBOMGroup(pkgNames...)

	pr := &pipelineRunner{
		interactive: b.Interactive,
		debug:       b.Debug,
		config:      b.workspaceConfig(ctx),
		runner:      b.Runner,
	}

	if b.EmptyWorkspace {
		log.Debugf("empty workspace requested")
	} else {
		// Prepare workspace directory
		if err := os.MkdirAll(b.WorkspaceDir, 0o755); err != nil {
			return fmt.Errorf("mkdir -p %s: %w", b.WorkspaceDir, err)
		}

		fs := apkofs.DirFS(ctx, b.SourceDir)
		if fs != nil {
			log.Infof("populating workspace %s from %s", b.WorkspaceDir, b.SourceDir)
			if err := b.populateWorkspace(ctx, fs); err != nil {
				return fmt.Errorf("unable to populate workspace: %w", err)
			}
		}
	}

	if err := os.MkdirAll(filepath.Join(b.WorkspaceDir, melangeOutputDirName, b.Configuration.Package.Name), 0o755); err != nil {
		return err
	}

	linterQueue := []linterTarget{}
	cfg := b.workspaceConfig(ctx)

	imgRef, err := b.buildGuest(ctx, b.Configuration.Environment, b.GuestFS)
	if err != nil {
		return fmt.Errorf("unable to build guest: %w", err)
	}

	cfg.ImgRef = imgRef
	log.Debugf("ImgRef = %s", cfg.ImgRef)

	if err := b.Runner.StartPod(ctx, cfg); err != nil {
		return fmt.Errorf("unable to start pod: %w", err)
	}
	if !b.DebugRunner {
		defer func() {
			if err := b.Runner.TerminatePod(context.WithoutCancel(ctx), cfg); err != nil {
				log.Warnf("unable to terminate pod: %s", err)
			}
		}()
	}

	// run the main pipeline
	log.Debug("running the main pipeline")
	pipelines := b.Configuration.Pipeline
	if err := pr.runPipelines(ctx, pipelines); err != nil {
		return fmt.Errorf("unable to run package %s pipeline: %w", b.Configuration.Name(), err)
	}

	// add the main package to the linter queue
	lintTarget := linterTarget{
		pkgName:  b.Configuration.Package.Name,
		disabled: b.Configuration.Package.Checks.Disabled,
	}
	linterQueue = append(linterQueue, lintTarget)

	// run any pipelines for subpackages
	for _, sp := range b.Configuration.Subpackages {
		if err := os.MkdirAll(filepath.Join(b.WorkspaceDir, melangeOutputDirName, sp.Name), 0o755); err != nil {
			return err
		}

		log.Infof("running pipeline for subpackage %s", sp.Name)

		ctx := clog.WithLogger(ctx, log.With("subpackage", sp.Name))

		if err := pr.runPipelines(ctx, sp.Pipeline); err != nil {
			return fmt.Errorf("unable to run subpackage %s pipeline: %w", sp.Name, err)
		}

		// add the subpackage to the linter queue
		lintTarget := linterTarget{
			pkgName:  sp.Name,
			disabled: sp.Checks.Disabled,
		}
		linterQueue = append(linterQueue, lintTarget)
	}

	// Store metadata for use after the workspace is loaded into memory
	xattrs, modes, owners, err := storeMetadata(b.WorkspaceDir)
	if err != nil {
		return fmt.Errorf("failed to store workspace xattrs: %w", err)
	}

	// Retrieve the post build workspace from the runner
	log.Infof("retrieving workspace from builder: %s", cfg.PodID)
	b.WorkspaceDirFS = apkofs.DirFS(ctx, b.WorkspaceDir)

	// Retrieve the os-release information from the runner
	releaseData, err := b.Runner.GetReleaseData(ctx, cfg)
	if err != nil {
		log.Warnf("failed to retrieve release data from runner, OS section will be unknown: %v", err)
		// If we can't retrieve the release data, we will use a default 'unknown' one similar to apko.
		releaseData = &apko_build.ReleaseData{
			ID:        "unknown",
			Name:      "melange-generated package",
			VersionID: "unknown",
		}
	}

	// Apply xattrs to files in the new in-memory filesystem
	for path, attrs := range xattrs {
		for attr, data := range attrs {
			if err := b.WorkspaceDirFS.SetXattr(path, attr, data); err != nil {
				log.Warnf("failed to restore xattr %s on %s: %v\n", attr, path, err)
			}
		}
	}

	for path, mode := range modes {
		if err := b.WorkspaceDirFS.Chmod(path, mode); err != nil {
			log.Warnf("failed to apply mode %04o (%s) to %s: %v", mode, mode, path, err)
		}
	}

	for path, owner := range owners {
		uid := owner["uid"]
		gid := owner["gid"]
		if err := b.WorkspaceDirFS.Chown(path, uid, gid); err != nil {
			log.Warnf("failed to change ownership of %s to %d:%d: %v", path, uid, gid, err)
		}
	}

	// For each `setcap` entry in the package/sub-package, pull out the capability and data and set the xattr
	// For example:
	// setcap:
	//   - path: /usr/bin/scary
	//     add:
	//       cap_sys_admin: "+ep"
	caps, err := config.ParseCapabilities(b.Configuration.Package.SetCap)
	if err != nil {
		log.Warnf("failed to collect encoded capabilities for %v: %v", b.Configuration.Package.SetCap, err)
	}

	for path, cap := range caps {
		enc := config.EncodeCapability(cap.Effective, cap.Permitted, cap.Inheritable)
		fullPath := filepath.Join(melangeOutputDirName, pkg.Name, path)
		if b.Runner.Name() == container.QemuName {
			fullPath := filepath.Join(WorkDir, melangeOutputDirName, pkg.Name, path)
			hex := fmt.Sprintf("0x%s", hex.EncodeToString(enc))
			cmd := []string{"/bin/sh", "-c", fmt.Sprintf("setfattr -n security.capability -v %s %s", hex, fullPath)}
			if err := b.Runner.Run(ctx, pr.config, map[string]string{}, cmd...); err != nil {
				return fmt.Errorf("failed to set capabilities within VM on %s: %w", path, err)
			}
		} else {
			if err := b.WorkspaceDirFS.SetXattr(fullPath, "security.capability", enc); err != nil {
				log.Warnf("failed to set capabilities on %s: %v", path, err)
			}
		}
	}

	if err := b.retrieveWorkspace(ctx, b.WorkspaceDirFS); err != nil {
		return fmt.Errorf("retrieving workspace: %w", err)
	}
	log.Infof("retrieved and wrote post-build workspace to: %s", b.WorkspaceDir)

	// perform package linting
	for _, lt := range linterQueue {
		log.Infof("running package linters for %s", lt.pkgName)

		// lint the in-memory filesystem which contains the correct mode bits, xattrs, etc.
		fsys, err := apkofs.Sub(b.WorkspaceDirFS, filepath.Join(melangeOutputDirName, lt.pkgName))
		if err != nil {
			return fmt.Errorf("failed to return filesystem for workspace subtree: %w", err)
		}

		// Downgrade disabled checks from required to warn
		require := slices.DeleteFunc(b.LintRequire, func(s string) bool {
			return slices.Contains(lt.disabled, s)
		})
		warn := slices.CompactFunc(append(b.LintWarn, lt.disabled...), func(a, b string) bool {
			return a == b
		})

		// Conditionally persist lint results based on flag
		outDir := ""
		if b.PersistLintResults {
			outDir = b.OutDir
		}

		if err := linter.LintBuild(ctx, b.Configuration, lt.pkgName, require, warn, fsys, outDir, b.Arch.ToAPK()); err != nil {
			return fmt.Errorf("unable to lint package %s: %w", lt.pkgName, err)
		}
	}

	// Perform all license related linting and analysis
	if _, _, err := license.LicenseCheck(ctx, b.Configuration, b.WorkspaceDirFS); err != nil {
		return fmt.Errorf("license check: %w", err)
	}

	// Get build config PURL for SBOM generation
	buildConfigPURL, err := b.getBuildConfigPURL()
	if err != nil {
		return fmt.Errorf("getting PURL for build config: %w", err)
	}

	// Create a filesystem rooted at the melange-out directory for SBOM generation
	outfs, err := apkofs.Sub(b.WorkspaceDirFS, melangeOutputDirName)
	if err != nil {
		return fmt.Errorf("creating SBOM filesystem: %w", err)
	}

	// Generate SBOMs post-build using the configured generator
	genCtx := &sbom.GeneratorContext{
		Configuration:   b.Configuration,
		WorkspaceDir:    b.WorkspaceDir,
		OutputFS:        outfs,
		SourceDateEpoch: b.SourceDateEpoch,
		Namespace:       namespace,
		Arch:            b.Arch.ToAPK(),
		ConfigFile: &sbom.ConfigFile{
			Path:          b.ConfigFile,
			RepositoryURL: b.ConfigFileRepositoryURL,
			Commit:        b.ConfigFileRepositoryCommit,
			License:       b.ConfigFileLicense,
			PURL:          buildConfigPURL,
		},
		ReleaseData: releaseData,
	}

	if err := b.SBOMGenerator.GenerateSBOM(ctx, genCtx); err != nil {
		return fmt.Errorf("generating SBOMs: %w", err)
	}

	// emit main package
	if err := b.Emit(ctx, pkg); err != nil {
		return fmt.Errorf("unable to emit package: %w", err)
	}

	// emit subpackages
	for _, sp := range b.Configuration.Subpackages {
		if err := b.Emit(ctx, pkgFromSub(&sp)); err != nil {
			return fmt.Errorf("unable to emit package: %w", err)
		}
	}

	// clean build environment
	log.Debugf("cleaning workspacedir")
	cleanEnv := map[string]string{}
	if err := pr.runner.Run(ctx, pr.config, cleanEnv, append(shellEmptyDir, WorkDir)...); err != nil {
		log.Warnf("unable to clean workspace: %s", err)
	}
	// if the Runner used WorkspaceDir as WorkDir, then this will be empty already.
	if err := os.RemoveAll(b.WorkspaceDir); err != nil {
		log.Warnf("unable to clean workspace: %s", err)
	}

	// generate APKINDEX.tar.gz and sign it
	if b.GenerateIndex {
		packageDir := filepath.Join(b.OutDir, b.Arch.ToAPK())
		log.Infof("generating apk index from packages in %s", packageDir)

		var apkFiles []string
		pkgFileName := fmt.Sprintf("%s-%s-r%d.apk", b.Configuration.Package.Name, b.Configuration.Package.Version, b.Configuration.Package.Epoch)
		apkFiles = append(apkFiles, filepath.Join(packageDir, pkgFileName))

		for _, subpkg := range b.Configuration.Subpackages {
			subpkgFileName := fmt.Sprintf("%s-%s-r%d.apk", subpkg.Name, b.Configuration.Package.Version, b.Configuration.Package.Epoch)
			apkFiles = append(apkFiles, filepath.Join(packageDir, subpkgFileName))
		}

		opts := []index.Option{
			index.WithPackageFiles(apkFiles),
			index.WithSigningKey(b.SigningKey),
			index.WithMergeIndexFileFlag(true),
			index.WithIndexFile(filepath.Join(packageDir, "APKINDEX.tar.gz")),
		}

		idx, err := index.New(opts...)
		if err != nil {
			return fmt.Errorf("unable to create index: %w", err)
		}

		if err := idx.GenerateIndex(ctx); err != nil {
			return fmt.Errorf("unable to generate index: %w", err)
		}
	}

	return nil
}

func (b *Build) SummarizePaths(ctx context.Context) {
	log := clog.FromContext(ctx)
	log.Debugf("  workspace dir: %s", b.WorkspaceDir)
}

func (b *Build) summarize(ctx context.Context) {
	log := clog.FromContext(ctx)
	log.Infof("melange %s with runner %s is building:", version.GetVersionInfo().GitVersion, b.Runner.Name())
	log.Debugf("  configuration file: %s", b.ConfigFile)
	b.SummarizePaths(ctx)
}

// buildFlavor determines if a build context uses glibc or musl, it returns
// "gnu" for GNU systems, and "musl" for musl systems.
func (b *Build) buildFlavor() string {
	if b.Libc == "" {
		return "gnu"
	}
	return b.Libc
}

func runAsUID(accts apko_types.ImageAccounts) string {
	switch accts.RunAs {
	case "":
		return "" // Runner defaults
	case "root", "0":
		return "0"
	default:
	}
	// If accts.RunAs is numeric, then return it.
	if _, err := strconv.Atoi(accts.RunAs); err == nil {
		return accts.RunAs
	}
	for _, u := range accts.Users {
		if accts.RunAs == u.UserName {
			return fmt.Sprint(u.UID)
		}
	}
	panic(fmt.Sprintf("unable to find user with username %s", accts.RunAs))
}

func runAs(accts apko_types.ImageAccounts) string {
	switch accts.RunAs {
	case "":
		return "" // Runner defaults
	case "root", "0":
		return "root"
	default:
	}
	// If accts.RunAs is numeric, then look up the username.
	parsed, err := strconv.ParseUint(accts.RunAs, 10, 32)
	if err != nil || parsed > math.MaxInt32 {
		return accts.RunAs
	}
	uid := uint32(parsed)
	for _, u := range accts.Users {
		if u.UID == uid {
			return u.UserName
		}
	}
	panic(fmt.Sprintf("unable to find user with UID %d", uid))
}

func runAsGID(accts apko_types.ImageAccounts) string {
	switch accts.RunAs {
	case "":
		return "" // Runner defaults
	case "root", "0":
		return "0"
	default:
	}
	if parsed, err := strconv.ParseUint(accts.RunAs, 10, 32); err == nil {
		uid := uint32(parsed)
		for _, u := range accts.Users {
			if u.UID == uid && u.GID != nil {
				return fmt.Sprint(*u.GID)
			}
		}
	} else {
		for _, u := range accts.Users {
			if accts.RunAs == u.UserName && u.GID != nil {
				return fmt.Sprint(*u.GID)
			}
		}
	}

	// Couldn't find group membership, return empty string to use Runner defaults
	// TODO(stevebeattie): we should probably log this fact, but we
	// don't have the context to do so
	return ""
}

func (b *Build) buildWorkspaceConfig(ctx context.Context) *container.Config {
	log := clog.FromContext(ctx)

	mounts := []container.BindMount{
		{Source: b.WorkspaceDir, Destination: container.DefaultWorkspaceDir},
		{Source: "/etc/resolv.conf", Destination: container.DefaultResolvConfPath},
	}

	if b.CacheDir != "" {
		if fi, err := os.Stat(b.CacheDir); err == nil && fi.IsDir() {
			mountSource, err := realpath.Realpath(b.CacheDir)
			if err != nil {
				log.Errorf("could not resolve path for --cache-dir: %s", err)
			}

			mounts = append(mounts, container.BindMount{Source: mountSource, Destination: container.DefaultCacheDir})
		} else {
			log.Debugf("--cache-dir %s not a dir; skipping", b.CacheDir)
		}
	}

	// TODO(kaniini): Disable networking capability according to the pipeline requirements.
	caps := container.Capabilities{
		Networking: true,
	}

	cfg := container.Config{
		Arch:         b.Arch,
		PackageName:  b.Configuration.Package.Name,
		Mounts:       mounts,
		Capabilities: caps,
		Environment: map[string]string{
			"SOURCE_DATE_EPOCH": fmt.Sprintf("%d", b.SourceDateEpoch.Unix()),
		},
		WorkspaceDir: b.WorkspaceDir,
		CacheDir:     b.CacheDir,
		Timeout:      b.Configuration.Package.Timeout,
		RunAsUID:     runAsUID(b.Configuration.Environment.Accounts),
		RunAs:        runAs(b.Configuration.Environment.Accounts),
		RunAsGID:     runAsGID(b.Configuration.Environment.Accounts),
	}

	if b.Configuration.Package.Resources != nil {
		cfg.CPU = b.Configuration.Package.Resources.CPU
		cfg.CPUModel = b.Configuration.Package.Resources.CPUModel
		cfg.Memory = b.Configuration.Package.Resources.Memory
		cfg.Disk = b.Configuration.Package.Resources.Disk
	}
	if b.Configuration.Capabilities.Add != nil {
		cfg.Capabilities.Add = b.Configuration.Capabilities.Add
	}
	if b.Configuration.Capabilities.Drop != nil {
		cfg.Capabilities.Drop = b.Configuration.Capabilities.Drop
	}

	maps.Copy(cfg.Environment, b.Configuration.Environment.Environment)

	return &cfg
}

func (b *Build) workspaceConfig(ctx context.Context) *container.Config {
	if b.containerConfig == nil {
		b.containerConfig = b.buildWorkspaceConfig(ctx)
	}

	return b.containerConfig
}

// retrieveWorkspace retrieves the workspace from the container and unpacks it
// to the workspace directory. The workspace retrieved from the runner is in a
// tar stream containing the workspace contents rooted at ./melange-out
func (b *Build) retrieveWorkspace(ctx context.Context, fs apkofs.FullFS) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "retrieveWorkspace")
	defer span.End()

	extraFiles := []string{}
	for _, v := range b.Configuration.Package.Copyright {
		if v.LicensePath != "" {
			extraFiles = append(extraFiles, v.LicensePath)
		}
	}

	r, err := b.Runner.WorkspaceTar(ctx, b.containerConfig, extraFiles)
	if err != nil {
		return err
	} else if r == nil {
		return nil
	}
	defer r.Close()

	tr := tar.NewReader(r)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		// Remove the leading "./" from LICENSE files in QEMU workspaces
		hdr.Name = strings.TrimPrefix(hdr.Name, "./")

		var uid, gid int
		fi := hdr.FileInfo()
		if stat, ok := fi.Sys().(*tar.Header); ok {
			uid = stat.Uid
			gid = stat.Gid
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if fi, err := fs.Stat(hdr.Name); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				if target, err := fs.Readlink(hdr.Name); err == nil {
					if fi, err = fs.Stat(target); err == nil && fi.IsDir() {
						break
					}
				}
			}

			if err := fs.MkdirAll(hdr.Name, hdr.FileInfo().Mode().Perm()); err != nil {
				return fmt.Errorf("unable to create directory %s: %w", hdr.Name, err)
			}

			if err := fs.Chown(hdr.Name, uid, gid); err != nil {
				return fmt.Errorf("unable to chown directory %s: %w", hdr.Name, err)
			}

		case tar.TypeReg:
			parentDir := filepath.Dir(hdr.Name)
			if err := fs.MkdirAll(parentDir, 0o755); err != nil {
				return fmt.Errorf("unable to create directory %s: %w", hdr.Name, err)
			}
			f, err := fs.OpenFile(hdr.Name, os.O_CREATE|os.O_WRONLY, hdr.FileInfo().Mode())
			if err != nil {
				return fmt.Errorf("unable to open file %s: %w", hdr.Name, err)
			}

			if _, err := io.CopyN(f, tr, hdr.Size); err != nil {
				return fmt.Errorf("unable to copy file %s: %w", hdr.Name, err)
			}

			if err := f.Close(); err != nil {
				return fmt.Errorf("unable to close file %s: %w", hdr.Name, err)
			}

			if err := fs.Chown(hdr.Name, uid, gid); err != nil {
				return fmt.Errorf("unable to chown file %s: %w", hdr.Name, err)
			}

		case tar.TypeSymlink:
			if target, err := fs.Readlink(hdr.Name); err == nil && target == hdr.Linkname {
				continue
			}

			if err := fs.Symlink(hdr.Linkname, hdr.Name); err != nil {
				return fmt.Errorf("unable to create symlink %s -> %s: %w", hdr.Name, hdr.Linkname, err)
			}

		case tar.TypeLink:
			if err := fs.Link(hdr.Linkname, hdr.Name); err != nil {
				return err
			}

		default:
			return fmt.Errorf("unexpected tar type %d for %s", hdr.Typeflag, hdr.Name)
		}

		for k, v := range hdr.PAXRecords {
			if !strings.HasPrefix(k, "SCHILY.xattr.") {
				continue
			}
			attrName := strings.TrimPrefix(k, "SCHILY.xattr.")
			// XFS specific priviledged copies of posix. xattrs
			if strings.HasPrefix(attrName, "trusted.") {
				continue
			}
			fmt.Println("setting xattr", attrName, "on", hdr.Name)
			if err := fs.SetXattr(hdr.Name, attrName, []byte(v)); err != nil {
				return fmt.Errorf("unable to set xattr %s on %s: %w", attrName, hdr.Name, err)
			}
		}
	}

	return nil
}

// sourceDateEpoch parses the SOURCE_DATE_EPOCH environment variable.
// If it is not set, it returns the defaultTime.
// If it is set, it MUST be an ASCII representation of an integer.
// If it is malformed, it returns an error.
func sourceDateEpoch(defaultTime time.Time) (time.Time, error) {
	v := strings.TrimSpace(os.Getenv("SOURCE_DATE_EPOCH"))
	if v == "" {
		clog.DefaultLogger().Warnf("SOURCE_DATE_EPOCH is specified but empty, setting it to %v", defaultTime)
		return defaultTime, nil
	}

	// The value MUST be an ASCII representation of an integer
	// with no fractional component, identical to the output
	// format of date +%s.
	sec, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		// If the value is malformed, the build process
		// SHOULD exit with a non-zero error code.
		return defaultTime, fmt.Errorf("failed to parse SOURCE_DATE_EPOCH: %w", err)
	}

	return time.Unix(sec, 0).UTC(), nil
}

// xattrIgnoreList contains a mapping of xattr names used by various
// security features which leak their state into packages.  We need to
// ignore these xattrs because they require special permissions to be
// set when the underlying security features are in use.
var xattrIgnoreList = map[string]bool{
	"com.apple.provenance":          true,
	"security.csm":                  true,
	"security.selinux":              true,
	"com.docker.grpcfuse.ownership": true,
	"trusted.SGI_ACL_FILE":          true,
	"trusted.SGI_ACL_DEFAULT":       true,
}

// Record on-disk metadata set during package builds in order to apply them in the new in-memory filesystem
// This will allow in-memory and bind mount runners to persist mode bits, ownership, and xattrs correctly
func storeMetadata(dir string) (map[string]map[string][]byte, map[string]fs.FileMode, map[string]map[string]int, error) {
	xattrs := make(map[string]map[string][]byte)
	modes := make(map[string]fs.FileMode)
	owners := make(map[string]map[string]int)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || d.Type()&fs.ModeSymlink == fs.ModeSymlink {
			return nil
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		fi, err := d.Info()
		if err != nil {
			return err
		}

		// store the file mode bits for every relative path in the provided directory
		// some paths may not be related to or used by the package itself (i.e., they may be candidates for cleanup)
		// but we may want to have them for future linting at the very least
		modes[relPath] = fi.Mode()

		// Store ownership info, defaulting to root when unavailable or invalid
		owners[relPath] = map[string]int{
			"uid": 0,
			"gid": 0,
		}
		if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
			if stat.Uid <= math.MaxInt32 {
				owners[relPath]["uid"] = int(stat.Uid)
			}
			if stat.Gid <= math.MaxInt32 {
				owners[relPath]["gid"] = int(stat.Gid)
			}
		}

		size, err := unix.Listxattr(path, nil)
		if err != nil || size == 0 {
			return nil
		}

		buf := make([]byte, size)
		read, err := unix.Listxattr(path, buf)
		if err != nil {
			return nil
		}

		attrs := stringsFromByteSlice(buf[:read])
		result := make(map[string][]byte)
		for _, attr := range attrs {
			if _, ok := xattrIgnoreList[attr]; ok {
				continue
			}

			s, err := unix.Getxattr(path, attr, nil)
			if err != nil {
				continue
			}

			data := make([]byte, s)
			_, err = unix.Getxattr(path, attr, data)
			if err != nil {
				continue
			}

			result[attr] = data
		}
		xattrs[relPath] = result
		return nil
	})

	return xattrs, modes, owners, err
}

// stringsFromByteSlice converts a sequence of attributes to a []string.
// On Linux, each entry is a NULL-terminated string.
// Taken from golang.org/x/sys/unix/syscall_linux_test.go.
func stringsFromByteSlice(buf []byte) []string {
	var result []string
	off := 0
	for i, b := range buf {
		if b == 0 {
			result = append(result, string(buf[off:i]))
			off = i + 1
		}
	}
	return result
}
