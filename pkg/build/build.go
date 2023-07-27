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
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	apko_iocomb "chainguard.dev/apko/pkg/iocomb"
	apko_log "chainguard.dev/apko/pkg/log"
	apkofs "github.com/chainguard-dev/go-apk/pkg/fs"
	"github.com/google/go-containerregistry/pkg/logs"
	"go.opentelemetry.io/otel"
	"k8s.io/kube-openapi/pkg/util/sets"

	"cloud.google.com/go/storage"
	"github.com/go-git/go-git/v5"
	"github.com/yookoala/realpath"
	"github.com/zealic/xignore"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"chainguard.dev/melange/pkg/cond"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/container"
	"chainguard.dev/melange/pkg/index"
	"chainguard.dev/melange/pkg/sbom"
)

type Build struct {
	Configuration      config.Configuration
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
	Namespace          string
	GenerateIndex      bool
	EmptyWorkspace     bool
	OutDir             string
	Logger             apko_log.Logger
	Arch               apko_types.Architecture
	ExtraKeys          []string
	ExtraRepos         []string
	DependencyLog      string
	BinShOverlay       string
	CreateBuildLog     bool
	ignorePatterns     []*xignore.Pattern
	CacheDir           string
	ApkCacheDir        string
	CacheSource        string
	BreakpointLabel    string
	ContinueLabel      string
	foundContinuation  bool
	StripOriginName    bool
	EnvFile            string
	VarsFile           string
	Runner             container.Runner
	RunnerName         string
	imgRef             string
	containerConfig    *container.Config
	Debug              bool
	DebugRunner        bool
	LogPolicy          []string

	EnabledBuildOptions []string
}

var ErrSkipThisArch = errors.New("error: skip this arch")

func New(ctx context.Context, opts ...Option) (*Build, error) {
	b := Build{
		WorkspaceIgnore: ".melangeignore",
		SourceDir:       ".",
		OutDir:          ".",
		CacheDir:        "./melange-cache/",
		Arch:            apko_types.ParseArchitecture(runtime.GOARCH),
		LogPolicy:       []string{"builtin:stderr"},
	}

	for _, opt := range opts {
		if err := opt(&b); err != nil {
			return nil, err
		}
	}

	writer, err := apko_iocomb.Combine(b.LogPolicy)
	if err != nil {
		return nil, err
	}

	// Enable printing warnings and progress from GGCR.
	logs.Warn.SetOutput(writer)
	logs.Progress.SetOutput(writer)

	logger := &apko_log.Adapter{
		Out:   writer,
		Level: apko_log.InfoLevel,
	}

	fields := apko_log.Fields{
		"arch": b.Arch.ToAPK(),
	}
	b.Logger = logger.WithFields(fields)

	// try to get the runner
	runner, err := container.GetRunner(ctx, b.RunnerName, b.Logger)
	if err != nil {
		return nil, fmt.Errorf("unable to get runner %s: %w", b.RunnerName, err)
	}
	b.Runner = runner

	// If no workspace directory is explicitly requested, create a
	// temporary directory for it.  Otherwise, ensure we are in a
	// subdir for this specific build context.
	if b.WorkspaceDir != "" {
		// If we are continuing the build, do not modify the workspace
		// directory path.
		// TODO(kaniini): Clean up the logic for this, perhaps by signalling
		// multi-arch builds to the build context.
		if b.ContinueLabel == "" {
			b.WorkspaceDir = filepath.Join(b.WorkspaceDir, b.Arch.ToAPK())
		}

		// Get the absolute path to the workspace dir, which is needed for bind
		// mounts.
		absdir, err := filepath.Abs(b.WorkspaceDir)
		if err != nil {
			return nil, fmt.Errorf("unable to resolve path %s: %w", b.WorkspaceDir, err)
		}

		b.WorkspaceDir = absdir
	} else {
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
				b.Logger.Printf("no configuration file provided -- using %s", chk)
				b.ConfigFile = chk
				break
			}
		}
	}

	// If no config file could be automatically detected, error.
	if b.ConfigFile == "" {
		return nil, fmt.Errorf("melange.yaml is missing")
	}

	parsedCfg, err := config.ParseConfiguration(
		b.ConfigFile,
		config.WithEnvFileForParsing(b.EnvFile),
		config.WithLogger(b.Logger),
		config.WithVarsFileForParsing(b.VarsFile))
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	b.Configuration = *parsedCfg

	if len(b.Configuration.Package.TargetArchitecture) == 1 &&
		b.Configuration.Package.TargetArchitecture[0] == "all" {
		b.Logger.Printf("WARNING: target-architecture: ['all'] is deprecated and will become an error; remove this field to build for all available archs")
	} else if len(b.Configuration.Package.TargetArchitecture) != 0 &&
		!sets.NewString(b.Configuration.Package.TargetArchitecture...).Has(b.Arch.ToAPK()) {
		return nil, ErrSkipThisArch
	}

	// SOURCE_DATE_EPOCH will always overwrite the build flag
	if v, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok {
		if v == "" {
			b.Logger.Warnf("SOURCE_DATE_EPOCH is specified but empty, setting it to 0")
			v = "0"
		}
		// The value MUST be an ASCII representation of an integer
		// with no fractional component, identical to the output
		// format of date +%s.
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			// If the value is malformed, the build process
			// SHOULD exit with a non-zero error code.
			return nil, fmt.Errorf("failed to parse SOURCE_DATE_EPOCH: %w", err)
		}

		b.SourceDateEpoch = time.Unix(sec, 0)
	}

	// Check that we actually can run things in containers.
	if !runner.TestUsability(ctx) {
		return nil, fmt.Errorf("unable to run containers using %s, specify --runner and one of %s", runner.Name(), GetAllRunners())
	}

	// Apply build options to the context.
	for _, optName := range b.EnabledBuildOptions {
		b.Logger.Printf("applying configuration patches for build option %s", optName)

		if opt, ok := b.Configuration.Options[optName]; ok {
			if err := b.ApplyBuildOption(opt); err != nil {
				return nil, err
			}
		}
	}

	return &b, nil
}

type Option func(*Build) error

// WithConfig sets the configuration file used for the package build context.
func WithConfig(configFile string) Option {
	return func(b *Build) error {
		b.ConfigFile = configFile
		return nil
	}
}

// WithBuildDate sets the timestamps for the build context.
// The string is parsed according to RFC3339.
// An empty string is a special case and will default to
// the unix epoch.
func WithBuildDate(s string) Option {
	return func(bc *Build) error {
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
	return func(b *Build) error {
		b.WorkspaceDir = workspaceDir
		return nil
	}
}

// WithGuestDir sets the guest directory to use.
func WithGuestDir(guestDir string) Option {
	return func(b *Build) error {
		b.GuestDir = guestDir
		return nil
	}
}

// WithWorkspaceIgnore sets the workspace ignore rules file to use.
func WithWorkspaceIgnore(workspaceIgnore string) Option {
	return func(b *Build) error {
		b.WorkspaceIgnore = workspaceIgnore
		return nil
	}
}

// WithEmptyWorkspace sets whether the workspace should be empty.
func WithEmptyWorkspace(emptyWorkspace bool) Option {
	return func(b *Build) error {
		b.EmptyWorkspace = emptyWorkspace
		return nil
	}
}

// WithPipelineDir sets the pipeline directory to extend the built-in pipeline directory.
func WithPipelineDir(pipelineDir string) Option {
	return func(b *Build) error {
		b.PipelineDir = pipelineDir
		return nil
	}
}

// WithBuiltinPipelineDirectory sets the pipeline directory to use.
func WithBuiltinPipelineDirectory(builtinPipelineDir string) Option {
	return func(b *Build) error {
		b.BuiltinPipelineDir = builtinPipelineDir
		return nil
	}
}

// WithSourceDir sets the source directory to use.
func WithSourceDir(sourceDir string) Option {
	return func(b *Build) error {
		b.SourceDir = sourceDir
		return nil
	}
}

// WithCacheDir sets the cache directory to use.
func WithCacheDir(cacheDir string) Option {
	return func(b *Build) error {
		b.CacheDir = cacheDir
		return nil
	}
}

// WithCacheSource sets the cache source directory to use.  The cache will be
// pre-populated from this source directory.
func WithCacheSource(sourceDir string) Option {
	return func(b *Build) error {
		b.CacheSource = sourceDir
		return nil
	}
}

// WithSigningKey sets the signing key path to use.
func WithSigningKey(signingKey string) Option {
	return func(b *Build) error {
		if signingKey != "" {
			if _, err := os.Stat(signingKey); err != nil {
				return fmt.Errorf("could not open signing key: %w", err)
			}
		}

		b.SigningKey = signingKey
		return nil
	}
}

// WithGenerateIndex sets whether or not the apk index should be generated.
func WithGenerateIndex(generateIndex bool) Option {
	return func(b *Build) error {
		b.GenerateIndex = generateIndex
		return nil
	}
}

// WithOutDir sets the output directory to use for the packages.
func WithOutDir(outDir string) Option {
	return func(b *Build) error {
		b.OutDir = outDir
		return nil
	}
}

// WithArch sets the build architecture to use for this build context.
func WithArch(arch apko_types.Architecture) Option {
	return func(b *Build) error {
		b.Arch = arch
		return nil
	}
}

// WithExtraKeys adds a set of extra keys to the build context.
func WithExtraKeys(extraKeys []string) Option {
	return func(b *Build) error {
		b.ExtraKeys = extraKeys
		return nil
	}
}

// WithExtraRepos adds a set of extra repos to the build context.
func WithExtraRepos(extraRepos []string) Option {
	return func(b *Build) error {
		b.ExtraRepos = extraRepos
		return nil
	}
}

// WithDependencyLog sets a filename to use for dependency logging.
func WithDependencyLog(logFile string) Option {
	return func(b *Build) error {
		b.DependencyLog = logFile
		return nil
	}
}

// WithBinShOverlay sets a filename to copy from when installing /bin/sh
// into a build environment.
func WithBinShOverlay(binShOverlay string) Option {
	return func(b *Build) error {
		b.BinShOverlay = binShOverlay
		return nil
	}
}

// WithBreakpointLabel sets a label to stop build execution at.  The build
// environment and workspace are preserved.
func WithBreakpointLabel(breakpointLabel string) Option {
	return func(b *Build) error {
		b.BreakpointLabel = breakpointLabel
		return nil
	}
}

// WithContinueLabel sets a label to continue build execution from.  This
// requires a preserved build environment and workspace.
func WithContinueLabel(continueLabel string) Option {
	return func(b *Build) error {
		b.ContinueLabel = continueLabel
		return nil
	}
}

// WithStripOriginName determines whether the origin name should be stripped
// from generated packages.  The APK solver uses origin names to flatten
// possible dependency nodes when solving for a DAG, which means that they
// should be stripped when building "bootstrap" repositories, as the
// cross-sysroot packages will be preferred over the native ones otherwise.
func WithStripOriginName(stripOriginName bool) Option {
	return func(b *Build) error {
		b.StripOriginName = stripOriginName
		return nil
	}
}

// WithEnvFile specifies an environment file to use to preload the build
// environment.  It should contain the CFLAGS and LDFLAGS used by the C
// toolchain as well as any other desired environment settings for the
// build environment.
func WithEnvFile(envFile string) Option {
	return func(b *Build) error {
		b.EnvFile = envFile
		return nil
	}
}

// WithVarsFile specifies a variables file to use to populate the build
// configuration variables block.
func WithVarsFile(varsFile string) Option {
	return func(b *Build) error {
		b.VarsFile = varsFile
		return nil
	}
}

// WithNamespace takes a string to be used as the namespace in PackageURLs
// identifying the built apk in the generated SBOM. If no namespace is provided
// "unknown" will be listed as namespace.
func WithNamespace(namespace string) Option {
	return func(b *Build) error {
		b.Namespace = namespace
		return nil
	}
}

// WithEnabledBuildOptions takes an array of strings representing enabled build
// options.  These options are referenced in the options block of the Configuration,
// and represent patches to the configured build process which are optionally
// applied.
func WithEnabledBuildOptions(enabledBuildOptions []string) Option {
	return func(b *Build) error {
		b.EnabledBuildOptions = enabledBuildOptions
		return nil
	}
}

// WithCreateBuildLog indicates whether to generate a package.log file containing the
// list of packages that were built.  Some packages may have been skipped
// during the build if , so it can be hard to know exactly which packages were built
func WithCreateBuildLog(createBuildLog bool) Option {
	return func(b *Build) error {
		b.CreateBuildLog = createBuildLog
		return nil
	}
}

// WithDebug indicates whether debug logging of pipelines should be enabled.
func WithDebug(debug bool) Option {
	return func(b *Build) error {
		b.Debug = debug
		return nil
	}
}

// WithDebugRunner indicates whether the runner should leave the build environment up on failures
func WithDebugRunner(debug bool) Option {
	return func(b *Build) error {
		b.DebugRunner = debug
		return nil
	}
}

// WithLogPolicy sets the logging policy to use during builds.
func WithLogPolicy(policy []string) Option {
	return func(b *Build) error {
		b.LogPolicy = policy
		return nil
	}
}

// WithRunner specifies what runner to use to wrap
// the build environment.
func WithRunner(runner string) Option {
	return func(b *Build) error {
		b.RunnerName = runner
		return nil
	}
}

func WithPackageCacheDir(apkCacheDir string) Option {
	return func(b *Build) error {
		b.ApkCacheDir = apkCacheDir
		return nil
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

// BuildGuest invokes apko to build the guest environment.
func (b *Build) BuildGuest(ctx context.Context) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "BuildGuest")
	defer span.End()

	// Prepare workspace directory
	if err := os.MkdirAll(b.WorkspaceDir, 0755); err != nil {
		return fmt.Errorf("mkdir -p %s: %w", b.WorkspaceDir, err)
	}

	// Prepare guest directory
	if err := os.MkdirAll(b.GuestDir, 0755); err != nil {
		return fmt.Errorf("mkdir -p %s: %w", b.GuestDir, err)
	}

	b.Logger.Printf("building workspace in '%s' with apko", b.GuestDir)

	bc, err := apko_build.New(b.GuestDir,
		apko_build.WithImageConfiguration(b.Configuration.Environment),
		apko_build.WithArch(b.Arch),
		apko_build.WithExtraKeys(b.ExtraKeys),
		apko_build.WithExtraRepos(b.ExtraRepos),
		apko_build.WithLogger(b.Logger),
		apko_build.WithDebugLogging(true),
		apko_build.WithCacheDir(b.ApkCacheDir),
	)
	if err != nil {
		return fmt.Errorf("unable to create build context: %w", err)
	}

	if err := bc.Refresh(); err != nil {
		return fmt.Errorf("unable to refresh build context: %w", err)
	}

	bc.Summarize()

	// lay out the contents for the image in a directory.
	if _, err := bc.BuildImage(ctx); err != nil {
		return fmt.Errorf("unable to generate image: %w", err)
	}
	// if the runner needs an image, create an OCI image from the directory and load it.
	loader := b.Runner.OCIImageLoader()
	if loader == nil {
		return fmt.Errorf("runner %s does not support OCI image loading", b.Runner.Name())
	}
	layerTarGZ, layer, err := bc.ImageLayoutToLayer(ctx)
	if err != nil {
		return err
	}
	defer os.Remove(layerTarGZ)

	b.Logger.Printf("using %s for image layer", layerTarGZ)

	ref, err := loader.LoadImage(ctx, layer, b.Arch, bc)
	if err != nil {
		return err
	}

	b.Logger.Printf("pushed %s as %v", layerTarGZ, ref)
	b.imgRef = ref

	b.Logger.Printf("successfully built workspace with apko")

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

// ApplyBuildOption applies a patch described by a BuildOption to a package build.
func (b *Build) ApplyBuildOption(bo config.BuildOption) error {
	// Patch the variables block.
	if b.Configuration.Vars == nil {
		b.Configuration.Vars = make(map[string]string)
	}

	for k, v := range bo.Vars {
		b.Configuration.Vars[k] = v
	}

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

	return nil
}

func (b *Build) LoadIgnoreRules() error {
	ignorePath := filepath.Join(b.SourceDir, b.WorkspaceIgnore)

	if _, err := os.Stat(ignorePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return err
	}

	b.Logger.Printf("loading ignore rules from %s", ignorePath)

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

		b.ignorePatterns = append(b.ignorePatterns, pattern)
	}

	return nil
}

func (b *Build) matchesIgnorePattern(path string) bool {
	for _, pat := range b.ignorePatterns {
		if pat.Match(path) {
			return true
		}
	}

	return false
}

func (b *Build) OverlayBinSh() error {
	if b.BinShOverlay == "" {
		return nil
	}

	targetPath := filepath.Join(b.GuestDir, "bin", "sh")

	inF, err := os.Open(b.BinShOverlay)
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

func (b *Build) fetchBucket(ctx context.Context, cmm CacheMembershipMap) (string, error) {
	tmp, err := os.MkdirTemp("", "melange-cache")
	if err != nil {
		return "", err
	}
	bucket, prefix, _ := strings.Cut(strings.TrimPrefix(b.CacheSource, "gs://"), "/")

	client, err := storage.NewClient(ctx)
	if err != nil {
		b.Logger.Printf("downgrading to anonymous mode: %s", err)

		client, err = storage.NewClient(ctx, option.WithoutAuthentication())
		if err != nil {
			return "", fmt.Errorf("failed to get storage client: %w", err)
		}
	}

	bh := client.Bucket(bucket)
	it := bh.Objects(ctx, &storage.Query{Prefix: prefix})
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
		rc, err := bh.Object(on).NewReader(ctx)
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
		b.Logger.Printf("cached gs://%s/%s -> %s", bucket, on, w.Name())
	}

	return tmp, nil
}

// IsBuildLess returns true if the build context does not actually do any building.
// TODO(kaniini): Improve the heuristic for this by checking for uses/runs statements
// in the pipeline.
func (b *Build) IsBuildLess() bool {
	return len(b.Configuration.Pipeline) == 0
}

func (b *Build) PopulateCache(ctx context.Context) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "PopulateCache")
	defer span.End()

	if b.CacheDir == "" {
		return nil
	}

	cmm, err := cacheItemsForBuild(b.ConfigFile)
	if err != nil {
		return fmt.Errorf("while determining which objects to fetch: %w", err)
	}

	b.Logger.Printf("populating cache from %s", b.CacheSource)

	// --cache-dir=gs://bucket/path/to/cache first pulls all found objects to a
	// tmp dir which is subsequently used as the cache.
	if strings.HasPrefix(b.CacheSource, "gs://") {
		tmp, err := b.fetchBucket(ctx, cmm)
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		b.Logger.Printf("cache bucket copied to %s", tmp)

		fsys := os.DirFS(tmp)

		// mkdir /var/cache/melange
		if err := os.MkdirAll(b.CacheDir, 0o755); err != nil {
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

			b.Logger.Printf("  -> %s", path)

			if err := copyFile(tmp, path, b.CacheDir, mode.Perm()); err != nil {
				return err
			}

			return nil
		})
	}

	return nil
}

func (b *Build) PopulateWorkspace(ctx context.Context) error {
	_, span := otel.Tracer("melange").Start(ctx, "PopulateWorkspace")
	defer span.End()

	if b.EmptyWorkspace {
		b.Logger.Printf("empty workspace requested")
		return nil
	}

	if err := b.LoadIgnoreRules(); err != nil {
		return err
	}

	b.Logger.Printf("populating workspace %s from %s", b.WorkspaceDir, b.SourceDir)

	fsys := os.DirFS(b.SourceDir)

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

		if b.matchesIgnorePattern(path) {
			return nil
		}

		b.Logger.Printf("  -> %s", path)

		if err := copyFile(b.SourceDir, path, b.WorkspaceDir, mode.Perm()); err != nil {
			return err
		}

		return nil
	})
}

func (sp SubpackageContext) ShouldRun(pb *PipelineBuild) (bool, error) {
	if sp.Subpackage.If == "" {
		return true, nil
	}

	lookupWith := func(key string) (string, error) {
		mutated, err := MutateWith(pb, map[string]string{})
		if err != nil {
			return "", err
		}
		nk := fmt.Sprintf("${{%s}}", key)
		return mutated[nk], nil
	}

	result, err := cond.Evaluate(sp.Subpackage.If, lookupWith)
	if err != nil {
		return false, fmt.Errorf("evaluating subpackage if-conditional: %w", err)
	}

	return result, nil
}

func (b *Build) BuildPackage(ctx context.Context) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "BuildPackage")
	defer span.End()

	b.Summarize()

	pkg, err := NewPackageContext(&b.Configuration.Package)
	if err != nil {
		return err
	}
	pb := PipelineBuild{
		Build:   b,
		Package: pkg,
	}

	if b.GuestDir == "" {
		guestDir, err := os.MkdirTemp(b.Runner.TempDir(), "melange-guest-*")
		if err != nil {
			return fmt.Errorf("unable to make guest directory: %w", err)
		}
		b.GuestDir = guestDir
	}

	b.Logger.Printf("evaluating pipelines for package requirements")
	for _, p := range b.Configuration.Pipeline {
		pctx, err := NewPipelineContext(&p, b.Logger)
		if err != nil {
			return fmt.Errorf("unable to make pipeline context: %w", err)
		}

		if err := pctx.ApplyNeeds(&pb); err != nil {
			return fmt.Errorf("unable to apply pipeline requirements: %w", err)
		}
	}

	for _, spkg := range b.Configuration.Subpackages {
		spkgctx, err := NewSubpackageContext(&spkg)
		if err != nil {
			return fmt.Errorf("invalid subpackage: %w", err)
		}
		pb.Subpackage = spkgctx
		for _, p := range spkgctx.Subpackage.Pipeline {
			pctx, err := NewPipelineContext(&p, b.Logger)
			if err != nil {
				return fmt.Errorf("invalid pipeline context: %w", err)
			}
			if err := pctx.ApplyNeeds(&pb); err != nil {
				return fmt.Errorf("unable to apply pipeline requirements: %w", err)
			}
		}
	}
	pb.Subpackage = nil

	if !b.IsBuildLess() {
		if err := b.BuildGuest(ctx); err != nil {
			return fmt.Errorf("unable to build guest: %w", err)
		}

		// TODO(kaniini): Make overlay-binsh work with Docker and Kubernetes.
		// Probably needs help from apko.
		if err := b.OverlayBinSh(); err != nil {
			return fmt.Errorf("unable to install overlay /bin/sh: %w", err)
		}

		if err := b.PopulateCache(ctx); err != nil {
			return fmt.Errorf("unable to populate cache: %w", err)
		}
	}

	if err := b.PopulateWorkspace(ctx); err != nil {
		return fmt.Errorf("unable to populate workspace: %w", err)
	}

	cfg := b.WorkspaceConfig()
	if !b.IsBuildLess() {
		cfg.Arch = b.Arch
		if err := b.Runner.StartPod(ctx, cfg); err != nil {
			return fmt.Errorf("unable to start pod: %w", err)
		}
		if !b.DebugRunner {
			defer func() {
				if err := b.Runner.TerminatePod(ctx, cfg); err != nil {
					b.Logger.Warnf("unable to terminate pod: %s", err)
				}
			}()
		}

		// run the main pipeline
		b.Logger.Printf("running the main pipeline")
		for _, p := range b.Configuration.Pipeline {
			pctx, err := NewPipelineContext(&p, b.Logger)
			if err != nil {
				return fmt.Errorf("invalid pipeline context: %w")
			}
			if _, err := pctx.Run(ctx, &pb); err != nil {
				return fmt.Errorf("unable to run pipeline: %w", err)
			}
		}
	}

	// Run the SBOM generator
	generator, err := sbom.NewGenerator()
	if err != nil {
		return fmt.Errorf("creating sbom generator: %w", err)
	}

	// Capture languages declared in pipelines
	langs := []string{}
	namespace := b.Namespace
	if namespace == "" {
		namespace = "unknown"
	}

	// run any pipelines for subpackages
	for _, sp := range b.Configuration.Subpackages {
		spctx, err := NewSubpackageContext(&sp)
		if err != nil {
			return fmt.Errorf("invalid subpackage context: %w", err)
		}
		if !b.IsBuildLess() {
			b.Logger.Printf("running pipeline for subpackage %s", sp.Name)
			pb.Subpackage = spctx

			result, err := spctx.ShouldRun(&pb)
			if err != nil {
				return err
			}
			if !result {
				continue
			}

			for _, p := range spctx.Subpackage.Pipeline {
				pctx, err := NewPipelineContext(&p, b.Logger)
				if err != nil {
					return fmt.Errorf("invalid pipeline context: %w", err)
				}
				if _, err := pctx.Run(ctx, &pb); err != nil {
					return fmt.Errorf("unable to run pipeline: %w", err)
				}
			}
		}
	}

	if err := os.MkdirAll(filepath.Join(b.WorkspaceDir, "melange-out", b.Configuration.Package.Name), 0o755); err != nil {
		return err
	}

	// Retrieve the post build workspace from the runner
	b.Logger.Infof("retrieving workspace from builder: %s", cfg.PodID)
	if err := b.RetrieveWorkspace(ctx); err != nil {
		return fmt.Errorf("retrieving workspace: %v", err)
	}
	b.Logger.Printf("retrieved and wrote post-build workspace to: %s", b.WorkspaceDir)

	// generate SBOMs for subpackages
	for _, sp := range b.Configuration.Subpackages {
		langs := []string{}

		spctx, err := NewSubpackageContext(&sp)
		if err != nil {
			return fmt.Errorf("invalid subpackage context: %w", err)
		}
		if !b.IsBuildLess() {
			b.Logger.Printf("generating SBOM for subpackage %s", sp.Name)
			pb.Subpackage = spctx

			result, err := spctx.ShouldRun(&pb)
			if err != nil {
				return err
			}
			if !result {
				continue
			}

			for _, p := range sp.Pipeline {
				langs = append(langs, p.SBOM.Language)
			}
		}

		if err := os.MkdirAll(filepath.Join(b.WorkspaceDir, "melange-out", sp.Name), 0o755); err != nil {
			return err
		}

		if err := generator.GenerateSBOM(ctx, &sbom.Spec{
			Path:           filepath.Join(b.WorkspaceDir, "melange-out", sp.Name),
			PackageName:    sp.Name,
			PackageVersion: fmt.Sprintf("%s-r%d", b.Configuration.Package.Version, b.Configuration.Package.Epoch),
			Languages:      langs,
			License:        b.Configuration.Package.LicenseExpression(),
			Copyright:      b.Configuration.Package.FullCopyright(),
			Namespace:      namespace,
			Arch:           b.Arch.ToAPK(),
		}); err != nil {
			return fmt.Errorf("writing SBOMs: %w", err)
		}
	}

	if err := generator.GenerateSBOM(ctx, &sbom.Spec{
		Path:           filepath.Join(b.WorkspaceDir, "melange-out", b.Configuration.Package.Name),
		PackageName:    b.Configuration.Package.Name,
		PackageVersion: fmt.Sprintf("%s-r%d", b.Configuration.Package.Version, b.Configuration.Package.Epoch),
		Languages:      langs,
		License:        b.Configuration.Package.LicenseExpression(),
		Copyright:      b.Configuration.Package.FullCopyright(),
		Namespace:      namespace,
		Arch:           b.Arch.ToAPK(),
	}); err != nil {
		return fmt.Errorf("writing SBOMs: %w", err)
	}

	// emit main package
	if err := pkg.Emit(ctx, &pb); err != nil {
		return fmt.Errorf("unable to emit package: %w", err)
	}

	// emit subpackages
	for _, sp := range b.Configuration.Subpackages {
		spctx, err := NewSubpackageContext(&sp)
		if err != nil {
			return fmt.Errorf("invalid subpackage context: %w", err)
		}
		pb.Subpackage = spctx

		result, err := spctx.ShouldRun(&pb)
		if err != nil {
			return err
		}
		if !result {
			continue
		}

		if err := spctx.Emit(ctx, &pb); err != nil {
			return fmt.Errorf("unable to emit package: %w", err)
		}
	}

	if !b.IsBuildLess() {
		// clean build guest container
		if err := os.RemoveAll(b.GuestDir); err != nil {
			b.Logger.Printf("WARNING: unable to clean guest container: %s", err)
		}
	}

	// clean build environment
	if err := os.RemoveAll(b.WorkspaceDir); err != nil {
		b.Logger.Printf("WARNING: unable to clean workspace: %s", err)
	}

	// generate APKINDEX.tar.gz and sign it
	if b.GenerateIndex {
		packageDir := filepath.Join(pb.Build.OutDir, pb.Build.Arch.ToAPK())
		b.Logger.Printf("generating apk index from packages in %s", packageDir)

		var apkFiles []string
		pkgFileName := fmt.Sprintf("%s-%s-r%d.apk", b.Configuration.Package.Name, b.Configuration.Package.Version, b.Configuration.Package.Epoch)
		apkFiles = append(apkFiles, filepath.Join(packageDir, pkgFileName))

		for _, subpkg := range b.Configuration.Subpackages {
			spctx, err := NewSubpackageContext(&subpkg)
			if err != nil {
				return fmt.Errorf("invalid subpackage context: %w", err)
			}
			pb.Subpackage = spctx

			result, err := spctx.ShouldRun(&pb)
			if err != nil {
				return err
			}
			if !result {
				continue
			}

			subpkgFileName := fmt.Sprintf("%s-%s-r%d.apk", subpkg.Name, b.Configuration.Package.Version, b.Configuration.Package.Epoch)
			apkFiles = append(apkFiles, filepath.Join(packageDir, subpkgFileName))
		}

		opts := []index.Option{
			index.WithPackageFiles(apkFiles),
			index.WithSigningKey(b.SigningKey),
			index.WithMergeIndexFileFlag(true),
			index.WithIndexFile(filepath.Join(packageDir, "APKINDEX.tar.gz")),
		}

		b, err := index.New(opts...)
		if err != nil {
			return fmt.Errorf("unable to create index b: %w", err)
		}

		if err := b.GenerateIndex(ctx); err != nil {
			return fmt.Errorf("unable to generate index: %w", err)
		}

		if err := b.WriteJSONIndex(filepath.Join(packageDir, "APKINDEX.json")); err != nil {
			return fmt.Errorf("unable to generate JSON index: %w", err)
		}
	}

	return nil
}

func (b *Build) SummarizePaths() {
	b.Logger.Printf("  workspace dir: %s", b.WorkspaceDir)

	if b.GuestDir != "" {
		b.Logger.Printf("  guest dir: %s", b.GuestDir)
	}
}

func (b *Build) Summarize() {
	b.Logger.Printf("melange is building:")
	b.Logger.Printf("  configuration file: %s", b.ConfigFile)
	b.SummarizePaths()
}

// BuildFlavor determines if a build context uses glibc or musl, it returns
// "gnu" for GNU systems, and "musl" for musl systems.
func (b *Build) BuildFlavor() string {
	for _, dir := range []string{"lib", "lib64"} {
		if _, err := os.Stat(filepath.Join(b.GuestDir, dir, "libc.so.6")); err == nil {
			return "gnu"
		}
	}

	return "musl"
}

// BuildTripletGnu returns the GNU autoconf build triplet, for example
// `x86_64-pc-linux-gnu`.
func (b *Build) BuildTripletGnu() string {
	return b.Arch.ToTriplet(b.BuildFlavor())
}

// BuildTripletRust returns the Rust/Cargo build triplet, for example
// `x86_64-unknown-linux-gnu`.
func (b *Build) BuildTripletRust() string {
	return b.Arch.ToRustTriplet(b.BuildFlavor())
}

func (b *Build) buildWorkspaceConfig() *container.Config {
	if b.IsBuildLess() {
		return &container.Config{}
	}

	mounts := []container.BindMount{
		{Source: b.WorkspaceDir, Destination: container.DefaultWorkspaceDir},
		{Source: "/etc/resolv.conf", Destination: container.DefaultResolvConfPath},
	}

	if b.CacheDir != "" {
		if fi, err := os.Stat(b.CacheDir); err == nil && fi.IsDir() {
			mountSource, err := realpath.Realpath(b.CacheDir)
			if err != nil {
				b.Logger.Printf("could not resolve path for --cache-dir: %s", err)
			}

			mounts = append(mounts, container.BindMount{Source: mountSource, Destination: container.DefaultCacheDir})
		} else {
			b.Logger.Printf("--cache-dir %s not a dir; skipping", b.CacheDir)
		}
	}

	// TODO(kaniini): Disable networking capability according to the pipeline requirements.
	caps := container.Capabilities{
		Networking: true,
	}

	cfg := container.Config{
		PackageName:  b.Configuration.Package.Name,
		Mounts:       mounts,
		Capabilities: caps,
		Logger:       b.Logger,
		Environment: map[string]string{
			"SOURCE_DATE_EPOCH": fmt.Sprintf("%d", b.SourceDateEpoch.Unix()),
		},
	}

	for k, v := range b.Configuration.Environment.Environment {
		cfg.Environment[k] = v
	}

	cfg.ImgRef = b.imgRef
	b.Logger.Printf("ImgRef = %s", cfg.ImgRef)

	return &cfg
}

func (b *Build) WorkspaceConfig() *container.Config {
	if b.containerConfig != nil {
		return b.containerConfig
	}

	b.containerConfig = b.buildWorkspaceConfig()
	return b.containerConfig
}

// RetrieveWorkspace retrieves the workspace from the container and unpacks it
// to the workspace directory. The workspace retrieved from the runner is in a
// tar stream containing the workspace contents rooted at ./melange-out
func (b *Build) RetrieveWorkspace(ctx context.Context) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "RetrieveWorkspace")
	defer span.End()

	r, err := b.Runner.WorkspaceTar(ctx, b.containerConfig)
	if err != nil {
		return err
	} else if r == nil {
		return nil
	}
	defer r.Close()

	gr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)

	fs := apkofs.DirFS(b.WorkspaceDir)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
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

		case tar.TypeReg:
			f, err := fs.OpenFile(hdr.Name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, hdr.FileInfo().Mode())
			if err != nil {
				return fmt.Errorf("unable to open file %s: %w", hdr.Name, err)
			}

			if _, err := io.CopyN(f, tr, hdr.Size); err != nil {
				return fmt.Errorf("unable to copy file %s: %w", hdr.Name, err)
			}

			if err := f.Close(); err != nil {
				return fmt.Errorf("unable to close file %s: %w", hdr.Name, err)
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
			fmt.Println("setting xattr", attrName, "on", hdr.Name)
			if err := fs.SetXattr(hdr.Name, attrName, []byte(v)); err != nil {
				return fmt.Errorf("unable to set xattr %s on %s: %w", attrName, hdr.Name, err)
			}
		}
	}

	return nil
}
