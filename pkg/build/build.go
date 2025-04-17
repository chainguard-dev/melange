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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	apkofs "chainguard.dev/apko/pkg/apk/fs"
	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
	"chainguard.dev/apko/pkg/sbom/generator/spdx"
	"cloud.google.com/go/storage"
	"github.com/chainguard-dev/clog"
	purl "github.com/package-url/packageurl-go"
	"github.com/yookoala/realpath"
	"github.com/zealic/xignore"
	"go.opentelemetry.io/otel"
	"golang.org/x/exp/maps"
	"golang.org/x/sys/unix"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"sigs.k8s.io/release-utils/version"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/container"
	"chainguard.dev/melange/pkg/index"
	"chainguard.dev/melange/pkg/linter"
	"chainguard.dev/melange/pkg/sbom"
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
	// Ordered directories where to find 'uses' pipelines.
	PipelineDirs          []string
	SourceDir             string
	GuestDir              string
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

	// Initialized in New and mutated throughout the build process as we gain
	// visibility into our packages' (including subpackages') composition. This is
	// how we get "build-time" SBOMs!
	SBOMGroup *SBOMGroup
}

func New(ctx context.Context, opts ...Option) (*Build, error) {
	b := Build{
		WorkspaceIgnore: ".melangeignore",
		SourceDir:       ".",
		OutDir:          ".",
		CacheDir:        "./melange-cache/",
		Arch:            apko_types.ParseArchitecture(runtime.GOARCH),
	}

	for _, opt := range opts {
		if err := opt(&b); err != nil {
			return nil, err
		}
	}

	log := clog.New(slog.Default().Handler()).With("arch", b.Arch.ToAPK())
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

	// Now that we can find out the names of all the packages we'll be producing, we
	// can start tracking SBOM data for each of them, using our SBOMGroup type.
	b.SBOMGroup = NewSBOMGroup(slices.Collect(b.Configuration.AllPackageNames())...)

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
	b.SBOMGroup.SetCreatedTime(b.SourceDateEpoch)

	// Check that we actually can run things in containers.
	if b.Runner != nil && !b.Runner.TestUsability(ctx) {
		return nil, fmt.Errorf("unable to run containers using %s, specify --runner and one of %s", b.Runner.Name(), GetAllRunners())
	}

	// Apply build options to the context.
	for _, optName := range b.EnabledBuildOptions {
		log.Infof("applying configuration patches for build option %s", optName)

		if opt, ok := b.Configuration.Options[optName]; ok {
			if err := b.applyBuildOption(opt); err != nil {
				return nil, err
			}
		}
	}

	return &b, nil
}

func (b *Build) Close(ctx context.Context) error {
	log := clog.FromContext(ctx)
	errs := []error{}
	if b.Remove {
		log.Debugf("deleting guest dir %s", b.GuestDir)
		errs = append(errs, os.RemoveAll(b.GuestDir))
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

	if b.Runner.Name() == container.QemuName {
		b.ExtraPackages = append(b.ExtraPackages, []string{
			"melange-microvm-init",
			"gnutar",
		}...)
	}

	// Work around LockImageConfiguration assuming multi-arch.
	imgConfig.Archs = []apko_types.Architecture{b.Arch}

	opts := []apko_build.Option{apko_build.WithImageConfiguration(imgConfig),
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

	bc.Summarize(ctx)
	log.Infof("auth configured for: %s", maps.Keys(b.Auth)) // TODO: add this to summarize

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

// applyBuildOption applies a patch described by a BuildOption to a package build.
func (b *Build) applyBuildOption(bo config.BuildOption) error {
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

	inF, err := os.Open(ignorePath)
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

func (b *Build) overlayBinSh() error {
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

func fetchBucket(ctx context.Context, cacheSource string, cmm CacheMembershipMap) (string, error) {
	log := clog.FromContext(ctx)
	tmp, err := os.MkdirTemp("", "melange-cache")
	if err != nil {
		return "", err
	}
	bucket, prefix, _ := strings.Cut(strings.TrimPrefix(cacheSource, "gs://"), "/")

	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Infof("downgrading to anonymous mode: %s", err)

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
		log.Infof("cached gs://%s/%s -> %s", bucket, on, w.Name())
	}

	return tmp, nil
}

// isBuildLess returns true if the build context does not actually do any building.
// TODO(kaniini): Improve the heuristic for this by checking for uses/runs statements
// in the pipeline.
func (b *Build) isBuildLess() bool {
	return len(b.Configuration.Pipeline) == 0
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

func (b *Build) populateCache(ctx context.Context) error {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "populateCache")
	defer span.End()

	if b.CacheDir == "" {
		return nil
	}

	cmm, err := cacheItemsForBuild(b.Configuration)
	if err != nil {
		return fmt.Errorf("while determining which objects to fetch: %w", err)
	}

	if b.CacheSource != "" {
		log.Debugf("populating cache from %s", b.CacheSource)
	}

	// --cache-dir=gs://bucket/path/to/cache first pulls all found objects to a
	// tmp dir which is subsequently used as the cache.
	if strings.HasPrefix(b.CacheSource, "gs://") {
		tmp, err := fetchBucket(ctx, b.CacheSource, cmm)
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		log.Infof("cache bucket copied to %s", tmp)

		fsys := apkofs.DirFS(tmp)

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

			log.Debugf("  -> %s", path)

			if err := copyFile(tmp, path, b.CacheDir, mode.Perm()); err != nil {
				return err
			}

			return nil
		})
	}

	return nil
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
	arch := b.Arch.ToAPK()

	// Add the APK package(s) to their respective SBOMs. We do this early in the
	// build process so that we can later add more kinds of packages that relate to
	// these packages, as we learn more during the build.
	for _, sp := range b.Configuration.Subpackages {
		sp := sp
		spSBOM := b.SBOMGroup.Document(sp.Name)

		apkSubPkg := &sbom.Package{
			Name:            sp.Name,
			Version:         pkg.FullVersion(),
			Copyright:       pkg.FullCopyright(),
			LicenseDeclared: pkg.LicenseExpression(),
			Namespace:       namespace,
			Arch:            arch,
			PURL:            pkg.PackageURLForSubpackage(namespace, arch, sp.Name),
		}
		spSBOM.AddPackageAndSetDescribed(apkSubPkg)
	}

	pSBOM := b.SBOMGroup.Document(pkg.Name)
	apkPkg := &sbom.Package{
		Name:            pkg.Name,
		Version:         pkg.FullVersion(),
		Copyright:       pkg.FullCopyright(),
		LicenseDeclared: pkg.LicenseExpression(),
		Namespace:       namespace,
		Arch:            arch,
		PURL:            pkg.PackageURL(namespace, arch),
	}
	pSBOM.AddPackageAndSetDescribed(apkPkg)

	if b.GuestDir == "" {
		guestDir, err := os.MkdirTemp(b.Runner.TempDir(), "melange-guest-*")
		if err != nil {
			return fmt.Errorf("unable to make guest directory: %w", err)
		}
		b.GuestDir = guestDir

		if b.Remove {
			defer os.RemoveAll(guestDir)
		}
	}

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

	if err := b.addSBOMPackageForBuildConfigFile(); err != nil {
		return fmt.Errorf("adding SBOM package for build config file: %w", err)
	}

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

		fs := apkofs.DirFS(b.SourceDir)
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

	if !b.isBuildLess() {
		// Prepare guest directory
		if err := os.MkdirAll(b.GuestDir, 0o755); err != nil {
			return fmt.Errorf("mkdir -p %s: %w", b.GuestDir, err)
		}

		log.Infof("building workspace in '%s' with apko", b.GuestDir)

		guestFS := apkofs.DirFS(b.GuestDir, apkofs.WithCreateDir())
		imgRef, err := b.buildGuest(ctx, b.Configuration.Environment, guestFS)
		if err != nil {
			return fmt.Errorf("unable to build guest: %w", err)
		}

		cfg.ImgRef = imgRef
		log.Debugf("ImgRef = %s", cfg.ImgRef)

		// TODO(kaniini): Make overlay-binsh work with Docker and Kubernetes.
		// Probably needs help from apko.
		if err := b.overlayBinSh(); err != nil {
			return fmt.Errorf("unable to install overlay /bin/sh: %w", err)
		}

		if err := b.populateCache(ctx); err != nil {
			return fmt.Errorf("unable to populate cache: %w", err)
		}

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

		for i, p := range pipelines {
			uniqueID := strconv.Itoa(i)
			pkg, err := p.SBOMPackageForUpstreamSource(b.Configuration.Package.LicenseExpression(), namespace, uniqueID)
			if err != nil {
				return fmt.Errorf("creating SBOM package for upstream source: %w", err)
			}

			if pkg == nil {
				// This particular pipeline step doesn't tell us about the upstream source code.
				continue
			}

			b.SBOMGroup.AddUpstreamSourcePackage(pkg)
		}

		// add the main package to the linter queue
		lintTarget := linterTarget{
			pkgName:  b.Configuration.Package.Name,
			disabled: b.Configuration.Package.Checks.Disabled,
		}
		linterQueue = append(linterQueue, lintTarget)
	}

	// run any pipelines for subpackages
	for _, sp := range b.Configuration.Subpackages {
		sp := sp
		if err := os.MkdirAll(filepath.Join(b.WorkspaceDir, melangeOutputDirName, sp.Name), 0o755); err != nil {
			return err
		}

		if !b.isBuildLess() {
			log.Infof("running pipeline for subpackage %s", sp.Name)

			ctx := clog.WithLogger(ctx, log.With("subpackage", sp.Name))

			if err := pr.runPipelines(ctx, sp.Pipeline); err != nil {
				return fmt.Errorf("unable to run subpackage %s pipeline: %w", sp.Name, err)
			}
		}

		// add the main package to the linter queue
		lintTarget := linterTarget{
			pkgName:  sp.Name,
			disabled: sp.Checks.Disabled,
		}
		linterQueue = append(linterQueue, lintTarget)
	}

	// Store xattrs and modes for use after the workspace is loaded into memory
	xattrs, modes, err := storeXattrs(b.WorkspaceDir)
	if err != nil {
		return fmt.Errorf("failed to store workspace xattrs: %w", err)
	}

	// Retrieve the post build workspace from the runner
	log.Infof("retrieving workspace from builder: %s", cfg.PodID)
	b.WorkspaceDirFS = apkofs.DirFS(b.WorkspaceDir)

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
  
  // For each `setcap` entry in the package/sub-package, pull out the capability and data and set the xattr
	// For example:
	// setcap:
	//   - path: /usr/bin/scary
	//     add:
	//       cap_sys_admin: "+ep"
	for _, c := range b.Configuration.Package.SetCap {
		for attr, data := range c.Add {
			if err := b.WorkspaceDirFS.SetXattr(c.Path, attr, []byte(data)); err != nil {
				log.Warnf("failed to set capability %q on %s: %v\n", attr, c.Path, err)
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
		path := filepath.Join(b.WorkspaceDir, melangeOutputDirName, lt.pkgName)

		// Downgrade disabled checks from required to warn
		require := slices.DeleteFunc(b.LintRequire, func(s string) bool {
			return slices.Contains(lt.disabled, s)
		})
		warn := slices.CompactFunc(append(b.LintWarn, lt.disabled...), func(a, b string) bool {
			return a == b
		})

		if err := linter.LintBuild(ctx, b.Configuration, lt.pkgName, path, require, warn); err != nil {
			return fmt.Errorf("unable to lint package %s: %w", lt.pkgName, err)
		}
	}

	li, err := b.Configuration.Package.LicensingInfos(b.WorkspaceDir)
	if err != nil {
		return fmt.Errorf("gathering licensing infos: %w", err)
	}
	b.SBOMGroup.SetLicensingInfos(li)

	// Convert the SBOMs we've been working on to their SPDX representation, and
	// write them to disk. We'll handle any subpackages first, and then the main
	// package, but the order doesn't really matter.

	for _, sp := range b.Configuration.Subpackages {
		spSBOM := b.SBOMGroup.Document(sp.Name)
		spdxDoc := spSBOM.ToSPDX(ctx)
		log.Infof("writing SBOM for subpackage %s", sp.Name)
		if err := b.writeSBOM(sp.Name, &spdxDoc); err != nil {
			return fmt.Errorf("writing SBOM for %s: %w", sp.Name, err)
		}
	}

	spdxDoc := pSBOM.ToSPDX(ctx)
	log.Infof("writing SBOM for %s", pkg.Name)
	if err := b.writeSBOM(pkg.Name, &spdxDoc); err != nil {
		return fmt.Errorf("writing SBOM for %s: %w", pkg.Name, err)
	}

	// emit main package
	if err := b.Emit(ctx, pkg); err != nil {
		return fmt.Errorf("unable to emit package: %w", err)
	}

	// emit subpackages
	for _, sp := range b.Configuration.Subpackages {
		sp := sp

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

	if !b.isBuildLess() {
		// clean build guest container
		if err := os.RemoveAll(b.GuestDir); err != nil {
			log.Warnf("unable to clean guest container: %s", err)
		}
	}

	// generate APKINDEX.tar.gz and sign it
	if b.GenerateIndex {
		packageDir := filepath.Join(b.OutDir, b.Arch.ToAPK())
		log.Infof("generating apk index from packages in %s", packageDir)

		var apkFiles []string
		pkgFileName := fmt.Sprintf("%s-%s-r%d.apk", b.Configuration.Package.Name, b.Configuration.Package.Version, b.Configuration.Package.Epoch)
		apkFiles = append(apkFiles, filepath.Join(packageDir, pkgFileName))

		for _, subpkg := range b.Configuration.Subpackages {
			subpkg := subpkg

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

// writeSBOM encodes the given SPDX document to JSON and writes it to the
// filesystem in the directory `/var/lib/db/sbom`. The pkgName parameter should
// be set to the name of the origin package or subpackage.
func (b Build) writeSBOM(pkgName string, doc *spdx.Document) error {
	apkFSPath := filepath.Join(melangeOutputDirName, pkgName)
	sbomDirPath := filepath.Join(apkFSPath, "/var/lib/db/sbom")
	if err := b.WorkspaceDirFS.MkdirAll(sbomDirPath, os.FileMode(0o755)); err != nil {
		return fmt.Errorf("creating SBOM directory: %w", err)
	}

	pkgVersion := b.Configuration.Package.FullVersion()
	sbomPath := getPathForPackageSBOM(sbomDirPath, pkgName, pkgVersion)
	f, err := b.WorkspaceDirFS.Create(sbomPath)
	if err != nil {
		return fmt.Errorf("opening SBOM file for writing: %w", err)
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(true)

	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encoding SPDX SBOM: %w", err)
	}

	return nil
}

func (b *Build) addSBOMPackageForBuildConfigFile() error {
	buildConfigPURL, err := b.getBuildConfigPURL()
	if err != nil {
		return fmt.Errorf("getting PURL for build config: %w", err)
	}

	b.SBOMGroup.AddBuildConfigurationPackage(&sbom.Package{
		Name:            b.ConfigFile,
		Version:         b.ConfigFileRepositoryCommit,
		LicenseDeclared: b.ConfigFileLicense,
		Namespace:       b.Namespace,
		Arch:            "", // This field doesn't make sense in this context
		PURL:            buildConfigPURL,
	})

	return nil
}

func getPathForPackageSBOM(sbomDirPath, pkgName, pkgVersion string) string {
	return filepath.Join(
		sbomDirPath,
		fmt.Sprintf("%s-%s.spdx.json", pkgName, pkgVersion),
	)
}

func (b *Build) SummarizePaths(ctx context.Context) {
	log := clog.FromContext(ctx)
	log.Debugf("  workspace dir: %s", b.WorkspaceDir)

	if b.GuestDir != "" {
		log.Debugf("  guest dir: %s", b.GuestDir)
	}
}

func (b *Build) summarize(ctx context.Context) {
	log := clog.FromContext(ctx)
	log.Infof("melange %s is building:", version.GetVersionInfo().GitVersion)
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

func (b *Build) buildWorkspaceConfig(ctx context.Context) *container.Config {
	log := clog.FromContext(ctx)
	if b.isBuildLess() {
		return &container.Config{
			Arch:         b.Arch,
			WorkspaceDir: b.WorkspaceDir,
		}
	}

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
		Timeout:      b.Configuration.Package.Timeout,
		RunAs:        b.Configuration.Environment.Accounts.RunAs,
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

	for k, v := range b.Configuration.Environment.Environment {
		cfg.Environment[k] = v
	}

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

// Record on-disk xattrs and mode bits set during package builds in order to apply them in the new in-memory filesystem
// This will allow in-memory and bind mount runners to persist xattrs correctly
func storeXattrs(dir string) (map[string]map[string][]byte, map[string]fs.FileMode, error) {
	xattrs := make(map[string]map[string][]byte)
	modes := make(map[string]fs.FileMode)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || d.Type()&fs.ModeSymlink == fs.ModeSymlink {
			return nil
		}

		fi, err := d.Info()
		if err != nil {
			return err
		}
		mode := fi.Mode()

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		// If the path is within the melange-out directory, store the relative path and mode bits
		if strings.Contains(path, melangeOutputDirName) {
			modes[relPath] = mode
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

	return xattrs, modes, err
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
