# Melange Public API - After Refactoring

This document lists all publicly-usable (exported, non-internal) methods, types, and constants in the melange module after the refactoring to move internal packages to `internal/`.

**Last Updated**: After moving `pkg/cli`, `pkg/cond`, `pkg/sign`, `pkg/license`, and `pkg/linter` to internal/
Also moved `SCABuildInterface` to internal/sca
Also moved `GeneratedMelangeConfig` to internal/convert/apkbuild and removed pkg/manifest
Also moved `pkg/source` to internal/source
Created compatibility layers for `pkg/renovate`, `pkg/tarball`, and `pkg/cli` (Diff function only)

## pkg/build

### Types
- `type Build struct`
- `type Compiled struct`
- `type Option func(*Build) error`
- `type PackageBuild struct`
- `type Runner string`
- `type SBOMGroup struct`
- `type SubstitutionMap struct`

### Variables
- `var ErrSkipThisArch = errors.New("error: skip this arch")`
- `var PipelinesFS embed.FS`

### Constants
- `const WorkDir = "/home/build"`

### Functions
- `func GetAllRunners() []Runner`
- `func New(ctx context.Context, opts ...Option) (*Build, error)`
- `func NewSubstitutionMap(cfg *config.Configuration, arch apkoTypes.Architecture, flavor string, buildOpts []string) (*SubstitutionMap, error)`

### Build Options
- `func WithArch(arch apko_types.Architecture) Option`
- `func WithBuildDate(s string) Option`
- `func WithCacheDir(cacheDir string) Option`
- `func WithCacheSource(sourceDir string) Option`
- `func WithConfig(configFile string) Option`
- `func WithConfiguration(config *config.Configuration, filename string) Option`
- `func WithConfigFileRepositoryURL(u string) Option`
- `func WithConfigFileRepositoryCommit(hash string) Option`
- `func WithConfigFileLicense(license string) Option`
- `func WithEmptyWorkspace(emptyWorkspace bool) Option`
- `func WithExtraKeys(extraKeys []string) Option`
- `func WithGenerateIndex(generateIndex bool) Option`
- `func WithLintRequire(linters []string) Option`
- `func WithLintWarn(linters []string) Option`
- `func WithOutDir(outDir string) Option`
- `func WithPipelineDir(pipelineDir string) Option`
- `func WithSigningKey(signingKey string) Option`
- `func WithSourceDir(sourceDir string) Option`
- `func WithWorkspaceDir(workspaceDir string) Option`

### Methods
- `func (b *Build) BuildPackage(ctx context.Context) error`
- `func (b *Build) Close(ctx context.Context) error`
- `func (b *Build) Compile(ctx context.Context) error`
- `func (b *Build) Emit(ctx context.Context, pkg *config.Package) error`
- `func (b *Build) SummarizePaths(ctx context.Context)`
- `func (c *Compiled) CompilePipelines(ctx context.Context, sm *SubstitutionMap, pipelines []config.Pipeline) error`
- `func (pc *PackageBuild) AppendBuildLog(dir string) error`
- `func (pc *PackageBuild) EmitPackage(ctx context.Context) error`
- `func (pc *PackageBuild) Filename() string`
- `func (pc *PackageBuild) GenerateControlData(w io.Writer) error`
- `func (pc *PackageBuild) GenerateDependencies(ctx context.Context, hdl sca.SCAHandle) error`
- `func (pc *PackageBuild) Identity() string`
- `func (pc *PackageBuild) ProvenanceFilename() string`
- `func (pc *PackageBuild) SignatureName() string`
- `func (pc *PackageBuild) Signer() sign.ApkSigner`
- `func (pc *PackageBuild) WorkspaceSubdir() string`
- `func (sg *SBOMGroup) Document(name string) *sbom.Document`
- `func (sm *SubstitutionMap) MutateWith(with map[string]string) (map[string]string, error)`
- `func (sm *SubstitutionMap) Subpackage(subpkg *config.Subpackage) *SubstitutionMap`
- `func (t *Test) Compile(ctx context.Context) error`



## pkg/config

### Types
- `type BuildOption struct`
- `type CPE struct`
- `type Capability struct`
- `type Capabilities struct`
- `type Checks struct`
- `type Configuration struct`
- `type ContentsOption struct`
- `type Copyright struct`
- `type EnvironmentOption struct`
- `type Input struct`
- `type ListOption struct`
- `type Needs struct`
- `type Package struct`
- `type PackageOption struct`
- `type Pipeline struct`
- `type PipelineAssertions struct`
- `type Resources struct`
- `type Scriptlets struct`
- `type Subpackage struct`
- `type Test struct`
- `type Trigger struct`
- `type Update struct`
- `type VarTransforms struct`

### Functions
- `func SHA256(text string) string`

### Methods
- `func (cfg Configuration) AllPackageNames() iter.Seq[string]`
- `func (cfg Configuration) GetVarsFromConfig() (map[string]string, error)`
- `func (cfg Configuration) Name() string`
- `func (cfg Configuration) PerformVarSubstitutions(nw map[string]string) error`
- `func (cfg Configuration) Root() *yaml.Node`
- `func (cpe CPE) IsZero() bool`
- `func (dep *Dependencies) Summarize(ctx context.Context)`
- `func (e ErrInvalidConfiguration) Error() string`
- `func (e ErrInvalidConfiguration) Unwrap() error`
- `func (p Package) CPEString() (string, error)`
- `func (p Package) FullCopyright() string`
- `func (p Package) FullVersion() string`
- `func (p Package) LicenseExpression() string`
- `func (p Package) LicensingInfos(WorkspaceDir string) (map[string]string, error)`
- `func (p Package) PackageURL(distro, arch string) *purl.PackageURL`
- `func (p Package) PackageURLForSubpackage(distro, arch, subpackage string) *purl.PackageURL`
- `func (p Pipeline) SBOMPackageForUpstreamSource(licenseDeclared, supplier string, uniqueID string) (*sbom.Package, error)`
- `func (schedule Schedule) GetScheduleMessage() (string, error)`

## pkg/index

### Types
- `type Index struct`
- `type Option func(*Index) error`

### Functions
- `func New(opts ...Option) (*Index, error)`
- `func WithExpectedArch(expectedArch string) Option`
- `func WithIndexFile(indexFile string) Option`
- `func WithMergeIndexFileFlag(mergeFlag bool) Option`
- `func WithPackageDir(packageDir string) Option`
- `func WithPackageFiles(packageFiles []string) Option`
- `func WithSigningKey(signingKey string) Option`
- `func WithSourceIndexFile(indexFile string) Option`

### Methods
- `func (idx *Index) GenerateIndex(ctx context.Context) error`
- `func (idx *Index) LoadIndex(ctx context.Context, sourceFile string) error`
- `func (idx *Index) UpdateIndex(ctx context.Context) error`
- `func (idx *Index) WriteArchiveIndex(ctx context.Context, destinationFile string) error`



## pkg/cli

### Functions (Deprecated - Compatibility Layer)
- `func Diff(oldName string, old []byte, newName string, new []byte, comments bool) []byte` - **Deprecated**: Use `util.Diff` instead

## pkg/renovate

### Types (Deprecated - Compatibility Layer)
- `type Context` - **Deprecated**: Alias for internal type
- `type Option` - **Deprecated**: Alias for internal type

### Functions (Deprecated - Compatibility Layer)
- `func New(opts ...Option) (*Context, error)` - **Deprecated**
- `func WithConfig(configFile string) Option` - **Deprecated**

## pkg/renovate/bump

### Types (Deprecated - Compatibility Layer)
- `type Option` - **Deprecated**: Alias for internal type

### Functions (Deprecated - Compatibility Layer)
- `func New(ctx context.Context, opts ...Option) renovate.Renovator` - **Deprecated**
- `func WithTargetVersion(v string) Option` - **Deprecated**
- `func WithExpectedCommit(c string) Option` - **Deprecated**

## pkg/tarball

### Types (Deprecated - Compatibility Layer)
- `type Context` - **Deprecated**: Alias for internal type
- `type Option` - **Deprecated**: Alias for internal type

### Functions (Deprecated - Compatibility Layer)
- `func NewContext(opts ...Option) (*Context, error)` - **Deprecated**
- `func WithOverrideUIDGID(uid, gid int) Option` - **Deprecated**
- `func WithOverrideUname(uname string) Option` - **Deprecated**
- `func WithOverrideGname(gname string) Option` - **Deprecated**
- `func WithSkipClose(skipClose bool) Option` - **Deprecated**

## pkg/util

### Functions
- `func MutateAndQuoteStringFromMap(with map[string]string, input string) (string, error)`
- `func MutateStringFromMap(with map[string]string, input string) (string, error)`
- `func Diff(oldName string, old []byte, newName string, new []byte, comments bool) []byte` - Moved from internal/cli

## Summary

The refactoring has successfully reduced the public API surface by:

1. **Moved to internal/**:
   - `pkg/convert` → `internal/convert` (entire package)
   - `pkg/tarball` → `internal/tarball` (entire package)
   - `pkg/sbom` → `internal/sbom` (entire package)
   - `pkg/container` → `internal/container` (entire package)
   - `pkg/sca` → `internal/sca` (entire package)
   - `pkg/renovate` → `internal/renovate` (entire package)
   - `pkg/http` → `internal/http` (entire package)
   - `pkg/cli` → `internal/cli` (entire package)
   - `pkg/cond` → `internal/cond` (entire package)
   - `pkg/sign` → `internal/sign` (entire package)
   - `pkg/license` → `internal/license` (entire package)
   - `pkg/linter` → `internal/linter` (entire package)
   - `pkg/source` → `internal/source` (entire package)

2. **Unexported identifiers in remaining packages**:
   - In `pkg/build`: unexported `newSBOMGroup`, `withWorkspaceIgnore`, `withBinShOverlay`, and several SBOMGroup methods
   - In `pkg/config`: unexported `WithFS`, changed `VersionHandler` to `versionHandler`, unexported monitor methods
   - In `pkg/manifest`: unexported setter methods on GeneratedMelangeConfig

The public API is now cleaner and more focused on the essential functionality that external users need. The CLI implementation, conditional expression evaluation, signing operations, license detection, and APK linting are now internal-only, preventing external packages from directly importing these implementation details.