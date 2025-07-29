# Exported Identifiers in Melange

This document lists all exported methods, functions, types, constants, and variables in the melange module, organized by package. This is intended to help identify candidates for moving to internal packages.

## pkg/build

### Types
- `type Build struct` - Main build context
- `type Compiled struct` - Compiled pipeline representation
- `type Test struct` - Test context
- `type PackageBuild struct` - Individual package build context
- `type SubstitutionMap struct` - Variable substitution map
- `type SCABuildInterface struct` - SCA interface implementation
- `type SBOMGroup struct` - SBOM group management

### Functions
- `func New(ctx context.Context, opts ...Option) (*Build, error)` - Create new build context
- `func NewTest(ctx context.Context, opts ...TestOption) (*Test, error)` - Create new test context

### Methods
- `func (b *Build) Close(ctx context.Context) error`
- `func (b *Build) BuildPackage(ctx context.Context) error`
- `func (b *Build) SummarizePaths(ctx context.Context)`
- `func (b *Build) Emit(ctx context.Context, pkg *config.Package) error`
- `func (b *Build) Compile(ctx context.Context) error`
- `func (t *Test) Compile(ctx context.Context) error`
- `func (t *Test) Close() error`
- `func (t *Test) BuildGuest(ctx context.Context, imgConfig apko_types.ImageConfiguration, guestFS apkofs.FullFS) (string, error)`
- `func (t *Test) IsTestless() bool`
- `func (t *Test) PopulateWorkspace(ctx context.Context, src fs.FS) error`
- `func (t *Test) TestPackage(ctx context.Context) error`
- `func (t *Test) SummarizePaths(ctx context.Context)`
- `func (t *Test) Summarize(ctx context.Context)`
- `func (c *Compiled) CompilePipelines(ctx context.Context, sm *SubstitutionMap, pipelines []config.Pipeline) error`
- `func (pc *PackageBuild) AppendBuildLog(dir string) error`
- `func (pc *PackageBuild) Identity() string`
- `func (pc *PackageBuild) Filename() string`
- `func (pc *PackageBuild) ProvenanceFilename() string`
- `func (pc *PackageBuild) WorkspaceSubdir() string`
- `func (pc *PackageBuild) GenerateControlData(w io.Writer) error`
- `func (pc *PackageBuild) SignatureName() string`
- `func (pc *PackageBuild) GenerateDependencies(ctx context.Context, hdl sca.SCAHandle) error`
- `func (pc *PackageBuild) EmitPackage(ctx context.Context) error`
- `func (pc *PackageBuild) Signer() sign.ApkSigner`
- `func (sm *SubstitutionMap) MutateWith(with map[string]string) (map[string]string, error)`
- `func (sm *SubstitutionMap) Subpackage(subpkg *config.Subpackage) *SubstitutionMap`
- `func (sg *SBOMGroup) SetCreatedTime(t time.Time)`
- `func (sg *SBOMGroup) SetLicensingInfos(li map[string]string)`
- `func (sg *SBOMGroup) Document(name string) *sbom.Document`
- `func (sg *SBOMGroup) AddBuildConfigurationPackage(p *sbom.Package)`
- `func (sg *SBOMGroup) AddUpstreamSourcePackage(p *sbom.Package)`
- SCABuildInterface methods implementing sca.SCAHandle interface

### Constants/Variables
- `const WorkDir = "/home/build"`
- `const BuiltinPipelineDir = "/usr/share/melange/pipelines"`
- `var ErrSkipThisArch = errors.New("error: skip this arch")`
- `var PipelinesFS embed.FS`

## pkg/cli

### Types
- `type KeygenContext struct` - Keygen command context
- Various option structs for commands

### Functions
- `func New() *cobra.Command` - Create root command
- `func BuildCmd(ctx context.Context, archs []apko_types.Architecture, baseOpts ...build.Option) error`
- `func TestCmd(ctx context.Context, archs []apko_types.Architecture, baseOpts ...build.TestOption) error`
- `func IndexCmd(ctx context.Context, opts ...index.Option) error`
- `func KeygenCmd(ctx context.Context, keyName string, bitSize int) error`
- Various other command implementations

### Methods
- `func (kc *KeygenContext) GenerateKeypair() (*rsa.PrivateKey, *rsa.PublicKey, error)`
- Command option methods

## pkg/config

### Types
- `type Configuration struct` - Main configuration
- `type Package struct` - Package configuration
- `type Pipeline struct` - Pipeline configuration
- `type Subpackage struct` - Subpackage configuration
- `type CPE struct` - Common Platform Enumeration
- `type Dependencies struct` - Dependency tracking
- `type Schedule struct` - Update schedule
- `type GitMonitor struct` - Git monitoring config
- `type GitHubMonitor struct` - GitHub monitoring config
- `type ReleaseMonitor struct` - Release monitoring config
- `type BuildOption struct` - Build options
- `type ListOption struct` - List options
- `type ContentsOption struct` - Contents options
- `type EnvironmentOption struct` - Environment options
- `type ErrInvalidConfiguration struct` - Configuration error

### Functions
- `func Parse(ctx context.Context, config string, opts ...ConfigOpt) (*Configuration, error)`
- `func ParseConfiguration(ctx context.Context, config string, opts ...ConfigOpt) (*Configuration, error)`

### Methods
- `func (cfg Configuration) GetVarsFromConfig() (map[string]string, error)`
- `func (cfg Configuration) PerformVarSubstitutions(nw map[string]string) error`
- `func (cfg Configuration) AllPackageNames() iter.Seq[string]`
- `func (cfg Configuration) Name() string`
- `func (cfg Configuration) Root() *yaml.Node`
- `func (p Package) CPEString() (string, error)`
- `func (p Package) PackageURL(distro, arch string) *purl.PackageURL`
- `func (p Package) PackageURLForSubpackage(distro, arch, subpackage string) *purl.PackageURL`
- `func (p Package) FullVersion() string`
- `func (p Package) LicenseExpression() string`
- `func (p Package) LicensingInfos(WorkspaceDir string) (map[string]string, error)`
- `func (p Package) FullCopyright() string`
- `func (p Pipeline) SBOMPackageForUpstreamSource(licenseDeclared, supplier string, uniqueID string) (*sbom.Package, error)`
- `func (dep *Dependencies) Summarize(ctx context.Context)`
- `func (schedule Schedule) GetScheduleMessage() (string, error)`
- Monitor interface methods (GetStripPrefix, GetStripSuffix, GetFilterPrefix, GetFilterContains)
- `func (e ErrInvalidConfiguration) Error() string`
- `func (e ErrInvalidConfiguration) Unwrap() error`

## pkg/container

### Types
- `type Config struct` - Container configuration
- `type BindMount struct` - Bind mount configuration
- `type Capabilities struct` - Capability settings
- `type Runner interface` - Container runner interface
- `type Loader interface` - Image loader interface
- `type Debugger interface` - Debug interface

### Functions
- `func BubblewrapRunner(remove bool) Runner` - Create bubblewrap runner
- `func QemuRunner() Runner` - Create qemu runner

### Constants
- `const QemuName = "qemu"`

## pkg/container/docker

### Functions
- `func NewRunner(ctx context.Context) (mcontainer.Runner, error)` - Create docker runner

## pkg/convert/apkbuild

### Types
- `type Context struct` - APKBUILD context
- `type NavigationMap struct` - Navigation map
- `type Dependency struct` - Dependency info
- `type ApkConvertor struct` - APK converter

### Functions
- `func New(ctx context.Context) (Context, error)` - Create new context

### Methods
- `func (c Context) Generate(ctx context.Context, apkBuildURI, pkgName string) error`

## pkg/convert/github

### Types
- `type GithubRepoClient struct` - GitHub client
- `type TagData struct` - Tag information

### Functions
- `func ParseGithubURL(u string) (string, string, error)` - Parse GitHub URL
- `func NewGithubRepoClient(client *github.Client, owner, repo string) *GithubRepoClient`

### Methods
- `func (grc *GithubRepoClient) Repo() string`
- `func (grc *GithubRepoClient) GetTags(ctx context.Context, tags []string) (map[string]*TagData, error)`
- `func (grc *GithubRepoClient) GetVersions(ctx context.Context, version string) ([]TagData, error)`

## pkg/convert/relmon

### Types
- `type Items struct` - Release monitoring items
- `type Item struct` - Single item
- `type MonitorFinder struct` - Monitor finder

### Functions
- `func NewMonitorFinder() *MonitorFinder` - Create monitor finder

### Methods
- `func (mf *MonitorFinder) FindMonitor(ctx context.Context, pkg string) (*Item, error)`

## pkg/convert/wolfios

### Types
- `type Context struct` - Wolfi OS context

### Functions
- `func New(client *http.Client, indexURL string) Context` - Create context
- `func Untar(dst string, r io.Reader) error` - Untar helper

### Methods
- `func (c Context) GetWolfiPackages(ctx context.Context) (map[string]bool, error)`

### Constants
- `const PackageIndex = "https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz"`

## pkg/cond

### Types
- `type VariableLookupFunction func(key string) (string, error)` - Variable lookup

### Functions
- `func Subst(inputExpr string, lookupFns ...VariableLookupFunction) (string, error)` - Substitute variables
- `func NullLookup(key string) (string, error)` - Null lookup function
- `func Evaluate(inputExpr string, lookupFns ...VariableLookupFunction) (bool, error)` - Evaluate expression

## pkg/http

### Types
- `type RLHTTPClient struct` - Rate-limited HTTP client

### Functions
- `func NewClient(rl *rate.Limiter) *RLHTTPClient` - Create new client

### Methods
- `func (c *RLHTTPClient) Do(req *http.Request) (*http.Response, error)`
- `func (c *RLHTTPClient) GetArtifactSHA256(ctx context.Context, artifactURI string) (string, error)`

## pkg/index

### Types
- `type Index struct` - APK index
- `type Option func(*Index) error` - Index option

### Functions
- `func New(opts ...Option) (*Index, error)` - Create new index
- `func WithMergeIndexFileFlag(mergeFlag bool) Option`
- `func WithIndexFile(indexFile string) Option`
- `func WithSourceIndexFile(indexFile string) Option`
- `func WithPackageFiles(packageFiles []string) Option`
- `func WithPackageDir(packageDir string) Option`
- `func WithSigningKey(signingKey string) Option`
- `func WithExpectedArch(expectedArch string) Option`

### Methods
- `func (idx *Index) LoadIndex(ctx context.Context, sourceFile string) error`
- `func (idx *Index) UpdateIndex(ctx context.Context) error`
- `func (idx *Index) GenerateIndex(ctx context.Context) error`
- `func (idx *Index) WriteArchiveIndex(ctx context.Context, destinationFile string) error`

## pkg/license

### Types
- `type Classifier interface` - License classifier interface
- `type License struct` - License information
- `type LicenseFile struct` - License file info
- `type LicenseDiff struct` - License difference

### Functions
- `func NewClassifier() (Classifier, error)` - Create classifier
- `func FindLicenseFiles(fsys fs.FS) ([]LicenseFile, error)` - Find license files
- `func IsLicenseFile(filename string) (bool, float64)` - Check if license file
- `func CollectLicenseInfo(ctx context.Context, fsys fs.FS) ([]License, error)` - Collect licenses
- `func IsLicenseMatchConfident(dl License) bool` - Check confidence
- `func LicenseCheck(ctx context.Context, cfg *config.Configuration, fsys fs.FS) ([]License, []LicenseDiff, error)` - Check licenses

## pkg/linter

### Functions
- `func DefaultRequiredLinters() []string` - Get required linters
- `func DefaultWarnLinters() []string` - Get warning linters
- `func LintBuild(ctx context.Context, cfg *config.Configuration, packageName string, path string, require, warn []string) error`
- `func LintAPK(ctx context.Context, path string, require, warn []string) error`

### Variables
- `var PkgconfDirRegex = regexp.MustCompile("^usr/(lib|share)/pkgconfig/")`

## pkg/manifest

### Types
- `type GeneratedMelangeConfig struct` - Generated config

### Methods
- `func (m *GeneratedMelangeConfig) SetPackage(pkg config.Package)`
- `func (m *GeneratedMelangeConfig) SetEnvironment(env apkotypes.ImageConfiguration)`
- `func (m *GeneratedMelangeConfig) SetPipeline(pipeline []config.Pipeline)`
- `func (m *GeneratedMelangeConfig) SetSubpackages(sub []config.Subpackage)`
- `func (m *GeneratedMelangeConfig) SetGeneratedFromComment(comment string)`
- `func (m *GeneratedMelangeConfig) Write(ctx context.Context, dir string) error`

## pkg/renovate

### Types
- `type Context struct` - Renovate context
- `type Option func(ctx *Context) error` - Context option
- `type RenovationContext struct` - Renovation context
- `type Renovator func(ctx context.Context, rc *RenovationContext) error` - Renovator function

### Functions
- `func New(opts ...Option) (*Context, error)` - Create context
- `func WithConfig(configFile string) Option` - Config option
- `func NodeFromMapping(parentNode *yaml.Node, key string) (*yaml.Node, error)` - YAML helper

### Methods
- `func (c *Context) Renovate(ctx context.Context, renovators ...Renovator) error`
- `func (rc *RenovationContext) LoadConfig(ctx context.Context) error`
- `func (rc *RenovationContext) WriteConfig() error`

## pkg/renovate/bump

### Types
- `type BumpConfig struct` - Bump configuration
- `type Option func(cfg *BumpConfig) error` - Bump option

### Functions
- `func New(ctx context.Context, opts ...Option) renovate.Renovator` - Create bumper
- `func WithTargetVersion(targetVersion string) Option`
- `func WithExpectedCommit(expectedCommit string) Option`

## pkg/renovate/cache

### Types
- `type CacheConfig struct` - Cache configuration
- `type Option func(cfg *CacheConfig) error` - Cache option

### Functions
- `func New(opts ...Option) renovate.Renovator` - Create cache renovator
- `func WithCacheDir(cacheDir string) Option`

## pkg/renovate/copyright

### Types
- `type CopyrightConfig struct` - Copyright configuration
- `type Option func(cfg *CopyrightConfig) error` - Copyright option

### Functions
- `func New(ctx context.Context, opts ...Option) renovate.Renovator` - Create copyright renovator
- `func WithLicenses(licenses []license.License) Option`
- `func WithDiffs(diffs []license.LicenseDiff) Option`
- `func WithFormat(format string) Option`

## pkg/sbom

### Types
- `type Document struct` - SBOM document
- `type Package struct` - SBOM package
- `type Element interface` - SBOM element interface

### Functions
- `func NewDocument() *Document` - Create document

### Methods
- `func (d Document) ToSPDX(ctx context.Context, releaseData *apko_build.ReleaseData) spdx.Document`
- `func (d *Document) AddPackageAndSetDescribed(p *Package)`
- `func (d *Document) AddPackage(p *Package)`
- `func (d *Document) AddRelationship(a, b Element, typ string)`
- `func (p Package) ToSPDX(ctx context.Context) spdx.Package`
- `func (p Package) ID() string`

## pkg/sca

### Types
- `type SCAFS interface` - SCA filesystem interface
- `type SCAHandle interface` - SCA handle interface
- `type DependencyGenerator func(context.Context, SCAHandle, *config.Dependencies, []string) error`

### Functions
- `func Analyze(ctx context.Context, hdl SCAHandle, generated *config.Dependencies) error` - Analyze dependencies

## pkg/sign

### Types
- `type ApkSigner interface` - APK signer interface
- `type KeyApkSigner struct` - Key-based signer

### Functions
- `func APK(_ context.Context, apkPath string, keyPath string) error` - Sign APK
- `func SignIndex(ctx context.Context, signingKey string, indexFile string) error` - Sign index
- `func HashData(data []byte, digestType crypto.Hash) ([]byte, error)` - Hash data
- `func EmitSignature(signer ApkSigner, controlData []byte, sde time.Time) ([]byte, error)` - Emit signature

## pkg/source

### Functions
- Various source handling functions (need to check source.go for details)

## pkg/tarball

### Types
- `type Context struct` - Tarball context
- `type Option func(*Context) error` - Context option

### Functions
- `func NewContext(opts ...Option) (*Context, error)` - Create context
- `func WithSourceDateEpoch(t time.Time) Option`
- `func WithOverrideUIDGID(uid, gid int) Option`
- `func WithOverridePerms(files []tar.Header) Option`
- `func WithOverrideUname(uname string) Option`
- `func WithRemapUIDs(uids map[int]int) Option`
- `func WithRemapGIDs(gids map[int]int) Option`
- `func WithOverrideGname(gname string) Option`
- `func WithSkipClose(skipClose bool) Option`
- `func WithUseChecksums(useChecksums bool) Option`

### Methods
- `func (c *Context) WriteArchive(dst io.Writer, src fs.FS) error`
- `func (c *Context) WriteTargz(ctx context.Context, dst io.Writer, src fs.FS, userinfofs fs.FS) error`
- `func (c *Context) WriteTar(ctx context.Context, dst io.Writer, src fs.FS, userinfosrc fs.FS) error`

## pkg/util

### Functions
- `func MutateStringFromMap(with map[string]string, input string) (string, error)`
- `func MutateAndQuoteStringFromMap(with map[string]string, input string) (string, error)`

---

This list includes all exported identifiers found in the pkg/ directory. Items marked as candidates for internal packages should be evaluated based on:
1. Whether they're used externally by consumers of the melange library
2. Whether they're implementation details vs part of the public API
3. Whether they're stable enough to maintain as public API