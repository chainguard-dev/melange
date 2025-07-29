# Melange API Refactoring Plan

This document outlines the plan to refactor exported methods in the melange module to reduce the public API surface and clarify what's intended for external use versus internal implementation details.

## Phase 1: Unexport Methods (No Breaking Changes)

These methods are only used within their defining package and can be made unexported immediately without breaking any functionality:

### pkg/build
- [ ] `NewSBOMGroup` → `newSBOMGroup`
- [ ] `WithTestWorkspaceIgnore` → `withTestWorkspaceIgnore`
- [ ] `WithTestBinShOverlay` → `withTestBinShOverlay`
- [ ] `WithWorkspaceIgnore` → `withWorkspaceIgnore`
- [ ] `WithBinShOverlay` → `withBinShOverlay`
- [ ] SBOMGroup methods:
  - [ ] `SetCreatedTime` → `setCreatedTime`
  - [ ] `SetLicensingInfos` → `setLicensingInfos`
  - [ ] `AddBuildConfigurationPackage` → `addBuildConfigurationPackage`
  - [ ] `AddUpstreamSourcePackage` → `addUpstreamSourcePackage`

### pkg/license
- [ ] `NewClassifier` → `newClassifier`
- [ ] `FindLicenseFiles` → `findLicenseFiles`
- [ ] `CollectLicenseInfo` → `collectLicenseInfo`
- [ ] `Classifier` interface → `classifier`
- [ ] `LicenseFile` type → `licenseFile`

### pkg/config
- [ ] `WithFS` → `withFS`
- [ ] Monitor interface methods:
  - [ ] `GetStripPrefix` → make these private methods
  - [ ] `GetStripSuffix` → make these private methods
  - [ ] `GetFilterPrefix` → make these private methods
  - [ ] `GetFilterContains` → make these private methods
- [ ] Unused types:
  - [ ] `CPE` → `cpe`
  - [ ] `Capability` → `capability`
  - [ ] `PipelineAssertions` → `pipelineAssertions`
  - [ ] `VarTransforms` → `varTransforms`
  - [ ] `VersionHandler` → `versionHandler`
  - [ ] `GitMonitor` → `gitMonitor`

### pkg/manifest
- [ ] All `GeneratedMelangeConfig` methods:
  - [ ] `SetPackage` → `setPackage`
  - [ ] `SetEnvironment` → `setEnvironment`
  - [ ] `SetPipeline` → `setPipeline`
  - [ ] `SetSubpackages` → `setSubpackages`
  - [ ] `SetGeneratedFromComment` → `setGeneratedFromComment`

### pkg/renovate
- [ ] `NodeFromMapping` → `nodeFromMapping`
- [ ] Config types:
  - [ ] `CacheConfig` → `cacheConfig`
  - [ ] `CopyrightConfig` → `copyrightConfig`
  - [ ] `BumpConfig` → `bumpConfig`

## Phase 2: Move to Internal Packages

These are used by other packages within melange but not by external consumers. Moving these requires creating new internal packages and updating imports:

### High Priority Moves

#### 1. Create `internal/convert`
Move from `pkg/convert`:
- [ ] `Context` type and all methods
- [ ] All subpackages (apkbuild, github, relmon, wolfios)
- Update imports in:
  - [ ] `pkg/cli/convert.go`
  - [ ] `pkg/cli/apkbuild.go`

#### 2. Create `internal/tarball`
Move from `pkg/tarball`:
- [ ] `Context` type and all methods
- [ ] All `With*` option functions
- Update imports in:
  - [ ] `pkg/build/`
  - [ ] `pkg/container/`

#### 3. Create `internal/sbom`
Move from `pkg/sbom`:
- [ ] `Package`, `Document`, `Element` types
- [ ] `NewDocument()` function
- [ ] All methods on these types
- Update imports in:
  - [ ] `pkg/build/`
  - [ ] `pkg/config/`

#### 4. Create `internal/container`
Move from `pkg/container`:
- [ ] `Runner`, `Loader`, `Debugger` interfaces
- [ ] `BubblewrapRunner()`, `QemuRunner()` functions
- [ ] `Config`, `BindMount`, `Capabilities` types
- [ ] All runner implementations
- Update imports in:
  - [ ] `pkg/build/`
  - [ ] `pkg/cli/`

#### 5. Create `internal/sca`
Move from `pkg/sca`:
- [ ] `SCAFS`, `SCAHandle` interfaces
- [ ] `Analyze()` function
- [ ] `DependencyGenerator` type
- Update imports in:
  - [ ] `pkg/build/`
  - [ ] `pkg/cli/scan.go`

#### 6. Create `internal/license`
Move from `pkg/license`:
- [ ] `IsLicenseMatchConfident()` function
- [ ] `LicenseCheck()` function
- [ ] Keep public: `License`, `LicenseDiff` types (used in config)
- Update imports in:
  - [ ] `pkg/cli/license_check.go`
  - [ ] `pkg/renovate/copyright/`

#### 7. Create `internal/renovate`
Move from `pkg/renovate`:
- [ ] Entire package contents
- Update imports in:
  - [ ] `pkg/cli/bump.go`
  - [ ] `pkg/cli/update_cache.go`

#### 8. Create `internal/http`
Move from `pkg/http`:
- [ ] `RLHTTPClient` type
- [ ] `NewClient()` function
- Update imports in:
  - [ ] `pkg/convert/apkbuild/`
  - [ ] `pkg/renovate/`

### Lower Priority Moves

#### 9. Create `internal/sign`
Move from `pkg/sign`:
- [ ] `EmitSignature()` function
- [ ] `HashData()` function
- [ ] Keep public: `APK()`, `SignIndex()` functions
- Update imports in:
  - [ ] `pkg/build/`

#### 10. Create `internal/util`
Move from `pkg/util`:
- [ ] `MutateStringFromMap()` function
- [ ] `MutateAndQuoteStringFromMap()` function
- Update imports in various packages

#### 11. Create `internal/source`
Move from `pkg/source`:
- [ ] Entire package contents
- Update imports in:
  - [ ] `pkg/build/`

## Phase 3: Document Public API

After refactoring, the public API should be clearly documented:

### Public API Surface

#### pkg/cli
- `New()` - Create root command
- Command functions for CLI usage

#### pkg/config
- `Parse()`, `ParseConfiguration()` - Parse configuration files
- `Configuration`, `Package`, `Pipeline`, `Subpackage` - Core types
- Public methods on these types

#### pkg/build
- `New()`, `NewTest()` - Create build/test contexts
- `Build`, `Test` - Core types
- Option functions used by CLI

#### pkg/index
- `New()` - Create index
- `Index` type and methods
- Option functions

#### pkg/linter
- `LintBuild()`, `LintAPK()` - Linting functions
- `DefaultRequiredLinters()`, `DefaultWarnLinters()`

#### pkg/sign
- `APK()` - Sign APK files
- `SignIndex()` - Sign index files

## Implementation Order

1. **Phase 1 first** - Can be done immediately with no breaking changes
2. **Phase 2 high priority** - Focus on most used internal packages
3. **Phase 2 lower priority** - Complete internal refactoring
4. **Phase 3** - Document the cleaned-up public API

## Testing Strategy

- Run full test suite after each change
- Ensure no external imports are broken
- Update import paths in tests as needed
- Verify CLI commands still work correctly

## Benefits

1. **Clearer API boundaries** - External users know what's stable
2. **Easier maintenance** - Internal changes won't break external users
3. **Better encapsulation** - Implementation details are hidden
4. **Reduced surface area** - Less to maintain as public API