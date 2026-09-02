# Plan: `noarch` architecture support in melange

## Goal

Allow a `melange.yaml` package to declare itself architecture-independent
(`target-architecture: [noarch]`, mirroring Alpine's APKBUILD `arch=noarch`),
so it is compiled **once** using the host's native CPU architecture, then its
apk output is copied and indexed into every requested per-arch output
directory as `arch=noarch`.

## Background / key finding

`apko_types.Architecture` (reused from `chainguard.dev/apko`) is a plain
string type whose `ParseArchitecture`/`ToAPK`/etc. already pass unknown
strings straight through unchanged. `Architecture("noarch")` round-trips
without any change to the vendored apko dependency. All work is internal to
melange.

The build/container/toolchain arch (`Build.Arch`, real `GOARCH`) must stay
separate from the *declared package arch* written into PKGINFO, SBOM, and
output paths. Only the latter becomes `"noarch"`.

## Steps

### 1. Config schema (`pkg/config/config.go`)

- Reuse `Package.TargetArchitecture []string` — no new field. Add `"noarch"`
  as a third sentinel value alongside the existing `"all"`.
- Validate exclusivity in `ParseConfiguration`: if `TargetArchitecture`
  contains `"noarch"`, it must be the *only* entry. Otherwise return a hard
  parse error (this is a config-authoring mistake, not a runtime warning like
  `"all"` gets).
- Add `func (p Package) IsNoArch() bool` helper (`len==1 && [0]=="noarch"`),
  used everywhere downstream instead of re-checking the slice.
- Update `docs/BUILD-FILE.md` (`target-architecture` section) and
  `docs/BUILD-PROCESS.md`.

### 2. Build-once within a single invocation (`pkg/cli/build.go: BuildCmd`, `pkg/build/build.go`)

- `Build.Arch` always resolves to `runtime.GOARCH` for a noarch package,
  never the requested `--arch`. Log a note if `--arch` was explicitly passed
  and differs from host (it's being ignored for the actual compile step).
- Effective arch set: if `--arch` is unspecified, default stays
  `apko_types.AllArchs` (no behavior change). If specified, use exactly that
  set.
- For a noarch package, `BuildCmd` builds **once** in-process (host arch)
  regardless of how many arches are in the effective set, then fans the
  result out to every arch in that set (see step 3).
- The "cache" is purely transient and scoped to this one command
  invocation — no cross-process cache, no locking/flock, no checksum
  bookkeeping. A later, separate `melange build` invocation always rebuilds
  from scratch.

### 3. Canonical build + copy-based replication (`pkg/build/build.go`, `pkg/build/package.go`)

- Build the single noarch apk (+ SBOM/attestation sidecars) into a staging
  path — a unique OS temp directory per `Build` instance
  (`os.MkdirTemp(os.TempDir(), "melange-noarch-*")`, lazily created and
  cached on first use so every `Emit` call for the same build reuses it),
  NOT a fixed name under `OutDir` (a fixed shared path would collide across
  concurrent processes/invocations sharing the same `--out-dir`) — with
  PKGINFO `arch = noarch` via a new `PackageArch()` helper on `Build`
  (`Build.Arch` itself stays untouched — only output/metadata call sites
  switch to this helper).
- The staging directory and its `defer os.RemoveAll(...)` cleanup are
  created/registered *before* the first `Emit` call (main package), so any
  emission failure still triggers cleanup — not only after replication
  succeeds.
- For each arch in the effective target set, **copy** (plain `io.Copy`, not
  hardlink — avoids `EXDEV`/shared-inode edge cases) the staged apk and
  sidecars into `${OutDir}/<arch>/<name>-<version>-r<epoch>.apk`. Content is
  identical (`arch=noarch` inside PKGINFO); only location differs.
- After copying into every arch dir in the effective set, remove the staging
  dir/file (`defer`-cleaned, including on error paths) — no orphaned cache
  left behind.

### 4. Index generation

- Drive the existing inline `GenerateIndex` step (`pkg/build/build.go`,
  around the `packageDir := filepath.Join(b.OutDir, b.Arch.ToAPK())` block)
  off the effective arch set from step 3: generate/update
  `APKINDEX.tar.gz` in every `${OutDir}/<arch>/` populated this run.
- `pkg/index/index.go` (`WithExpectedArch`/`ExpectedArch`): accept
  `pkg.Arch == "noarch"` unconditionally, regardless of `ExpectedArch` —
  needed both for the inline step and for standalone
  `melange index --arch ...` runs over a directory mixing noarch and native
  packages.

### 5. Linting

- Add a new linter (or extend `pkg/linter/linters/binaryarch.go`): when
  `Package.IsNoArch()` is true, flag **any** ELF binary found in the package
  output (native code has no business in a noarch package).
- Register default-on in `pkg/linter/linter.go`, overridable via
  `Package.Checks.Disabled`.

### 6. SBOM (`pkg/build/build.go` SBOM `GeneratorContext.Arch`) — DONE, no dedicated change needed

- Use `PackageArch()` (→ `"noarch"`) so SBOM/PURL output matches PKGINFO.
  Generated once against the staged canonical build, then copied alongside
  each replicated apk like the package file itself.
- Turned out to already be fully satisfied by step 3's `PackageArch()`
  wiring (`GeneratorContext.Arch` already used it; SBOM is embedded in the
  apk's data section, not a sidecar, so it's covered by step 3's
  copy-replication with no extra work). One adjacent, previously-missed
  spot was fixed in passing: `pkg/build/compiler_config.go`'s FDO
  package-metadata linker template used `.Arch.ToAPK` instead of
  `.PackageArch` for its embedded `"architecture"` field.

### 7. `rebuild.go` — DONE, no code change needed

- `pkginfo.Arch == "noarch"` ⇒ rebuild using `runtime.GOARCH`, not a literal
  `"noarch"` guest platform (current code feeds `pkginfo.Arch` straight into
  `apko_types.ParseArchitecture` and uses it as the guest arch).
- Verified already fully handled end-to-end by step 2's shared
  `build.New` noarch-override: `RebuildCmd` passes the apk's embedded
  original `.melange.yaml` config via `WithConfiguration`, which is set
  before `New`'s noarch-override block runs; that block unconditionally
  resets `b.Arch` to the host arch whenever `Configuration.Package.IsNoArch()`
  is true, regardless of the literal `"noarch"` string fed in via
  `ParseArchitecture(pkginfo.Arch)`. `ReplicateArchs` stays `["noarch"]`,
  so the rebuilt apk lands at `${OutDir}/noarch/...`, which is exactly
  where `RebuildCmd`'s diff step looks for it.

### 8. Tests

- Config: `target-architecture: [noarch]` valid; `[noarch, x86_64]` rejected
  at parse time.
- `BuildCmd`: noarch + multiple `--arch` values → exactly one guest build
  invoked, N copies produced, staging dir empty afterward.
- No `--arch` flag ⇒ defaults to `AllArchs`: one build, copies into every
  supported arch dir.
- Index: noarch apk accepted into `x86_64/` and `aarch64/` indexes despite
  the PKGINFO `arch` string not matching `ExpectedArch`.
- Linter: ELF binary present in a noarch package fails lint; absent, passes.

## Explicit decisions already made (do not re-litigate without reason)

1. Reuse `target-architecture: [noarch]`; no new YAML key.
2. `noarch` must be the sole entry in `target-architecture` — hard error
   otherwise.
3. Melange (not external tooling) owns building once + replicating +
   indexing per requested arch, since melange also owns indexing here.
4. Replication uses plain file copy, not hardlinks.
5. The canonical staged build is deleted once all requested arches for the
   current invocation have been populated. No cross-invocation caching.
6. No `--arch` flag ⇒ default effective arch set is `apko_types.AllArchs`
   (unchanged existing default).
