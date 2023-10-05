# Major changes from 0.4.0 to 0.5.0

* Rename Contexts to Builds by @jonjohnsonjr in https://github.com/chainguard-dev/melange/pull/525

* Add missing context propagation by @jonjohnsonjr in https://github.com/chainguard-dev/melange/pull/527

* Bug fix: silent env var replacement by @luhring in https://github.com/chainguard-dev/melange/pull/533

* Add otel spans by @jonjohnsonjr in https://github.com/chainguard-dev/melange/pull/529

* docs: explain how build cache works practically by @luhring in https://github.com/chainguard-dev/melange/pull/537

* build: package: forcibly treat libc as a shared library by @kaniini in https://github.com/chainguard-dev/melange/pull/538

* Change git-checkout depth default to 1 by @luhring in https://github.com/chainguard-dev/melange/pull/539

* Fix/python version issue by @mesaglio in https://github.com/chainguard-dev/melange/pull/532

* pull in apko with fix for blank SOURCE_DATE_EPOCH by @deitch in https://github.com/chainguard-dev/melange/pull/542

* Remove use of deprecated WaitImmediate by @jonjohnsonjr in https://github.com/chainguard-dev/melange/pull/528

* lima startup issues fixed by @deitch in https://github.com/chainguard-dev/melange/pull/543

* add dir option to ruby pipelines as not all gemspecs live in the root… by @rawlingsj in https://github.com/chainguard-dev/melange/pull/544

* K8s runner template bugs by @joshrwolf in https://github.com/chainguard-dev/melange/pull/550

* K8s runner retry exec by @joshrwolf in https://github.com/chainguard-dev/melange/pull/549

* Refactor some pipelines to more safely use pipeline expansions by @kaniini in https://github.com/chainguard-dev/melange/pull/554

* use go-apk.FullFS for retrieving builder workspaces by @joshrwolf in https://github.com/chainguard-dev/melange/pull/548

* Correct the variable name in the patch pipeline by @mattmoor in https://github.com/chainguard-dev/melange/pull/555

* Avoid using pargzip for compression by @jonjohnsonjr in https://github.com/chainguard-dev/melange/pull/558

* skip the cache mount for kubernetes runner builds by @joshrwolf in https://github.com/chainguard-dev/melange/pull/566

* Make sure we log errors. by @mattmoor in https://github.com/chainguard-dev/melange/pull/570

* Log errors bundling, enable GGCR Warn/Progress logs by @mattmoor in https://github.com/chainguard-dev/melange/pull/574

* add k8s runner config loading from envvars by @joshrwolf in https://github.com/chainguard-dev/melange/pull/571

* Remove `wget -q` from `fetch` by @mattmoor in https://github.com/chainguard-dev/melange/pull/575

* Tweak the strip pipeline so that it never fails for deleted files by @mattmoor in https://github.com/chainguard-dev/melange/pull/573

* convert/python: check if release is found by @Dentrax in https://github.com/chainguard-dev/melange/pull/572

* Fix subpackage SBOM generation by @jonjohnsonjr in https://github.com/chainguard-dev/melange/pull/569

* renovate: update to use new config infrastructure by @Elizafox in https://github.com/chainguard-dev/melange/pull/585

* pipelines: meson/configure: explicitly invoke meson setup action by @kaniini in https://github.com/chainguard-dev/melange/pull/582

* Updates on ci and release by @cpanato in https://github.com/chainguard-dev/melange/pull/583

* Make var transforms work in bump by @Elizafox in https://github.com/chainguard-dev/melange/pull/586

* container: bubblewrap: do not defer closing files by @kaniini in https://github.com/chainguard-dev/melange/pull/596

* build: package: add pkgconf-based SCA to catalog SDKs which use it by @kaniini in https://github.com/chainguard-dev/melange/pull/590

* Version transform block in melange by @Elizafox in https://github.com/chainguard-dev/melange/pull/588

* Add docs about custom pipelines, defining and using. by @vaikas in https://github.com/chainguard-dev/melange/pull/604

* Support for setting context in .melange.k8s.yaml by @tcnghia in https://github.com/chainguard-dev/melange/pull/605

* allow override go version for uses: go/build and go/install by @rawlingsj in https://github.com/chainguard-dev/melange/pull/606

* add melange sign command, slightly refactor and make public the signing methods by @joshrwolf in https://github.com/chainguard-dev/melange/pull/607

* support substitutions in provides lists by @imjasonh in https://github.com/chainguard-dev/melange/pull/610

* Add ${{targets.contextdir}} by @kaniini in https://github.com/chainguard-dev/melange/pull/622

* add --force option to recreate apk indexes with given signatures by @joshrwolf in https://github.com/chainguard-dev/melange/pull/626

* cli: index: add --signing-key, --source and --merge options by @kaniini in https://github.com/chainguard-dev/melange/pull/629

* feat: support --recurse-submodules in git clone by @stormqueen1990 in https://github.com/chainguard-dev/melange/pull/639

* readlinkfs: ignore some security-module specific xattrs by @kaniini in https://github.com/chainguard-dev/melange/pull/640

* Add --wolfi-defaults flag, clean up flag handling. by @vaikas in https://github.com/chainguard-dev/melange/pull/641

* Add a maven/configure-mirror pipeline to redirect to GCP. by @dlorenc in https://github.com/chainguard-dev/melange/pull/644

* add builtin pipelines for python by @imjasonh in https://github.com/chainguard-dev/melange/pull/642

* package: dereference symlinks for aliased pkg-config modules by @kaniini in https://github.com/chainguard-dev/melange/pull/653

* feat: add output logs for the apkbuild converter by @stormqueen1990 in https://github.com/chainguard-dev/melange/pull/660

* Change default python-version from 3.11 to 3. by @vaikas in https://github.com/chainguard-dev/melange/pull/649

* feat: add new Perl pipelines for Makefile generation and cleanup by @stormqueen1990 in https://github.com/chainguard-dev/melange/pull/657

* add ${{package.full-version}} = ${{package.version}}-r${{package.epoch}} by @vaikas in https://github.com/chainguard-dev/melange/pull/662

* config: copy all subpackage variables when doing a range expansion by @kaniini in https://github.com/chainguard-dev/melange/pull/661

* docs: add documentation for built-in pipelines by @stormqueen1990 in https://github.com/chainguard-dev/melange/pull/665

* construct the package.full-version in higher context than just pipeline. by @vaikas in https://github.com/chainguard-dev/melange/pull/667

* package: constrain library SCA to library search paths only by @kaniini in https://github.com/chainguard-dev/melange/pull/669

* Add environment var overriding to the pipeline. by @Elizafox in https://github.com/chainguard-dev/melange/pull/676

* package: only constrain library search paths for provides entries by @kaniini in https://github.com/chainguard-dev/melange/pull/678

* Add pecl pipelines for phpize & install. by @vaikas in https://github.com/chainguard-dev/melange/pull/679

* Add regression tests for workdir propagation, fix long-standing bug with propagation across referenced pipelines by @kaniini in https://github.com/chainguard-dev/melange/pull/681

* git-checkout: Allow tags to matched annotated tag SHAs, don't allow by @wlynch in https://github.com/chainguard-dev/melange/pull/686

* Binary package linting by @Elizafox in https://github.com/chainguard-dev/melange/pull/680

* add goreleaser pipeline by @developer-guy in https://github.com/chainguard-dev/melange/pull/671

* Disable linters on -compat packages by @Elizafox in https://github.com/chainguard-dev/melange/pull/691

* log and continue when .pc file can't be loaded by @imjasonh in https://github.com/chainguard-dev/melange/pull/694

* Add dev, opt, and srv linters by @Elizafox in https://github.com/chainguard-dev/melange/pull/697

* Add worldwrite linter by @Elizafox in https://github.com/chainguard-dev/melange/pull/698

* build: do not run linters on skipped subpackages by @kaniini in https://github.com/chainguard-dev/melange/pull/701

* Add post-file walk linting and empty package linting by @Elizafox in https://github.com/chainguard-dev/melange/pull/700

* Refactor the package linter into a submodule by @Elizafox in https://github.com/chainguard-dev/melange/pull/706

* build: refactor package linter invocation by @kaniini in https://github.com/chainguard-dev/melange/pull/708

* pipelines: strip: use -g by default when stripping by @kaniini in https://github.com/chainguard-dev/melange/pull/722

* update alpine-go to latest git to fix indexing by @kaniini in https://github.com/chainguard-dev/melange/pull/723

* Add stripped file linter by @Elizafox in https://github.com/chainguard-dev/melange/pull/724

* Enable linters to warn (via callback) instead of just failing. by @mattmoor in https://github.com/chainguard-dev/melange/pull/739

# Major changes from 0.3.0 to 0.4.0

* The embedded apko component has been updated to 0.9.0.

* Add support for running builds on a Kubernetes cluster.

* Add support for caching APK dependencies.

* Use `-trimpath` in Go pipelines.

* Add a `split/debug` pipeline.

* Scan subpackage pipelines for additional dependencies when calculating
  the final build dependency list.

* Optionally delete fetched artifacts after unpacking them.  This will
  still not be done by default for backwards compatibility.

* Allow underscores and capitalization in variables, such as `${{vars.FOO-BAR}}`.

* Handle `SOURCE_DATE_EPOCH=` without a valid integer, treating it as equivalent
  to `SOURCE_DATE_EPOCH=0`.

* Add support for JSON representation of an APK index.

* Add support for extended attributes in generated APK packages.

* Set the `builddate` property in generated `.PKGINFO` files.

* Add support for quilt-style patch series files to the `patch` pipeline.

* Add an optional `deps` property to the `go/build` pipeline.

* Skip ELF soname analysis SCA phase for binaries which have an ELF interpreter
  set.

* Add support for configuring the logger behavior using the `--log-policy`
  option.

# Major changes from 0.2.0 to 0.3.0

* The embedded apko component has been updated to 0.7.3.

* Add support for running on non-Linux hosts which provide a Docker
  daemon, such as Macs running Docker Desktop.

* Add generic support for parsing a Melange configuration without needing
  an explicit build context.

* Added support for tracking advisories (e.g. with OpenVEX) in Melange
  configuration files.

* Several new pipelines relating to the Go and Ruby ecosystems.

* The `provider_priority` setting can now be configured for packages and
  subpackages.

* Add support for user-defined build variables and user-defined variable
  transforms.

* Add the `working-directory` modifier for pipeline elements.

* Track ELF interpreters as explicit dependencies.

* Add if-conditionals for subpackages to allow them to be skipped when
  appropriate.

* Self-provided dependencies are now filtered out of the dependency set
  for packages.

* An experimental conversion tool (for APKBUILDs, Gemfiles and PyPI
  packages) is now provided.

* Dependencies on shared libraries are now automatically calculated for
  `-dev` packages.  For example, if a `-dev` package has the symlink:

      /usr/lib/libfoo.so

  A dependency will then be generated for `so:libfoo.so.X` by checking
  the other packages for the symlink target and reading the SONAME.

* The parser used for if-conditionals is now also used for variable
  substitutions in `runs` blocks and related.  This provides consistency
  between how variables are handled in conditionals and at substitution
  time.

* The Bubblewrap runner is now invoked with the under-documented
  `--new-session` flag to protect against CVE-2017-5226.  We do not
  believe Melange itself to be vulnerable to CVE-2017-5226 however,
  this is just done as a precaution.

* The `--debug` option has been added to `melange build`, which
  automatically enables tracing for shell fragments in the build
  pipeline.

* The `melange query` and `melange package-version` commands have been
  added to help extract useful information from package definitions.

# Major changes from 0.1.0 to 0.2.0

* Added experimental support for running containers using Docker,
  rather than Bubblewrap.

* Added initial support for generating SBOMs for each package.
  These SBOMs will be used with other composition tools to generate
  so-called multi-layer SBOMs.

* Added support for breakpoint labels in pipelines.  These allow
  a build to be suspended or resumed from a specific point in the
  pipeline.  Care must be used to ensure the build environment
  locations are supplied when resuming a build, or a new build
  environment will be created.

* Added support for source cache directories.  This includes fetching
  sources from Google Cloud Storage buckets instead of their URIs.
  The melange `update-cache` command can be used to manage source cache
  directories, including remote GCS buckets.

* Added support for conditionals in build pipelines.  These allow
  specific pipeline elements to be skipped if a conditional is false:

```yaml
pipeline:
  - if: ${{foo}} == ${{bar}}
    runs: |
      echo "foo equals bar"
  - if: ${{foo}} != ${{bar}}
    runs: |
      echo "foo does not equal bar"
```

* Added support for sub-pipeline assertion guards.  These allow a user to
  specify that at least N steps in the sub-pipeline ran successfully in
  order for the sub-pipeline itself to pass.  In this example, the
  sub-pipeline would pass for x86_64 and aarch64, but fail for s390x,
  as there has not been a branch defined in the pipeline that would run
  on s390x:

```yaml
pipeline:
  - assertions:
      required-steps: 1
    pipeline:
      - if: ${{build.arch}} == 'x86_64'
        uses: fetch
        with:
          uri: https://example.com/binaries-x86_64.tar.gz
          expected-sha256: 8f754fdd5af783fe9020978c64e414cb45f3ad0a6f44d045219bbf2210ca3cb9
      - if: ${{build.arch}} == 'aarch64'
        uses: fetch
        with:
          uri: https://example.com/binaries-arm64.tar.gz
          expected-sha256: f406136010e6a1cdce3fb6573506f00d23858af49dd20a46723c3fa5257b7796
```

* Builtin pipeline data is now embedded into the Melange binary itself.

* Added support for meta-programming with `data` and `range` specifiers.
  At the moment, this only applies to subpackages, but could be expanded to
  pipeline elements in the future:

```yaml
data:
  - name: lagomorphs
    items:
      hare: 'lepus saxatilis'
      rabbit: 'sylvìlagus floridanus'
      pika: 'ochotona princeps'

subpackages:
  - range: lagomorphs
    name: "lagomorph-${{range.key}}"
    description: "data about the lagomorph ${{range.value}}"
    pipeline:
      [...]
```

* Added experimental support for renovating Melange YAML manifests.  This
  includes the `melange bump` command which can be used to update the version
  of a package in a manifest.

# Changes for Melange 0.1.0

* Initial release.
