# Changes from 0.3.1 to 0.3.2

* Fix cosign flags in goreleaser which was preventing release
  artifacts from being uploaded to GitHub.

# Changes from 0.3.0 to 0.3.1

* Libraries which do not fit the normal UNIX SONAME pattern will now be
  considered as possible dependency providers.

* Darwin binaries are now built at release time.

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
