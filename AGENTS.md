# AGENTS.md

melange builds APK packages from declarative YAML. Its most important job is
building Wolfi, and other package repositories that use it, without errors. A
change here can break a package build long after it merges, the next time that
package is touched. melange is also a Go library: other projects import
`chainguard.dev/melange/pkg/...`.

## Layout

- `main.go`, `pkg/cli/`: the `melange` commands (`build`, `test`, `compile`,
  `rebuild`, `lint`, `scan`, `bump`, `keygen`, `sign`, `index` and others).
- `pkg/config/`: the YAML schema, parsing and variable substitution.
  `schema.json` and `schema.cue` are generated from the Go types by
  `internal/gen-schema`.
- `pkg/build/`: compiling a configuration, running its pipelines, splitting
  subpackages, writing APKs, SBOMs, SLSA provenance and the `-source`
  companion package.
- `pkg/build/pipelines/`: the built-in pipelines that `uses:` resolves
  (`fetch`, `git-checkout`, `split/*`, `go/*`, `autoconf/*` and so on). Each
  directory's `README.md` is generated.
- `pkg/container/`: the bubblewrap, docker and qemu runners.
- `pkg/sca/`: dependency and provides detection (shared libraries, Go
  toolchains, Python, pkg-config and more).
- `pkg/linter/`: post-build package linters.
- `pkg/renovate/`: `melange bump` and the config rewriters.
- `pkg/source/`, `pkg/license/`, `pkg/sbom/`, `pkg/sign/`, `pkg/index/`,
  `pkg/tarball/`: their namesakes.
- `e2e-tests/`: melange files run by `e2e-tests/run-tests`, under the qemu
  runner. The file name picks the mode (`*-build.yaml`, `*-test.yaml`,
  `*-build-test.yaml`, `*-nopkg-*`); see `e2e-tests/README.md`.
- `examples/`: example configurations, also built and rebuilt in CI.
- `docs/`: user documentation. `docs/md/` is generated.
- `.chainguard/ci/`: Chainguard Checks CI. `.chainguard/reviewers.yaml`: the
  code reviewer. `.github/workflows/` keeps the qemu runner jobs and the
  release.

## Commands

```sh
make melange              # build ./melange
make lint                 # gofmt, goimports and golangci-lint
make unit                 # go test ./... -race
make integration          # go test -race -tags=integration ./... (builds real packages)
make test-e2e-unit        # go generate, then go test -tags e2e; set E2E_PKG to scope it
make test-e2e-pipelines   # e2e-tests/ under qemu; set E2E_TESTS to pick files
go generate ./internal/gen-schema   # regenerate schema.json and schema.cue
make docs-repo            # regenerate docs/md
make docs-pipeline        # regenerate pkg/build/pipelines/**/README.md
```

The lint check fails if `make docs-repo`, `make docs-pipeline` or
`go mod tidy` leaves the tree dirty, so a change to a CLI flag, a pipeline or
`go.mod` MUST run them.

## Requirements language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY" and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
(RFC 2119 and RFC 8174) when, and only when, they appear in all capitals, as
shown here.

## Compatibility

- An existing melange file MUST build the same package after the change.
- A new configuration field or pipeline input MUST be OPTIONAL, with a default
  that keeps today's behaviour. A change MUST NOT rename or remove one;
  packages in Wolfi and elsewhere use them.
- A new linter MUST be opt-in or a warning, and MUST be clean across Wolfi
  before it becomes an error.
- An SCA change MUST be checked against representative APKs, for both the
  dependency it adds and the ones it MUST NOT add.
- Exported identifiers under `pkg/` are API. Callers outside `pkg/cli` use
  types such as `build.Build`, `config.Configuration` and the CLI option
  structs. A change MUST NOT make one work only when called from the command.

## Conventions

### Configuration

- A new field in `pkg/config` MUST survive parsing, which runs every
  configuration through the `replace*` substitution functions in
  `config.go`. Two shapes exist:
  - `replaceNeeds`, `replacePipeline`, `replaceTest` and `replaceUpdate` copy
    their input and override only the substituted fields, so a new field is
    carried through. A change to them MUST keep that shape.
  - The rest, including `replacePackage`, `replaceSubpackage`,
    `replaceDependencies`, `replaceScriptlets`, `replaceCopyright`,
    `replaceEntrypoint` and the `replaceImage*` functions, build a new struct
    from an explicit field list. A new field on one of those types MUST be added to that list, or
    it is dropped silently.
- A field MUST also survive compilation. `melange compile` output, and the
  `.melange.yaml` embedded in every APK, are run again by `melange test` and
  `melange rebuild`, so what `Compile` gathers MUST land in the compiled
  configuration.
- `schema.json` and `schema.cue` MUST be regenerated with the Go type change.
- Build and test containers are separate. Something a test pipeline needs
  (packages, capabilities, environment) MUST be set on that test, not on the
  build, and a subpackage's test MUST NOT widen its siblings'.

### Pipelines

- `runs:` blocks run under `/bin/sh` from busybox, wrapped by
  `pkg/build/pipeline.go` as `set -e -o pipefail`, the fragment, then
  `exit 0`. A failing command inside an `&&` list or an `if` is not fatal,
  so a check MUST `exit 1` itself.
- `${{inputs.x}}` and `${{targets.*}}` are spliced into the script text
  before the shell parses it. A script MUST assign an input to a quoted
  variable before use; a value can hold spaces, newlines, globs or quotes.
- A path input MUST be validated: reject absolute paths, `..`, globs and
  `.`. A script MUST NOT follow a symlink out of the tree.
- busybox `cp` writes through hard links and existing inodes, unlike GNU
  `cp`. A script SHOULD move files with `mv` rather than `cp` and `rm`.
- Every command a pipeline runs MUST be in its `needs.packages`.
- Every input MUST have a `description`, and the generated `README.md` MUST
  be updated.
- Script behaviour MUST be tested in `pkg/build/*_pipeline_test.go`, which
  run the real script under busybox `sh`, and SHOULD be tested in
  `e2e-tests/` when it needs a real build. `MELANGE_REQUIRE_SCRIPT_TOOLS=1`
  turns a missing tool into a failure instead of a skip.

### Runners

bubblewrap, docker and qemu differ in user, `HOME`, umask, environment
handling and how files reach the guest. A fix for one runner MUST say what the
other two do. The Checks tests run bubblewrap and docker; only the GitHub
workflows run qemu, which needs KVM.

### Sources and provenance

- Recorded URLs (in SBOMs, provenance and the `-source` companion) MUST NOT
  carry userinfo, a query or a fragment.
- Code that reads or writes a tree the build controls MUST use `Lstat`, MUST
  refuse symlinks it did not create, and MUST keep paths under their root.
- Output MUST be reproducible: honour `SOURCE_DATE_EPOCH`, sort what is
  iterated from maps or directories, and keep `melange rebuild` producing the
  same bytes.

### Go and commits

- golangci-lint runs with `.golangci.yml`. Code MUST log with the `clog`
  logger from the context and MUST NOT use `fmt.Print*`. Lint does not
  catch this today. Imports group `chainguard.dev/melange` last.
- Errors SHOULD be wrapped with `%w` and say what was being done.
- Commits MUST follow Conventional Commits, and SHOULD be scoped by area:
  `fix(qemu): ...`, `feat(build): ...`, `fix(pipelines): ...`,
  `feat(config): ...`, `build(deps): ...`, `ci: ...`.
- A bug fix MUST come with a test that fails without the fix.
- The pull request template asks whether the change builds Wolfi, how SCA
  output changed, and whether a new linter is clean. A pull request SHOULD
  answer the parts that apply.

## CI and releases

Chainguard Checks runs `.chainguard/ci/go.yaml` (lint, build, integration and
e2e-tagged tests), `e2e.yaml` (the docker runner, `melange rebuild` of the
examples, and real wolfi-dev/os packages) and `workflows.yaml` (actionlint and
zizmor). Checks run with allowlisted egress and only the packages the file
lists; a test that needs a new host or package MUST add it there.
On GitHub, `wolfi-presubmit.yaml` builds the wolfi-dev/os packages under qemu
and `melange-test-pipelines.yaml` runs `e2e-tests/` under qemu, one job per
file.

`release.yaml` tags and releases `main` every Monday when it has changed, or
when run by hand.
