# Built-in cargo pipeline

Melange includes a built-in pipeline to compile rust packages.

To get started quickly, checkout the `cargo/build` pipeline:
[cargo-build.yaml](https://github.com/chainguard-dev/melange/blob/main/examples/cargo-build.yaml)

## Building rust packages with `cargo/build`

The `cargo/build` pipeline is a declarative interface to the `cargo auditable build`
command. This pipeline builds a rust package, embedding a JSON dependency tree in its
own linker section of the produced binary.

Here's a sample melange configuration file cloning and running the same
sample project as above:

```yaml
package:
  name: eza
  version: 0.18.6
  epoch: 1
  description: "A modern, maintained replacement for ls"
  copyright:
    - license: MIT

environment:
  contents:
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    repositories:
      - https://packages.wolfi.dev/os

environment:
  contents:
    packages:
      - build-base
      - busybox
      - ca-certificates-bundle
      - libgit2-dev
      - zlib-dev

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/eza-community/eza
      tag: v${{package.version}}
      expected-commit: 1918eb866840486f3ad00a2d89d45f051072b2a9

  - uses: cargo/build
    with:
      output: ${{package.name}}
```

(:bulb: Experiment with this code, 
[download it from the examples directory](https://github.com/chainguard-dev/melange/blob/main/examples/cargo-build.yaml))

## Build Parameters

The `cargo/build` pipeline supports passing a few parameters to cargo by setting
them in the melange configuration file. As of this writing, you can define the
following values:

```yaml
  output:
    description: |
      Filename to use when writing the binary. The final install location inside
      the apk will be in prefix / install-dir / output

  opts:
    description: |
      Options to pass to cargo build. Defaults to release

  modroot:
    description: |
      Top directory of the rust package, this is where the target package lives.
      Before building, the cargo pipeline wil cd into this directory. Defaults
      to current working directory

  prefix:
    description: |
      Installation prefix. Defaults to usr
```

For the most up to date supported features check the
[build](https://github.com/chainguard-dev/melange/blob/main/pkg/build/pipelines/go/build.yaml)
pipeline.

Feel free to request more features in the built-in pipelines by
[filing a new issue](https://github.com/chainguard-dev/melange/issues/new) in 
the melange repository!
