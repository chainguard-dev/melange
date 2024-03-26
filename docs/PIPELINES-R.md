# Built-in R pipeline

Melange includes a built-in pipeline to compile R packages.

To get started quickly, checkout the `R/build` pipeline:
[cran-build.yaml](https://github.com/chainguard-dev/melange/blob/main/examples/R-build.yaml)

## Building R packages with `R/build`

The `R/build` pipeline is a declarative interface that leverages the R package
manager. This pipeline builds an R package from source and installs it to the
standard R library directory.

Here's a sample melange configuration file cloning and running the same
sample project as above:

```yaml
package:
  name: cran-proxy
  version: 0.4_27
  epoch: 0
  description: Distance and similarity measures
  copyright:
    - license: GPL-2.0-or-later

environment:
  contents:
    packages:
      - R
      - R-dev
      - busybox

var-transforms:
  - from: ${{package.version}}
    match: '_'
    replace: '-'
    to: mangled-package-version

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/cran/proxy
      tag: ${{vars.mangled-package-version}}
      expected-commit: 311a8569a534460ef04473ffa442dc7b72ba9a41

  - uses: R/build
    with:
      package: proxy
      version: ${{vars.mangled-package-version}}

  - uses: strip

update:
  enabled: true
  version-transform:
    - match: '_'
      replace: '-'
  github:
    identifier: cran/proxy
    use-tag: true
```

(:bulb: Experiment with this code, 
[download it from the examples directory](https://github.com/chainguard-dev/melange/blob/main/examples/R-build.yaml))

## Build Parameters

The `R/build` pipeline supports passing a few parameters the R package manager by
setting them in the melange configuration file. As of this writing, you can define
the following values:

```yaml
  package:
    description: |
      The R package to install
    required: true

  path:
    description: |
      Path to R package source or source tarball
    default: "."

  version:
    description: |
      The R package version
    required: true
```

For the most up to date supported features check the
[build](https://github.com/chainguard-dev/melange/blob/main/pkg/build/pipelines/R/build.yaml)
pipeline.

Feel free to request more features in the built-in pipelines by
[filing a new issue](https://github.com/chainguard-dev/melange/issues/new) in 
the melange repository!
