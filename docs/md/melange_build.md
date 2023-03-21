---
title: "melange build"
slug: melange_build
url: /chainguard/chainguard-enforce/melange-docs/melange_build/
draft: false
images: []
type: "article"
toc: true
---
## melange build

Build a package from a YAML configuration file

### Synopsis

Build a package from a YAML configuration file.

```
melange build [flags]
```

### Examples

```
  melange build [config.yaml]
```

### Options

```
      --arch strings                architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config
      --breakpoint-label string     stop build execution at the specified label
      --build-date string           date used for the timestamps of the files inside the image
      --build-option strings        build options to enable
      --cache-dir string            directory used for cached inputs (default "/var/cache/melange")
      --continue-label string       continue build execution at the specified label
      --create-build-log            creates a package.log file containing a list of packages that were built by the command
      --dependency-log string       log dependencies to a specified file
      --empty-workspace             whether the build workspace should be empty
      --env-file string             file to use for preloaded environment variables
      --generate-index              whether to generate APKINDEX.tar.gz (default true)
      --guest-dir string            directory used for the build environment guest
  -h, --help                        help for build
  -k, --keyring-append strings      path to extra keys to include in the build environment keyring
      --namespace string            namespace to use in package URLs in SBOM (eg wolfi, alpine) (default "unknown")
      --out-dir string              directory where packages will be output (default "./packages/")
      --overlay-binsh string        use specified file as /bin/sh overlay in build environment
      --pipeline-dir string         directory used to extend defined built-in pipelines
  -r, --repository-append strings   path to extra repositories to include in the build environment
      --signing-key string          key to use for signing
      --source-dir string           directory used for included sources
      --strip-origin-name           whether origin names should be stripped (for bootstrap)
      --vars-file string            file to use for preloaded build configuration variables
      --workspace-dir string        directory used for the workspace at /home/build
```

### SEE ALSO

* [melange](/chainguard/chainguard-enforce/melange-docs/melange/)	 - 

