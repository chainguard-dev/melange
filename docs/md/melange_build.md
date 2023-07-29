---
title: "melange build"
slug: melange_build
url: /open-source/melange/reference/melange_build/
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
      --apk-cache-dir string        directory used for cached apk packages (default is system-defined cache directory)
      --arch strings                architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config
      --breakpoint-label string     stop build execution at the specified label
      --build-date string           date used for the timestamps of the files inside the image
      --build-option strings        build options to enable
      --cache-dir string            directory used for cached inputs (default "./melange-cache/")
      --cache-source string         directory or bucket used for preloading the cache
      --continue-label string       continue build execution at the specified label
      --create-build-log            creates a package.log file containing a list of packages that were built by the command
      --debug                       enables debug logging of build pipelines
      --debug-runner                when enabled, the builder pod will persist after the build suceeds or fails
      --dependency-log string       log dependencies to a specified file
      --empty-workspace             whether the build workspace should be empty
      --env-file string             file to use for preloaded environment variables
      --generate-index              whether to generate APKINDEX.tar.gz (default true)
      --guest-dir string            directory used for the build environment guest
  -h, --help                        help for build
  -k, --keyring-append strings      path to extra keys to include in the build environment keyring
      --log-policy strings          logging policy to use (default [builtin:stderr])
      --namespace string            namespace to use in package URLs in SBOM (eg wolfi, alpine) (default "unknown")
      --out-dir string              directory where packages will be output (default "./packages/")
      --overlay-binsh string        use specified file as /bin/sh overlay in build environment
      --pipeline-dir string         directory used to extend defined built-in pipelines
  -r, --repository-append strings   path to extra repositories to include in the build environment
      --runner string               which runner to use to enable running commands, default is based on your platform. Options are ["bubblewrap" "docker" "lima" "kubernetes"] (default "bubblewrap")
      --signing-key string          key to use for signing
      --source-dir string           directory used for included sources
      --strip-origin-name           whether origin names should be stripped (for bootstrap)
      --vars-file string            file to use for preloaded build configuration variables
      --workspace-dir string        directory used for the workspace at /home/build
```

### SEE ALSO

* [melange](/open-source/melange/reference/melange/)	 - 

