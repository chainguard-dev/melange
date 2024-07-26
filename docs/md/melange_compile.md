---
title: "melange compile"
slug: melange_compile
url: /docs/md/melange_compile.md
draft: false
images: []
type: "article"
toc: true
---
## melange compile

Compile a YAML configuration file

### Synopsis

Compile a YAML configuration file.

```
melange compile [flags]
```

### Examples

```
  melange compile [config.yaml]
```

### Options

```
      --apk-cache-dir string        directory used for cached apk packages (default is system-defined cache directory)
      --arch string                 architectures to compile for
      --build-date string           date used for the timestamps of the files inside the image
      --build-option strings        build options to enable
      --cache-dir string            directory used for cached inputs (default "./melange-cache/")
      --cache-source string         directory or bucket used for preloading the cache
      --cpu string                  default CPU resources to use for builds
      --create-build-log            creates a package.log file containing a list of packages that were built by the command
      --debug                       enables debug logging of build pipelines
      --debug-runner                when enabled, the builder pod will persist after the build succeeds or fails
      --dependency-log string       log dependencies to a specified file
      --empty-workspace             whether the build workspace should be empty
      --env-file string             file to use for preloaded environment variables
      --fail-on-lint-warning        turns linter warnings into failures
      --generate-index              whether to generate APKINDEX.tar.gz (default true)
      --guest-dir string            directory used for the build environment guest
  -h, --help                        help for compile
  -i, --interactive                 when enabled, attaches stdin with a tty to the pod on failure
  -k, --keyring-append strings      path to extra keys to include in the build environment keyring
      --log-policy strings          logging policy to use (default [builtin:stderr])
      --memory string               default memory resources to use for builds
      --disk string                 disk size to use for builds
      --namespace string            namespace to use in package URLs in SBOM (eg wolfi, alpine) (default "unknown")
      --out-dir string              directory where packages will be output (default "./packages/")
      --overlay-binsh string        use specified file as /bin/sh overlay in build environment
      --package-append strings      extra packages to install for each of the build environments
      --pipeline-dir string         directory used to extend defined built-in pipelines
  -r, --repository-append strings   path to extra repositories to include in the build environment
      --rm                          clean up intermediate artifacts (e.g. container images)
      --runner string               which runner to use to enable running commands, default is based on your platform. Options are ["bubblewrap" "docker" "qemu"]
      --signing-key string          key to use for signing
      --source-dir string           directory used for included sources
      --strip-origin-name           whether origin names should be stripped (for bootstrap)
      --timeout duration            default timeout for builds
      --vars-file string            file to use for preloaded build configuration variables
      --workspace-dir string        directory used for the workspace at /home/build
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "info")
```

### SEE ALSO

* [melange](/docs/md/melange.md)	 - 

