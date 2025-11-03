---
title: "melange build"
slug: melange_build
url: /docs/md/melange_build.md
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
      --apk-cache-dir string                                    directory used for cached apk packages (default is system-defined cache directory)
      --arch strings                                            architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config
      --build-date string                                       date used for the timestamps of the files inside the image
      --build-option strings                                    build options to enable
      --cache-dir string                                        directory used for cached inputs (default "./melange-cache/")
      --cache-source string                                     directory or bucket used for preloading the cache
      --cleanup                                                 when enabled, the temp dir used for the guest will be cleaned up after completion (default true)
      --cpu string                                              default CPU resources to use for builds
      --cpumodel string                                         default memory resources to use for builds
      --create-build-log                                        creates a package.log file containing a list of packages that were built by the command
      --debug                                                   enables debug logging of build pipelines
      --debug-runner                                            when enabled, the builder pod will persist after the build succeeds or fails
      --dependency-log string                                   log dependencies to a specified file
      --disk string                                             disk size to use for builds
      --empty-workspace                                         whether the build workspace should be empty
      --env-file string                                         file to use for preloaded environment variables
      --generate-index                                          whether to generate APKINDEX.tar.gz (default true)
      --generate-provenance                                     generate SLSA provenance for builds (included in a separate .attest.tar.gz file next to the APK)
      --git-commit string                                       commit hash of the git repository containing the build config file (defaults to detecting HEAD)
      --git-repo-url string                                     URL of the git repository containing the build config file (defaults to detecting from configured git remotes)
  -h, --help                                                    help for build
      --ignore-signatures                                       ignore repository signature verification
  -i, --interactive                                             when enabled, attaches stdin with a tty to the pod on failure
  -k, --keyring-append strings                                  path to extra keys to include in the build environment keyring
      --license string                                          license to use for the build config file itself (default "NOASSERTION")
      --lint-require strings                                    linters that must pass (default [dev,infodir,setuidgid,tempdir,usrmerge,varempty,worldwrite])
      --lint-warn strings                                       linters that will generate warnings (default [binaryarch,cudaruntimelib,dll,duplicate,dylib,lddcheck,maninfo,nonlinux,object,opt,pkgconf,python/docs,python/multiple,python/test,sbom,srv,staticarchive,strip,unsupportedarch,usrlocal])
      --memory string                                           default memory resources to use for builds
      --namespace string                                        namespace to use in package URLs in SBOM (eg wolfi, alpine) (default "unknown")
      --out-dir string                                          directory where packages will be output (default "./packages/")
      --override-host-triplet-libc-substitution-flavor string   override the flavor of libc for ${{host.triplet.*}} substitutions (e.g. gnu,musl) -- default is gnu (default "gnu")
      --package-append strings                                  extra packages to install for each of the build environments
      --persist-lint-results                                    persist lint results to JSON files in packages/{arch}/ directory
      --pipeline-dir string                                     directory used to extend defined built-in pipelines
  -r, --repository-append strings                               path to extra repositories to include in the build environment
      --rm                                                      clean up intermediate artifacts (e.g. container images, temp dirs) (default true)
      --runner string                                           which runner to use to enable running commands, default is based on your platform. Options are ["bubblewrap" "docker" "qemu"]
      --signing-key string                                      key to use for signing
      --source-dir string                                       directory used for included sources
      --strip-origin-name                                       whether origin names should be stripped (for bootstrap)
      --timeout duration                                        default timeout for builds
      --trace string                                            where to write trace output
      --vars-file string                                        file to use for preloaded build configuration variables
      --workspace-dir string                                    directory used for the workspace at /home/build
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [melange](/docs/md/melange.md)	 - 

