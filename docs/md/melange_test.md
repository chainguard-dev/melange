---
title: "melange test"
slug: melange_test
url: /docs/md/melange_test.md
draft: false
images: []
type: "article"
toc: true
---
## melange test

Test a package with a YAML configuration file

### Synopsis

Test a package from a YAML configuration file containing a test pipeline.

```
melange test [flags]
```

### Examples

```
  melange test <test.yaml> <package-name>
```

### Options

```
      --apk-cache-dir string        directory used for cached apk packages (default is system-defined cache directory)
      --arch strings                architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config
      --cache-dir string            directory used for cached inputs
      --cache-source string         directory or bucket used for preloading the cache
      --debug                       enables debug logging of test pipelines (sets -x for steps)
      --debug-runner                when enabled, the builder pod will persist after the build succeeds or fails
      --guest-dir string            directory used for the build environment guest
  -h, --help                        help for test
  -k, --keyring-append strings      path to extra keys to include in the build environment keyring
      --log-policy strings          logging policy to use (default [builtin:stderr])
      --overlay-binsh string        use specified file as /bin/sh overlay in build environment
      --pipeline-dirs strings       directories used to extend defined built-in pipelines
  -r, --repository-append strings   path to extra repositories to include in the build environment
      --runner string               which runner to use to enable running commands, default is based on your platform. Options are ["bubblewrap" "docker" "lima" "kubernetes"] (default "bubblewrap")
      --source-dir string           directory used for included sources
      --test-option strings         build options to enable
      --workspace-dir string        directory used for the workspace at /home/build
```

### SEE ALSO

* [melange](/docs/md/melange.md)	 - 

