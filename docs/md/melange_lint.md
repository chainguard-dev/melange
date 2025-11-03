---
title: "melange lint"
slug: melange_lint
url: /docs/md/melange_lint.md
draft: false
images: []
type: "article"
toc: true
---
## melange lint

EXPERIMENTAL COMMAND - Lints an APK, checking for problems and errors

### Synopsis

Lint is an EXPERIMENTAL COMMAND - Lints an APK file, checking for problems and errors.

```
melange lint [flags]
```

### Examples

```
  melange lint [--enable=foo[,bar]] [--disable=baz] [--persist-lint-results] [--out-dir=./output] foo.apk
```

### Options

```
  -h, --help                   help for lint
      --lint-require strings   linters that must pass (default [dev,infodir,setuidgid,tempdir,usrmerge,varempty,worldwrite])
      --lint-warn strings      linters that will generate warnings (default [binaryarch,cudaruntimelib,dll,duplicate,dylib,lddcheck,maninfo,nonlinux,object,opt,pkgconf,python/docs,python/multiple,python/test,sbom,srv,staticarchive,strip,unsupportedarch,usrlocal])
      --out-dir string         directory where lint results JSON files will be saved (requires --persist-lint-results) (default "packages")
      --persist-lint-results   persist lint results to JSON files in packages/{arch}/ directory
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [melange](/docs/md/melange.md)	 - 

