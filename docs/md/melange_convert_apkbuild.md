---
title: "melange convert apkbuild"
slug: melange_convert_apkbuild
url: /chainguard/chainguard-enforce/melange-docs/melange_convert_apkbuild/
draft: false
images: []
type: "article"
toc: true
---
## melange convert apkbuild

Converts an APKBUILD package into a melange.yaml

### Synopsis

Converts an APKBUILD package into a melange.yaml.

```
melange convert apkbuild [flags]
```

### Examples

```
  convert apkbuild libx11
```

### Options

```
      --additional-keyrings stringArray       additional repositories to be added to convert environment config
      --additional-repositories stringArray   additional repositories to be added to convert environment config
      --base-uri-format string                URI to use for querying APKBUILD for provided package name (default "https://git.alpinelinux.org/aports/plain/main/%s/APKBUILD")
      --exclude-packages stringArray          packages to exclude from auto generation of melange configs when detected in APKBUILD files
  -h, --help                                  help for apkbuild
      --out-dir string                        directory where convert config will be output (default "./generated")
```

### SEE ALSO

* [melange convert](/chainguard/chainguard-enforce/melange-docs/melange_convert/)	 - Attempts to converts files into melange configuration files

