---
title: "melange convert apkbuild"
slug: melange_convert_apkbuild
url: /docs/md/melange_convert_apkbuild.md
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
      --base-uri-format string         URI to use for querying APKBUILD for provided package name (default "https://git.alpinelinux.org/aports/plain/main/%s/APKBUILD")
      --exclude-packages stringArray   packages to exclude from auto generation of melange configs when detected in APKBUILD files
  -h, --help                           help for apkbuild
```

### Options inherited from parent commands

```
      --additional-keyrings stringArray       additional repositories to be added to convert environment config
      --additional-repositories stringArray   additional repositories to be added to convert environment config
      --log-level string                      log level (e.g. debug, info, warn, error) (default "INFO")
  -o, --out-dir string                        directory where convert config will be output (default ".")
      --use-github                            **experimental** if true, tries to use github to figure out the release commit details (python only for now). To prevent rate limiting, you can set the GITHUB_TOKEN env variable to a github token. (default true)
      --use-relmon                            **experimental** if true, tries to use release-monitoring to fetch release monitoring data.
      --wolfi-defaults                        if true, adds wolfi repo, and keyring to config (default true)
```

### SEE ALSO

* [melange convert](/docs/md/melange_convert.md)	 - EXPERIMENTAL COMMAND - Attempts to convert packages/gems/apkbuild files into melange configuration files

