---
title: "melange license-check"
slug: melange_license-check
url: /docs/md/melange_license-check.md
draft: false
images: []
type: "article"
toc: true
---
## melange license-check

Gather and check licensing data

### Synopsis

Check a melange source, source tree or APK for license data correctness.

```
melange license-check file [flags]
```

### Examples

```
  melange license-check vim.yaml
```

### Options

```
      --fix              fix license issues in the melange yaml file
      --format string    license fix strategy format: 'simple' or 'flat' (default "flat")
  -h, --help             help for license-check
      --workdir string   path to the working directory, e.g. where the source will be extracted to
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [melange](/docs/md/melange.md)	 - 

