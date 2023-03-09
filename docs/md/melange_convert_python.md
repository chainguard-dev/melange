---
title: "melange convert python"
slug: melange_convert_python
url: /chainguard/chainguard-enforce/melange-docs/melange_convert_python/
draft: false
images: []
type: "article"
toc: true
---
## melange convert python

Converts a pypi python package into a melange.yaml

### Synopsis

Converts pypi python package into a melange.yaml.

```
melange convert python [flags]
```

### Examples

```

# Convert the latest botocore python package
convert python botocore
```

### Options

```
      --base-uri-format string   URI to use for querying gems for provided package name (default "https://pypi.org")
  -h, --help                     help for python
      --package-version string   version of the python package to convert
      --python-version string    version of the python to build the package (default "3.11")
```

### SEE ALSO

* [melange convert](/chainguard/chainguard-enforce/melange-docs/melange_convert/)	 - EXPERIMENTAL COMMAND - Attempts to convert packages/gems/apkbuild files into melange configuration files

