---
title: "melange convert python"
slug: melange_convert_python
url: /open-source/melange/reference/melange_convert_python/
draft: false
images: []
type: "article"
toc: true
---
## melange convert python

Converts a python package into a melange.yaml

### Synopsis

Converts an python package into a melange.yaml.

```sh
$ melange convert python [flags]
```

### Examples

```sh
# Convert the latest botocore python package
$ convert python botocore
```

### Options

```
      --additional-keyrings stringArray       additional repositories to be added to convert environment config
      --additional-repositories stringArray   additional repositories to be added to convert environment config
      --base-uri-format string                URI to use for querying gems for provided package name (default "https://pypi.org")
  -h, --help                                  help for python
      --out-dir string                        directory where convert config will be output (default "./generated")
      --package-version string                version of the python package to convert
      --python-version string                 version of the python to build the package (default "3.11")
```

### SEE ALSO

* [melange convert](/open-source/melange/reference/melange_convert/)	 - EXPERIMENTAL COMMAND - Attempts to convert packages/gems/apkbuild files into melange configuration files

