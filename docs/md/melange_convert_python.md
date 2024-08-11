---
title: "melange convert python"
slug: melange_convert_python
url: /docs/md/melange_convert_python.md
draft: false
images: []
type: "article"
toc: true
---
## melange convert python

Converts a python package into a melange.yaml

### Synopsis

Converts an python package into a melange.yaml.

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
      --preserve-base-uri        preserve the base URI for PyPI packages instead of using the friendly URL
      --python-version string    version of the python to build the package (default "3")
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

