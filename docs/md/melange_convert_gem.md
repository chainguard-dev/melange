---
title: "melange convert gem"
slug: melange_convert_gem
url: /open-source/melange/reference/melange_convert_gem/
draft: false
images: []
type: "article"
toc: true
---
## melange convert gem

Converts an gem into a melange.yaml

### Synopsis

Converts an gem into a melange.yaml.

```
melange convert gem [flags]
```

### Examples

```

# Convert the latest fluentd gem
convert gem fluentd
```

### Options

```
      --additional-keyrings stringArray       additional repositories to be added to convert environment config
      --additional-repositories stringArray   additional repositories to be added to convert environment config
      --base-uri-format string                URI to use for querying gems for provided package name (default "https://rubygems.org/api/v1/gems/%s.json")
  -h, --help                                  help for gem
      --out-dir string                        directory where convert config will be output (default "./generated")
      --ruby-version string                   version of ruby to use throughout generated manifests (default "3.2")
```

### SEE ALSO

* [melange convert](/open-source/melange/reference/melange_convert/)	 - EXPERIMENTAL COMMAND - Attempts to convert packages/gems/apkbuild files into melange configuration files

