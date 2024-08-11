---
title: "melange convert gem"
slug: melange_convert_gem
url: /docs/md/melange_convert_gem.md
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
      --base-uri-format string   URI to use for querying gems for provided package name (default "https://rubygems.org/api/v1/gems/%s.json")
  -h, --help                     help for gem
      --ruby-version string      version of ruby to use throughout generated manifests (default "3.2")
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

