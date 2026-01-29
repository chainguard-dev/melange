---
title: "melange source get"
slug: melange_source_get
url: /docs/md/melange_source_get.md
draft: false
images: []
type: "article"
toc: true
---
## melange source get

Extract source code from melange configuration

### Synopsis

Extract source code by cloning git repositories from melange configuration.

This command parses a melange configuration file and extracts sources to the given directory
Currently only supports git-checkout.


```
melange source get [config.yaml] [flags]
```

### Examples

```
  melange source get vim.yaml -o ./src
```

### Options

```
  -h, --help   help for get
```

### Options inherited from parent commands

```
      --log-level string    log level (e.g. debug, info, warn, error) (default "INFO")
  -o, --output string       output directory for extracted source (default "./source")
      --source-dir string   directory where patches and other sources are located (defaults to ./package-name/)
```

### SEE ALSO

* [melange source](/docs/md/melange_source.md)	 - Manage melange source code

