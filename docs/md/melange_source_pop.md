---
title: "melange source pop"
slug: melange_source_pop
url: /docs/md/melange_source_pop.md
draft: false
images: []
type: "article"
toc: true
---
## melange source pop

Generate patches from modified source and update melange configuration

### Synopsis

Generate git format-patch patches from commits made on top of the expected-commit
and update the melange configuration to use git-am pipeline instead of patch pipeline.

This command:
1. Reads the expected-commit from git-checkout pipeline
2. Generates patches from expected-commit..HEAD in the cloned source
3. Writes patches to the source directory
4. Updates the YAML to replace 'patch' with 'git-am' pipeline


```
melange source pop [config.yaml] [flags]
```

### Examples

```
  melange source pop apk-tools.yaml
```

### Options

```
  -h, --help   help for pop
```

### Options inherited from parent commands

```
      --log-level string    log level (e.g. debug, info, warn, error) (default "INFO")
  -o, --output string       output directory for extracted source (default "./source")
      --source-dir string   directory where patches and other sources are located (defaults to ./package-name/)
```

### SEE ALSO

* [melange source](/docs/md/melange_source.md)	 - Manage melange source code

