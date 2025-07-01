---
title: "melange package-version"
slug: melange_package-version
url: /docs/md/melange_package-version.md
draft: false
images: []
type: "article"
toc: true
---
## melange package-version

Report the target package for a YAML configuration file

### Synopsis

Report the target package for a YAML configuration file.
		Equivalent to running:

			melange query config.yaml '{{ .Package.Name }}-{{ .Package.Version }}-r{{ .Package.Epoch }}'

		

```
melange package-version [flags]
```

### Examples

```
  melange package-version [config.yaml]
```

### Options

```
  -h, --help   help for package-version
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [melange](/docs/md/melange.md)	 - 

