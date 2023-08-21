---
title: "melange query"
slug: melange_query
url: /docs/md/melange_query.md
draft: false
images: []
type: "article"
toc: true
---
## melange query

Query a Melange YAML file for information

### Synopsis

Query a Melange YAML file for information.
		Uses templates with go templates syntax to query the YAML file.

```
melange query [flags]
```

### Examples

```
  melange query config.yaml "{{ .Package.Name }}-{{ .Package.Version }}-{{ .Package.Epoch }}"
```

### Options

```
  -h, --help   help for query
```

### SEE ALSO

* [melange](/docs/md/melange.md)	 - 

