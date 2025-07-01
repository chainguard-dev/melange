---
title: "melange index"
slug: melange_index
url: /docs/md/melange_index.md
draft: false
images: []
type: "article"
toc: true
---
## melange index

Creates a repository index from a list of package files

### Synopsis

Creates a repository index from a list of package files.

```
melange index [flags]
```

### Examples

```
  melange index -o APKINDEX.tar.gz *.apk
```

### Options

```
  -a, --arch string          Index only packages which match the expected architecture
  -h, --help                 help for index
  -m, --merge                Merge pre-existing index entries
  -o, --output string        Output generated index to FILE (default "APKINDEX.tar.gz")
      --signing-key string   Key to use for signing the index (optional)
  -s, --source string        Source FILE to use for pre-existing index entries (default "APKINDEX.tar.gz")
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [melange](/docs/md/melange.md)	 - 

