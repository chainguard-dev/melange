---
title: "melange index"
slug: melange_index
url: /open-source/melange/reference/melange_index/
draft: false
images: []
type: "article"
toc: true
---
## melange index

Creates a repository index from a list of package files

### Synopsis

Creates a repository index from a list of package files.

```sh
$ melange index [flags]
```

### Examples

```sh
$ melange index -o APKINDEX.tar.gz *.apk
```

### Options

```
  -a, --arch string     Index only packages which match the expected architecture
  -h, --help            help for index
  -o, --output string   Output generated index to FILE (default "APKINDEX.tar.gz")
```

### SEE ALSO

* [melange](/open-source/melange/reference/melange/)	 - 

