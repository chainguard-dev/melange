---
title: "melange sign-index"
slug: melange_sign-index
url: /docs/md/melange_sign-index.md
draft: false
images: []
type: "article"
toc: true
---
## melange sign-index

Sign an APK index

### Synopsis

Sign an APK index.

```
melange sign-index [flags]
```

### Examples

```

    # Re-sign an index with the same signature
    melange sign-index [--signing-key=key.rsa] <APKINDEX.tar.gz>

    # Sign a new index with a new signature
    melange sign-index [--signing-key=key.rsa] <APKINDEX.tar.gz> --force
    
```

### Options

```
  -f, --force                when toggled, overwrites the specified index with a new index using the provided signature
  -h, --help                 help for sign-index
      --signing-key string   the signing key to use (default "melange.rsa")
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [melange](/docs/md/melange.md)	 - 

