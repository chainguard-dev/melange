---
title: "melange compare-versions"
slug: melange_compare-versions
url: /docs/md/melange_compare-versions.md
draft: false
images: []
type: "article"
toc: true
---
## melange compare-versions

Compare two package versions

### Synopsis

Compare two package versions according to a specified operator.

The operator can be: eq (equal), ne (not-equal),
                     lt (less-than), le (less-than or equal),
                     gt (greater-than), ge (greater-than or equal)

```
melange compare-versions [flags]
```

### Examples

```
melange compare-versions version1 operator version2
```

### Options

```
  -h, --help     help for compare-versions
  -s, --silent   don't print anything; use the return code ($?) to signal whether the comparison is true or false
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [melange](/docs/md/melange.md)	 - 

