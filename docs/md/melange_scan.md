---
title: "melange scan"
slug: melange_scan
url: /docs/md/melange_scan.md
draft: false
images: []
type: "article"
toc: true
---
## melange scan

Scan an existing APK to regenerate .PKGINFO

```
melange scan [flags]
```

### Examples

```
melange scan bash.yaml
```

### Options

```
      --arch strings               architectures to scan (default is x86_64)
      --comments                   include comments in .PKGINFO diff
      --diff                       show diff output
  -h, --help                       help for scan
  -k, --keyring-append string      path to key to include in the build environment keyring (default "local-melange.rsa.pub")
      --namespace string           namespace to use in package URLs in SBOM (eg wolfi, alpine) (default "unknown")
  -p, --package string             which package's .PKGINFO to print (if there are subpackages)
  -r, --repository-append string   path to repository to include in the build environment (default "./packages")
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [melange](/docs/md/melange.md)	 - 

