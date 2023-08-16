---
title: "melange sign"
slug: melange_sign
url: /open-source/melange/reference/melange_sign/
draft: false
images: []
type: "article"
toc: true
---
## melange sign

Sign an APK package

### Synopsis

Signs an APK package on disk with the provided key. The package is replaced with the APK containing the new signature.

```
melange sign [flags]
```

### Examples

```

		melange sign [--signing-key=key.rsa] package.apk

		melange sign [--signing-key=key.rsa] *.apk
		
```

### Options

```
  -h, --help                 help for sign
  -k, --signing-key string   The signing key to use. (default "local-melange.rsa")
```

### SEE ALSO

* [melange](/open-source/melange/reference/melange/)	 - 

