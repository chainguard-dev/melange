---
title: "melange initramfs"
slug: melange_initramfs
url: /docs/md/melange_initramfs.md
draft: false
images: []
type: "article"
toc: true
---
## melange initramfs

Build a base initramfs for the QEMU runner

### Synopsis

Build a base initramfs that can be used with the QEMU runner.

The generated initramfs can be reused across multiple builds by setting
the QEMU_BASE_INITRAMFS environment variable to point to the output file.

The generated initramfs does NOT contain SSH host keys.
Keys and modules are injected at runtime for each build.

```
melange initramfs [flags]
```

### Examples

```
  # Generate default initramfs for x86_64
  melange initramfs --arch x86_64 --output ./initramfs.cpio

  # Generate with custom package and repos
  melange initramfs \
    --arch aarch64 \
    --output ./custom-initramfs.cpio \
    --init-package my-custom-init \
    --repository https://my.repo.dev/packages

  # Use the generated initramfs in a build
  QEMU_BASE_INITRAMFS=./initramfs.cpio melange build --runner qemu ...
```

### Options

```
      --arch string           target architecture (e.g., x86_64, aarch64)
  -h, --help                  help for initramfs
      --init-package string   init package to use (default "microvm-init")
  -k, --keyring strings       extra keys for APK signature verification
  -o, --output string         output path for the initramfs (required)
  -p, --package strings       additional packages to include
  -r, --repository strings    APK repositories to use (default [https://apk.cgr.dev/chainguard])
```

### Options inherited from parent commands

```
      --log-level string   log level (e.g. debug, info, warn, error) (default "INFO")
```

### SEE ALSO

* [melange](/docs/md/melange.md)	 - 

