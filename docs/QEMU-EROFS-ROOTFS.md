# EROFS guest rootfs for the QEMU runner

By default the QEMU runner hands the guest a tar of the build environment on a
block device, and the guest init unpacks it onto a freshly formatted scratch
disk on every boot. For a typical build environment that is several hundred
megabytes of extraction before the first pipeline step runs.

Setting `QEMU_ROOTFS_FORMAT=erofs` builds the guest rootfs as an
[EROFS](https://docs.kernel.org/filesystems/erofs.html) image instead. EROFS is
a read-only on-disk filesystem, so the guest mounts it directly and overlays
the scratch disk on top. Nothing is unpacked at boot.

```sh
QEMU_ROOTFS_FORMAT=erofs melange build --runner qemu ...
```

## Requirements

This needs support on both sides and will fail confusingly if only one is in
place.

- **apko** must support `--format=erofs`.
- **The guest kernel** needs `CONFIG_EROFS_FS` and `CONFIG_OVERLAY_FS`.
  `linux-qemu-melange` has both built in.
- **The guest init** (`microvm-init`) must honour the `melange.rootfs=` kernel
  command line argument that melange adds. An init without that support will
  try to `tar -xpf` an EROFS image and panic.

## Values

| value | meaning |
| --- | --- |
| unset, or `tar` | Default. A gzipped tar layer the guest unpacks. |
| `erofs` | Uncompressed EROFS. Written by apko in pure Go, no external tools. |
| `erofs+ALGO[,level=N]` | Compressed EROFS, where `ALGO` is `zstd`, `lz4`, `lz4hc` or `deflate`. Mounts natively but needs `mkfs.erofs` (from `erofs-utils`) on the **host**, and the guest kernel needs the matching decompressor. |

## Measurements

Building `examples/gnu-hello.yaml` with `linux-qemu-melange` 6.18.41. "Boot" is
the span from QEMU starting to sshd being reachable, which is where the
unpacking cost lives. All three formats produced a byte-identical `.apk`.

| format | guest image | host build | boot |
| --- | --- | --- | --- |
| `tar` | 578 MB (uncompressed, as fed to the VM) | ~3s | 9.0s |
| `erofs` | 582 MB (+0.7%) | ~3s | 4.7s |
| `erofs+zstd` | 276 MB (−52%) | ~10s | 5.0s |

Boot roughly halves. The rest of the build is unchanged within noise, so on a
short build the total is a wash and the win shows up as a flat per-build saving
that matters most when building many packages.

## How it fits together

melange asks apko for the layer in the requested format, then attaches the
resulting image to the VM read-only and adds `melange.rootfs=<format>` to the
kernel command line. The guest init mounts it as an overlayfs lowerdir with the
scratch disk supplying `upperdir` and `workdir`:

```
/dev/vdb  (EROFS, read-only)  ->  /lower  \
                                           +->  overlay  ->  /mount
/dev/vda  (xfs scratch disk)  ->  /rw     /
```

The scratch disk stays mounted at `/rw`. That matters because overlayfs refuses
an `upperdir` that is itself on an overlay: when the cache directory is shared
over 9p, its writable overlay has to put `upperdir`/`workdir` on `/rw` rather
than under `/mount`.

Very little is actually written to the rootfs during a build — outside the
`/home/build` workspace it is `/etc/resolv.conf`, `/etc/hosts`,
`/etc/ld.so.cache`, `/var/cache/ldconfig/aux-cache` and `/.dockerenv`, all
written by init. The overlay exists to keep arbitrary pipelines working, not
because the volume of writes demands it.
