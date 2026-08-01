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
- **The guest init** (`microvm-init`) must recognise an EROFS rootfs. An init
  without that support will try to `tar -xpf` an EROFS image and panic.

The init detects the format by sniffing the EROFS superblock magic on the
rootfs block device, not from anything melange passes it. So the two sides
upgrade independently in one direction: an erofs-aware init still boots tar
images, and can therefore be rolled out before any host enables this. The
reverse does not hold — enabling this against an init that predates the support
fails at boot, and melange cannot detect that in advance.

## Values

| value | meaning |
| --- | --- |
| unset, or `tar` | Default. A gzipped tar layer the guest unpacks. |
| `erofs` | Uncompressed EROFS. Written by apko in pure Go, no external tools. |
| `erofs+ALGO[,level=N]` | Compressed EROFS, where `ALGO` is `zstd`, `lz4`, `lz4hc` or `deflate`. Mounts natively but needs `mkfs.erofs` (from `erofs-utils`) on the **host**, and the guest kernel needs the matching decompressor. |

## Measurements

`linux-qemu-melange` 6.18.41, x86_64, three runs each. "Boot" is QEMU start to
sshd reachable, which is where the unpacking cost lives. Every run produced a
byte-identical `.apk`.

| guest environment | uncompressed tar fed to the VM | tar boot | erofs boot |
| --- | --- | --- | --- |
| `build-base`, `busybox` | 578 MB | 9.0s | 5.0s |
| `+ rust, go, openjdk-21, nodejs, python3, cmake, ninja, perl, git` | 1.73 GB | 17.7s | 5.7s |

EROFS boot is effectively constant: tripling the environment roughly doubled the
tar path and left EROFS where it was. Extraction cost scales with rootfs size, a
mount does not.

Image sizes for the same two environments:

| format | small | large |
| --- | --- | --- |
| uncompressed tar (what the VM reads today) | 578 MB | 1.73 GB |
| `erofs` | 582 MB (+0.7%) | 1.75 GB (+1.0%) |
| `erofs+zstd` | 276 MB (−52%) | 818 MB (−54%) |

Compressed EROFS costs host CPU when the image is built (~10s vs ~3s for the
small environment) and buys back roughly half the bytes, while still mounting
natively.

Total build wall clock on a *small* package with a small environment is a wash —
the saving is flat, so it disappears into noise on one short build and shows up
in aggregate, or immediately on a large environment.

## How it fits together

melange asks apko for the layer in the requested format and attaches the
resulting image to the VM read-only. The guest init recognises it and mounts it
as an overlayfs lowerdir, with the scratch disk supplying `upperdir` and
`workdir`:

```
/dev/vdb  (EROFS, read-only)  ->  /lower    \
                                             +->  overlay  ->  /mount
/dev/vda  (xfs scratch disk)  ->  /scratch  /
```

The scratch disk stays mounted at `/scratch`. That matters because overlayfs
refuses an `upperdir` that is itself on an overlay: when the cache directory is
shared over 9p, its writable overlay has to put `upperdir`/`workdir` on
`/scratch` rather than under `/mount`.

Very little is actually written to the rootfs during a build — outside the
`/home/build` workspace it is `/etc/resolv.conf`, `/etc/hosts`,
`/etc/ld.so.cache`, `/var/cache/ldconfig/aux-cache` and `/.dockerenv`, all
written by init. The overlay exists to keep arbitrary pipelines working, not
because the volume of writes demands it.
