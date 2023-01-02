# melange on mac

Currently `melange` relies on `apk`, which is currently
not available for mac.

This page documents workarounds to run
`melange` on a mac.

## OCI Container (Docker)

Use the [official container image](https://github.com/chainguard-images/images/tree/main/images/melange):

```
$ docker run --privileged -v "$PWD":/work cgr.dev/chainguard/melange build examples/gnu-hello.yaml
```

## Lima

We maintain an example configuration file for
[Lima](https://github.com/lima-vm/lima)
(see [`lima/melange-playground.yaml`](./lima/melange-playground.yaml)).

This provides a VM with the following:

- 1 CPU, 2GiB memory, 10GiB disk
- Latest release of `melange` (from GitHub releases)
- Useful tools such as `vim`
- Example config files from the repo at `/examples`


Root shell is needed for `apko build`. We also override `$HOME` with
your mac's `$HOME` (mounted into the VM) so that Docker credential
helpers work properly with `apko publish`.

The commands below assume to be run in this
directory of the repository, and require `limactl`.

### Start environment

```
limactl start --tty=false lima/melange-playground.yaml
```

### Obtain a shell

```
limactl shell melange-playground sudo su -c "HOME=\"${HOME}\" ash"
```

### Build an example apk

```
melange build --keyring-append /usr/lib/wolfi-signing.rsa.pub --arch amd64 /examples/go-hello.yaml
```

