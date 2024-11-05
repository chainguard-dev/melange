# melange

Build apk packages using declarative pipelines.

Commonly used to provide custom packages for container images built with [apko][apko]. The majority
of apks are built for use with either the [Wolfi](https://github.com/wolfi-dev) or [Alpine Linux](https://www.alpinelinux.org/) ecosystems.

Key features:

 - **Pipeline-oriented builds.** Every step of the build pipeline is defined and
   controlled by you, unlike traditional package managers which have distinct
   phases.
 - **Multi-architecture by default.** QEMU is used to emulate various
   architectures, avoiding the need for cross-compilation steps.

## Why

Secure software factories are the evolution of DevOps, allowing a
user to prove the provenance of all artifacts incorporated
into a software appliance.  By building and capturing software
artifacts into packages, DevOps teams can manage their software
artifacts as if they were any other component of an image.

This is especially useful when building software appliances in
the form of OCI container images with [apko][apko].

   [apko]: https://github.com/chainguard-dev/apko

## Installation

You can install Melange from Homebrew:

```shell
brew install melange
```

You can also install Melange from source:

```shell
go install chainguard.dev/melange@latest
```

You can also use the Melange container image:

```shell
docker run cgr.dev/chainguard/melange version
```

To use the examples, you'll generally want to mount your current directory into the container and provide elevated privileges, e.g.:

```shell
docker run --privileged -v "$PWD":/work cgr.dev/chainguard/melange build examples/gnu-hello.yaml
```

Running outside of a container requires [Docker](https://docs.docker.com/get-docker/), but should also work with other runtimes such as [podman](https://podman.io/getting-started/installation).

## Quickstart

A melange build file looks like:

```yaml
package:
  name: hello
  version: 2.12
  epoch: 0
  description: "the GNU hello world program"
  copyright:
    - attestation: |
        Copyright 1992, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2005,
        2006, 2007, 2008, 2010, 2011, 2013, 2014, 2022 Free Software Foundation,
        Inc.
      license: GPL-3.0-or-later
  dependencies:
    runtime:

environment:
  contents:
    repositories:
      - https://dl-cdn.alpinelinux.org/alpine/edge/main
    packages:
      - alpine-baselayout-data
      - busybox
      - build-base
      - scanelf
      - ssl_client
      - ca-certificates-bundle

pipeline:
  - uses: fetch
    with:
      uri: https://ftp.gnu.org/gnu/hello/hello-${{package.version}}.tar.gz
      expected-sha256: cf04af86dc085268c5f4470fbae49b18afbc221b78096aab842d934a76bad0ab
  - uses: autoconf/configure
  - uses: autoconf/make
  - uses: autoconf/make-install
  - uses: strip
```

We can build this with:

```shell
melange build examples/gnu-hello.yaml
```

or, with Docker:

```shell
docker run --privileged --rm -v "${PWD}":/work \
  cgr.dev/chainguard/melange build examples/gnu-hello.yaml
```

This will create a `packages` folder, with an entry for each architecture supported by the package. If you only want to build for the current architecture, you can add `--arch $(uname -m)` to the build command. Inside the architecture directory you should find apk files for each package built in the pipeline.

If you want to sign your apks, create a signing key with the `melange keygen` command:

```shell
melange keygen
```
```
 generating keypair with a 4096 bit prime, please wait...
 wrote private key to melange.rsa
 wrote public key to melange.rsa.pub
```

And then pass the `--signing-key` argument to `melange build`.

### Tips for building on Ubuntu

1. Non-native builds will fail unless `qemu-user-static` is installed:

```
2024/11/04 17:58:21 INFO installing wget (1.24.5-r0)
2024/11/04 17:58:21 WARN /etc/os-release is missing
2024/11/04 17:58:22 INFO built image layer tarball as /tmp/apko-temp-2053276993/apko-aarch64.tar.gz
2024/11/04 17:58:22 INFO using /tmp/apko-temp-2053276993/apko-aarch64.tar.gz for image layer
2024/11/04 17:58:23 INFO ImgRef = /tmp/melange-guest-749444813
2024/11/04 17:58:23 WARN bwrap: execvp /bin/sh: Exec format error
2024/11/04 17:58:23 INFO deleting guest dir /tmp/melange-guest-1329218525
2024/11/04 17:58:23 INFO deleting workspace dir /tmp/melange-workspace-2108047943
2024/11/04 17:58:23 INFO removing image path /tmp/melange-guest-749444813
2024/11/04 17:58:23 ERRO failed to build package: unable to start pod: exit status 1
```

You can install `qemu-user-static` with `sudo apt install qemu-user-static`.

2. `melange build` may be blocked by AppArmor, an issue similar to those described in [LP: #2046844](https://launchpad.net/bugs/2046844). You can unblock it by adding an apparmor profile, such as:

```
$ cat /etc/apparmor.d/melange
abi <abi/4.0>,
include <tunables/global>

profile melange /home/user/go/bin/melange flags=(unconfined) {
  userns,

  # Site-specific additions and overrides. See local/README for details.
  include if exists <local/melange>
}
```
Modify the path to the `melange` binary as appropriate. Then run `sudo systemctl reload apparmor`.


## Debugging melange Builds

To include debug-level information on melange builds, edit your `melange.yaml` file and include `set -x` in your pipeline. You can add this flag at any point of your pipeline commands to further debug a specific section of your build.

```yaml
...
pipeline:
  - name: Build Minicli application
    runs: |
      set -x
      APP_HOME="${{targets.destdir}}/usr/share/hello-minicli"
...
```

## Default Substitutions

Melange provides the following default substitutions which can be referenced in the build file pipeline:

| **Substitution**            | **Description**                                                          |
|-----------------------------|--------------------------------------------------------------------------|
| `${{package.name}}`         | Package name                                                             |
| `${{package.version}}`      | Package version                                                          |
| `${{package.epoch}}`        | Package epoch                                                            |
| `${{package.full-version}}` | `${{package.version}}-r${{package.epoch}}`                               |
| `${{package.description}}`  | Package description                                                      |
| `${{targets.outdir}}`       | Directory where targets will be stored                                   |
| `${{targets.contextdir}}`   | Directory where targets will be stored for main packages and subpackages |
| `${{targets.destdir}}`      | Directory where targets will be stored for main                          |
| `${{targets.subpkgdir}}`    | Directory where targets will be stored for subpackages                   |
| `${{build.arch}}`           | Architecture of current build (e.g. x86_64, aarch64)                     |
| `${{build.goarch}}`         | GOARCH of current build (e.g. amd64, arm64)                              |

An example build file pipeline with substitutions:

```yaml
pipeline:
  - name: 'Create tmp dir'
    runs: mkdir ${{targets.destdir}}/var/lib/${{package.name}}/tmp
```

[More detailed documentation](./docs/)

## Usage with apko

To use a melange built apk in apko, either upload it to a package repository or use a "local" repository. Using a local repository allows a melange build and apko build to run in the same directory (or GitHub repo) without using external storage.
An example of this approach can be seen in the [nginx-image-demo repo](https://github.com/chainguard-dev/nginx-image-demo/).
