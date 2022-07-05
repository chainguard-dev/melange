# melange

Build APK packages using declarative pipelines.

Commonly used to provide custom packages for container images built with
[apko][apko].

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

## Install

Melange has a dependency on [apk-tools](https://gitlab.alpinelinux.org/alpine/apk-tools).
Currently the easiest way to run melange is inside an Alpine VM or
container. If you're on MacOS, you can use a Lima VM, as [documented for
apko](https://github.com/chainguard-dev/apko/blob/main/mac/README.md).

## Quickstart

A melange build file looks like:

```
package:
  name: hello
  version: 2.12
  epoch: 0
  description: "the GNU hello world program"
  target-architecture:
    - all
  copyright:
    - paths:
      - "*"
      attestation: |
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

    # melange build examples/gnu-hello.yaml

This will create a `packages` folder, with an entry for each architecture
supported by the package. If you only want to build for the current
architecture, `--arch $(uname -m)`. Inside the architecture directory will be
APK files for each package built in the pipeline.

If you want to sign your APKs, create a signing key with the
`melange keygen` command:

    # melange keygen
    generating keypair with a 4096 bit prime, please wait...
    wrote private key to melange.rsa
    wrote public key to melange.rsa.pub

And then pass the `--signing-key` argument to `melange build`.

You can also sign APK indexes (generated with the `apk index`
command) using `melange sign-index`.

The quickest way to get an environment for running apko on Mac or Linux is to clone the repo and use the scripts under the hack
directory:

```
$ ./hack/make-devenv.sh
...
[melange] ❯ make install
...
[melange] ❯ melange build examples/gnu-hello.yaml --workspace-dir="$(pwd)/workspace"
...
```

## Usage with apko

To use a melange built APK in apko, either upload it to a package repository or
use a "local" repository. Using a local repository allows a melange build and
apko build to run in the same directory (or GitHub repo) without using external
storage. An example of this approach can be seen in the [nginx-image-demo
repo](https://github.com/chainguard-dev/nginx-image-demo/). 

### Coming soon: Keyless signatures

We are working to enable keyless signatures using [Sigstore
Fulcio](https://github.com/SigStore/fulcio), which can be used with traditional
signed indices to remove the need to have sensitive key material inside the
build environment.
