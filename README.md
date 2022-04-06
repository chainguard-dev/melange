# melange

Build APK packages using declarative pipelines!

## Why

Secure software factories are the evolution of DevOps, allowing a
user to prove the provenance of all artifacts that get incorporated
into a software appliance.  By building and capturing software
artifacts into packages, DevOps teams can manage their software
artifacts as if they were any other component of an image.

This is especially useful when building software appliances in
the form of OCI container images with [apko][apko].

   [apko]: https://github.com/chainguard-dev/apko

## How

To build an unsigned APK, use the `melange build` command:

    # melange build examples/gnu-hello.yaml

This will create a set of APKs for every architecture supported
by the package.  You can use `--arch $(uname -m)` to bound the
architecture set to only the current system architecture if
desired.

If you want to sign your APKs, create a signing key with the
`melange keygen` command:

    # melange keygen
    generating keypair with a 4096 bit prime, please wait...
    wrote private key to melange.rsa
    wrote public key to melange.rsa.pub

And then pass the `--signing-key` argument to `melange build`.

You can also sign APK indexes (generated with the `apk index`
command) using `melange sign-index`.

## Features

### Multi-architecture builds by default.

No having to fuss with cross-compilation, like BuildKit, Melange
supports the use of QEMU to emulate various architectures, usually
at half-native speed.

### Pipeline oriented builds.

Every step of the build pipeline is defined and controlled by you,
unlike traditional package managers which have distinct phases.

Implement whatever build logic you want!

### Coming soon: Keyless signatures

We are working to enable keyless signatures using Sigstore Fulcio,
which can be used with traditional signed indices to remove the need
to have sensitive key material inside the build environment.
