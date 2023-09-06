# melange build file

This documents the melange build file structure, fields, when, and why to use various fields.

# High level structure overview

The following are the high level sections for the build file, with detailed descriptions for each of them, and their fields in the sections following.

 ## Required
 ### package

   Package metadata about this package, name, version, etc.
 ### environment

    Specification for the packages build environment
 ### pipeline

    Ordered list of pipelines that produce this package

## Optional
### subpackages

   List of subpackages that this package also produces. For example, docs.
### data

   Arbitrary list of data available for templating in the pipeline.
### [update](./UPDATE.md)

   Defines how this package is auto updated
### vars

   Map of arbitrary variables available for templating in the pipeline.
### [var-transforms](./VAR-TRANSFORMS.md)

   List of transformations to create for the builtin template variables.
### options

   Deviations to the build

# package

Details about the particular package that will be used to find and use it.

### name
Unique name for the package. Convention is to use the same name as the YAML file without extension. This is what people will search for, so it's a good idea to keep it consistent with how the package is named in other distributions. for example:
```
name: python-3.10
```

### version
Version of the package. For example:
```
version: 3.10.12
```

### epoch
Monotonically increasing value (starting at 0) indicating same version of the
package, but with changes (security patches for example) applied to it.
```
epoch: 0
```

**NOTE** the above 3 fields are used to construct the package filename of the
form: `<name>-<version>-r<epoch>.apk` for our example above, this would be:
`python-3.10-3.10.12-r0.apk`.

### description
Human readable description of the package. Make this meaningful, as this information shows up when searching for the package with apk, for example:
```
description: "the Python programming language"
```

### url [optional]
The URL to the packages homepage.

### commit [optional]
The git commit of the package build configuration
  TODO(vaikas): is the 'is package build configuration' this file?
  TODO(vaikas): why would I use this? I did not see an example use.

### target-architecture [optional]
List of architectures for which this package should be built for. Valid
architectures are: `386`, `amd64`, `arm/v6`, `arm/v7`, `arm64`, `ppc64le`,
`s390x`, `x86_64`, `aarch64`, special `all` that builds it for all of them.
Leaving this out defaults to `all`.
  TODO(vaikas): rekor-cli.yaml sets this to all? So is that not the default?
  TODO(vaikas): Saw something about riscv64. Does all include that?

### copyright
List of copyrights for this package. Each entry in the list consists of 3
fields that define the scope (paths, and which license applies to it):

#### license
The license for either the package or part of the package (if there are multiple entries). It is important to note that only packages with OSI-approved licenses can be included in Wolfi. You can check the relevant package info in the licenses page at [opensource.org](https://opensource.org/licenses/).

#### paths [optional]
The license paths that this license applies to

#### attestation
Attestations for this license.

For example, saying that this entire package has license `PSF-2.0`
```
copyright:
  - license: PSF-2.0
```

  TODO(vaikas): Add attestation example (only found TODO)
  TODO(vaikas): Add paths example (only found *)

### dependencies
List of packages that this package depends on at runtime, but not during build
time. These will get installed by apk as system dependencies when the package is
installed. For example, saying that a package depends on `openssl`, `socat`, and
`curl` at runtime:
```
dependencies:
  runtime:
    - openssl
    - socat
    - curl
```

#### provides
Provides allows you to create "aliases" for a package. If your `package.name` is
for example `php-8.1`, but you want somebody be able to get this package by
`php`, you could provide a section like this:

```
  dependencies:
    provides:
      - php=8.1.23
```

The above example is pinned to the version 8.1.23, but it's typically better to
provide a floating version, so that when the package gets upgraded, the user
will get the latest one. For that melange provides a `${{package.full-version}}`
variable. It gets expanded to `${{package.version}}-r${{package-epoch}}`. So for
the example above, you could do this
```
  dependencies:
    provides:
      - php=${{package.full-version}}
```

You can also do the same thing to provide parallel version streams, so again
using our php example, there are 8.1.X and 8.2.X streams, so the condensed
example here:
`php-8.1.yaml`:
```
package:
  name: php-8.1
  version: 8.1.23
  epoch: 0
  dependencies:
    provides:
      - php=${{package.full-version}}
```

`php-8.2.yaml`:
```
package:
  name: php-8.2
  version: 8.2.10
  epoch: 1
  dependencies:
    provides:
      - php=${{package.full-version}}
```

When user does `apk add php-8.1`, they will get the `php 8.1.23` because they
are explicitly asking for the 8.1 version, and will get the latest version of
8.1. When user does `apk add php-8.2`, they will get the `php 8.2.10` because
they again explicitly asked for the 8.2 version. Now if they just ask for php
`apk add php`, they will get the latest version `php 8.2.10` assuming they have
no other additional constraints defined.

### options
Options that describe the package functionality. Currently there are three
options, and these are used by SCA tools to control their behaviour.

`no-provides` - This is a virtual package which provides no files, executables,
or libraries. Turns off the SCA-based dependency generators. A good example of
this is a package placeholder that then provides more targeted packages, for
example:

```
options:
  no-provides: true
```

`no-depends` - This is a self contained package that does not depend on any
other package. Turns off SCA-based dependency generators.

```
options:
  no-depends: true
```

`no-commands` - This package should not be searched for commands. By default, we
look through /usr/bin, etc looking for commands. If we find commands we
generate provider entries for them. This allows for things like apk search
cmd:foo, apk add cmd:bar to work. By default melange does the right thing, so
you probably need a good reason to turn this off.

```
options:
  no-commands: true
```

### scriptlets
List of executable scripts that run at various stages of the package lifecycle,
triggered by configurable events. These are useful to handle tasks that only
happen during install, uninstall, upgrade. The life-cycle events are:
`pre-install`, `post-install`, `pre-deinstall`, `post-deinstall`, `pre-upgrade`,
 `post-upgrade`. The script should contain the shebang interpereter, for
example:

 ```
scriptlets:
  post-deinstall: |
    #!/bin/busybox sh
    /bin/busybox --install -s
```

In addition to lifecycle events, you can define `Trigger` which defines a list
of paths to monitor, which causes a script to run. The script should contain the
shebang interpreter, for example:

```
scriptlets:
  trigger:
    paths:
      - /bin
      - /sbin
      - /usr/bin
      - /usr/sbin
    script: |
      #!/bin/busybox sh
      /bin/busybox --install -s
```

TODO(vaikas): What does it mean to monitor, when new files are added/removed to
those directories? Something else??

# environment
Environment defines the build environment, including what the dependencies are,
including repositories, packages, etc.

## Local building
When building locally, you'll also need to include information about where to find Wolfi packages. This is not needed when submitting the package to the Wolfi OS repository. The "contents" node is used for that:

```yaml
environment:
  contents:
    repositories:
    - https://packages.wolfi.dev/bootstrap/stage3
    - https://packages.wolfi.dev/os
    keyring:
    - https://packages.wolfi.dev/bootstrap/stage3/wolfi-signing.rsa.pub
    - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
```

## contents
Contents has 3 lists that define where to look for packages, how to validate the
repository, and which packages to install.

### repositories
Which repositories to fetch the packages from. **NOTE** Do not mix Alpine apk
repositories with Wolfi apk repositories.

### keyring
These are used to validate the authenticity of a repository.

TODO(vaikas): Are there any constraints here, or if any key in the keyring
matches a repository, then all is well. I'd assume so.

### packages
Packages is the list of packages to install for running the pipeline.

For example:
```
environment:
  contents:
    repositories:
      - https://packages.wolfi.dev/os
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    packages:
      - busybox
      - ca-certificates-bundle
      - go
```

TODO(vaikas): Are there ways to control which version of the packages gets
installed?

## environment
environment allows you to control environmental variables to set while running
the pipeline. For example, to set the env variable `CGO_ENABLED` to `0`:

```
environment:
  environment:
    CGO_ENABLED: "0"
```

TODO(vaikas): melange config points to apko here:
 https://github.com/chainguard-dev/melange/blob/main/pkg/config/config.go#L256
 which points to [ImageConfiguration](https://github.com/chainguard-dev/apko/blob/main/pkg/build/types/types.go#L106), which has a ton of stuff, is all that
 really supported, or just `environment`

# pipeline
Pipeline defines the ordered steps to build the package.

