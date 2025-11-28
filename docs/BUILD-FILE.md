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
```yaml
name: python-3.10
```

### version
Version of the package. For example:
```yaml
version: 3.10.12
```

### epoch
Monotonically increasing value (starting at 0) indicating same version of the
package, but with changes (security patches for example) applied to it.
```yaml
epoch: 0
```

**NOTE** the above 3 fields are used to construct the package filename of the
form: `<name>-<version>-r<epoch>.apk` for our example above, this would be:
`python-3.10-3.10.12-r0.apk`.

### description
Human readable description of the package. Make this meaningful, as this information shows up when searching for the package with apk, for example:
```yaml
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
```yaml
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
```yaml
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

```yaml
  dependencies:
    provides:
      - php=8.1.23
```

The above example is pinned to the version 8.1.23, but it's typically better to
provide a floating version, so that when the package gets upgraded, the user
will get the latest one. For that melange provides a `${{package.full-version}}`
variable. It gets expanded to `${{package.version}}-r${{package-epoch}}`. So for
the example above, you could do this
```yaml
  dependencies:
    provides:
      - php=${{package.full-version}}
```

You can also do the same thing to provide parallel version streams, so again
using our php example, there are 8.1.X and 8.2.X streams, so the condensed
example here:

`php-8.1.yaml`:
```yaml
package:
  name: php-8.1
  version: 8.1.23
  epoch: 0
  dependencies:
    provides:
      - php=${{package.full-version}}
```

`php-8.2.yaml`:
```yaml
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

```yaml
options:
  no-provides: true
```

`no-depends` - This is a self contained package that does not depend on any
other package. Turns off SCA-based dependency generators.

```yaml
options:
  no-depends: true
```

`no-commands` - This package should not be searched for commands. By default, we
look through /usr/bin, etc looking for commands. If we find commands we
generate provider entries for them. This allows for things like apk search
cmd:foo, apk add cmd:bar to work. By default melange does the right thing, so
you probably need a good reason to turn this off.

```yaml
options:
  no-commands: true
```

`no-versioned-shlib-deps` - The generated `depends` for shared
libraries shipped by this package should not be versioned.  By
default, melange will generate versioned `depends` for shared
libraries.

```yaml
options:
  no-versioned-shlib-deps: true
```

### scriptlets
List of executable scripts that run at various stages of the package lifecycle,
triggered by configurable events. These are useful to handle tasks that only
happen during install, uninstall, upgrade. The life-cycle events are:
`pre-install`, `post-install`, `pre-deinstall`, `post-deinstall`, `pre-upgrade`,
`post-upgrade`. The script should contain the shebang interpereter, for
example:

```yaml
scriptlets:
  post-deinstall: |
    #!/bin/busybox sh
    /bin/busybox --install -s
```

In addition to lifecycle events, you can define `Trigger` which defines a list
of paths to monitor, which causes a script to run. The script should contain the
shebang interpreter, for example:

```yaml
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

### timeout
Optional timeout duration for the build. Specifies the maximum amount of time the build is allowed to take before timing out. The value is specified in seconds as an integer.

```yaml
package:
  timeout: 3600  # 1 hour in seconds
```

### resources
Optional resource specifications for the build. Used by external schedulers (like elastic build) to provision appropriately-sized build pods/VMs. For local builds with the QEMU runner, these can be used as resource limits via CLI flags.

**Resource Fields:**

- `cpu`: CPU resource count as a quoted string (e.g., `"4"`, `"8"`, `"16"`)
- `cpumodel`: Specific CPU model requirements (e.g., `"intel-xeon"`, `"amd-epyc"`)
- `memory`: Memory size in Kubernetes format (e.g., `"8Gi"`, `"16Gi"`, `"128Mi"`)
- `disk`: Disk space in Kubernetes format (e.g., `"50Gi"`, `"100Gi"`, `"1Ti"`)

**Value Formats:**
- CPU values are typically whole numbers as strings: `"1"`, `"2"`, `"4"`, `"8"`, etc.
- Memory and disk use Kubernetes resource quantities: `Mi` (mebibytes), `Gi` (gibibytes), `Ti` (tebibytes)
- All fields are optional and interpretation depends on the scheduler/runner

**How resources are interpreted:**
- **External schedulers**: Use these values to provision build pods/VMs
- **QEMU runner** (via CLI flags like `--cpu`, `--memory`): Treats values as **maximum limits**
  - CPU: Defaults to all available cores, capped at the specified value if lower
  - Memory: Defaults to 85% of available memory, capped at the specified value if lower
- **Docker/Bubblewrap runners**: Resource fields are not enforced

```yaml
package:
  resources:
    cpu: "8"
    memory: "16Gi"
    disk: "100Gi"
```

### test-resources
Optional resource specifications for test execution. Used by external schedulers to provision test pods/VMs with different resource constraints than the build phase.

**When to use test-resources:**
- Tests require significantly different resources than builds
- Integration tests need more CPU/memory than unit tests
- Tests can run with fewer resources to optimize costs
- External schedulers need separate test and build resource specifications

**How test-resources are interpreted:**

The `test-resources` field is primarily **informational** for external schedulers:

**For external schedulers** (reading the YAML):
- Use `test-resources` if specified, otherwise fall back to `resources`
- This determines test pod/VM sizing

**For local testing with `melange test`:**
- The `test-resources` field in the YAML is **NOT automatically used** by melange
- Resources must be explicitly specified via CLI flags: `--cpu`, `--memory`, `--disk`, `--cpumodel`, `--timeout`
- Resource enforcement depends on the runner (same as `resources` field):
  - **QEMU runner**: Enforces CPU and memory as **maximum limits** (caps at specified value)
  - **Docker/Bubblewrap runners**: Do not enforce resource limits

**Resource fields** are identical to `resources` (see above for formats and interpretation).

Example where tests need less resources than build:
```yaml
package:
  resources:
    cpu: "8"
    memory: "16Gi"
    disk: "100Gi"
  test-resources:
    cpu: "4"
    memory: "8Gi"
    disk: "50Gi"
```

Example where tests need more resources than build:
```yaml
package:
  resources:
    cpu: "2"
    memory: "4Gi"
  test-resources:
    cpu: "32"
    memory: "128Gi"
    disk: "500Gi"
```

Example with only test-resources specified:
```yaml
package:
  test-resources:
    cpu: "4"
    memory: "8Gi"
  # No build resources specified - scheduler uses defaults
```

# environment
Environment defines the build environment, including what the dependencies are,
including repositories, packages, etc.

**NOTE**: environment configuration can only be specified in
the top level build configuration. Environment settings cannot be
extended or modified in a subpackage build definition. This is different
from subpackage test definitions, where separate environments can be
specified for each subpackage that differ from the main package.

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
Packages is the list of packages to install in the build environment for running the pipeline; in other words, these are the necessary build time dependencies for the package.

For example:
```yaml
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

To specify a version for packages, you can use the following syntax:
```yaml
environment:
  packages:
    - go>1.21    # install anything newer than 1.21, excluding 1.21
    - foo=~4.5.6 # install any version with a name starting with "4.5.6" (e.g., 4.5.6-r7)
    - python3    # install the latest stable version of python3.
```
For additional information, see the [Chainguard Academy article](https://edu.chainguard.dev/open-source/wolfi/apk-version-selection/).

## accounts
Accounts support adding additional users and groups into the build
environment, as well as running the build under a different user than
the build runner's default.

### run-as
Specifies which user to run the build under, the user must already
exist or be created in the build environment using the `users` field.

Generally the default is the preferred user to use. There are some
situations where specifying a specific user for the build is preferred,
especially as ongoing work is done to de-privilege the build when
using the QEMU runner; if the build requires a privileged operation like
making a binary setuid, it mey be necessary to specify building as `root`.

Tests are more likely to be situations where running as the non-default
user may be desired.

### users
List of users to inject into the build image

#### username
The name of the user

#### uid
The uid of the user

#### gid
The primary gid of the user

### groups
List of groups to inject into the build image

#### groupname
The name of the group

#### gid
The gid of the grpup

An example creating two users in the same group, and running the build as
one of the users:

```yaml
environment:
  accounts:
    users:
      - username: user_one
        uid: 2000
        gid: 1500
      - username: user_two
        uid: 2001
        gid: 1500
    groups:
      - groupname: webusers
      - gid 1500
    run-as: user_one
```

## environment
environment allows you to control environmental variables to set while running
the pipeline. For example, to set the env variable `CGO_ENABLED` to `0`:

```yaml
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

