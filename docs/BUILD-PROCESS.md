# Melange Build Process

This document describes the Melange build process.

## `melange.yaml`

The melange yaml file consists of the following components that are key to the build process. Note that this is not
the official or a comprehensive `melange.yaml` reference.

* `package.target-architectures`: describes which architectures to build for (if empty, build for all available archs).
* `package.dependences.runtime`: list of apk packages that need to be available in the final apk package, hence `runtime`.
* `environment.contents`: list of apk packages and their source repositories that need to be available during the build, but not in the final apk package.
* `pipeline`: list of steps to execute during the build.

For examples, see the [examples directory](../examples/).

Note that each step in the `pipeline` can be a `runs`, step, which executes commands, or it can be a `uses` step, which
runs yet another pipeline. Each such pipeline optionally can declare that it needs certain apk packages available
at build time to run its steps. For example, the built-in pipeline [`fetch`](../pipelines/fetch.yaml) needs the `wget` package:

```yaml
needs:
  packages:
    - wget
```

## Where does Melange build?

The melange build process involves three normally distinct directories.

* Source directory: Location of your sources for building the apk. It defaults to your current directory.
* Guest directory: Directory where the build process will occur, including laying down packages and placing your compiled source.
* Workspace directory: Directory where your sources will be copied over to enable working with, compiling and manipulating them without changing your actual sources.

The usage of the directories is:

1. Create a guest directory, normally in `/tmp` space, and lay out all of the package contents.
1. Create the workspace directory, copy your sources over to it.
1. Bind-mount the workspace directory into the guest as `{GUEST_DIR}/home/build`.
1. Run the build process in the guest.

For example, if our source directory is `/home/user/src` with 3 files `main.go`, `go.mod` and `go.sum`; our guest
directory is `/tmp/guest` with busybox as a dependency, and our workspace is `/tmp/ws`, then:

```
/home/user/src                <-- source directory
/home/user/src/main.go        <-- original file in source
/home/user/src/go.mod         <-- original file in source
/home/user/src/go.sum         <-- original file in source

/tmp/ws                       <-- workspace directory, bind-mounted to runner:/home/build
/tmp/ws/main.go               <-- copied from source directory
/tmp/ws/go.mod                <-- copied from source directory
/tmp/ws/go.sum                <-- copied from source directory

/tmp/guest                     <-- temporary guest directory created by melange
/tmp/guest/bin                 <-- files and dirs created by apk package dependencies
/tmp/guest/bin/busybox         <-- files and dirs created by apk package dependencies
/tmp/guest/home/build          <-- bind-mounted from workspace at /tmp/ws
/tmp/guest/home/build/main.go  <-- file bind-mounted from workspace at /tmp/ws
/tmp/guest/home/build/go.mod   <-- file bind-mounted from workspace at /tmp/ws
/tmp/guest/home/build/go.sum   <-- file bind-mounted from workspace at /tmp/ws
```

Details of how the above happens follows below.

Note that because the workspace is bind-mounted into the guest, changes due to the pipeline
are persisted in the workspace directory, and not erased when the guest is removed during cleanup.
Normally, the workspace is removed as well, but if you set the workspace directory as the same as
the source directory, then the workspace is not removed, and all changes due to the build process
persist.

## Building a Package

The build process is as follows. The core routine is [`BuildPackage()`](../pkg/build/build.go#L716).

1. Evaluate each step in the pipeline to see if it has a `needs` section. If so, then add its listed packages to the build time package requirements defined in `environment.contents`.
1. Use [apko](https://github.com/chainguard-dev/apko) to create a tar stream of the packages listed in `environment.contents` and lay them out onto the workspace directory.
1. Overlay `/bin/sh`. This is an optimization step, and is not discussed here. Read [Shell Overlay](./SHELL-OVERLAY.md) for more information.
1. Populate the build cache. This is an optimization step, and is not discussed here. Read [Build Cache](./BUILD-CACHE.md) for more information.
1. Create the workspace directory and bind-mount it into the guest at `/home/build`.
1. Populate the workspace. This copies over all of the files from the source directory to the workspace. Note that some files or directories can be excluded or ignored from copying to the workspace.
1. Execute each step in the pipelines inside the workspace. This is done by:
   1. Checking if the step is a `uses`. If so, execute `Run()` on it.
   1. If it is a `runs`, then execute the commands in the step.
1. Build any subpackages using the same process.
1. Emit the final apk package as a `.apk` file.
1. Emit any subpackages as `.apk` files.
1. Clean up guest and workspace directories.
1. If requested an index, generate and sign `APKINDEX`.

## Containing the Build

All of the build takes place within the guest directory. While apk packages can be simply laid out,
the pipeline runs steps may modify files outside of the workspace directory. They further may assume that
certain dependencies are in "standard" locations, e.g. `/usr/bin/gcc`, while the actual installation
is relative to the workspace directory, e.g. `${GUEST_DIR}/usr/bin/gcc`.

To resolve this issue and contain the build, all run commands are executed inside a virtual container
created by [bubblewrap](https://github.com/containers/bubblewrap)/. The root filesystem for this
container is the guest directory, placing everything in its proper location.

bubblewrap, or the `bwrap` command, itself is used when the actual `runs` command in each pipeline is executed.

## Alternate Architectures

When melange builds for the architecture on which it is running - amd64 on amd64, arm64 on arm64, riscv64 on riscv64
etc. - all `runs` commands inside pipelines run natively on the processor.

On the other hand, when building for alternative architecture, e.g. for arm64 while on amd64, the commands are run
using [binfmt_misc](https://en.wikipedia.org/wiki/Binfmt_misc) user-mode emulation.

melange does not need to do anything to make this work, provided `binfmt_misc` is installed on the host system.
