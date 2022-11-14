# Shell Overlay

When melange builds for the architecture on which it is running - amd64 on amd64, arm64 on arm64, riscv64 on riscv64
etc. - all `runs` commands inside pipelines run natively on the processor.

On the other hand, when building for alternative architecture, e.g. for arm64 while on amd64, the commands are run
using [binfmt_misc](https://en.wikipedia.org/wiki/Binfmt_misc) user-mode emulation.

While this does work, it can be slow, sometimes painfully so.

To speed up this process, we have the option to replace the actual `/bin/sh` shell used to execute commands with
one for the native architecture. As shell scripts are just interpreted languages, this is a valid approach.

When setting a shell overlay via `--overlay-binsh <shell>`, melange will copy the `<shell>` provided into the workspace.
This replacement shell is expected to be for the actual host architecture, rather than the target architecture.
Since it is the host's architecture, it will execute at native speed.

To highlight how this works, look at this sample partial `melange.yaml` file:

```yaml
package:
  name: shelltest
  version: 0
  epoch: 0
  description: "a hello world program"
  target-architecture:
    - riscv64
    - amd64
  dependencies:
    runtime:

environment:
  contents:
    repositories:
      - https://dl-cdn.alpinelinux.org/alpine/edge/main
    packages:
      - busybox

pipeline:
  - runs: |
        echo "Hello World"
        cat /etc/os-release
```

If I run this naively on an `amd64` machine, then two packages will be built, one each for amd64 and riscv64.

The `amd64` build will run the two commands each in `/bin/sh` as available from the `busybox` package. Since
we are running on `amd64`, these shell commands will execute at native speed.

When it comes to building the `riscv64` package, the `/bin/sh` installed in the workspace from the `busybox` package
is for `riscv64`. Running the two commands in the pipeline requires the kernel to use user-mode emulation
via `binfmt_misc`.

We can speed this up significantly by building for `riscv64`, but using an `amd64` `/bin/sh` to interpret the shell
commands. To do this, we can use the `--overlay-binsh /bin/sh` option, which tells melange, "copy my local `/bin/sh`
which is compiled for my native processor architecture `amd64`, into the workspace, and use that for interpreting
shell commands." This means that all shell commands get executed at native speed.