# Built-in go Pipelines

Melange includes built-in pipelines to compile go projects. The first one, 
`go/build` gives authors more control on the compiler invocation while
`go/install` focuses on simplicity.

To get started quickly, we offer two working examples:
[go-build.yaml](https://github.com/chainguard-dev/melange/blob/main/examples/go-build.yaml) 
and
[go-install.yaml](https://github.com/chainguard-dev/melange/blob/main/examples/go-install.yaml)

## Simple and quick builds with `go/install`

For projects not needing sophisticated interactions with `go build` or control
over how source is downloaded, `go/install` provides a quick and simple way to
compile any publicly available go project.

Internally `go/install` is an interface to the `go install` command. It will
download the source code and dependencies and build them. Any produced binaries
will be installed into the specified directory.

Here's a sample of a one-shot compilation of an example project:

```yaml
package:
  name: hello
  version: v0.0.1
  epoch: 0
  description: "A project that will greet the world infinitely"
environment:
  contents:
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    repositories:
      - https://packages.wolfi.dev/os
pipeline:
  - uses: go/install
    with:
      package: github.com/puerco/hello
      version: HEAD
```

(:bulb: Experiment with this code, 
[download it from the examples directory](https://github.com/chainguard-dev/melange/blob/main/examples/go-install.yaml))

## Building golang projects with `go/build`

The `go/build` pipeline is a declarative interface to the `go build` command.
This pipeline executes `go build` on already installed or cloned go projects. It 
can compile more than one package and the collection and installation of
built artifacts is manual.

Here's a sample melange configuration file cloning and running the same
sample project as above:

```yaml
package:
  name: hello
  version: v0.0.1
  epoch: 0
  description: "A project that will greet the world infinitely"
environment:
  contents:
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    repositories:
      - https://packages.wolfi.dev/os
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/uservers/miniprow.git
      destination: build-dir
  - run: |
      git checkout ${{package.version}}
  - uses: go/build
    with:
      modroot: build-dir
      tags: enterprise
      packages: main.go
      output: hello
```

(:bulb: Experiment with this code, 
[download it from the examples directory](https://github.com/chainguard-dev/melange/blob/main/examples/go-build.yaml))

## Build Parameters

Both `go/install` and `go/build` support passing a few parameters to the go
compiler by setting them in the melange configuration file. As of this writing,
you can define the following values:

```yaml
  tags:
    description: |
      A comma-separated list of build tags to pass to the go compiler
      
  ldflags:
    description:
      List of [pattern=]arg to pass to the go compiler with -ldflags
```

For the most up to date supported features check the
[buid](https://github.com/chainguard-dev/melange/blob/main/pkg/build/pipelines/go/build.yaml)
and
[install](https://github.com/chainguard-dev/melange/blob/main/pkg/build/pipelines/go/install.yaml)
pipeline definitions. Feel free to request more features in
the built-in pipelines by
[filing a new issue](https://github.com/chainguard-dev/melange/issues/new) in 
the melange repository!
