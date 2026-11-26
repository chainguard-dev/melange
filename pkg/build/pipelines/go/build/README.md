<!-- start:pipeline-reference-gen -->
# Pipeline Reference


- [go/build/v2](#gobuildv2)

## go/build/v2

Run a build using the go compiler

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| amd64 | false | GOAMD64 microarchitecture level to use  | v2 |
| arm64 | false | GOARM64 microarchitecture level to use  | v8.0 |
| buildmode | false | The -buildmode flag value. See "go help buildmode" for more information.  | default |
| experiments | false | A comma-separated list of Golang experiment names (ex: loopvar) to use when building the binary.  |  |
| extra-args | false | A space-separated list of extra arguments to pass to the go build command.  |  |
| ignore-untracked-files | false | If true, we will provide a gitignore that ignore all untracked files.  | true |
| install-dir | false | Directory where binaries will be installed  | bin |
| ldflags | false | List of [pattern=]arg to append to the go compiler with -ldflags  |  |
| modroot | false | Top directory of the go module, this is where go.mod lives. Before buiding the go pipeline wil cd into this directory.  | . |
| output | false | Filename to use when writing the binary. The final install location inside the apk will be in prefix / install-dir / output. This is optional, by default the name of the package is used.  |  |
| packages | false | List of space-separated packages to compile. Files can also be specified. This value is passed as an argument to go build. All paths are relative to inputs.modroot. Can be multiple packages. Defaults to "." build current package. To build all packages use "./...".  | . |
| prefix | false | Prefix to relocate binaries  | usr |
| strip | false | Set of strip ldflags passed to the go compiler  | -w |
| tags | false | A comma-separated list of build tags to append to the go compiler  |  |
| toolchaintags | false | A comma-separated list of default toolchain go build tags  | netgo,osusergo |
| vendor | false | If true, the go mod command will also update the vendor directory  | false |


<!-- end:pipeline-reference-gen -->