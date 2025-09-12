
<!-- start:pipeline-reference-gen -->
# Pipeline Reference


- [go/build](#gobuild)
- [go/bump](#gobump)
- [go/covdata](#gocovdata)
- [go/install](#goinstall)

## go/build

Run a build using the go compiler

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| amd64 | false | GOAMD64 microarchitecture level to use  | v2 |
| arm64 | false | GOARM64 microarchitecture level to use  | v8.0 |
| buildmode | false | The -buildmode flag value. See "go help buildmode" for more information.  | default |
| deps | false | space separated list of go modules to update before building. example: github.com/foo/bar@v1.2.3  |  |
| experiments | false | A comma-separated list of Golang experiment names (ex: loopvar) to use when building the binary.  |  |
| extra-args | false | A space-separated list of extra arguments to pass to the go build command.  |  |
| go-package | false | The go package to install  | go |
| ignore-untracked-files | false | If true, we will provide a gitignore that ignore all untracked files.  | true |
| install-dir | false | Directory where binaries will be installed  | bin |
| ldflags | false | List of [pattern=]arg to append to the go compiler with -ldflags |  |
| modroot | false | Top directory of the go module, this is where go.mod lives. Before buiding the go pipeline wil cd into this directory.  | . |
| output | true | Filename to use when writing the binary. The final install location inside the apk will be in prefix / install-dir / output  |  |
| packages | true | List of space-separated packages to compile. Files can also be specified. This value is passed as an argument to go build. All paths are relative to inputs.modroot.  |  |
| prefix | false | Prefix to relocate binaries  | usr |
| strip | false | Set of strip ldflags passed to the go compiler | -w |
| tags | false | A comma-separated list of build tags to append to the go compiler  |  |
| tidy | false | If true, "go mod tidy" will run before the build  | false |
| toolchaintags | false | A comma-separated list of default toolchain go build tags  | netgo,osusergo |
| vendor | false | If true, the go mod command will also update the vendor directory  | false |

## go/bump

Bump go deps to a certain version

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| deps | true | The deps to bump, space separated |  |
| go-version | false | The go version to set the go.mod syntax to |  |
| modroot | false | The root of the module | . |
| replaces | false | The replaces to add to the go.mod file |  |
| show-diff | false | Show the difference between the go.mod file before and after the bump | false |
| tidy | false | Run go mod tidy command before and after the bump | true |
| tidy-compat | false | Set the go version for which the tidied go.mod and go.sum files should be compatible |  |
| work | false | Use go work vendor instead of go mod vendor for projects with go work enabled | false |

## go/covdata

Get coverage data with the covdata go tool

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| cover-dir | false | The GOCOVERDIR path where coverage data files have been generated. It's required to be set as environment variable as well before running the Go binary. | /home/build |
| package | false | The go package to install | go |

## go/install

Run a build using the go compiler

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| amd64 | false | GOAMD64 microarchitecture level to use  | v2 |
| arm64 | false | GOARM64 microarchitecture level to use  | v8.0 |
| experiments | false | A comma-separated list of Golang experiment names (ex: loopvar) to use when building the binary.  |  |
| go-package | false | The go package to install  | go |
| install-dir | false | Directory where binaries will be installed  | bin |
| ldflags | false | List of [pattern=]arg to append to the go compiler with -ldflags |  |
| package | true | Import path to the package  |  |
| prefix | false | Prefix to relocate binaries  | usr |
| strip | false | Set of strip ldflags passed to the go compiler | -w |
| tags | false | A comma-separated list of build tags to append to the go compiler  |  |
| toolchaintags | false | A comma-separated list of default toolchain go build tags  | netgo,osusergo |
| version | false | Package version to install. This can be a version tag (v1.0.0), a commit hash or another ref (eg latest or HEAD).  |  |


<!-- end:pipeline-reference-gen -->