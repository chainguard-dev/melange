<!-- start:pipeline-reference-gen -->
# Pipeline Reference


- [cargo/build](#cargobuild)

## cargo/build

Compile an auditable rust binary with Cargo

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| install-dir | false | Directory where binaries will be installed  | bin |
| jobs | false | Override the number of parallel jobs. It defaults to the number of CPUs.  |  |
| modroot | false | Top directory of the rust package, this is where the target package lives. Before building, the cargo pipeline wil cd into this directory. Defaults to current working directory  | . |
| opts | false | Options to pass to cargo build. Defaults to release  | --release |
| output | false | Filename to use when writing the binary. The final install location inside the apk will be in prefix / install-dir / output  |  |
| output-dir | false | Directory where the binaris will be placed after building. Defaults to target/release  | target/release |
| prefix | false | Installation prefix. Defaults to usr  | usr |
| rustflags | false | Rustc flags to be passed to pass to all compiler invocations that Cargo performs. In contrast with cargo rustc, this is useful for passing a flag to all compiler instances. This string is split by whitespace.  |  |


<!-- end:pipeline-reference-gen -->