<!-- start:pipeline-reference-gen -->
# Pipeline Reference


- [goreleaser/build](#goreleaserbuild)

## goreleaser/build

Run a build using the GoReleaser

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| args | false | List of space-separated args to pass to the GoReleaser `release` command.  |  |
| config-file | false | Path to the GoReleaser config file. If not specified, the default config file will be used.  |  |
| output | true | Filename to use when writing the binary. The final install location inside the apk will be in /usr/bin by default.  | ${{targets.contextdir}}/usr/bin/${{package.name}} |
| skip | true | List of comma-separated skip values to pass to the GoReleaser `release` command.  | docker,ko,publish |
| snapshot | false | If true, the GoReleaser `release` command will be run with the `--snapshot` flag.  | false |
| working-dir | false | Top directory of the go module, this is where go.mod lives. Before buiding the go pipeline wil cd into this directory.  | . |


<!-- end:pipeline-reference-gen -->