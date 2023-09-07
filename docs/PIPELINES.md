# Built-in Pipelines

Melange provides several built-in pipelines to facilitate the process of building
packages for popular ecosystems, such as Python, Perl, and Maven.

## How built-in pipelines are located

Pipelines are invoked in Melange builds by their file path. All built-in pipelines
are located in the [`pkg/build/pipelines` directory](/pkg/build/pipelines/).
Therefore, to consume a pipeline that has a file name of `fetch.yaml` and is
located in the `sample` folder, the syntax in your Melange YAML would be:
```yaml
...
pipeline:
  - uses: sample/fetch
```

## Creating new built-in pipelines

New pipelines can be created by adding YAML files to the [`pkg/build/pipelines` directory](/pkg/build/pipelines/).
Melange needs to be rebuilt before the new pipelines become available. For local
tests, you can install a development version of Melange using `go install .` in the
root directory. For CI builds, it is necessary to bump the melange dependency in
`wolfictl`.

### Bump the Melange dependency on `wolfictl`

To bump the Melange dependency on `wolfictl`:
1. Fork and clone the [wolfi-dev/wolfictl](https://github.com/wolfi-dev/wolfictl)
    repository locally.
1. From the root of the repository, run the following commands:
    ```shell
    go get chainguard.dev/melange@main
    go mod tidy
    ```
1. Submit a pull request with your changes.
1. A new image with your updated version will be created when the image creation
    workflow runs again.

## Ecosystem-specific pipeline documentation

* [go pipelines](PIPELINES-GO.md)
