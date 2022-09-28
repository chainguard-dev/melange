## melange build

Build a package from a YAML configuration file

### Synopsis

Build a package from a YAML configuration file.

```
melange build [flags]
```

### Examples

```
  melange build [config.yaml]
```

### Options

```
      --arch strings                architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config.
      --build-date string           date used for the timestamps of the files inside the image
      --dependency-log string       log dependencies to a specified file
      --empty-workspace             whether the build workspace should be empty
      --generate-index              whether to generate APKINDEX.tar.gz (default true)
  -h, --help                        help for build
  -k, --keyring-append strings      path to extra keys to include in the build environment keyring
      --out-dir string              directory where packages will be output (default "/Users/strongjz/Documents/code/go/src/github.com/chainguard-dev/melange/packages")
      --overlay-binsh string        use specified file as /bin/sh overlay in build environment
      --pipeline-dir string         directory used to store defined pipelines (default "/usr/share/melange/pipelines")
  -r, --repository-append strings   path to extra repositories to include in the build environment
      --signing-key string          key to use for signing
      --source-dir string           directory used for included sources
      --template string             template to apply to melange config (optional)
      --use-proot                   whether to use proot for fakeroot
      --workspace-dir string        directory used for the workspace at /home/build
```

### SEE ALSO

* [melange](melange.md)	 - 

