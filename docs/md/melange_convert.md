---
title: "melange convert"
slug: melange_convert
url: /docs/md/melange_convert.md
draft: false
images: []
type: "article"
toc: true
---
## melange convert

EXPERIMENTAL COMMAND - Attempts to convert packages/gems/apkbuild files into melange configuration files

### Synopsis

Convert is an EXPERIMENTAL COMMAND - Attempts to convert packages/gems/apkbuild files into melange configuration files
								Check that the build executes and builds the apk as expected, using the wolfi-dev/sdk to test the install of built apk
								Dependencies are recursively generated and a lot of assumptions are made for you, there be dragons here.
							

### Options

```
      --additional-keyrings stringArray       additional repositories to be added to convert environment config
      --additional-repositories stringArray   additional repositories to be added to convert environment config
  -h, --help                                  help for convert
  -o, --out-dir string                        directory where convert config will be output (default "./generated")
      --wolfi-defaults                        if true, adds wolfi repo, and keyring to config (default true)
```

### SEE ALSO

* [melange](/docs/md/melange.md)	 - 
* [melange convert apkbuild](/docs/md/melange_convert_apkbuild.md)	 - Converts an APKBUILD package into a melange.yaml
* [melange convert gem](/docs/md/melange_convert_gem.md)	 - Converts an gem into a melange.yaml
* [melange convert python](/docs/md/melange_convert_python.md)	 - Converts a python package into a melange.yaml

