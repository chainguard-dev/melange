<!-- start:pipeline-reference-gen -->
# Pipeline Reference


- [split/alldocs](#splitalldocs)
- [split/bin](#splitbin)
- [split/debug](#splitdebug)
- [split/dev](#splitdev)
- [split/infodir](#splitinfodir)
- [split/lib](#splitlib)
- [split/locales](#splitlocales)
- [split/manpages](#splitmanpages)
- [split/static](#splitstatic)

## split/alldocs

Split all docs

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| package | false | The package to split all docs from  |  |

## split/bin

Split executable files

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| package | false | The package to split executable files from  |  |

## split/debug

Split debug files

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| package | false | The package to split debug files from  |  |

## split/dev

Split development files

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| package | false | The package to split development files from  |  |

## split/infodir

Split GNU info pages

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| package | false | The package to split info pages files from  |  |

## split/lib

Split shared library files

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| package | false | The package to split shared library files from  |  |
| paths | false | Optional newline-separated additional paths to search for shared libraries. By default, searches lib/ and usr/lib/. This adds to those defaults. Example:   usr/lib64   opt/lib searches usr/lib64/ and opt/lib/ in addition to the defaults  |  |
| patterns | false | Optional newline-separated patterns to filter library files. If provided, matches lib<pattern>.so.* for each pattern. If not provided, matches all *.so.* files. Example:   ssl   crypto matches libssl.so.* and libcrypto.so.*  |  |

## split/locales

Split locales

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| package | false | The package to split locales from  |  |

## split/manpages

Split manpages

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| package | false | The package to split manpages from  |  |

## split/static

Split static library files

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| package | false | The package to split static library files from  |  |


<!-- end:pipeline-reference-gen -->