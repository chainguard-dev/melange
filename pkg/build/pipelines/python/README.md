<!-- start:pipeline-reference-gen -->
# Pipeline Reference


- [python/build-wheel](#pythonbuild-wheel)
- [python/build](#pythonbuild)
- [python/import](#pythonimport)
- [python/install](#pythoninstall)
- [python/test](#pythontest)

## python/build-wheel

Build a Python wheel

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |

## python/build

Build a Python wheel

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |

## python/import

Test a python package import, with optional from clause

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| from | false | The package to import from (used with 'from <from> import <import>'). Deprecated, use 'imports' instead.  |  |
| import | false | The package to import. Deprecated, use 'imports' instead.  |  |
| imports | false | Commands to import packages, each line is a separate command. Example:   from libfoo import bar   # test that otherthing can be imported from asdf   from asdf import otherthing   import bark # this is like woof  full-line and inline comments are supported via '#'  |  |
| python | false | Which python to use | DEFAULT |

## python/install

Install a Python package

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |

## python/test

Test a python package

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| command | true | The command to run.  |  |


<!-- end:pipeline-reference-gen -->