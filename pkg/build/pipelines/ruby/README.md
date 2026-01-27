<!-- start:pipeline-reference-gen -->
# Pipeline Reference


- [ruby/build](#rubybuild)
- [ruby/clean](#rubyclean)
- [ruby/install](#rubyinstall)
- [ruby/require](#rubyrequire)
- [ruby/test](#rubytest)

## ruby/build

Build a ruby gem

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| dir | false | The working directory  | . |
| gem | true | Gem name  |  |
| opts | false | Options to pass to gem build  |  |
| output | false | Gem output filename  |  |

## ruby/clean

Clean a ruby gem

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |

## ruby/install

Install a ruby gem

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| dir | false | The working directory  | . |
| gem | false | Gem name  |  |
| gem-file | false | The full filename of the gem to build  |  |
| opts | false | Options to pass to the gem install command  |  |
| version | true | Gem version to install. This can be a version tag (1.0.0)  |  |

## ruby/require

Test a Ruby package require, with optional load clause

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| require | false | The package to require.  |  |
| requires | false | Commands to require packages, each line is a separate command. Example:   require 'foo'   # test that otherthing can be required from asdf   require 'asdf'   require 'bark' # this is like woof  full-line and inline comments are supported via '#'  |  |
| ruby | false | Which Ruby to use | DEFAULT |
| version | false | Which Ruby version to use | 3.2 |

## ruby/test

Test a Ruby package

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| command | true | The command to run.  |  |


<!-- end:pipeline-reference-gen -->