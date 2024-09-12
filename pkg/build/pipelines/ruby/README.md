<!-- start:pipeline-reference-gen -->
# Pipeline Reference


- [ruby/build](#rubybuild)
- [ruby/clean](#rubyclean)
- [ruby/install](#rubyinstall)

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


<!-- end:pipeline-reference-gen -->