<!-- start:pipeline-reference-gen -->
# Pipeline Reference


- [pecl/install](#peclinstall)
- [pecl/phpize](#peclphpize)

## pecl/install

Installs and enables a PHP PECL module.

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| extension | true | Name of the PECL extension to install. |  |

## pecl/phpize

PHP phpize and configure a PHP PECL module. Requires php-dev version to be installed.

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| php-config | false | php-config to use | php-config |
| prefix | false | prefix to use for configure | /usr |


<!-- end:pipeline-reference-gen -->