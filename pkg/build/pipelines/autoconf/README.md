<!-- start:pipeline-reference-gen -->
# Pipeline Reference


- [autoconf/configure](#autoconfconfigure)
- [autoconf/make-install](#autoconfmake-install)
- [autoconf/make](#autoconfmake)

## autoconf/configure

Run autoconf configure script

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| build | false | The GNU triplet which describes the build system.  | ${{host.triplet.gnu}} |
| dir | false | The directory containing the configure script.  | . |
| host | false | The GNU triplet which describes the host system.  | ${{host.triplet.gnu}} |
| opts | false | Options to pass to the ./configure command.  |  |

## autoconf/make-install

Run autoconf make install

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| dir | false | The directory containing the Makefile.  | . |
| opts | false | Options to pass to the make command.  |  |

## autoconf/make

Run autoconf make

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| dir | false | The directory containing the Makefile.  | . |
| opts | false | Options to pass to the make command.  |  |


<!-- end:pipeline-reference-gen -->