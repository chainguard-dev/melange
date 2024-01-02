# Testing

Melange provides an ability to test packages with a `test` command. Tests are
implemented using the same `pipeline`, and `subpackages` centric ways to define
tests, so it should be very familiar continuation from `build` to `test`.

## Overview

The keyword `test:` starts a new test block, and can be embedded either at the
top level, or inside a subpackage. You can test the 'main' package, and
subpackages, or any combination of them. Each `test` block has a section for
specifying the test configuration including the necessary packages, (partly to
ensure the minimal set of packages, and therefore testing runtime dependencies
definitions), as well as any environmental variables. This section again, looks
exactly like a build pipelines, and therefore should feel very familiar.

### Test environment (workspace)

Just like with the build, there is a single shared `workspace` that gets mounted
as the `CWD` for each of the `test` runs. You can add any test fixtures, for
example, if you are testing some python packages, you could create `foo-test.py`
file, and by using a `--source-dir` pointing to the directory, the files in that
directory will then be available for your tests in the current directory. For
example, say you are testing `py3-pandas` package, and would like to exercise
some data transformations, you could create a file
`/tmp/testfiles/pandas-test.py`:

```python
import numpy as np
import pandas as pd
s = pd.Series([1,3,5,np.nan, 6, 8])
dates = pd.date_range("20130101", periods=6)
df = pd.DataFrame(np.random.randn(6, 4), index=dates, columns=list("ABCD"))
```

Then you could make sure this file ends up in your workspace as
`./pandas-test.py` by specifying `--source-dir /tmp/testfiles`

### Execution environment (guest)

Unlike a `build` guest, each `test` will get their own "fresh" container built
using apko that only contains the Package Under Test (PUT), that is defaulted to
each container depending on the context, as well as any additional packages
specified in the `test.environment.contents.packages`. For example, the "main"
`test` pipeline will get the main package added by default. For subpackages, the
subpackage that has the `test` block gets added by default.

For example, with a test environment like this for the main package
(for example, `py3-pandas`):
```yaml
package:
  name: py3-pandas
# Stuff omitted for readability
test:
  environment:
    contents:
      packages:
        - busybox
        - python-3
```

Will get a test execution containing the following packages (and their
transitive dependencies as per apk solver):
 * py3-pandas
 * busybox
 * python-3

And a subpackage test like this:
```yaml
package:
  name: php-8.2-msgpack
# Again stuff omitted for readability
subpackages:
  - name: ${{package.name}}-dev
    description: PHP 8.2 msgpack development headers
    test:
      environment:
        contents:
          packages:
            - busybox
            - wolfi-base
      pipeline:
        - runs: |
            # Just make sure the expected define is in the expected file
            # location.
            grep PHP_MSGPACK_VERSION /usr/include/php/ext/msgpack/php_msgpack.h
```

This will get a test execution containing the following packages (and their
transitive dependencies as per apk solver):
 * php-8.2-msgpack
 * busybox
 * wolfi-base

### Execution environment, repo configuration

Because we use the apk solver, and apko to build the guest containers, it's easy
to configure if you are testing either local, or remote, or combination of the
packages by simply configuring the appropriate repos. By using these, you can
easily add tests to existing packages without having to rebuild them, or fetch
them directly and juggle them. You can also iterate on the package and tests at
the same time, by rebuilding your local package (and ofc adding the repo
configuration for it). Because we rely on the normal apk solver rules for
figuring out which package to install into the guest context, it is flexible
enough to test whatever combinations of packages that you want to test with.

As discussed above, you can specify which packages are tested, as well as which
packages a particular test needs to perform the tests (for example, you could
try to `curl` a URL to test a package, so that would require curl). You can
configure these with `--keyring-append` as well as `--repository-append`
variables. As usual by default the "highest" one wins, so if you are testing
local changes to a package, you can build a local version, and by bumping the
epoch it will become the PUT, or you can configure/test PUT dependencies this
way (build a local copy, and it will be picked up by APK resolver). This is very
similar to how we build/test images with local versions of packages, so again,
this should feel very natural.

### Execution environmnent, specifying extra test packages

If you want to have a minimal test specification, and tests need a package, you
can specify `--test-package-append` (you can specify multiple times), so that
you don't need to include those in your `test.environment.contents.packages`.
Note that these packages are added to each test environment (including
subpackages).

### Where to define the tests?

So, this is one open question, but the short answer is that you can add these
tests inline with the existing yaml files that specify the build, OR you can
define them in alternate location. Because of the way the melange configuration
parsing currently works, you may need to add some "placeholders" to satisfy
the configuration parser. For example, here's a simple test file that I've been
using to test things that has some "placeholder" fields that are not really
actually used, but will allow one to decouple the test/build file if that's the
direction we want to go:

```yaml
package:
  name: php-8.2-msgpack
  version: 2.2.0
  epoch: 0
  description: "Tests for PHP extension msgpack"
  copyright:
    - license: BSD-3-Clause

# This is mandatory, so just put an empty one there. Otherwise, config parsing
# will fail.
pipeline:

test:
  environment:
    contents:
      packages:
        - wolfi-base
        - apk-tools
  pipeline:
    - runs: |
        # Stuff goes here.
```

## Using pipelines

Not surprisingly you can also use predefined pipelines, just like in the build
step by using `uses:` instead of `runs:`. You can specify the location of the
predefined pipelines using the `--pipeline-dir` to point to the directory where
the custom pipelines are located.

## Specifying package to test / reusing tests

You can leave out the package name from the command line if you want, in which
case the PUT is pulled from the package.Name. However, for versioned packages,
say for example, php-8.1, php-8.2, php-8.3, it is beneficial to reuse some of
the tests. In those cases, you can specify the testfile and also which package
to use for testing by providing a second argument to the `test` command that is
the name of the package used for the tests.

Lastly, if you want to test a specific version of the package, you can specify
the constraint in the argument. For example:

 * Use package.Name

 ```shell
 melange test ./testfile.yaml
 ```

 * Use above testfile, but a different package to run tests against

 ```shell
 melange test ./testfile.yaml mypackage
 ```

 * Use above testfile, but specify a particular version of the package

 ```shell
 melange test ./testfile.yaml mypackage=2.2.0-r2
 ```

## Full example

Here's a full example invocation, where I'm testing with my local mac, so just
testing the aarch64 (hence `--arch aarch64`` flag), and I'm pulling in the
abovementioned `py3-pandas-test.yaml` file as specified from the current
directory, and I do want to test the py3-pandas package (second argument), and
the keyring/repository append flags pull in my local changes, so that I can
iterate on package building, as well as testing at the same time. If you are
only writing tests for existing packages, you could drop the "local"
keyring/repository, and then only released packages would be pulled in for
testing.

```shell
melange test ./py3-pandas-test.yaml py3-pandas \
--source-dir /tmp/testfiles --arch aarch64 \
--keyring-append /Users/vaikas/projects/go/src/github.com/wolfi-dev/os/local-melange.rsa.pub \
--repository-append /Users/vaikas/projects/go/src/github.com/wolfi-dev/os/packages \
--repository-append https://packages.wolfi.dev/os \
--keyring-append https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
```
