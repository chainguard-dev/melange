# e2e-tests
.yaml files in this directory will be built by melange via
the 'run-tests' script.

Melange options are based on yaml file name.

 * `*-build.yaml`: run 'melange build'
 * `*-test.yaml`: run 'melange test'
 * `*-build-test`: run 'melange build && melange test'

    If the yaml file name matches '*-nopkg', then the flag `--test-package-append`
    will be appended for `busybox` and `python-3`.  The intent of these tests
    is to verify that the test-package-append works.
