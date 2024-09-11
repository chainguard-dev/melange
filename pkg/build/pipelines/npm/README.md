<!-- start:pipeline-reference-gen -->
# Pipeline Reference

## npm/install

Install a portable npm package.

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| overrides | false | Space, comma or newline-separated list of package@version to use in npm overrides, e.g. "yargs@^17.0.0 get-stdin@^9.0.0".  |  |
| package | true | The name of the package to npm install.  |  |
| prefix | false | The -prefix argument to pass to npm install; where /bin and /lib will be copied to.  | ${{targets.contextdir}}/usr/ |
| version | true | The version of the package to npm install.  |  |


<!-- end:pipeline-reference-gen -->