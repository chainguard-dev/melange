# Defining and using custom pipelines

Melange allows one to create additional / custom pipelines to cover needs that
built-in pipelines do not cover. This document covers how to define additional
pipelines, and then how to use them.

## Defining custom pipelines

You define new pipelines by creating a yaml definition for it, you can find an
[example conditional](../examples/conditional.yaml) that shows how you would
define a custom pipeline. The convention here is that by naming the pipeline
(in this case `conditional.yaml`) means that it will then be available for use
in your definitions as `conditional`, for example:

```yaml
pipeline:
  - uses: conditional
```

## Defining the location for custom pipelines

Now that you have defined your custom pipeline, you can then point melange at
them by invoking melange with `--pipeline-dir` flag. If for example your custom
pipelines were at: `/home/custom/pipelines`, you would invoke melange by
specifying that flag like this:

```shell
steps:
- name: Build melange package with custom pipelines
  run: ./melange build --pipeline-dir=/home/custom/pipelines/ ...
```

