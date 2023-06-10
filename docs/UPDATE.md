# Update

`update:` provides information on how a melange package can be updated either manually or using automation for example as the [Wolfi project does](https://github.com/wolfi-dev/wolfictl/blob/main/docs/update.md).

__IMPORTANT:__ Adding update configuration does not mean melange package will be kept up to date, it is a way to describe "how"
it can be updated.

There are currently two ways to describe where to search for latest versions of a package.

 1. `release-monitor:` to query https://release-monitoring.org/
 2. `github:` to query https://github.com via it's graphql API

## Release Monitor

This is a service that matched a package with an identifier.  The melange config should describe the Identifier in https://release-monitoring.org/

```yaml
package:
  name: alsa-lib
  version: 1.2.8

...

update:
  enabled: true # provide a flag to easily prevent a package from receiving auto update PRs
  manual: true # indicates that this package should be manually updated, usually taking care over special version numbers which can be hard to automate
  shared: false # indicate that an update to this package requires an epoch bump of downstream dependencies, e.g. golang, java
  release-monitor:
    identifier: 38 # Mandatory, ID number for release monitor
    strip-prefix: v # Optional, if the version obtained from the update service contains a prefix which should be ignored
    strip-suffix: ignore_me # Optional, if the version obtained from the update service contains a suffix which should be ignored
```

## GitHub

This assumes you are using the graphql API and the Identifier matches the organisation/repositoryname

```yaml
package:
  name: cosign
  version: 2.0.0
  epoch: 0

...

update:
  enabled: true # provide a flag to easily toggle a package from receiving auto update PRs
  manual: true # indicates that this package should be manually updated, usually taking care over special version numbers which can be hard to automate
  shared: false # indicate that an update to this package requires an epoch bump of downstream dependencies, e.g. golang, java
  github: # alternative today is `release_monitor:`
    identifier: sigstore/cosign # Mandatory, org/repo for github
    strip-prefix: v # Optional, if the version obtained from the update service contains a prefix which should be ignored
    strip-suffix: ignore_me # Optional, if the version obtained from the update service contains a suffix which should be ignored
    use-tag: true # Optional, override the default of using a GitHub release to identify related tag to fetch.  Not all projects use GitHub releases but just use tags
    tag-filter: foo # Optional, filter to apply when searching tags on a GitHub repository, some repos maintain a mixture of tags for different major versions for example
```

## Ignore versions

Some upstream projects create tags that can interfere with version comparisons, you may find the need to ignore these.

To achieve this you can specify a list of regex patterns to identify versions that you want to ignore:

```yaml
update:
  enabled: true
  ignore-regex-patterns:
    - "ignore_me*"
    - "*ignore_me"
```
