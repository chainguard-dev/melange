# Update

`update:` provides information on how a melange package can be updated either manually or using automation for example as the [Wolfi project does](https://github.com/wolfi-dev/wolfictl/blob/main/docs/update.md).

__IMPORTANT:__ Adding update configuration does not mean melange package will be kept up to date, it is a way to describe "how"
it can be updated.

There are currently two ways to describe where to search for latest versions of a package.

 1. `release-monitor:` to query https://release-monitoring.org/
 2. `github:` to query https://github.com via it's graphql API
 3. `git:` to query local git checkout

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
  require-sequential: true # Default: false - indicates that automated pull requests should be merged in order rather than superseding and closing previous unmerged PRs
  release-monitor:
    identifier: 38 # Mandatory, ID number for release monitor
    strip-prefix: v # Optional, if the version obtained from the update service contains a prefix which should be ignored
    strip-suffix: ignore_me # Optional, if the version obtained from the update service contains a suffix which should be ignored
    version-filter-prefix: v17.2 # Optional, filter to apply when searching versions with a prefix
    version-filter-contains: foo # Optional, filter to apply when searching versions with any match
```

## GitHub

This assumes you are using the graphql API and the Identifier matches the organisation/repositoryname.  The default behaviour is to use the GitHub Releases API as this returns a richer set of data.  This can be changed below with `use-tag: true`.

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
  require-sequential: true # Default: false - indicates that automated pull requests should be merged in order rather than superseding and closing previous unmerged PRs
  github: # alternative today is `release_monitor:`
    identifier: sigstore/cosign # Mandatory, org/repo for github
    strip-prefix: v # Optional, if the version obtained from the update service contains a prefix which should be ignored
    strip-suffix: ignore_me # Optional, if the version obtained from the update service contains a suffix which should be ignored
    use-tag: true # Optional, override the default of using a GitHub release to identify related tag to fetch.  Not all projects use GitHub releases but just use tags
    tag-filter: foo # Deprecated: Use tag-filter-prefix instead
    tag-filter-prefix: v17.2 # Optional, filter to apply when searching tags with a prefix on a GitHub repository, some repos maintain a mixture of tags for different major versions for example
    tag-filter-contains: foo # Optional, filter to apply when searching tags with any match on a GitHub repository, some repos maintain a mixture of tags for different major versions for example
```

## Git

Git uses vanilla git to check for updates.  This is useful for projects that use unsupported Git Provider APIs.

The git repository queried is the first repository specified in the `pipeline: / uses: git-checkout` section of the melange config.

It is recommended to use a `schedule` as described below when using Git as this is a less performant approach to using APIs such as GitHub and Release Monitoring.

```yaml
update:
  enabled: true
  git: {} # no specialized version handling required
  schedule:
    period: daily # options are daily|weekly|monthly
    reason: upstream project does not support tags or releases
```

```yaml
update:
  enabled: true
  git:
    tag-filter-prefix: v17.2
    strip-prefix: v
    strip-suffix: ignore_me
    tag-filter-contains: foo
  schedule:
    period: daily
    reason: upstream project does not support tags or releases
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

## Version Transform

Some projects create tags than are not compliance with apk format. You can manipulate this with regex on `version-transform` section.

Example:

```patch
 package:
   name: owfs
-  version: 3.2.3
+  version: 3.2p4
   epoch: 0
```

With this version
```yaml
update:
  enabled: true
  version-transform:
    - match: p(\d+)$
      replace: .${1}
```

the next update pr will be like:

```patch
 package:
   name: owfs
-  version: 3.2.3
+  version: 3.2.4
   epoch: 0
```

# Schedule

Schedule describes how often tooling should check for an update, this overrides any default behaviour provided by an update service.

```yaml
update:
  enabled: true
  github:
    identifier: sigstore/cosign 
  schedule:
    period: daily # options are daily|weekly|monthly
```
