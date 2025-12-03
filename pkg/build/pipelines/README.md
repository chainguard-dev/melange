# Melange pipelines

This directory contains built-in pipelines. For more information on how to add
new built-in pipelines, consult [Creating a new built-in pipeline](/docs/PIPELINES.md#creating-new-built-in-pipelines).

<!-- start:pipeline-reference-gen -->
# Pipeline Reference


- [fetch](#fetch)
- [git-checkout](#git-checkout)
- [patch](#patch)
- [strip](#strip)

## fetch

Fetch and extract external object into workspace

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| delete | false | Whether to delete the fetched artifact after unpacking.  | false |
| directory | false | The directory to extract the artifact into (passed to `tar -C`)  | . |
| dns-timeout | false | The timeout (in seconds) to use for DNS lookups. The fetch will fail if the timeout is hit.  | 20 |
| expected-none | false | There is no expected checksum.  |  |
| expected-sha256 | false | The expected SHA256 of the downloaded artifact.  |  |
| expected-sha512 | false | The expected SHA512 of the downloaded artifact.  |  |
| extract | false | Whether to extract the downloaded artifact as a source tarball.  | true |
| purl-name | false | package-URL (PURL) name for use in SPDX SBOM External References  | ${{package.name}} |
| purl-version | false | package-URL (PURL) version for use in SPDX SBOM External References  | ${{package.version}} |
| retry-limit | false | The number of times to retry fetching before failing.  | 5 |
| strip-components | false | The number of path components to strip while extracting.  | 1 |
| timeout | false | The timeout (in seconds) to use for connecting and reading. The fetch will fail if the timeout is hit.  | 5 |
| uri | true | The URI to fetch as an artifact.  |  |

## git-checkout

Check out sources from git

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| branch | false | The branch to check out, otherwise HEAD is checked out. For reproducibility, tag is generally favored over branch. Branch and tag are mutually exclusive.  |  |
| cherry-picks | false | List of cherry picks to apply. New line separated entries. Lines can be empty. Any content on a line after `#` is ignored. After removing comments, each line is of the form:      [branch/]commit-id: comment explaining cherry-pick  comment and commit-id are required.  branch on origin that the commit lives should be provided or git is not guaranteed to have a reference to the commit-id.    Example:     cherry-picks: |       3.10/62705d869aca4055e8a96e2ed4f9013e9917c661:  |  |
| depth | false | The depth to use when cloning. Use -1 to get full branch history. If 'branch' and 'expected-commit' are provided the default is -1. Otherwise, default is to use '1' (shallow clone).  | unset |
| destination | false | The path to check out the sources to.  | . |
| expected-commit | false | The expected commit hash  |  |
| recurse-submodules | false | Indicates whether --recurse-submodules should be passed to git clone.  | false |
| repository | true | The repository to check out sources from.  |  |
| sparse-paths | false | List of directory paths to checkout when using sparse-checkout (cone mode). This is useful for monorepos where you only need specific subdirectories. When specified, only these directories will be checked out from the repository. Uses cone mode for optimal performance. Example:   sparse-paths:     - omnibump     - shared/lib  |  |
| tag | false | The tag to check out.  Branch and tag are mutually exclusive.  |  |
| type-hint | false | Type hint to use during SBOM generation for the provided git repository. This is primarily used to identify Gitlab based sources which are not heuristically identifiable as Gitlab.  Supported hints: gitlab.  |  |

## patch

Apply patches

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| fuzz | false | Sets the maximum fuzz factor. This option only applies to context diffs, and causes patch to ignore up to that many lines in looking for places to install a hunk.  | 2 |
| patches | false | A list of patches to apply, as a whitespace delimited string.  |  |
| series | false | A quilt-style patch series file to apply.  |  |
| strip-components | false | The number of path components to strip while extracting.  | 1 |

## strip

Strip binaries

### Inputs

| Name | Required | Description | Default |
| ---- | -------- | ----------- | ------- |
| opts | false | The option flags to pass to the strip command.  | -g |


<!-- end:pipeline-reference-gen -->