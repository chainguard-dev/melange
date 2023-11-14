# Melange Release Process

## Patch releases

The most common type of release of Melange is a patch release. Generally we should aim to do these as often as necessary to release _backward compatible_ changes, especially to release updated dependencies to fix vulnerabilities.

To cut a release:
- go to https://github.com/chainguard-dev/melange/releases/new
- click "Choose a tag" then "Find or create a new tag"
- type a new patch version tag for the latest minor version
  - for example, if the latest version is `v0.5.5`, create a patch release `v0.5.6`
- click "Create new tag: v0.X.Y on publish"
  - you can leave the release title empty
- click "Generate release notes"
  - make any editorial changes to the release notes you think are relevant
- make sure "Set as the latest release" is checked
- click **"Publish release"**

### Monitor the release automation

Once the tag is pushed, the [`Create Release` action](https://github.com/chainguard-dev/melange/actions/workflows/release.yaml)
will attach the appropriate release artifacts and update release notes.

At the time of this writing, the release job takes 20 to 30 minutes to execute.

Make any editorial changes to the release notes you think are necessary.
You may want to highlight certain changes or remove items that aren't interesting.

Once the `Release` action has been completed successfully, find your release on
the [releases page](https://github.com/chainguard-dev/melange/releases)

## Minor releases

Occasionally there are large or breaking changes to Melange that we want to highlight with a new minor release.
A minor release should be cut shortly after a breaking change is made, so that regular patch releases don't release breaking changes.

The process for cutting a release is exactly the same as above, except that you should pick a new minor version.

For example, if the latest version is `v0.5.5`, create a minor release `v0.6.0`.
