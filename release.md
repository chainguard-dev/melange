# Melange Release Process

## Prerequisites

Set up the repos correctly, and make sure you have right access to the repo to
perform tag pushes. It can be helpful to create a distrinct repo just for the
tags push so that you don't accidentally push by accident. For example, my repos
look like this:

```shell
git remote -v
```

And output:
```
origin	git@github.com:vaikas/melange.git (fetch)
origin	git@github.com:vaikas/melange.git (push)
upstream	git@github.com:chainguard-dev/melange (fetch)
upstream	no_push (push)
upstream-tag	git@github.com:chainguard-dev/melange (fetch)
upstream-tag	git@github.com:chainguard-dev/melange (push)
```

Note that my regular `upstream` is configured with `no_push` to make sure I
don't accidentally try to push anything there.

## Steps

### Sync tags

Ensure that your local branch is up-to-date from the upstream:

```shell
git pull upstream main --tags
```

### Pick a new version number

The Melange repo uses [semver](https://semver.org/). Your first step is to
determine the latest tag used.

List the latest tags in date order:

```shell
git tag | tail
```

Example output:

```
v0.1.0
v0.2.0
v0.3.0
v0.3.1
v0.3.2
v0.4.0
v0.5.0
```

Show a list of changes since the latest version (v0.5.0):

```shell
git log v0.5.0..
```

If the commits include a new feature or breaking change, bump the minor version.
If it only includes bug fixes, bump the patch version.

### Tagging

Once you have a version number in mind (for our example v0.5.1), tag it locally:

```shell
git tag -a v0.5.1 -m v0.5.1
```

Then push the tag upstream:

```shell
git push upstream-tag v0.5.1
```

### Monitor the release automation

Once the tag is pushed, the [`Create Release` action](https://github.com/chainguard-dev/melange/actions/workflows/release.yaml)
will generate the appropriate release artifacts and create a draft release.

At the time of this writing, the release job takes 20 to 30 minutes to execute.

### Publish

Once the `Release` action has been completed successfully, find your release on
the [releases page](https://github.com/chainguard-dev/melange/releases)

