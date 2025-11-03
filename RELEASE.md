# Melange Release Process

To cut a release:

1. Go to https://github.com/chainguard-dev/melange/actions/workflows/release.yaml.
2. Click on the `Run workflow ▼` button.
3. In the dropdown, ensure that the `main` branch is selected.
4. In the dropdown, click on the `Run workflow` button.
5. Wait for the workflow to complete successfully.

After workflow completes the new release will show up in [tags](https://github.com/chainguard-dev/melange/tags)
and [releases](https://github.com/chainguard-dev/melange/releases).

### Useful things to know

#### Detecting whether a new release is needed

The release workflow checks to see if there are any changes since the last release. If there are no changes, the workflow will end execution early and not create a new release.

#### Automatic triggering

In addition to being triggerable manually (as described at the top of this document), the workflow also runs automatically every Monday at 00:00:00 UTC. Just like with manual triggering, if there are no new changes since the last release, the workflow will end early without creating a new release.
