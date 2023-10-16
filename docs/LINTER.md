# Post-build Linting

After building a package, Melange does some basic lint checks on the package it just produced.

This can prevent common mistakes and misconfigurations, and is a good way to catch errors early.

The available linters are:

- `dev`: If this package is creating /dev nodes, it should use udev instead; otherwise, remove any files in /dev.
- `opt`: This package should be a -compat package (see below)
- `setuidgid`: Unset the setuid/setgid bit on the relevant files, or remove this linter.
- `srv`: This package should be a -compat package (see below)
- `strip`: Ensure the binary is stripped in the pipeline.
- `tempdir`: Remove any offending files in temporary dirs in the pipeline.
- `usrlocal`: This package should be a -compat package (see below)
- `varempty`: Remove any offending files in /var/empty in the pipeline.
- `worldwrite`: Change the permissions of any world-writeable files in the package, disable the linter, or make this a -compat package (see below)

### Default linters

At present, all linters are enabled by default. This is subject to change in the future as more linters are added.

### `-compat` packages

In nearly every case, binaries should be available in `/usr/bin/`, libraries in `/usr/lib/`, and so on.

However, some upstream components (e.g., Helm charts) will expect things to be in `/usr/local/bin` or in `/` or in another location.
To handle these cases, we use the convention that subpackages ending in `-compat` will move or symlink elements from the "normal" location in `/usr/bin` etc., into `/usr/local/bin` for compatibility with these upstream components.

To encourage this convention, we have a linter that will fail if a package builds components into locations that are likely to be for upstream compatibility, where the package is not named like `-compat`.

When a linter finds an issue, you should normally have the main package install into `/usr/bin`, and have a `-compat` subpackage that moves or symlinks the files into the expected location outside of the normal location.

### Disabling lints

When a lint fails, it is sending a clear signal that something is wrong. Therefore, lints should only be disabled after discussion with other team members ensuring it is in fact the right thing to do.

When in doubt, assume the linter is correct, and a true problem exists. Follow the guidance given by the lint diagnostic to fix it.

When disabling a lint, a justification should be provided in the form of a comment, to help other maintainers.

To disable a lint, use something similar to the following configuration:

```yaml
package:
  name: foobar
  version: 1.0.0
  epoch: 42
  checks:
    disable:
      - setuidgid  # Package is meant to have setuid binaries
      - debug      # Toolchain problems require we keep debug info
        ...
```
