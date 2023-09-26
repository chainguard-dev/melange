# Post-build Linting

After building a package, Melange does some basic lint checks on the package it just produced.

This can prevent common mistakes and misconfigurations, and is a good way to catch errors early.

The available linters are:

- `dev`: If this package is creating /dev nodes, it should use udev instead; otherwise, remove any files in /dev.
- `opt`: This package should be a -compat package (see below)
- `setuidgid`: Unset the setuid/setgid bit on the relevant files, or remove this linter.
- `srv`: This s package should be a -compat package (see below)
- `tempdir`: Remove any offending files in temporary dirs in the pipeline.
- `usrlocal`: This package should be a -compat package (see below)
- `varempty`: Remove any offending files in /var/empty in the pipeline.
- `worldwrite`: Change the permissions of any world-writeable files in the package, disable the linter, or make this a -compat package (see below)

### `-compat` packages

In nearly every case, binaries should be available in `/usr/bin/`, libraries in `/usr/lib/`, and so on.

However, some upstream components (e.g., Helm charts) will expect things to be in `/usr/local/bin` or in `/` or in another location.
To handle these cases, we use the convention that subpackages ending in `-compat` will move or symlink elements from the "normal" location in `/usr/bin` etc., into `/usr/local/bin` for compatibility with these upstream components.

To encourage this convention, we have a linter that will fail if a package builds components into locations that are likely to be for upstream compatibility, where the package is not named like `-compat`.

When a linter finds an issue, you should normally have the main package install into `/usr/bin`, and have a `-compat` subpackage that moves or symlinks the files into the expected location outside of the normal location.
