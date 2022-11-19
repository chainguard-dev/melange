# Build Cache

Like all build systems, there are dependencies that may be required to build a package.
These dependencies often are large and immutable, and can be cached to speed up the build process.

For example, go has its modules cache, npm keeps installed packages in `node_modules`, or maven stores downloaded
packages in its `.m2` directory.

As each build often requires all of the same packages, it can be very inefficient to download and install them
with each build. To optimize this, melange has an optional build cache.

It is a simple cache, a directory that will be mounted into the build workspace at a specified directory.
It is up to the user to populate the cache with desired contents prior to a build.

For example, you could run melange with a go pipeline as:

```
melange build --cache-dir $(go env GOMODCACHE) ...
```
