# Variable Transformations

Using `var-transforms:` in a melange config gives the ability to create a new variable from an existing one using regular expressions.

This can be useful when say an upstream project version that's used to fetch a tag or tarball is a nonstandard version format.

Example:

In the case of Java, the OpenJDK project includes a `+` in the version see [here](https://github.com/openjdk/jdk17u/tags).

Using one of these tags as an example: `jdk-17.0.7+5`

This version cannot be used by apk to resolve, as the `+` is classed as build information.

So the OpenJDK melange `package.version` should not contain the `+`, i.e.

```yaml
package:
  name: openjdk-17
  version: 17.0.7.5
```

However, as we want to reuse the version as a variable when fetching the tarball, we need to transform this version to include the `+`.

For this we can use `var-transforms`:

```yaml
var-transforms:
  - from: ${{package.version}}
    match: \.(\d+)$
    replace: +$1
    to: mangled-package-version

```

This instructs melange at build time to take the `package.version` variable, using a regex expression to match the third occurrence of `.` with `+`, and use the new value in a new variable called `mangled-package-version`.

We can now use the new variable in our fetch.

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://github.com/openjdk/jdk17u/archive/refs/tags/jdk-${{vars.mangled-package-version}}.tar.gz
```

Using regular expressions can be difficult, here are some helpful sites when you create one:

 - https://regex101.com/
 - https://regexr.com/
