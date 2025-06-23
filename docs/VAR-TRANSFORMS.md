# Variable Transformations

Using `var-transforms:` in a melange config gives the ability to create a new variable from an existing one using regular expressions.

This can be useful when say an upstream project version that's used to fetch a tag or tarball is a nonstandard version format.

If you are using expand in the replace string, `$1` or `${1}`, your regex need to match all from left to right. If your `package.version` can be `1.2.3.4` or `1.2.3.4-1` your regex need to contemplate `.*` right characters.

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

`mangled-package-version` can also be used with `git-checkout`:

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/openjdk/jdk12u
      tag: ${{vars.mangled-package-version}}
      expected-commit: 5018cdd1904357c04c9c41e0f8fe8994916cb638
```


Note: If `melange bump` is run, it will attempt to update the `expected-commit` value.


Other example:

In some case, you need to join two or more regex match subgroups with `_`. Here you must use `${1}` instead of `$1`. More information [here](https://github.com/golang/go/issues/32885#issuecomment-507477621)

If you like to change `package.version` from "1.3.6.8" to "1.3.6_8", a possible `var-transform` definition is:

```yaml
var-transforms:
  - from: ${{package.version}}
    match: ^(\d+\.\d+\.\d+).(\d+).*
    replace: "${1}_${2}"
    to: mangled-version-binary
```

---

Using regular expressions can be difficult, here are some helpful sites when you create one:

 - https://regex101.com/
 - https://regexr.com/
