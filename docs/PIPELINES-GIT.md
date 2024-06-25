# Built-in git pipeline

Melange includes a built-in pipeline to checkout git repos.

To get started quickly, checkout the `git-checkout` pipeline.


How to use it?

```
  - uses: git-checkout
    with:
      repository: <UPDATE-ME>
      tag: ${{package.version}}
      expected-commit: <UPDATE-ME>

```

You have these inputs (defined in https://github.com/chainguard-dev/melange/blob/main/pkg/build/pipelines/git-checkout.yaml):

How to use the cherry-picking feature?


To fix  https://nvd.nist.gov/vuln/detail/CVE-2024-4032 for example you can do something nice:

```
pipeline:
  - uses: git-checkout
    with:
      expected-commit: 976ea78599d71f22e9c0fefc2dc37c1d9fc835a4
      repository: https://github.com/python/cpython.git
      tag: v3.10.14
      cherry-picks: |
        3.10/c62c9e518b784fe44432a3f4fc265fb95b651906: CVE-2024-4032
```

Note the format of cherry-picking: ``[branch/]commit: comment here``
