## Melange Pull Request Template

<!--
*** PULL REQUEST CHECKLIST: PLEASE START HERE ***

The single most important feature of melange is that we can build Wolfi.

Many changes to melange introduce a risk of breaking the build, and sometimes
these are not flushed out until a package is changed (much) later.  This
pertains to basic execution, SCA changes, linter changes, and more.
-->

### Functional Changes

- [ ] This change can build all of Wolfi without errors (describe results in notes)

Notes:

### SCA Changes

- [ ] Examining several representative APKs show no regression / the desired effect (details in notes)

Notes:

### Linter

- [ ] The new check is clean across Wolfi
- [ ] The new check is opt-in or a warning

Notes:
