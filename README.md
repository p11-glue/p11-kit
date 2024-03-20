# p11-kit
[![test](https://github.com/p11-glue/p11-kit/actions/workflows/test.yaml/badge.svg?branch=master)](https://github.com/p11-glue/p11-kit/actions/workflows/test.yaml) [![Coverage Status](https://img.shields.io/coveralls/p11-glue/p11-kit.svg)](https://coveralls.io/r/p11-glue/p11-kit) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/1627/badge)](https://bestpractices.coreinfrastructure.org/en/projects/1627)

p11-kit aims to solve problems with coordinating the use of [PKCS #11]
by different components or libraries living in the same process, by
providing a way to load and enumerate PKCS #11 modules, as well as a
standard configuration setup for installing PKCS #11 modules in such a
way that they're discoverable.

# Documentation

 * [Main site](https://p11-glue.github.io/p11-glue/p11-kit.html)
 * [Manual](https://p11-glue.github.io/p11-glue/p11-kit/manual/)

# Building

To build and install p11-kit, you can use the following commands:

```console
$ meson setup _build
$ meson compile -C _build
$ meson test -C _build
# meson install -C _build
```

If you install it locally for testing purposes, you may want to
specify `-Dsystemd=disabled -Dbash_completion=disabled` at the
invocation of `meson _build`, to avoid installing files to the
system locations.

# Releases

Releases are made available via the [primary github site](https://github.com/p11-glue/p11-kit/releases). They are signed with OpenPGP key of one of the maintainers: [Daiki Ueno](https://keys.openpgp.org/search?q=462225C3B46F34879FC8496CD605848ED7E69871), [Zoltan Fridrich](https://keys.openpgp.org/search?q=5D46CB0F763405A7053556F47A75A648B3F9220C).

[PKCS #11]: https://en.wikipedia.org/wiki/PKCS_11
