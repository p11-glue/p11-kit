# p11-kit

[![Build Status](https://travis-ci.org/p11-glue/p11-kit.svg?branch=master)](https://travis-ci.org/p11-glue/p11-kit) [![Coverage Status](https://img.shields.io/coveralls/p11-glue/p11-kit.svg)](https://coveralls.io/r/p11-glue/p11-kit) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/1627/badge)](https://bestpractices.coreinfrastructure.org/en/projects/1627) [![Total alerts](https://img.shields.io/lgtm/alerts/g/p11-glue/p11-kit.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/p11-glue/p11-kit/alerts/) [![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/p11-glue/p11-kit.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/p11-glue/p11-kit/context:cpp)

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
$ meson _build
$ ninja -C _build
$ ninja -C _build test
# ninja -C _build install
```

If you install it locally for testing purposes, you may want to
specify `-Dsystemd=disabled -Dbash_completion=disabled`.

# Releases

Releases are made available via the [primary github site](https://github.com/p11-glue/p11-kit/releases). They are signed with the current maintainer's [OpenPGP key](https://keys.openpgp.org/search?q=462225C3B46F34879FC8496CD605848ED7E69871).

[PKCS #11]: https://en.wikipedia.org/wiki/PKCS_11
