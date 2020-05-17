# p11-kit

[![Build Status](https://travis-ci.org/p11-glue/p11-kit.svg?branch=master)](https://travis-ci.org/p11-glue/p11-kit) [![Coverage Status](https://img.shields.io/coveralls/p11-glue/p11-kit.svg)](https://coveralls.io/r/p11-glue/p11-kit) [![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/1627/badge)](https://bestpractices.coreinfrastructure.org/en/projects/1627)

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
specify `-Dsystemd=false -Dbash_completion=false`.

# Releases

Releases are made available via the [primary github site](https://github.com/p11-glue/p11-kit/releases).

They are signed with Daiki Ueno's OpenPGP key:

```
pub   4096R/D7E69871 2009-07-23
      Key fingerprint = 4622 25C3 B46F 3487 9FC8  496C D605 848E D7E6 9871
uid                  Daiki Ueno <ueno@unixuser.org>
uid                  Daiki Ueno <ueno@gnu.org>
sub   4096R/C8C530D6 2010-02-04
```

# Reporting security issues

If you find an issue that could potentially impact security, report it
to ueno@gnu.org, encrypted with the above mentioned OpenPGP key.

[PKCS #11]: https://en.wikipedia.org/wiki/PKCS_11
