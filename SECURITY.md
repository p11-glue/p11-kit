# Security Policy

## Reporting procedure

Report any security sensitive issues as a **confidential** issue using
the [Security and quality][security] tab in the p11-kit GitHub repository.
Alternatively, you can report to any of the [maintainers][maintainers]
directly.

The report should be self-contained and actionable without requiring
us to follow any links or perform any extra actions. It is also
desirable that the report contains a standalone reproducer.

## Threat model

The following issues are **not** considered vulnerabilities:

* Issues in the PKCS#11 modules themselves
* Attacks that require malicious PKCS#11 modules
* Issues in the RPC mechanism between p11-kit server and client, as
  they operate within the same trust boundary
* API misuse
* Attacks requiring local root/administrator access
* Attacks requiring modification of trusted configuration files or
  certificate stores
* Denial of Service via malformed configuration files (an attacker
  with write access to configuration already has significant system
  access)
* Issues in bundled test utilities and fixtures
* Side-channel attacks that require physical access to the machine
* Theoretical vulnerabilities without a practical attack scenario

## Disclosure

We do not maintain a fixed disclosure window. When to release a fix is
up to the maintainers, depending on the severity of the issue and
their capacity to handle it.

## Releasing fixes

Our releases are mostly feature-based with no fixed schedule. However,
releasing security fixes is prioritized and may result in an expedited
release. Only the current development branch is the target for fixing
security issues.

At release time, the NEWS entries must reflect the issues addressed,
including references to the relevant CVE identifiers when assigned.

[security]: https://github.com/p11-glue/p11-kit/security/advisories
[maintainers]: https://github.com/p11-glue/p11-kit/blob/master/README.md#releases
