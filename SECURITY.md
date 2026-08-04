# Security Policy

## Supported versions

| Version        | Supported            |
| -------------- | -------------------- |
| Latest release | :white_check_mark:   |
| Anything older | :x: — please upgrade |

## What this library is responsible for

*libedhoc* implements the EDHOC protocol (RFC 9528). Several things it depends
on are deliberately the application's, and a report about them is a report
about the application, not about this library:

- **Key material.** Long-lived secrets are opaque handles into the crypto
  backend bound with `edhoc_bind_crypto()`. How well those keys are protected
  is a property of that backend.
- **Erasing secrets.** The `zeroize` callback bound with
  `edhoc_bind_platform()` must not be elided by the compiler. Supplying a plain
  `memset` defeats every erasure the library performs.
- **Trusting a peer.** EDHOC proves possession of a private key and nothing
  more. Path building, trust anchors and revocation happen in
  `authenticate_peer` (RFC 9528: Appendix D).
- **Distinct connection identifiers.** C_I and C_R must differ for a session
  used with OSCORE (RFC 9528: 3.3.3); the library refuses to derive a security
  context otherwise, but the identifiers themselves are chosen by the
  application.

Everything else — message parsing, the key schedule, the transcript, and the
state machine — is in scope, including anything reachable from a peer before
authentication completes.

## Reporting a vulnerability

Please report vulnerabilities **privately**. Do not open a public GitHub issue.

- Preferred: GitHub **Private Vulnerability Reporting** —
  <https://github.com/kamil-kielbasa/libedhoc/security/advisories/new>.
- Email: <kamkie1996@gmail.com>.

Include enough information to reproduce: affected version / commit, target
(Linux, Zephyr board), Kconfig diff, cipher suite and authentication method,
repro steps, and the observed vs. expected behaviour. PoC code is welcome.

You will get an acknowledgement within **7 days**. Coordinated disclosure
is the default; an embargoed fix and CVE will be arranged where applicable.
