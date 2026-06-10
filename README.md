# libedhoc

[![CI / Linux](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-linux.yml/badge.svg?branch=main)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-linux.yml)
[![CI / Zephyr](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-zephyr.yml/badge.svg?branch=main)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-zephyr.yml)
[![CI / Sandbox](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-sandbox.yml/badge.svg?branch=main)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-sandbox.yml)
[![codecov](https://codecov.io/gh/kamil-kielbasa/libedhoc/branch/main/graph/badge.svg)](https://codecov.io/gh/kamil-kielbasa/libedhoc)

[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://kamil-kielbasa.github.io/libedhoc/)
[![Release](https://img.shields.io/github/v/release/kamil-kielbasa/libedhoc)](https://github.com/kamil-kielbasa/libedhoc/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![RFC](https://img.shields.io/badge/RFC-9528-informational)](https://datatracker.ietf.org/doc/html/rfc9528)
[![RFC](https://img.shields.io/badge/RFC-9529-informational)](https://datatracker.ietf.org/doc/rfc9529/)

A C implementation of the Ephemeral Diffie-Hellman Over COSE (EDHOC) protocol — a lightweight authenticated key exchange designed for constrained devices. EDHOC provides mutual authentication, forward secrecy, and identity protection, and is intended for usage in constrained scenarios; a main use case is to establish an Object Security for Constrained RESTful Environments (OSCORE) security context. Standardised by the IETF as [RFC 9528](https://datatracker.ietf.org/doc/html/rfc9528), verified against [RFC 9529](https://datatracker.ietf.org/doc/html/rfc9529) test vectors.

## Features

- Context-based API with safe access control using context handles
- CoAP-friendly message composition and processing
- OSCORE session export for establishing secure communication channels
- Separate interfaces for cryptographic keys, operations, credentials, and EAD
- Private keys accessible only by identifier; raw key material never exposed
- All CBOR encoding/decoding encapsulated and hidden from the user
- Stack-only allocations using VLA; no heap required
- Native Zephyr RTOS support with west manifest integration
- Verified with cppcheck, clang-tidy, ASan, UBSan, Valgrind, and LibFuzzer

### Cipher Suites

| Suite | AEAD               | Hash    | ECDH    | Signature |
|-------|--------------------|---------|---------|-----------|
| 0     | AES-CCM-16-64-128  | SHA-256 | X25519  | EdDSA     |
| 2     | AES-CCM-16-64-128  | SHA-256 | P-256   | ES256     |
| 24    | A256GCM            | SHA-384 | P-384   | ES384     |

### Authentication Methods

All four EDHOC authentication methods (0–3) are supported, combining Signature Keys and Static DH Keys for initiator and responder.

## Metrics

| Metric                   | Value                                                          |
|--------------------------|----------------------------------------------------------------|
| Line coverage            | 92.8%                                                          |
| Function coverage        | 100%                                                           |
| Test count               | 706+ (unit, integration, fuzz)                                 |
| Library flash footprint  | ~20 KiB (cipher suite 2, P-256/ES256, native_sim)              |
| Static RAM (data + bss)  | 0 bytes (all state on stack)                                   |

Coverage details on the [Codecov dashboard](https://codecov.io/gh/kamil-kielbasa/libedhoc). Memory and timing benchmarks are available as [CI artifacts](../../actions/workflows/ci-zephyr.yml).

## Documentation

Full documentation is hosted on GitHub Pages: <https://kamil-kielbasa.github.io/libedhoc/>.

| Document                                                                                                            | What you will find                                                              |
|---------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| [Introduction](https://kamil-kielbasa.github.io/libedhoc/getting_started/introduction.html)                         | What EDHOC and libedhoc are, supported methods and cipher suites                |
| [Quick Start](https://kamil-kielbasa.github.io/libedhoc/getting_started/quick_start.html)                           | Smallest working build & handshake skeleton                                     |
| [Concepts at a Glance](https://kamil-kielbasa.github.io/libedhoc/getting_started/concepts.html)                     | The EDHOC mental model — roles, methods, cipher suites, exporters              |
| [Protocol Flow](https://kamil-kielbasa.github.io/libedhoc/guide/protocol_flow.html)                                 | Full CoAP + EDHOC message-exchange diagram                                      |
| [Configuration](https://kamil-kielbasa.github.io/libedhoc/guide/configuration.html)                                 | Kconfig / compile-time options and logging                                      |
| [API Reference](https://kamil-kielbasa.github.io/libedhoc/api/index.html)                                           | Lifecycle, error model, and per-module API pages                                |
| [Error Codes](https://kamil-kielbasa.github.io/libedhoc/reference/error_codes.html)                                 | `enum edhoc_error_code` and the runtime error-getter API                        |
| [Values](https://kamil-kielbasa.github.io/libedhoc/reference/values.html)                                           | CBOR shortcut constants and extract/expand labels                               |
| [Glossary](https://kamil-kielbasa.github.io/libedhoc/reference/glossary.html)                                       | Definitions of every EDHOC / libedhoc term used in the docs                     |
| [Testing](https://kamil-kielbasa.github.io/libedhoc/project/testing.html)                                           | Test architecture and how to run the suites                                     |
| [Contributing](https://kamil-kielbasa.github.io/libedhoc/project/contributing.html)                                 | Workflow for submitting changes                                                 |

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) (or the hosted [Contributing](https://kamil-kielbasa.github.io/libedhoc/project/contributing.html) page) for the full workflow.

## Security

For vulnerability reporting and the supported-version policy, see [SECURITY.md](SECURITY.md).

## License

MIT License. See the [LICENSE](LICENSE) file for details.

## Related Projects

- [node-edhoc](https://github.com/stoprocent/node-edhoc) — A TypeScript/Node.js implementation of EDHOC.

## Contact

email: kamkie1996@gmail.com
