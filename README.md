# libedhoc

[![CI / Linux](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-linux.yml/badge.svg?branch=main)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-linux.yml)
[![CI / Zephyr](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-zephyr.yml/badge.svg?branch=main)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-zephyr.yml)
[![CI / Sandbox](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-sandbox.yml/badge.svg?branch=main)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-sandbox.yml)
[![codecov](https://codecov.io/gh/kamil-kielbasa/libedhoc/branch/main/graph/badge.svg)](https://codecov.io/gh/kamil-kielbasa/libedhoc)

[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://kamil-kielbasa.github.io/libedhoc/)
[![Release](https://img.shields.io/endpoint?url=https://kamil-kielbasa.github.io/libedhoc/release.json)](https://github.com/kamil-kielbasa/libedhoc/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[![RFC](https://img.shields.io/badge/RFC-9528-informational)](https://datatracker.ietf.org/doc/html/rfc9528)
[![RFC](https://img.shields.io/badge/RFC-9529-informational)](https://datatracker.ietf.org/doc/rfc9529/)
[![draft](https://img.shields.io/badge/draft-lake--pqsuites-orange)](https://datatracker.ietf.org/doc/draft-ietf-lake-pqsuites/)

A C implementation of the Ephemeral Diffie-Hellman Over COSE (EDHOC) protocol — a lightweight authenticated key exchange designed for constrained devices. EDHOC provides mutual authentication, forward secrecy, and identity protection, and is intended for usage in constrained scenarios; a main use case is to establish an Object Security for Constrained RESTful Environments (OSCORE) Security Context. Standardised by the IETF as [RFC 9528](https://datatracker.ietf.org/doc/html/rfc9528), verified against [RFC 9529](https://datatracker.ietf.org/doc/html/rfc9529) test vectors.

## Features

- **Handle-only key material** — private keys and derived secrets are held by reference in the backend key store (a software keystore, TrustZone or a secure element); a leaked context exposes nothing.
- **Post-quantum ready** — the ephemeral key exchange is modelled as a KEM, so post-quantum KEM algorithms drop straight in; classical NIKE schemes (Diffie-Hellman) plug into the same interface through a thin shim, with no change on the wire.
- **Bring your own crypto** — every primitive is reached through a small vtable; use the bundled production-ready cipher suites or drive your own secure element / accelerator.
- **Clean interfaces** — separate callback groups for cryptography, credentials, platform and optional EAD, keeping your application code cleanly separated from the protocol engine.
- **Transport-agnostic** — the library only produces and consumes CBOR message buffers, so you carry them over CoAP or any transport; all CBOR encoding/decoding is hidden.
- **Predictable footprint** — handshake buffers come from a stack (VLA, default, no heap), heap or custom memory backend, and the protocol core keeps no static state, so RAM use is bounded and known up front.
- **Portable** — builds with GCC and Clang; runs on Linux and Zephyr RTOS (as a west module).
- **Quality-gated** — cppcheck, clang-tidy, ASan, UBSan, Valgrind and LibFuzzer in CI.

### Cipher Suites

| Suite | Key exchange | Signature | AEAD               | Hash     |
|-------|--------------|-----------|--------------------|----------|
| 0     | X25519       | EdDSA     | AES-CCM-16-64-128  | SHA-256  |
| 2     | P-256        | ES256     | AES-CCM-16-64-128  | SHA-256  |
| 4     | X25519       | EdDSA     | ChaCha20/Poly1305  | SHA-256  |
| 24    | P-384        | ES384     | A256GCM            | SHA-384  |
| -24   | ML-KEM-512   | ML-DSA-44 | AES-CCM-16-128-128 | SHAKE256 |

Suite `-24` is an experimental post-quantum suite on a private-use code point,
tracking [draft-ietf-lake-pqsuites](https://datatracker.ietf.org/doc/draft-ietf-lake-pqsuites/).
All four authentication methods (0–3) are supported, in any combination of
signature and static-DH keys for the Initiator and Responder.

## Documentation

Full documentation is hosted on GitHub Pages: <https://kamil-kielbasa.github.io/libedhoc/>.

| Document                                                                                                            | What you will find                                                              |
|---------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| [Introduction](https://kamil-kielbasa.github.io/libedhoc/getting_started/introduction.html)                         | What EDHOC and libedhoc are, supported methods and cipher suites                |
| [Quick Start](https://kamil-kielbasa.github.io/libedhoc/getting_started/quick_start.html)                           | Smallest working build & handshake skeleton                                     |
| [Protocol Flow](https://kamil-kielbasa.github.io/libedhoc/guide/protocol_flow.html)                                 | Full CoAP + EDHOC message-exchange diagram                                      |
| [Security & Key Handling](https://kamil-kielbasa.github.io/libedhoc/guide/security.html)                            | How keys are held (handles / key store) and the KEM/DH model                    |
| [Configuration](https://kamil-kielbasa.github.io/libedhoc/guide/configuration.html)                                 | Kconfig / compile-time options, memory backend and logging                      |
| [API Reference](https://kamil-kielbasa.github.io/libedhoc/api/index.html)                                           | Lifecycle, error model, and per-module API pages                                |
| [Error Codes](https://kamil-kielbasa.github.io/libedhoc/api/errors.html)                                            | `enum edhoc_error_code` and the runtime error-getter API                        |
| [Glossary](https://kamil-kielbasa.github.io/libedhoc/reference/glossary.html)                                       | Definitions of every EDHOC / libedhoc term used in the docs                     |

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow.

## Security

For vulnerability reporting and the supported-version policy, see [SECURITY.md](SECURITY.md).

## Related Projects

- [node-edhoc](https://github.com/stoprocent/node-edhoc) — A TypeScript/Node.js implementation of EDHOC.

## Contact

email: kamkie1996@gmail.com
