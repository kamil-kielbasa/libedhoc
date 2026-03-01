[![CI / Linux](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-linux.yml/badge.svg?branch=main)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-linux.yml)
[![CI / Zephyr](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-zephyr.yml/badge.svg?branch=main)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-zephyr.yml)
[![CI / Sandbox](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-sandbox.yml/badge.svg?branch=main)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-sandbox.yml)
[![CI / Documentation](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-docs.yml/badge.svg?branch=main)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/ci-docs.yml)
[![codecov](https://codecov.io/gh/kamil-kielbasa/libedhoc/branch/main/graph/badge.svg)](https://codecov.io/gh/kamil-kielbasa/libedhoc)

# libedhoc

A C implementation of the Ephemeral Diffie-Hellman Over COSE (EDHOC) protocol — a lightweight authenticated key exchange designed for constrained devices. EDHOC provides mutual authentication, forward secrecy, and identity protection. Standardized by the IETF as [RFC 9528](https://datatracker.ietf.org/doc/html/rfc9528), verified against [RFC 9529](https://datatracker.ietf.org/doc/html/rfc9529) test vectors.

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
|-------|-------------------|---------|---------|-----------|
| 0     | AES-CCM-16-64-128 | SHA-256 | X25519  | EdDSA     |
| 2     | AES-CCM-16-64-128 | SHA-256 | P-256   | ES256     |

### Authentication Methods

All four EDHOC authentication methods (0–3) are supported, combining Signature Keys and Static DH Keys for initiator and responder.

## Metrics

| Metric | Value |
|--------|-------|
| Line coverage | 92.8% |
| Function coverage | 100% |
| Test count | 635+ (unit, integration, fuzz) |
| Library flash footprint | ~20 KiB (cipher suite 2, P-256/ES256, native_sim) |
| Static RAM (data + bss) | 0 bytes (all state on stack) |

Coverage details on the [Codecov dashboard](https://codecov.io/gh/kamil-kielbasa/libedhoc). Memory and timing benchmarks available as [CI artifacts](../../actions/workflows/ci-zephyr.yml).

## Documentation

Full documentation including API reference, build instructions, configuration, and testing guide:

<https://kamil-kielbasa.github.io/libedhoc/>

## Contributing

Contributions are welcome. To contribute:

1. Fork the repository and create a new branch.
2. Implement your feature or bugfix.
3. Write tests if applicable.
4. Open a pull request.

Please follow the existing code style and structure.

## License

MIT License. See the [LICENSE](LICENSE) file for details.

## Related Projects

- [node-edhoc](https://github.com/stoprocent/node-edhoc) — A TypeScript/Node.js implementation of EDHOC.

## Contact

email: kamkie1996@gmail.com
