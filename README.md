[![Linux CI (Build & Test)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/build-and-tests.yml/badge.svg?branch=main)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/build-and-tests.yml)
[![Zephyr Sample CI (Build)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/build-zephyr-sample.yml/badge.svg?branch=main)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/build-zephyr-sample.yml)
[![Yocto Sandbox CI (Build)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/test-sandbox-build.yml/badge.svg?branch=main)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/test-sandbox-build.yml)
[![Docs CI (Build & Publish)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/documentation.yml/badge.svg?branch=main)](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/documentation.yml)

# libedhoc: A C implementation of the Ephemeral Diffie-Hellman Over COSE (RFC 9528)

## About libedhoc

**libedhoc** is a C implementation of the Ephemeral Diffie-Hellman Over COSE (EDHOC) protocol — a lightweight authenticated key exchange designed for constrained devices. It provides mutual authentication, forward secrecy, and identity protection. EDHOC is standardized by the IETF as [RFC 9528](https://datatracker.ietf.org/doc/html/rfc9528). The implementation has been tested for conformance with [RFC 9529](https://datatracker.ietf.org/doc/html/rfc9529).

## Features

- **Context-based API**: Safe access control using context handles for all operations
- **CoAP-friendly**: Native support for CoAP message composition and processing
- **OSCORE integration**: Dedicated API for exporting cryptographic material to establish OSCORE sessions
- **Clear separation of concerns**: Distinct interfaces for cryptographic keys, operations, credentials, and EAD
- **Secure key handling**: Private keys accessible only by identifier; raw key material never exposed
- **Encapsulated CBOR**: All encoding/decoding hidden from the user
- **Predictable memory usage**: Stack-only allocations using VLA; no heap required
- **Code quality**: Verified with static analysis (cppcheck) and dynamic analysis (valgrind)
- **Platform support**: Native Zephyr RTOS support with west manifest integration

### Supported Cipher Suites

| Suite | AEAD               | Hash    | ECDH    | Signature |
|-------|-------------------|---------|---------|-----------|
| 0     | AES-CCM-16-64-128 | SHA-256 | X25519  | EdDSA     |
| 2     | AES-CCM-16-64-128 | SHA-256 | P-256   | ES256     |

### Supported Authentication Methods

All four EDHOC authentication methods (0-3) are supported, combining Signature Keys and Static DH Keys for initiator and responder.

## Quick Start

### Installation with West (Zephyr)

Add to your `west.yml`:

```yaml
manifest:
  projects:
    - name: libedhoc
      url: https://github.com/kamil-kielbasa/libedhoc
      revision: main
      path: modules/lib/libedhoc
```

Then update dependencies:

```bash
west update
```

### Installation with CMake

Clone the repository and add to your project:

```bash
git clone https://github.com/kamil-kielbasa/libedhoc.git
```

In your `CMakeLists.txt`:

```cmake
add_subdirectory(path/to/libedhoc)
target_link_libraries(your_target PRIVATE libedhoc)
```

### Basic Usage

```c
#include "edhoc.h"
#include "edhoc_cipher_suite_2.h"

// Initialize context
struct edhoc_context ctx = { 0 };
edhoc_context_init(&ctx);

// Configure cipher suite and methods
edhoc_set_methods(&ctx, &method, ARRAY_SIZE(method));
edhoc_set_cipher_suites(&ctx, &cipher_suite, ARRAY_SIZE(cipher_suite));
edhoc_set_connection_id(&ctx, &conn_id);

// Bind crypto operations
edhoc_bind_keys(&ctx, edhoc_cipher_suite_2_get_keys());
edhoc_bind_crypto(&ctx, edhoc_cipher_suite_2_get_crypto());
edhoc_bind_credentials(&ctx, &credentials);

// Compose and exchange EDHOC messages
edhoc_message_1_compose(&ctx, msg1_buf, sizeof(msg1_buf), &msg1_len);
// ... exchange messages with peer ...

// Cleanup
edhoc_context_deinit(&ctx);
```

## Build Instructions

### Requirements

- **Compiler**: GCC or Clang with C99 support
- **CMake**: Version 3.16 or higher
- **Dependencies**: zcbor (automatically fetched if not found)

### Building the Library

```bash
mkdir build && cd build
cmake -DLIBEDHOC_BUILD_COMPILER_GCC=ON ..
make
```

### Running Tests

```bash
cmake -DLIBEDHOC_BUILD_COMPILER_GCC=ON -DLIBEDHOC_ENABLE_MODULE_TESTS=ON ..
make
ctest
```

### Building Documentation

```bash
sphinx-build doc build/doc
```

## Documentation

Documentation and further information can be found at <https://kamil-kielbasa.github.io/libedhoc/>.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository and create a new branch.
2. Implement your feature or bugfix.
3. Write tests if applicable.
4. Open a pull request.

Please ensure your code follows the existing style and structure of the project.

## License

This library is open-source software distributed under the MIT License. It is provided without any warranty of any kind. See the LICENSE file for details.

## Related Projects

- [node-edhoc](https://github.com/stoprocent/node-edhoc) - A TypeScript Node.js implementation of the Ephemeral Diffie-Hellman Over COSE.

## Contact

email: kamkie1996@gmail.com
