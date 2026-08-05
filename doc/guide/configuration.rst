Configuration
=============

*libedhoc* is configured at compile time. On Zephyr the options below are
ordinary ``CONFIG_*`` Kconfig symbols; on other targets they are passed as
compiler defines (see `Supported targets`_).

Kconfig library configuration
*****************************

.. role:: C(code)
  :language: C
  :class: highlight

:C:`LIBEDHOC_ENABLE`
    | Enable building *libedhoc* for the Zephyr target.

:C:`LIBEDHOC_KEY_ID_LEN`
    | Size of the opaque key handle the library stores to reference a key
      inside the crypto backend's key store.
    | Must match the handle size of the bound backend.

:C:`LIBEDHOC_MAX_NR_OF_CIPHER_SUITES`
    | Capacity of the cipher suite list a peer may offer or accept.
    | Values greater than ``3`` require regeneration of the CBOR backend.

:C:`LIBEDHOC_MAX_NR_OF_METHODS`
    | Capacity of the method list a peer may offer or accept, from ``1`` to
      ``4``.

:C:`LIBEDHOC_MAX_LEN_OF_CONN_ID`
    | Longest connection identifier (C_I / C_R) this peer accepts.
    | Identifiers are byte strings; one byte covers the range that
      RFC 9528: 3.3.2 sends as a bare CBOR integer, which is the common case.

:C:`LIBEDHOC_MAX_LEN_OF_KEM_ENCAPSULATION_KEY`
    | Buffer holding the ephemeral encapsulation key (``G_X``).
    | Set it to the largest suite you build in: ``32`` for X25519, ``65`` for
      P-256, ``97`` for P-384, ``800`` for ML-KEM-512.

:C:`LIBEDHOC_MAX_LEN_OF_KEM_CIPHERTEXT`
    | Buffer holding the ephemeral ciphertext (``G_Y``).
    | Set it to the largest suite you build in: ``32`` for X25519, ``65`` for
      P-256, ``97`` for P-384, ``768`` for ML-KEM-512.

:C:`LIBEDHOC_MAX_LEN_OF_MAC`
    | Buffers holding a transcript hash or a MAC.
    | Set it to the hash length of the largest suite you build in: ``32`` for
      SHA-256, ``48`` for SHA-384, ``64`` for SHA-512 and SHAKE256.

:C:`LIBEDHOC_MAX_NR_OF_EAD_TOKENS`
    | Capacity of the EAD (External Authorization Data) token list carried in
      each message. Set to ``0`` to disable EAD.
    | Values greater than ``3`` require regeneration of the CBOR backend.

:C:`LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID`
    | Longest COSE ``kid`` key identifier this peer accepts, from ``1`` to
      ``32``.

:C:`LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN`
    | Capacity of the ``x5chain`` certificate list, from ``1`` to ``3``.
    | Values greater than ``3`` require regeneration of the CBOR backend.

Reference cipher suites
***********************

Each bundled reference cipher suite has its own gate. A disabled suite is not
compiled in, and both :c:func:`edhoc_cipher_suite_get_params` and
:c:func:`edhoc_cipher_suite_get_crypto` return ``NULL`` for it.

.. list-table::
   :header-rows: 1

   * - Symbol
     - Suite
   * - :C:`LIBEDHOC_CIPHER_SUITE_0_ENABLE`
     - X25519 / EdDSA / AES-CCM-16-64-128 / SHA-256
   * - :C:`LIBEDHOC_CIPHER_SUITE_2_ENABLE`
     - P-256 / ES256 / AES-CCM-16-64-128 / SHA-256
   * - :C:`LIBEDHOC_CIPHER_SUITE_4_ENABLE`
     - X25519 / EdDSA / ChaCha20-Poly1305 / SHA-256
   * - :C:`LIBEDHOC_CIPHER_SUITE_24_ENABLE`
     - P-384 / ES384 / A256GCM / SHA-384
   * - :C:`LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE`
     - ML-KEM-512 / ML-DSA-44 / AES-CCM-16-128-128 / SHAKE256

Logging
*******

Set the compile-time log level with ``CONFIG_LIBEDHOC_LOG_LEVEL``; each level
enables the ones below it:

.. list-table::
   :header-rows: 1

   * - Level
     - Value
   * - ``EDHOC_LOG_LEVEL_NONE`` (default)
     - 0
   * - ``EDHOC_LOG_LEVEL_ERR``
     - 1
   * - ``EDHOC_LOG_LEVEL_WRN``
     - 2
   * - ``EDHOC_LOG_LEVEL_INF``
     - 3
   * - ``EDHOC_LOG_LEVEL_DBG``
     - 4

Memory backend
**************

*libedhoc* allocates its handshake working buffers through a compile-time
selectable backend, chosen with ``CONFIG_LIBEDHOC_MEM_BACKEND``:

.. list-table::
   :header-rows: 1

   * - Backend
     - Value
     - Notes
   * - Stack
     - ``0``
     - C99 variable-length arrays; no heap, zero static RAM (default).
   * - Heap
     - ``1``
     - ``calloc`` / ``k_calloc``; needs a heap sized for the working set.
   * - Custom
     - ``2``
     - Application-provided ``edhoc_mem_alloc`` / ``edhoc_mem_free``.

Supported targets
*****************

*libedhoc* is portable C and is regularly built and tested on:

* **Linux** — via CMake. Pass the options above as ``-DCONFIG_LIBEDHOC_*``, or
  consume an installed build through ``find_package(libedhoc)`` (the generated
  :file:`edhoc_config.h` carries the build-time configuration).
* **macOS** — via CMake and Apple Clang on Arm64 and x86_64. The same presets
  and configuration options as the Linux host build are supported.
* **Zephyr RTOS** — as a west module. The options above are ordinary Kconfig
  symbols and the dependencies (zcbor, mbedTLS) are pulled by the manifest.
