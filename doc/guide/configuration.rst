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
    | Key identifier length in bytes.

:C:`LIBEDHOC_MAX_NR_OF_CIPHER_SUITES`
    | Maximum number of cipher suites in chain for negotiation.
    | Values greater than ``3`` require regeneration of the CBOR backend.

:C:`LIBEDHOC_MAX_NR_OF_METHODS`
    | Maximum number of authentication methods for negotiation.

:C:`LIBEDHOC_MAX_LEN_OF_CONN_ID`
    | Maximum length of connection identifier in bytes.

:C:`LIBEDHOC_MAX_LEN_OF_KEM_ENCAPSULATION_KEY`
    | Maximum length of the KEM encapsulation key (``G_X``) in bytes.

:C:`LIBEDHOC_MAX_LEN_OF_KEM_CIPHERTEXT`
    | Maximum length of the KEM ciphertext (``G_Y``) in bytes.

:C:`LIBEDHOC_MAX_LEN_OF_NIKE_KEY`
    | Maximum length of the static Diffie-Hellman (NIKE) key in bytes.

:C:`LIBEDHOC_MAX_LEN_OF_MAC`
    | Maximum length of hash in bytes.

:C:`LIBEDHOC_MAX_NR_OF_EAD_TOKENS`
    | Maximum number of EAD (External Authorization Data) tokens.
    | Values greater than ``3`` require regeneration of the CBOR backend.

:C:`LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN`
    | Maximum number of certificates in X.509 chain.
    | Values greater than ``3`` require regeneration of the CBOR backend.

:C:`LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID`
    | Maximum length of authentication credentials key identifier in bytes.

:C:`LIBEDHOC_MAX_LEN_OF_HASH_ALG`
    | Maximum length of authentication credentials hash algorithm in bytes.

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
* **Zephyr RTOS** — as a west module. The options above are ordinary Kconfig
  symbols and the dependencies (zcbor, mbedTLS) are pulled by the manifest.
