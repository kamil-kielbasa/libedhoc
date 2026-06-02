Configuration
=============

Kconfig library configuration
*****************************

.. role:: C(code)
  :language: C
  :class: highlight

:C:`LIBEDHOC_ENABLE`
    | Enable building libedhoc for Zephyr target.

:C:`LIBEDHOC_KEY_ID_LEN`
    | Key identifier length in bytes.

:C:`LIBEDHOC_MAX_NR_OF_CIPHER_SUITES`
    | Maximum number of cipher suites in chain for negotiation.
    | Values greater than ``3`` require regeneration of the CBOR backend.

:C:`LIBEDHOC_MAX_LEN_OF_CONN_ID`
    | Maximum length of connection identifier in bytes.

:C:`LIBEDHOC_MAX_LEN_OF_ECC_KEY`
    | Maximum length of ECC (Elliptic Curve Cryptography) key in bytes.

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

Linux target
************

| All configuration parameters listed above must be passed as compiler defines during the build.
| Each must be prefixed with :C:`CONFIG_`.

Zephyr target
*************

| The library can be used as a Zephyr module. A west manifest is provided for easy integration.

**Initialize workspace:**

.. code-block:: bash

   west init -l libedhoc
   west update

**Build sample application:**

.. code-block:: bash

   west build -b native_sim libedhoc/sample/benchmark

| All Kconfig options are automatically prefixed with :C:`CONFIG_` by the Zephyr build system.
| Dependencies (zcbor, mbedtls) are automatically pulled via the west manifest.

Logging
*******

The logging module provides compile-time configurable log levels via
``CONFIG_LIBEDHOC_LOG_LEVEL``. Headers:

* :file:`include/edhoc_log.h`
* Backend: :file:`port/log/linux/edhoc_log_backend.h` (Linux) or
  :file:`port/log/zephyr/edhoc_log_backend.h` (Zephyr).

.. list-table::
   :header-rows: 1

   * - Level
     - Macro
     - Value
   * - None
     - ``EDHOC_LOG_LEVEL_NONE``
     - 0
   * - Error
     - ``EDHOC_LOG_LEVEL_ERR``
     - 1
   * - Warning
     - ``EDHOC_LOG_LEVEL_WRN``
     - 2
   * - Info
     - ``EDHOC_LOG_LEVEL_INF``
     - 3
   * - Debug
     - ``EDHOC_LOG_LEVEL_DBG``
     - 4

Set ``CONFIG_LIBEDHOC_LOG_LEVEL`` to the desired level during compilation.
Each level enables all levels below it. The Linux backend outputs
timestamped, colour-coded messages to ``stdout`` / ``stderr``. The Zephyr
backend delegates to the Zephyr logging subsystem.
