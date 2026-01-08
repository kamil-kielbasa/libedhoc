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
    | Values bigger than `3` requires regeneration of CBOR backend.

:C:`LIBEDHOC_MAX_LEN_OF_CONN_ID`
    | Maximum length of connection identifier in bytes.

:C:`LIBEDHOC_MAX_LEN_OF_ECC_KEY`
    | Maximum length of ECC (Elliptic Curve Cryptography) key in bytes.

:C:`LIBEDHOC_MAX_LEN_OF_MAC`
    | Maximum length of hash in bytes.

:C:`LIBEDHOC_MAX_NR_OF_EAD_TOKENS`
    | Maximum number of EAD (External Authorization Data) tokens.
    | Values bigger than `3` requires regeneration of CBOR backend.

:C:`LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN`
    | Maximum number of certificates in X.509 chain.
    | Values bigger than `3` requires regeneration of CBOR backend.

:C:`LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID`
    | Maximum length of authentication credentials key identifier in bytes.

:C:`LIBEDHOC_MAX_LEN_OF_HASH_ALG`
    | Maximum length of authentication credentials hash algorithm in bytes.

Linux target
************

| All of above library configuration parameters must be passed for building process.
| Please add prefix :C:`CONFIG_`.

Zephyr target
*************

| The library can be used as a Zephyr module. A west manifest is provided for easy integration.

**Initialize workspace:**

.. code-block:: bash

   west init -l libedhoc
   west update

**Build sample application:**

.. code-block:: bash

   west build -b native_sim libedhoc/sample

| All Kconfig options are automatically prefixed with :C:`CONFIG_` by the Zephyr build system.
| Dependencies (zcbor, mbedtls) are automatically pulled via the west manifest.
