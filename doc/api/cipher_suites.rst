Cipher Suites
=============

A :term:`cipher suite` bundles the key-exchange, signature, AEAD and hash
algorithms of a handshake. The public header describes every suite as plain
data (``struct edhoc_cipher_suite``) and resolves it to a crypto backend
through a pair of getters keyed by ``enum edhoc_cipher_suite_id``.

*libedhoc* ships **production-ready** cipher-suite implementations built on
widely-used, audited libraries. Each suite is selected individually with its
own Kconfig gate (``CONFIG_LIBEDHOC_CIPHER_SUITE_<id>_ENABLE``); a disabled
suite is dropped from the build and its ``get_crypto`` getter returns ``NULL``.

.. list-table:: Supplied cipher-suite implementations
   :header-rows: 1
   :widths: 16 54 30

   * - Suite
     - Algorithms (key exchange / signature / AEAD / hash)
     - Backend dependencies
   * - 0
     - X25519 / EdDSA / AES-CCM-16-64-128 / SHA-256
     - mbed TLS (PSA Crypto) + compact25519
   * - 2
     - P-256 / ES256 / AES-CCM-16-64-128 / SHA-256
     - mbed TLS (PSA Crypto)
   * - 4
     - X25519 / EdDSA / ChaCha20-Poly1305 / SHA-256
     - mbed TLS (PSA Crypto) + compact25519
   * - 24
     - P-384 / ES384 / A256GCM / SHA-384
     - mbed TLS (PSA Crypto)
   * - -24 *(draft)*
     - ML-KEM-512 / ML-DSA-44 / AES-CCM-16-128-128 / SHAKE256
     - mbed TLS (PSA Crypto) + liboqs + XKCP

Suite ``-24`` is work in progress, tracking the `draft-ietf-lake-pqsuites
<https://datatracker.ietf.org/doc/draft-ietf-lake-pqsuites/>`_ specification;
its code point is provisional.

Bring your own backend
----------------------

The supplied suites are the batteries-included option, not a hard requirement.
All cryptography is reached through the :doc:`crypto` vtable, so you can provide
your own implementation for any suite — for example to drive a secure element
or an accelerator that *libedhoc* knows nothing about — and bind it with
``edhoc_bind_crypto()``. The supplied suites also serve as complete working
examples for doing exactly that.

Public interface
----------------

| Header file: :file:`include/edhoc/cipher_suite.h`

.. doxygengroup:: edhoc-cipher-suite
   :project: libedhoc
   :members:

.. doxygengroup:: edhoc-cipher-suite-getters
   :project: libedhoc
   :members:

.. note::

   The suite implementations under `library/cipher_suites/
   <https://github.com/kamil-kielbasa/libedhoc/tree/main/library/cipher_suites>`_
   are internal: their headers are not installed and are not part of the public
   API. Reach a suite through :c:func:`edhoc_cipher_suite_get_crypto`, or read
   the sources as a starting point when writing your own backend.
