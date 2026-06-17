Experimental post-quantum cipher suite 1
========================================

**Important:** libedhoc does **not** support this cipher suite in the core EDHOC
library. The draft
`draft-spm-lake-pqsuites-02
<https://datatracker.ietf.org/doc/html/draft-spm-lake-pqsuites-02>`_ is still
in progress and no IANA cipher-suite value is assigned yet.

What exists today is an **internal helper** under ``helpers/`` only. It is not
wired into public ``edhoc.h`` API. Use it to prototype KEM-shaped crypto callbacks
and algorithm sizes; do not expect a full post-quantum EDHOC handshake from the core library.

Suite parameters (draft TBD1)
-----------------------------

+----------------------+---------------------------+
| Role                 | Algorithm                 |
+======================+===========================+
| EDHOC AEAD           | AES-CCM-16-128-128        |
| EDHOC hash / KDF     | SHAKE256 (KMAC256)        |
| EDHOC MAC length     | 16 bytes                  |
| Key exchange (KEM)   | ML-KEM-512                |
| Signature            | ML-DSA-44                 |
| Application AEAD     | AES-CCM-16-64-128         |
| Application hash     | SHA-256                   |
+----------------------+---------------------------+

``Supports DH/NIKE``: No (the helper uses ``value = -1`` until IANA assigns a
number).

ECDH vs KEM key exchange
------------------------

The helper introduces ``struct edhoc_crypto_pqc`` as a KEM-shaped evolution of
``struct edhoc_crypto``. Existing ECDH cipher suites can implement the KEM vtable
as NIKE-as-KEM (``encapsulate`` / ``decapsulate`` wrapping ``key_agreement``).

+------------------+-------------------------------+-------------------------------+
| EDHOC step       | ECDH (RFC 9528)               | KEM (draft)                   |
+==================+===============================+===============================+
| Initiator,       | generates ephemeral           | generates pair                |
| message_1        | ``(x, G_X)``, sends ``G_X``   | ``(dk, ek)``, sends ``ek``    |
|                  |                               | in field ``G_X``              |
+------------------+-------------------------------+-------------------------------+
| Responder,       | generates ``(y, G_Y)``;       | computes                      |
| message_2        | ``G_XY = DH(y, G_X)``;        | ``(c, K) = Encaps(ek)``;      |
|                  | sends ``G_Y``                 | sends ciphertext ``c``        |
|                  |                               | in field ``G_Y``              |
+------------------+-------------------------------+-------------------------------+
| Initiator,       | ``G_XY = DH(x, G_Y)``         | ``K = Decaps(dk, c)``         |
| after message_2  |                               |                               |
+------------------+-------------------------------+-------------------------------+
| Shared secret    | ``G_XY``                      | ``G_XY = K``                  |
+------------------+-------------------------------+-------------------------------+

API surface
-----------

Public symbols are in :file:`helpers/include/edhoc_exp_pqc_cipher_suite_1.h`:

* ``struct edhoc_crypto_pqc`` — KEM-shaped crypto vtable
  (``encapsulate`` / ``decapsulate`` replace ``key_agreement``).
* ``struct edhoc_cipher_suite_pqc`` — cipher-suite descriptor with KEM length
  fields.
* ``edhoc_exp_pqc_cipher_suite_1_get_crypto()``, ``_get_keys()``, ``_get_suite()``.

Compared to production helpers (suites 0, 2, 24):

* ``struct edhoc_crypto::key_agreement`` maps to
  ``struct edhoc_crypto_pqc::encapsulate`` (Responder) and
  ``struct edhoc_crypto_pqc::decapsulate`` (Initiator).
* ``struct edhoc_crypto::make_key_pair`` still generates the Initiator ephemeral
  material; for ML-KEM it produces ``(dk, ek)`` instead of ``(x, G_X)``.
* ``struct edhoc_cipher_suite`` ECC length fields map to
  ``struct edhoc_cipher_suite_pqc`` KEM length fields
  (``kem_public_key_length``, ``kem_ciphertext_length``, etc.).

Key import uses ``PSA_KEY_TYPE_RAW_DATA`` for ML-KEM / ML-DSA material and
standard PSA AES key types for AEAD. Ephemeral ML-KEM private keys from
``make_key_pair`` are stored in static slots that simulate PSA key identifiers.

Backend split
-------------

+---------------------------+------------------------------------------+
| Primitive                 | Backend                                  |
+===========================+==========================================+
| ML-KEM-512, ML-DSA-44     | liboqs                                   |
| AES-CCM-16-128-128        | PSA (mbed TLS)                           |
| SHAKE256 hash             | liboqs SHA3                              |
| EDHOC_Extract / Expand    | KMAC256 via liboqs SHA3 (RFC 9528 §4.1)  |
+---------------------------+------------------------------------------+

Tests
-----

Unity group ``cipher_suite_exp_pqc_1`` covers ML-KEM round-trip, ML-DSA
sign/verify, SHAKE256 hash, KMAC extract/expand, and AES-CCM encrypt/decrypt on
Linux. Requires ``LIBEDHOC_ENABLE_EXPERIMENTAL_PQC=ON``. See
:doc:`../project/testing`.

Limitations
-----------

* No full EDHOC handshake integration in the core library.
* Draft specification and IANA cipher-suite value not final — experimental only.
* Large key and signature sizes (ML-DSA-44 signatures are 2420 bytes).
