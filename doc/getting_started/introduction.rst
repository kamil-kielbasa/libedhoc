Introduction
============

About libedhoc
--------------

*libedhoc* is a C implementation of the :term:`EDHOC` protocol — a
lightweight authenticated key exchange for IoT and constrained devices. A
successful handshake gives both peers :term:`mutual authentication`,
:term:`forward secrecy` and :term:`identity protection`, and yields fresh
keying material — most often to bootstrap an :term:`OSCORE` Security Context.
EDHOC is standardised by the IETF as :term:`RFC 9528`; *libedhoc* is verified
against the :term:`RFC 9529` test vectors.

To see code, jump to the :doc:`quick_start`.

Roles
-----

A handshake runs between two peers: the :term:`Initiator` and the
:term:`Responder`. *libedhoc* is *role-agnostic* — both sides use the same
:term:`context` type and the role is implied by which ``compose`` /
``process`` calls the application makes. The library is transport-agnostic
too: the message buffers it produces can be carried over :term:`CoAP` (see
:doc:`../guide/protocol_flow`) or any other transport.

Features
--------

* **Standards-based** — implements :term:`RFC 9528` and passes the
  :term:`RFC 9529` test vectors.
* **Handle-only key material** — secrets stay in the backend :term:`key store`
  and are used by reference (see :doc:`../guide/security`).
* **Post-quantum ready** — a :term:`KEM`-shaped crypto interface; classical
  :term:`ECDH` plugs in as a shim with no change on the wire.
* **Small callback interfaces** — cryptography, credentials, platform and
  optional :term:`EAD`; :term:`CBOR` is fully hidden.
* **OSCORE-ready** — exports the :term:`OSCORE` Security Context, with
  CoAP + EDHOC framing helpers (:term:`RFC 9668`).
* **Predictable memory** — stack (:term:`VLA`, default, no heap), heap or a
  custom backend.
* **Quality-gated** — cppcheck, clang-tidy, Valgrind, ASan, UBSan and
  LibFuzzer run in CI.
* **Zephyr-native** — usable as a Zephyr module via a west manifest.

EDHOC methods
-------------

.. list-table:: Supported authentication methods.
   :header-rows: 1

   * - Value
     - Initiator authentication key
     - Responder authentication key
   * - 0
     - Signature key
     - Signature key
   * - 1
     - Signature key
     - Static DH key
   * - 2
     - Static DH key
     - Signature key
   * - 3
     - Static DH key
     - Static DH key

EDHOC cipher suites
-------------------

.. list-table:: Supported cipher suites.
   :header-rows: 1

   * - Suite
     - Key exchange
     - Signature
     - AEAD
     - Hash
   * - 0
     - X25519
     - EdDSA
     - AES-CCM-16-64-128
     - SHA-256
   * - 2
     - P-256
     - ES256
     - AES-CCM-16-64-128
     - SHA-256
   * - 4
     - X25519
     - EdDSA
     - ChaCha20/Poly1305
     - SHA-256
   * - 24
     - P-384
     - ES384
     - A256GCM
     - SHA-384
   * - -24
     - ML-KEM-512
     - ML-DSA-44
     - AES-CCM-16-128-128
     - SHAKE256

Suite ``-24`` is an experimental :term:`PQC` suite on a private-use code
point, tracking `draft-ietf-lake-pqsuites
<https://datatracker.ietf.org/doc/draft-ietf-lake-pqsuites/>`_; enable it only
when you need post-quantum security.

Authentication credentials
--------------------------

Each peer presents a credential (:term:`CRED_I` or :term:`CRED_R`), identified
on the wire by one of the :term:`COSE` credential types:

.. list-table::
   :header-rows: 1

   * - Label
     - Type
     - Carried value
   * - 4
     - :term:`kid`
     - Key identifier
   * - 33
     - :term:`x5chain`
     - Ordered chain of X.509 certificates
   * - 34
     - :term:`x5t`
     - Hash of an X.509 certificate

libedhoc embeds no credential storage or validation: the application supplies
the fetch/verify callbacks and may consult a :term:`CRL` or any other trust
policy. See :doc:`../api/credentials`.

Where next?
-----------

* :doc:`quick_start` — a minimal handshake in code.
* :doc:`../guide/security` — key handling and the KEM/DH model.
* :doc:`../guide/protocol_flow` — the CoAP + EDHOC message exchange.
* :doc:`../api/index` — the complete API reference.
