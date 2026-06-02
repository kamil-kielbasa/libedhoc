Introduction
============

About libedhoc
--------------

**libedhoc** is a C implementation of the :term:`EDHOC` protocol — a
lightweight authenticated key exchange designed for IoT and constrained
devices. It provides :term:`mutual authentication`, :term:`forward secrecy`
and :term:`identity protection`. EDHOC is standardised by the IETF as
:term:`RFC 9528` and the implementation has been tested for conformance with
:term:`RFC 9529`. A main use case is to bootstrap an :term:`OSCORE` security
context.

For a quick read-through of the protocol concepts see
:doc:`concepts`; to get something running, jump straight to
:doc:`quick_start`.

Features
--------

* Context-based API: all operations use a :term:`context` handle for safe
  access control.
* :term:`CoAP`-friendly message composition and processing.
* Dedicated API for exporting cryptographic material to establish
  :term:`OSCORE` sessions.
* Clear separation of concerns with distinct interfaces for:

  * cryptographic keys,
  * cryptographic operations,
  * authentication credentials,
  * external authorization data (:term:`EAD`).

* Secure key handling: private authentication keys are accessible only by
  identifier; direct access to raw key material is prohibited.
* :term:`CBOR` encoding/decoding is fully encapsulated and hidden from the
  user.
* Predictable memory usage: all operations use stack allocation via the
  :term:`VLA` feature; no heap allocations.
* Code quality verified with static analysis (*cppcheck*, *clang-tidy*) and
  dynamic analysis (*Valgrind*, *ASan*, *UBSan*, *LibFuzzer*).
* Native Zephyr RTOS support with a west manifest for seamless integration.

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

.. list-table:: Supported cipher suites implemented in the library.
   :header-rows: 1

   * - Value
     - Array
     - Description
   * - 0
     - | 10, -16, 8, 4,
       | -8, 10, -16
     - | AES-CCM-16-64-128, SHA-256, 8,
       | X25519, EdDSA, AES-CCM-16-64-128, SHA-256
   * - 2
     - | 10, -16, 8,
       | 1, -7, 10, -16
     - | AES-CCM-16-64-128, SHA-256, 8,
       | P-256, ES256, AES-CCM-16-64-128, SHA-256

Authentication credentials
--------------------------

.. list-table:: Supported credential identifications from the COSE IANA registry.
   :header-rows: 1

   * - Label
     - Name
     - Description
   * - 4
     - :term:`kid`
     - Key identifier
   * - 33
     - :term:`x5chain`
     - An ordered chain of X.509 certificates
   * - 34
     - :term:`x5t`
     - Hash of an X.509 certificate

The authentication credentials interface provides the following benefits:

#. Flexible credential verification: the application controls the
   verification logic and decides what to persist in its own context.
#. Support for Certificate Revocation Lists (:term:`CRL`).
#. Extensibility for additional authorization-specific checks as needed.

Where next?
-----------

* :doc:`concepts` — the EDHOC mental model.
* :doc:`quick_start` — a minimal handshake in code.
* :doc:`../guide/protocol_flow` — full CoAP + EDHOC message exchange.
* :doc:`../api/index` — complete API reference.
