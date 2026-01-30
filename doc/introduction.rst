Introduction
============

About libedhoc
**************

**libedhoc** is a C implementation of the Ephemeral Diffie-Hellman Over COSE (EDHOC)
protocol — a lightweight authenticated key exchange designed for constrained devices.
It provides mutual authentication, forward secrecy, and identity protection.
EDHOC is standardized by the IETF as `RFC 9528`_.
The implementation has been tested for conformance with `RFC 9529`_.

.. _RFC 9528: https://datatracker.ietf.org/doc/html/rfc9528
.. _RFC 9529: https://datatracker.ietf.org/doc/html/rfc9529

Features
********

* Context-based API: all operations use a context handle for safe access control.
* `CoAP`_-friendly message composition and processing.
* Dedicated API for exporting cryptographic material to establish `OSCORE`_ sessions.
* Clear separation of concerns with distinct interfaces for:

  * cryptographic keys
  * cryptographic operations
  * authentication credentials
  * external authorization data (EAD)

* Secure key handling: private authentication keys are accessible only by identifier;
  direct access to raw key material is prohibited.
* CBOR encoding/decoding is fully encapsulated and hidden from the user.
* Predictable memory usage: all operations use stack allocation via the `VLA`_ feature;
  no heap allocations.
* Code quality verified with static analysis (*cppcheck*) and dynamic analysis (*valgrind*).
* Native Zephyr RTOS support with west manifest for seamless integration.

.. _CoAP: https://datatracker.ietf.org/doc/html/rfc7252
.. _OSCORE: https://datatracker.ietf.org/doc/html/rfc8613
.. _VLA: https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1256.pdf

EDHOC methods
*************

.. list-table:: Supported authentication methods.

   * - **Value**
     - **Initiator Authentication Key**
     - **Responder Authentication Key**
   * - 0
     - Signature Key
     - Signature Key
   * - 1
     - Signature Key
     - Static DH Key
   * - 2
     - Static DH Key
     - Signature Key
   * - 3
     - Static DH Key
     - Static DH Key

EDHOC cipher suites
*******************

.. list-table:: Supported cipher suites implemented in the library.

   * - **Value**
     - **Array**
     - **Description**
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
**************************

.. list-table:: Supported authentication methods from `COSE IANA`_.

   * - **Label**
     - **Name**
     - **Description**
   * - 4
     - kid
     - Key identifier
   * - 33
     - x5chain
     - An ordered chain of X.509 certificates
   * - 34
     - x5t
     - Hash of an X.509 certificate

.. _COSE IANA: https://www.iana.org/assignments/cose/cose.xhtml

The authentication credentials interface provides the following benefits:

#. Flexible credential verification: users control the verification logic and determine
   what data to persist in the application context.
#. Support for Certificate Revocation Lists (`CRL`_).
#. Extensibility for additional authorization-specific checks as needed.

.. _CRL: https://datatracker.ietf.org/doc/html/rfc5280

API usage example
*****************

The diagram below illustrates a typical EDHOC message flow integrated with CoAP.

::

                           EDHOC API flow
                        ====================
  Initiator                                                   Responder
  |                                                                   |
  | edhoc_context_init()                         edhoc_context_init() |
  | edhoc_set_methods()                           edhoc_set_methods() |
  | edhoc_set_cipher_suites()               edhoc_set_cipher_suites() |
  | edhoc_set_conn_id()                           edhoc_set_conn_id() |
  | edhoc_bind_ead()                                 edhoc_bind_ead() |
  | edhoc_bind_keys()                               edhoc_bind_keys() |
  | edhoc_bind_crypto()                           edhoc_bind_crypto() |
  | edhoc_bind_credentials()                 edhoc_bind_credentials() |
  |                                                                   |
  | edhoc_message_1_compose()                                         |
  |                                                                   |
  |                     Header: POST (Code=0.02)                      |
  |                   Uri-Path: "/.well-known/edhoc"                  |
  |          Content-Format: application/cid-edhoc+cbor-seq           |
  |                  Payload: true, EDHOC message_1                   |
  |                                                                   |
  +--------------------------- POST --------------------------------->|
  |                                                                   |
  |                                         edhoc_message_1_process() |
  |                                         edhoc_message_2_compose() |
  |                                                                   |
  |                      Header: 2.04 Changed                         |
  |             Content-Format: application/edhoc+cbor-seq            |
  |                     Payload: EDHOC message_2                      |
  |                                                                   |
  |<---------------------------- 2.04 --------------------------------+
  |                                                                   |
  | edhoc_message_2_process()                                         |
  | edhoc_message_3_compose()                                         |
  |                                                                   |
  |                     Header: POST (Code=0.02)                      |
  |                     Uri-Path: "/.well-known/edhoc"                |
  |          Content-Format: application/cid-edhoc+cbor-seq           |
  |                     Payload: C_R, EDHOC message_3                 |
  |                                                                   |
  +--------------------------- POST --------------------------------->|
  |                                                                   |
  |                                         edhoc_message_3_process() |
  |                                         edhoc_message_4_compose() |
  |                                                                   |
  |                       Header: 2.04 Changed                        |
  |             Content-Format: application/edhoc+cbor-seq            |
  |                     Payload: EDHOC message_4                      |
  |                                                                   |
  |<---------------------------- 2.04 --------------------------------+
  |                                                                   |
  | edhoc_message_4_process()                                         |
  |                                                                   |
  | edhoc_export_oscore_session()       edhoc_export_oscore_session() |
  | edhoc_export_key_update()               edhoc_export_key_update() |
  | edhoc_export_oscore_session()       edhoc_export_oscore_session() |
  | edhoc_context_deinit()                     edhoc_context_deinit() |
  |                                                                   |
