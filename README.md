![GitHub CI](https://github.com/kamil-kielbasa/libedhoc/actions/workflows/github-ci.yml/badge.svg)


# libedhoc: A C implementation of the Ephemeral Diffie-Hellman Over COSE (RFC 9528)

ABOUT LIBEDHOC
==============

**libedhoc** is a C implementation of a lightweight authenticated Diffie-Hellman key exchange with ephemeral keys for constrained devices. It provides mutual authentication, forward secrecy, and identity protection. This protocol, EDHOC, is standardized by the IETF as [RFC 9528](https://datatracker.ietf.org/doc/html/rfc9528). Code has been tested according to [RFC 9529](https://datatracker.ietf.org/doc/html/rfc9529).

MAIN FEATURES
=============

* Any access for API is possible only by context handle.
* EDHOC messages compose & process are [CoAP](https://datatracker.ietf.org/doc/html/rfc7252) friendly.
* Dedicated API for exporting cryptographic material for OSCORE session.
* Separate interface for:
  * cryptographics keys.
  * cryptographics operations.
  * authentication credentials.
  * external authorization data.

* For signature method only key identifier is available. Binary format of cryptographics keys is forbidden.
* Any CBOR operations are hidden away from user.
* Any memory operations are performed on stack, using VLA C99 feature.
* Code has been verified by `cppcheck` and `valgrind`.

EDHOC METHOD's
==============

Currently implementation supports only method **0**.  
There are currently works in progress on support [static Diffie-Hellman keys](https://datatracker.ietf.org/doc/html/rfc9529#name-authentication-with-static-).


```
+-------------+--------------------+--------------------+
| Method Type | Initiator          | Responder          |
|       Value | Authentication Key | Authentication Key |
+-------------+--------------------+--------------------+
|           0 | Signature Key      | Signature Key      |
|           1 | Signature Key      | Static DH Key      |
|           2 | Static DH Key      | Signature Key      |
|           3 | Static DH Key      | Static DH Key      |
+-------------+--------------------+--------------------+
```

EDHOC CIPHER SUITES
===================

Supproted EDHOC cipher suites by example implementations in unit tests:

```
+--------------------------------------------------------------------+
|                  Cipher suite                                      |
+------------------------+-------------------------------------------+
| Value |     Array      |                 Description               |
+-------+----------------+-------------------------------------------+
|     0 | 10, -16, 8,    | AES-CCM-16-64-128, SHA-256, 8,            |
|       | 4, -8, 10, -16 | X25519, EdDSA, AES‑CCM‑16‑64‑128, SHA-256 |
+-------+----------------+-------------------------------------------+
|     2 | 10, -16, 8,    | AES-CCM-16-64-128, SHA-256, 8,            |
|       | 1, -7, 10, -16 | P-256, ES256, AES‑CCM‑16‑64‑128, SHA-256  |
+-------+----------------+-------------------------------------------+
```

AUTHENTICATION
==============

Supported authentication methods:
```
+-----------------------------------------------------------------+
| COSE Header Parameters                                          |
+-------------+----------+----------------------------------------+
| Label       | Name     | Description                            |
+-------------+----------+----------------------------------------+
| 4           | kid      | Key identifier                         |
| 33          | x5chain  | An ordered chain of X.509 certificates |
| 34          | x5t      | Hash of an X.509 certificate           |
+-------------+----------+----------------------------------------+
```

#### Separe interface for verification of authentication credentials gives many advantages:  

1) user decide how to parse peer credentials.
2) possibility to introduce [CRL](https://datatracker.ietf.org/doc/html/rfc5280).
3) perform extra checks e.g. to the needs of authorization.

Credentials verification callback will contain also **user context** which allows to save necessary data during verification step for further usage by other layers.

PROJECT STRUCTURE
=================

```
| - backends    (CBOR generated code)
| - externals   (zcbor and mbedtls submodules)
| - include     (all header files)
| - library     (source code)
| - scripts     (CDDL models and zcbor script)
| - tests       (unit tests)
```

USAGE EXAMPLE
=============

```
                                 EDHOC API flow
                              ====================
        Initiator                                                   Responder
        |                                                                   |
        | edhoc_context_init()                         edhoc_context_init() |
        | edhoc_set_method()                             edhoc_set_method() |
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
```

LICENSE INFORMATION
===================

This library is published as open-source software without any warranty of any kind. Use is permitted under the terms of the GPL-2.0 license.

CONTACT
=======

email: kamkie1996@gmail.com
