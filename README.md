# libedhoc: A C implementation of the Ephemeral Diffie-Hellman Over COSE (RFC-9528)

ABOUT LIBEDHOC
==============

**libedhoc** is a C implementation of a lightweight authenticated Diffie-Hellman key exchange with ephemeral keys for constrained devices. It provides mutual authentication, forward secrecy, and identity protection. This protocol, EDHOC, is standardized by the IETF as [RFC 9528](https://datatracker.ietf.org/doc/html/draft-ietf-lake-edhoc-16). Current implementation supproted EDHOC in version 16.

MAIN FEATURES
=============

* Any access for API is possible only by context handle.
* [CoAP](https://datatracker.ietf.org/doc/html/rfc7252) friendly API for EDHOC message flow.
* Separate interface for cryptographics keys, operations and authentication credentials.
* For signature method only key identifier is available. Binary format of crypto keys is forbidden.
* Support for external authorization data (EAD) compose and process by callbacks.
* CBOR operations are hidden away from user.
* Any memory operations are performed on stack, using VLA C99 feature.
* Code has been verified by `cppcheck` and `valgrind`.

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
        | edhoc_export_secret_and_salt()     edhoc_export_secret_and_salt() |
        | edhoc_context_deinit()                     edhoc_context_deinit() |
        |                                                                   |
```

CONTACT
=======

email: kamkie1996@gmail.com
