Protocol Flow
=============

This page shows the canonical EDHOC handshake as it travels over
:term:`CoAP`. The diagram is reproduced from RFC 9528 and annotated with the
*libedhoc* API calls the :term:`Initiator` and :term:`Responder` make at each
step.

For a code-level walkthrough see :doc:`../getting_started/quick_start`; for
the API surface see :doc:`../api/messages`.

CoAP + EDHOC message exchange
-----------------------------

::

                           EDHOC API flow
                        ====================
  Initiator                                                   Responder
  |                                                                   |
  | edhoc_context_init()                         edhoc_context_init() |
  | edhoc_set_methods()                           edhoc_set_methods() |
  | edhoc_set_cipher_suites()               edhoc_set_cipher_suites() |
  | edhoc_set_connection_id()               edhoc_set_connection_id() |
  | edhoc_bind_ead()                                 edhoc_bind_ead() |
  | edhoc_bind_crypto()                           edhoc_bind_crypto() |
  | edhoc_bind_platform()                       edhoc_bind_platform() |
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
  | edhoc_export_oscore_context()       edhoc_export_oscore_context() |
  | edhoc_context_deinit()                     edhoc_context_deinit() |
  |                                                                   |

Notes
-----

* ``message_4`` is optional; it is composed and processed only when the
  selected :term:`authentication method` requires it or when the application
  asks for it explicitly.
* After completion, both peers export the :term:`OSCORE` Security Context
  (see :doc:`../api/exporters`) and deinitialise; an optional
  ``EDHOC-KeyUpdate`` refreshes it before a later export.
* The CoAP framing (``POST`` to ``/.well-known/edhoc``,
  ``application/edhoc+cbor-seq``) follows RFC 9528 Appendix A.2; *libedhoc*
  itself only produces and consumes the inner CBOR-sequence payload.
