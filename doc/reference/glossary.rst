Glossary
========

This glossary collects the protocol- and library-specific terms used across
the libedhoc documentation. Each term can be cross-referenced from any page
with the ``:term:`` role, e.g. :literal:`:term:\`EDHOC\``.

.. glossary::
   :sorted:

   AEAD
      Authenticated Encryption with Associated Data. The symmetric primitive
      used by EDHOC ciphersuites to protect messages 2–4 and the OSCORE
      traffic derived from the handshake.

   authentication method
      One of the four EDHOC authentication methods (``0`` – ``3``) defined
      in RFC 9528. Each method picks the credential type used by the
      :term:`Initiator` and :term:`Responder`: a :term:`signature key` or a
      :term:`static DH key`.

   CBOR
      Concise Binary Object Representation (RFC 8949). The compact binary
      encoding format used by EDHOC, :term:`COSE` and :term:`OSCORE`.

   CBOR sequence
      Concatenation of CBOR data items without an enclosing array. EDHOC
      messages are transmitted as a CBOR sequence.

   cipher suite
      Ordered set of AEAD, hash, ECDH and signature algorithms used by
      EDHOC. libedhoc implements suite ``0`` (X25519 / EdDSA) and suite ``2``
      (P-256 / ES256).

   CoAP
      Constrained Application Protocol (RFC 7252). The most common transport
      for EDHOC handshakes on constrained devices.

   connection identifier
      Short byte string — ``C_I`` chosen by the :term:`Initiator`, ``C_R``
      chosen by the :term:`Responder` — used to correlate EDHOC and
      :term:`OSCORE` state. See :doc:`../api/helpers`.

   context
      The ``struct edhoc_context`` state object that owns all EDHOC
      handshake state. Its lifecycle is described on :doc:`../api/index`.

   COSE
      CBOR Object Signing and Encryption (RFC 9052). Provides the
      cryptographic envelopes and credential-identification header
      parameters used by EDHOC.

   CRED_I
      The authentication credential of the :term:`Initiator`.

   CRED_R
      The authentication credential of the :term:`Responder`.

   CRL
      Certificate Revocation List (RFC 5280). The application may consult a
      CRL inside the credentials interface callback.

   EAD
      External Authorization Data. Optional, application-defined items
      carried in the ``EAD_1`` … ``EAD_4`` fields of the four EDHOC messages.

   ECDH
      Elliptic-Curve Diffie-Hellman. The ephemeral key-agreement primitive
      that gives EDHOC its forward secrecy.

   EdDSA
      Edwards-curve Digital Signature Algorithm. The signature scheme used
      by EDHOC cipher suite ``0``.

   EDHOC
      Ephemeral Diffie-Hellman Over COSE — the lightweight authenticated
      key-exchange protocol implemented by libedhoc and defined in
      :term:`RFC 9528`.

   ES256
      ECDSA with NIST P-256 and SHA-256. The signature scheme used by
      EDHOC cipher suite ``2``.

   forward secrecy
      Security property guaranteeing that past session keys remain safe
      even if long-term authentication keys are later compromised.

   identity protection
      Security property guaranteeing that a peer's credential identifier is
      not exposed to passive eavesdroppers (and, for the responder, also
      not to active attackers). See RFC 9528 §9.

   mutual authentication
      Security property guaranteeing that, at the end of a successful
      handshake, each peer has cryptographic evidence of the other peer's
      identity. See RFC 9528 §9.

   ID_CRED_I
      COSE-encoded identifier of :term:`CRED_I`.

   ID_CRED_R
      COSE-encoded identifier of :term:`CRED_R`.

   Initiator
      The EDHOC peer that sends ``message_1`` and picks its
      :term:`connection identifier` ``C_I``.

   kid
      COSE Key Identifier header parameter (RFC 9052, label ``4``). One of
      the supported credential identifications.

   LAKE
      Lightweight Authenticated Key Exchange — the IETF Working Group that
      standardised EDHOC.

   OSCORE
      Object Security for Constrained RESTful Environments (RFC 8613). The
      primary consumer of the keys exported by EDHOC.

   PRK
      Pseudo-Random Key — intermediate value in the EDHOC key schedule
      (``PRK_2e``, ``PRK_3e2m``, ``PRK_4e3m``, ``PRK_out``).

   PRK exporter
      The interface that derives application keys (e.g. OSCORE Master Secret
      and Master Salt) from ``PRK_out``.

   Responder
      The EDHOC peer that replies with ``message_2`` and picks its
      :term:`connection identifier` ``C_R``.

   RFC 9528
      *Ephemeral Diffie-Hellman Over COSE (EDHOC)* — Selander, Preuß
      Mattsson & Palombini, IETF Standards Track, March 2024. The base EDHOC
      specification.

   RFC 9529
      *Traces of Ephemeral Diffie-Hellman Over COSE (EDHOC)* — Selander et
      al., IETF Informational, March 2024. The test-vector traces used for
      conformance testing.

   signature key
      Long-term private key used to sign EDHOC handshake messages when the
      selected :term:`authentication method` calls for signature-based
      authentication.

   static DH key
      Long-term Diffie-Hellman key used for authentication when the selected
      :term:`authentication method` calls for static-DH authentication.

   transcript hash
      Running hash (``TH_2``, ``TH_3``, ``TH_4``) that binds the EDHOC
      messages together cryptographically.

   VLA
      Variable-Length Array — the C99 feature that libedhoc relies on to
      keep all handshake state on the stack with no heap allocations.

   x5chain
      COSE header parameter ``33`` (RFC 9360) carrying an ordered chain of
      X.509 certificates.

   x5t
      COSE header parameter ``34`` (RFC 9360) carrying the hash of an X.509
      certificate.

.. seealso::

   :doc:`../getting_started/concepts`
       Higher-level explanation of the EDHOC mental model.

   :doc:`links`
       Index of the RFCs and external resources referenced from the
       definitions above.
