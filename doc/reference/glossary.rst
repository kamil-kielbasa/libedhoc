Glossary
========

This glossary collects the protocol- and library-specific terms used across
the *libedhoc* documentation.

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
      Ordered set of key-exchange, signature, AEAD and hash algorithms used by
      EDHOC. *libedhoc* ships reference suites ``0``, ``2``, ``4`` and ``24`` and
      the experimental post-quantum suite ``-24``; see
      :doc:`../api/cipher_suites`.

   CoAP
      Constrained Application Protocol (RFC 7252). The most common transport
      for EDHOC handshakes on constrained devices.

   connection identifier
      Short byte string — ``C_I`` chosen by the :term:`Initiator`, ``C_R``
      chosen by the :term:`Responder` — used to correlate EDHOC and
      :term:`OSCORE` state. See :doc:`../api/coap`.

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

   DHKEM
      The RFC 9180 construction that turns a Diffie-Hellman group into a
      :term:`KEM`. EDHOC does **not** use DHKEM; *libedhoc*'s classical shim
      exposes bare :term:`ECDH` so the wire format of :term:`RFC 9528` is
      preserved.

   EAD
      External Authorization Data. Optional, application-defined items
      carried in the ``EAD_1`` … ``EAD_4`` fields of the four EDHOC messages.

   ECDH
      Elliptic-Curve Diffie-Hellman. The classical ephemeral key-agreement
      primitive behind EDHOC's :term:`forward secrecy`; in *libedhoc* it is
      exposed through the :term:`KEM` interface by a thin shim.

   EdDSA
      Edwards-curve Digital Signature Algorithm. The signature scheme used
      by EDHOC cipher suite ``0``.

   EDHOC
      Ephemeral Diffie-Hellman Over COSE — the lightweight authenticated
      key-exchange protocol implemented by *libedhoc* and defined in
      :term:`RFC 9528`.

   ES256
      ECDSA with NIST P-256 and SHA-256. The signature scheme used by
      EDHOC cipher suite ``2``.

   forward secrecy
      Security property guaranteeing that past session keys remain safe
      even if long-term authentication keys are later compromised.

   handle
      Opaque reference to a key held in the backend :term:`key store`. *libedhoc*
      passes secrets by handle, never as raw bytes.

   HKDF
      HMAC-based Key Derivation Function (RFC 5869). The EDHOC key schedule
      instantiates ``EDHOC_Extract`` / ``EDHOC_Expand`` with HKDF for the SHA-2
      suites (and KMAC256 for the SHAKE256 suite).

   ID_CRED_I
      COSE-encoded identifier of :term:`CRED_I`.

   ID_CRED_R
      COSE-encoded identifier of :term:`CRED_R`.

   identity protection
      Security property guaranteeing that a peer's credential identifier is
      not exposed to passive eavesdroppers (and, for the responder, also
      not to active attackers). See RFC 9528 §9.

   Initiator
      The EDHOC peer that sends ``message_1`` and picks its
      :term:`connection identifier` ``C_I``.

   KEM
      Key Encapsulation Mechanism. The shape of *libedhoc*'s ephemeral
      key-exchange interface (``generate_key_pair`` / ``encapsulate`` /
      ``decapsulate``): :term:`ML-KEM` maps to it directly and classical
      :term:`ECDH` maps to it through a shim.

   key store
      Where key :term:`handle`\ s resolve inside the crypto backend — volatile
      key slots in software, a :term:`TrustZone` secure world or a
      :term:`secure element`. Secrets never leave it.

   kid
      COSE Key Identifier header parameter (RFC 9052, label ``4``). One of
      the supported credential identifications.

   LAKE
      Lightweight Authenticated Key Exchange — the IETF Working Group that
      standardised EDHOC.

   ML-DSA
      Module-Lattice Digital Signature Algorithm (FIPS 204). The post-quantum
      signature scheme of the experimental cipher suite ``-24``.

   ML-KEM
      Module-Lattice Key Encapsulation Mechanism (FIPS 203). The post-quantum
      :term:`KEM` of the experimental cipher suite ``-24``.

   mutual authentication
      Security property guaranteeing that, at the end of a successful
      handshake, each peer has cryptographic evidence of the other peer's
      identity. See RFC 9528 §9.

   NIKE
      Non-Interactive Key Exchange — a Diffie-Hellman-style primitive where
      both parties hold long-lived key pairs. Static-DH authentication
      (methods 1/2/3) requires a NIKE suite.

   OSCORE
      Object Security for Constrained RESTful Environments (RFC 8613). The
      primary consumer of the keys exported by EDHOC.

   PQC
      Post-Quantum Cryptography — algorithms designed to resist attacks by a
      quantum computer, such as :term:`ML-KEM` and :term:`ML-DSA`.

   PRK
      Pseudo-Random Key — intermediate value in the EDHOC key schedule
      (``PRK_2e``, ``PRK_3e2m``, ``PRK_4e3m``, ``PRK_out``).

   PRK exporter
      The interface that derives application keys (e.g. OSCORE Master Secret
      and Master Salt) from ``PRK_out``.

   PSA
      Platform Security Architecture. The Arm-defined crypto API (implemented
      by mbed TLS and by secure enclaves) whose key-handle model *libedhoc*
      follows.

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

   RFC 9668
      *Using EDHOC with the Constrained Application Protocol (CoAP) and OSCORE*
      — IETF Standards Track. Profiles EDHOC over CoAP and the combined
      EDHOC + OSCORE flow.

   secure element
      A dedicated tamper-resistant chip that stores keys and performs
      cryptography, exposing keys only by :term:`handle`.

   SHAKE256
      Extendable-output function from the SHA-3 family (FIPS 202), used as the
      hash of the experimental post-quantum cipher suite ``-24``.

   signature key
      Long-term private key used to sign EDHOC handshake messages when the
      selected :term:`authentication method` calls for signature-based
      authentication.

   static DH key
      Long-term Diffie-Hellman key used for authentication when the selected
      :term:`authentication method` calls for static-DH authentication.

   TF-M
      Trusted Firmware-M — the reference secure-world firmware for Arm
      :term:`TrustZone`-M; it can host the :term:`key store` on Cortex-M
      devices.

   transcript hash
      Running hash (``TH_2``, ``TH_3``, ``TH_4``) that binds the EDHOC
      messages together cryptographically.

   TrustZone
      Arm's hardware security extension that partitions a CPU into a normal and
      a secure world; the secure world can host the :term:`key store`.

   VLA
      Variable-Length Array — the C99 feature used by *libedhoc*'s default
      stack memory backend to keep handshake state on the stack with no heap
      allocations. Optional heap and custom memory backends are also available.

   x5chain
      COSE header parameter ``33`` (RFC 9360) carrying an ordered chain of
      X.509 certificates.

   x5t
      COSE header parameter ``34`` (RFC 9360) carrying the hash of an X.509
      certificate.

   zeroize
      Overwrite a buffer to erase sensitive data in a way the compiler may not
      elide. *libedhoc*'s mandatory platform ``zeroize`` callback (see
      :doc:`../api/platform`) wipes every transient secret after use.

.. seealso::

   :doc:`../getting_started/introduction`
       Higher-level introduction to EDHOC and *libedhoc*.

   :doc:`links`
       Index of the RFCs and external resources referenced from the
       definitions above.
