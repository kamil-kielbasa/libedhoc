Concepts at a Glance
====================

This page sketches the EDHOC mental model used throughout the libedhoc
documentation. Every term marked in *italics* is defined in
:doc:`../reference/glossary`.

Security properties
-------------------

A successful EDHOC handshake provides :term:`mutual authentication`,
:term:`forward secrecy` and :term:`identity protection` of the responder
credential against active attackers (and of the initiator credential
against passive attackers). See RFC 9528 §9 for the full security
analysis.

Roles
-----

An :term:`EDHOC` handshake involves two peers, the :term:`Initiator` (I) and
the :term:`Responder` (R). RFC 9528 Appendix A.2 defines a forward and a
reverse message flow over :term:`CoAP`; libedhoc is transport-agnostic and
supports both. The library itself is *role-agnostic*: the same
:term:`context` type is used on both sides, and the role is implied by
which ``compose`` / ``process`` calls you make.

Methods and cipher suites
-------------------------

A handshake is parameterised by:

* an :term:`authentication method` (``0`` – ``3``) that selects whether each
  peer authenticates with a :term:`signature key` or a :term:`static DH key`;
* a :term:`cipher suite` that bundles an :term:`AEAD`, a hash, an
  :term:`ECDH` group and a signature algorithm. libedhoc supports suites
  ``0`` (X25519 / :term:`EdDSA`) and ``2`` (P-256 / :term:`ES256`).

.. list-table:: Authentication methods
   :header-rows: 1

   * - Value
     - Initiator key
     - Responder key
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

Credentials
-----------

Each peer presents an authentication credential — :term:`CRED_I` or
:term:`CRED_R` — identified on the wire by one of the COSE credential
identifications: :term:`kid`, :term:`x5chain` or :term:`x5t`. libedhoc does
not embed credential storage or validation; the application supplies a
credentials callback and is free to consult a :term:`CRL` or any other
policy.

Key schedule and exports
------------------------

The handshake yields a chain of :term:`PRK` values culminating in
``PRK_out``. Application keys are derived from ``PRK_out`` through the
:term:`PRK exporter`. The most common use of the exporter is to bootstrap an
:term:`OSCORE` security context — see :doc:`../api/exporters`.

Wire format and transport
-------------------------

EDHOC messages are :term:`CBOR sequence`\ s, normally transported over
:term:`CoAP`. libedhoc itself is transport-agnostic; the message buffers it
returns can be handed to any CoAP stack. The diagram on
:doc:`../guide/protocol_flow` shows the canonical CoAP exchange.

Feature → reference matrix
--------------------------

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - Feature / module
     - Concept page
     - API page
   * - Context lifecycle & setup
     - This page
     - :doc:`../api/context`
   * - Message composition / processing
     - :doc:`../guide/protocol_flow`
     - :doc:`../api/messages`
   * - OSCORE export / key update
     - This page
     - :doc:`../api/exporters`
   * - Authentication credentials
     - This page
     - :doc:`../api/credentials`
   * - Cryptographic keys & operations
     - This page
     - :doc:`../api/crypto`
   * - External Authorization Data (EAD)
     - This page
     - :doc:`../api/ead`
   * - Cipher-suite helpers
     - This page
     - :doc:`../api/helpers`
