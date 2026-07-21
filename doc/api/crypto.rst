Cryptographic Interface
=======================

libedhoc never touches raw key material directly: every cryptographic
primitive is reached through a single user-supplied callback interface, the
**operations interface**, covering key generation, encapsulation and
decapsulation, static Diffie-Hellman key agreement, AEAD, hash, HKDF, signing
and verification. Keys never cross the interface boundary as raw bytes — they
live inside the backend key store and are referenced by an opaque handle only.
Private :term:`signature key`\ s and :term:`static DH key`\ s are referenced by
identifier only, and a derived key handle carries the key-usage policy it will
serve.

A set of ready-made bindings for :term:`cipher suite` 0, 2 and 24 against
mbed TLS / PSA Crypto lives under ``library/cipher_suites/`` and is documented
on :doc:`helpers`.

| Header file: :file:`include/edhoc/crypto.h`

Key usage
---------

.. doxygengroup:: edhoc-interface-crypto-usage
   :project: libedhoc
   :members:

Operations
----------

.. doxygengroup:: edhoc-interface-crypto-operations
   :project: libedhoc
   :members:
