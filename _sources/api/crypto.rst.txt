Cryptographic Interface
=======================

libedhoc never touches raw key material directly: all cryptographic primitives
are reached through two user-supplied callback interfaces — the **keys
interface** for key import/generation/destruction by identifier, and the
**operations interface** for ECDH, AEAD, hash, HKDF, signing and
verification. Private :term:`signature key`\ s and :term:`static DH key`\ s
are referenced by identifier only.

A pair of ready-made bindings for :term:`cipher suite` 0 and 2 against
mbed TLS / PSA Crypto lives under ``helpers/`` and is documented on
:doc:`helpers`.

| Header file: :file:`include/edhoc_crypto.h`

Keys
----

.. doxygengroup:: edhoc-interface-crypto-keys
   :project: libedhoc
   :members:

Operations
----------

.. doxygengroup:: edhoc-interface-crypto-operations
   :project: libedhoc
   :members:
