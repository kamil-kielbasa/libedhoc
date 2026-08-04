Cryptographic Interface
=======================

*libedhoc* computes no cryptography itself: every primitive is reached through a
single user-supplied callback interface, the **operations interface**:

* **Ephemeral key exchange** — a :term:`KEM`: ``generate_key_pair`` /
  ``encapsulate`` / ``decapsulate``.
* **Static Diffie-Hellman** — ``key_agreement`` (:term:`NIKE` suites, methods
  1/2/3).
* **AEAD** — ``aead_encrypt`` / ``aead_decrypt``.
* **Hash** — multipart ``hash_init`` / ``hash_update`` / ``hash_finish``.
* **Key derivation** — :term:`HKDF` ``extract`` / ``expand`` (handle and raw
  forms).
* **Signature** — ``sign`` / ``verify``.

Keys never cross the boundary as raw bytes: they live in the backend
:term:`key store` and are passed by opaque :term:`handle` only, and each
derived handle carries the key-usage policy it will serve.

Ready-made, production-ready bindings for every supported suite live under
``library/cipher_suites/``; see :doc:`cipher_suites`.

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
