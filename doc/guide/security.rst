Security & Key Handling
=======================

*libedhoc* is built so that raw secret key material never sits in library
memory. This page explains where key material lives, how the crypto interface
models both classical and post-quantum key exchange, and how transient secrets
are wiped.

Handle-only key material
------------------------

Every private key and derived secret — the long-lived authentication key, the
session's ephemeral key, the shared secret and the PRK chain — is an opaque
**handle** into the crypto backend's :term:`key store`, never a raw byte buffer
inside the :term:`context`. Depending on the backend, the key store may be:

* volatile key slots in a software crypto library;
* the secure world of a :term:`TrustZone` / TF-M system;
* dedicated slots on a :term:`secure element`.

The guarantee is *confinement*: a secret is born inside a backend call (key
generation, key agreement, extract, expand), is referenced only by its handle,
and is never serialised. **A leaked context therefore reveals no key
material.**

.. list-table:: What is held by reference, and what is raw
   :header-rows: 1
   :widths: 34 16 50

   * - Material
     - Form
     - Rationale
   * - Ephemeral and static keys, shared secrets, the PRK chain, exported keys
     - handle
     - Secret — stays in the key store.
   * - Peer public keys (``G_X`` / ``G_Y``), transcript hashes, ``info``
     - raw
     - Public protocol inputs.
   * - Keystream, IV / nonce, MAC, exporter bytes
     - raw
     - One-shot outputs; the keystream and any decrypted plaintext are
       :term:`zeroize`\ d immediately after use.

The library computes no cryptography itself: it sequences backend calls and
assembles the public inputs. See :doc:`../api/crypto`.

Ephemeral key exchange: one KEM-shaped interface
------------------------------------------------

The crypto interface models the ephemeral exchange as a :term:`KEM`
(``generate_key_pair`` / ``encapsulate`` / ``decapsulate``):

* **Post-quantum** — :term:`ML-KEM` (and other KEMs) drop in directly.
* **Classical** — :term:`ECDH` plugs in as a thin **shim** that exposes bare
  ECDH through the KEM calls. It is deliberately *not* :term:`DHKEM`
  (RFC 9180), so the bytes on the wire stay exactly those of RFC 9528
  (``G_X`` = encapsulation key, ``G_Y`` = ciphertext) and classical interop is
  preserved.

Static Diffie-Hellman authentication (methods 1/2/3) uses a separate
``key_agreement`` entry, available only on :term:`NIKE` suites.

Memory zeroization
------------------

Transient raw secrets — the keystream, decrypted plaintext, IVs and MACs — are
wiped with a compiler-non-elidable ``zeroize`` the moment they are no longer
needed, including on error paths. The application supplies ``zeroize`` through
the mandatory platform binding (see :doc:`../api/platform`).
