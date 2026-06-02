Helpers, Macros and Utilities
=============================

This page collects the optional, ready-made helpers shipped under
``helpers/`` together with small utility groups from the core headers.

Cipher suite 0
--------------

| Header file: :file:`helpers/include/edhoc_cipher_suite_0.h`

.. doxygengroup:: edhoc-cipher-suite-0-api
   :project: libedhoc
   :members:

Cipher suite 2
--------------

| Header file: :file:`helpers/include/edhoc_cipher_suite_2.h`

.. note::

   In the bundled reference (``helpers/src/edhoc_cipher_suite_2.c``), what
   would be a single ``psa_sign_message``-style operation is **split** into
   two steps — **hash, then sign** — so you can map each step to the crypto
   setup you have. That is useful when **sending a large blob for signing is
   expensive**, for example with some secure elements; the library still
   passes the **full** COSE ``Sign1`` bytes into the ``signature`` / ``verify``
   callbacks.

.. doxygengroup:: edhoc-cipher-suite-2-api
   :project: libedhoc
   :members:

Connection identifier helpers
-----------------------------

| Header file: :file:`helpers/include/edhoc_helpers.h`

.. doxygengroup:: edhoc-api-connection-id
   :project: libedhoc
   :members:

Buffer utilities
----------------

.. doxygengroup:: edhoc-api-buffer-utils
   :project: libedhoc
   :members:

Macros
------

| Header file: :file:`include/edhoc_macros.h`

.. doxygengroup:: edhoc-macros
   :project: libedhoc
   :members:
