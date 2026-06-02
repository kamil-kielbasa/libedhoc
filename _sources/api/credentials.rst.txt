Authentication Credentials
==========================

The credentials interface lets the application supply its own credential
(``CRED_I`` or ``CRED_R``) and verify the peer's credential. libedhoc does
not embed credential storage or validation logic: the user controls how
credentials are looked up, verified (including :term:`CRL` checks) and
persisted in the application context.

Supported credential identifications (from the COSE IANA registry) are
:term:`kid`, :term:`x5chain` and :term:`x5t`.

| Header file: :file:`include/edhoc_credentials.h`

.. doxygengroup:: edhoc-interface-credentials
   :project: libedhoc
   :members:
