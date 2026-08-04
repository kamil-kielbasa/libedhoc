Authentication Credentials
==========================

The credentials interface lets the application supply its own credential
(``CRED_I`` or ``CRED_R``) and authenticate the peer's credential. *libedhoc*
does not embed credential storage or validation logic: the user controls how
credentials are looked up, authenticated (including :term:`CRL` checks) and
persisted in the application context.

Supported credential identifications (from the COSE IANA registry) are
:term:`kid`, :term:`x5chain` and :term:`x5t`.

Two callbacks
-------------

``select_local`` presents the local credential. The library zeroes
``struct edhoc_credential_selected`` before every call, so the callback only
sets what its ``label`` selects; leaving ``label`` unset is rejected. CRED
belongs to the variant: ``kid`` names it in ``kid.credential``, ``x5t`` in
``x509_hash.certificate``, and for ``x5chain`` the library takes
``x509_chain.certificate[0]``, which RFC 9528 fixes as CRED.

``authenticate_peer`` decides whether to trust what the peer sent. It reads
``struct edhoc_credential_received`` and, on success, fills
``struct edhoc_credential_trusted`` with the credential, its format and the
public key to authenticate with. Every buffer in ``received`` is a view into
the message being processed: valid until the processing call returns, and safe
to hand straight back in ``trusted``.

A ``kid`` is a byte string on both callbacks. Its compact CBOR integer form
(RFC 9528: 3.3.2) is a transport encoding that the library applies and undoes
on its own.

| Header file: :file:`include/edhoc/credentials.h`

.. doxygengroup:: edhoc-interface-credentials
   :project: libedhoc
   :members:
