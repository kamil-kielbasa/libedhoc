CoAP Integration
================

*libedhoc* is transport-agnostic, but running :term:`EDHOC` over :term:`CoAP`
(:term:`RFC 9528`, Appendix A, and the combined EDHOC + :term:`OSCORE` profile
of :term:`RFC 9668`) needs a little framing: prepending the
:term:`connection identifier` or the ``true`` flag to a message and extracting
it again on receipt. These helpers are dependency-free byte manipulation and
ship as part of the library core.

| Header file: :file:`include/edhoc/coap.h`

Connection identifiers
----------------------

.. doxygengroup:: edhoc-api-connection-id
   :project: libedhoc
   :members:

Message framing
---------------

.. doxygengroup:: edhoc-api-buffer-utils
   :project: libedhoc
   :members:
