Exporters
=========

After a successful handshake the EDHOC key schedule yields ``PRK_out``, from
which application keys are derived using the :term:`PRK exporter`. The most
common consumer is :term:`OSCORE` — :c:func:`edhoc_export_oscore_session`
returns the Master Secret, Master Salt and the two Sender/Recipient IDs
required to bootstrap an OSCORE security context.

A key update (``KEY_UPDATE``) can be performed on an established context to
re-derive ``PRK_out`` from fresh entropy without running a new handshake; the
OSCORE export must then be re-run to obtain refreshed keys.

| Header file: :file:`include/edhoc/edhoc.h`

.. doxygengroup:: edhoc-api-exporters
   :project: libedhoc
   :members:
