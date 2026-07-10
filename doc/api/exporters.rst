Exporters
=========

After a successful handshake the EDHOC key schedule yields ``PRK_out``, from
which application keys are derived using the :term:`PRK exporter`. The most
common consumer is :term:`OSCORE` — :c:func:`edhoc_export_oscore_session`
returns the Master Secret, Master Salt and the two Sender/Recipient IDs
required to bootstrap an OSCORE security context.

Applications that derive non-OSCORE keying material can provide the full
RFC 9528 exporter input through
:c:func:`edhoc_export_prk_exporter_with_context`. The existing
:c:func:`edhoc_export_prk_exporter` function is a compatibility shorthand for
an empty exporter context. As required by RFC 9528, applications must use each
``(label, context)`` pair for only one purpose.

A key update (``KEY_UPDATE``) can be performed on an established context to
re-derive ``PRK_out`` from fresh entropy without running a new handshake; the
OSCORE export must then be re-run to obtain refreshed keys.

| Header file: :file:`include/edhoc.h`

.. doxygengroup:: edhoc-api-exporters
   :project: libedhoc
   :members:
