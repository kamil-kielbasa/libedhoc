Exporters
=========

After a successful handshake the EDHOC key schedule yields ``PRK_out``, from
which application keys are derived with the :term:`PRK exporter`. Each exporter
comes in two forms: a raw-bytes form (``_raw``) that writes the secret into a
caller buffer, and a key-handle form that returns it as an opaque
:term:`handle` kept inside the crypto backend, so the bytes never leave it.

*libedhoc* also provides a dedicated export of the :term:`OSCORE` Security
Context (in both forms) — the Master Secret, Master Salt and Sender/Recipient
IDs needed to establish OSCORE. A key update (RFC 9528, Section 4.4)
rotates ``PRK_out`` from an application-supplied context — identical on both
peers — so a later export gives fresh keys without a new handshake.

| Header file: :file:`include/edhoc/edhoc.h`

Exporter API
------------

.. doxygengroup:: edhoc-api-exporters
   :project: libedhoc
   :members:

Exporter labels
---------------

The permitted exporter labels and the private-use range are defined in
:file:`include/edhoc/values.h`.

.. doxygengroup:: edhoc-exporter-labels
   :project: libedhoc
   :members:
