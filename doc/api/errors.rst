EDHOC Error Codes
=================

All API functions return ``EDHOC_SUCCESS`` (``0``) on success or a negative C
error code on failure. After a message compose or process failure, call
:c:func:`edhoc_error_get_code` to retrieve the EDHOC-level error code carried
in (or to be carried in) the on-the-wire error message defined in RFC 9528,
Section 6.

| Header file: :file:`include/edhoc/values.h`

Error code enumeration
----------------------

.. doxygengroup:: edhoc-error-codes
   :project: libedhoc
   :members:

Runtime error API
-----------------

.. doxygengroup:: edhoc-api-error
   :project: libedhoc
   :members:
