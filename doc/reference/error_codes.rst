EDHOC Error Codes
=================

This page documents the EDHOC error-code enumeration and the runtime
error-getter API used to retrieve EDHOC-level information after a message
processing or composition failure.

All public functions return ``EDHOC_SUCCESS`` (``0``) on success or a
negative C error code. After a failure, call :c:func:`edhoc_error_get_code`
to retrieve the EDHOC error code carried in (or to be carried in) the
on-the-wire error message defined in RFC 9528, Section 6.

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
