Platform Services
=================

libedhoc delegates a small set of platform-provided services to the
application. Currently this is a single **mandatory** callback, ``zeroize`` — a
memory wipe used to erase sensitive data from a buffer once it is no longer
needed, in a way the compiler may not elide.

The binding is mandatory: the message-processing API refuses to run (returns
``EDHOC_ERROR_BAD_STATE``) until a platform with a valid ``zeroize`` is bound
with :c:func:`edhoc_bind_platform`.

| Header file: :file:`include/edhoc/platform.h`

.. doxygengroup:: edhoc-interface-platform
   :project: libedhoc
   :members:
