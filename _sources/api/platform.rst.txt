Platform Services
=================

*libedhoc* delegates platform-provided services to the application through a
small callback interface. Binding it is **mandatory**: the message API does not
run until a valid platform is bound with :c:func:`edhoc_bind_platform`.

| Header file: :file:`include/edhoc/platform.h`

.. doxygengroup:: edhoc-interface-platform
   :project: libedhoc
   :members:
