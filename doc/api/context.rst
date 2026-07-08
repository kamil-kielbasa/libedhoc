EDHOC Context
=============

The EDHOC :term:`context` is the central state object of the library. A
context is initialised, configured with methods and cipher suites, bound to a
set of callbacks (keys, crypto, credentials, platform, optionally EAD), driven
through the message-exchange phase, and finally torn down. See the lifecycle
section of :doc:`index` for the strict call order.

The context is **opaque**: its layout is internal to the library. Allocate
storage sized by ``edhoc_context_size()`` — on the stack (a VLA) or on the heap
— and drive it through the API; do not declare a ``struct edhoc_context`` by
value.

| Header file: :file:`include/edhoc/edhoc_types.h`

Context object
--------------

.. doxygengroup:: edhoc-context
   :project: libedhoc
   :members:

Library version
---------------

| Header file: :file:`include/edhoc/edhoc.h`

.. doxygengroup:: edhoc-api-version
   :project: libedhoc
   :members:

Setters
-------

The setters configure a freshly-initialised context with the local
:term:`authentication method`\ (s), :term:`cipher suite`\ (s) and the local
:term:`connection identifier`. They may be called in any order, but must all
run before any binder or message-exchange call.

| Header file: :file:`include/edhoc/edhoc.h`

.. doxygengroup:: edhoc-api-setters
   :project: libedhoc
   :members:
