EDHOC Context
=============

The EDHOC :term:`context` is the central state object of *libedhoc*. It is
initialised, configured and bound to the application's callbacks, driven
through the message-exchange phase, and finally torn down. See the lifecycle
section of :doc:`index` for the strict call order.

The context is **opaque** and forward-declared, so it must be allocated through
``edhoc_context_size()`` — on the stack (a :term:`VLA`) or on the heap.

| Header file: :file:`include/edhoc/types.h`

Context object
--------------

.. doxygengroup:: edhoc-types
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
:term:`connection identifier`. They may be called in any order, and must all
run before the message-exchange phase.

| Header file: :file:`include/edhoc/edhoc.h`

.. doxygengroup:: edhoc-api-setters
   :project: libedhoc
   :members:
