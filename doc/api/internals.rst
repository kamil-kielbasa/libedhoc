Internal Building Blocks
========================

.. note::

   The groups on this page document **internal building blocks** that the
   public API is built on. They are exposed here for advanced users and
   library contributors. Application code should normally use the higher-level
   APIs from :doc:`messages`, :doc:`exporters` and friends instead.

| Header file: :file:`include/edhoc_common.h`

Common structures
-----------------

.. doxygengroup:: edhoc-common-structures
   :project: libedhoc
   :members:

CBOR encode/decode
------------------

.. doxygengroup:: edhoc-common-cbor
   :project: libedhoc
   :members:

MAC context
-----------

.. doxygengroup:: edhoc-common-mac-context
   :project: libedhoc
   :members:

Sign-or-MAC
-----------

.. doxygengroup:: edhoc-common-sign-or-mac
   :project: libedhoc
   :members:
