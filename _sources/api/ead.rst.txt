External Authorization Data
===========================

EDHOC carries optional :term:`EAD` items in fields ``EAD_1`` … ``EAD_4`` of
the four handshake messages. libedhoc exposes a thin callback interface that
lets the application produce outgoing EAD tokens and inspect incoming ones
without changing the protocol state machine.

| Header file: :file:`include/edhoc_ead.h`

.. doxygengroup:: edhoc-interface-ead
   :project: libedhoc
   :members:
