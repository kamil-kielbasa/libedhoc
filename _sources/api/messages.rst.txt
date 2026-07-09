EDHOC Messages
==============

The EDHOC handshake consists of four messages — ``message_1`` through
``message_4`` — plus an out-of-band ``error`` message. The
:term:`Initiator` composes the odd-numbered messages and the
:term:`Responder` composes the even-numbered ones; the matching ``process``
call consumes a message received from the peer.

| Header file: :file:`include/edhoc.h`

.. doxygengroup:: edhoc-api-messages
   :project: libedhoc
   :members:
