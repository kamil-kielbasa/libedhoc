libedhoc
========

*libedhoc* is a C implementation of the Ephemeral Diffie-Hellman Over COSE
(EDHOC) protocol — a lightweight authenticated key exchange for IoT and
constrained devices. It provides :term:`mutual authentication`,
:term:`forward secrecy` and :term:`identity protection`, and is standardised
by the IETF as
`RFC 9528 <https://datatracker.ietf.org/doc/html/rfc9528>`_ and verified
against the test vectors of
`RFC 9529 <https://datatracker.ietf.org/doc/html/rfc9529>`_.

Start here
----------

- **New to EDHOC?** Read the :doc:`getting_started/introduction`.
- **Want code?** Follow the :doc:`getting_started/quick_start`.
- **Integrating the library?** See :doc:`guide/protocol_flow`,
  :doc:`guide/security` and :doc:`guide/configuration`.
- **Looking up a function or type?** Open the :doc:`api/index`.

.. toctree::
   :hidden:
   :caption: Getting Started

   getting_started/introduction
   getting_started/quick_start

.. toctree::
   :hidden:
   :caption: Guide

   guide/protocol_flow
   guide/security
   guide/configuration

.. toctree::
   :hidden:
   :caption: API Reference

   api/index

.. toctree::
   :hidden:
   :caption: Resources

   reference/glossary
   reference/links
   project/changelog
