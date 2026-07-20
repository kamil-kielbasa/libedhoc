libedhoc
========

**libedhoc** is a C implementation of the Ephemeral Diffie-Hellman Over COSE
(EDHOC) protocol — a lightweight authenticated key exchange for IoT and
constrained devices. It provides :term:`mutual authentication`,
:term:`forward secrecy` and :term:`identity protection`, and is standardised
by the IETF as
`RFC 9528 <https://datatracker.ietf.org/doc/html/rfc9528>`_ and verified
against the test vectors of
`RFC 9529 <https://datatracker.ietf.org/doc/html/rfc9529>`_.

Where to start
--------------

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - I want to…
     - Go to
   * - Learn what EDHOC and libedhoc are
     - :doc:`getting_started/introduction`, :doc:`getting_started/concepts`
   * - Build and run my first handshake
     - :doc:`getting_started/quick_start`, :doc:`guide/configuration`
   * - See the protocol message flow
     - :doc:`guide/protocol_flow`
   * - Look up a function or type
     - :doc:`api/index`
   * - Decode an error or constant
     - :doc:`reference/error_codes`, :doc:`reference/values`
   * - Learn a term
     - :doc:`reference/glossary`
   * - Contribute or run tests
     - :doc:`project/contributing`, :doc:`project/testing`

.. toctree::
   :hidden:
   :caption: Getting Started

   getting_started/introduction
   getting_started/quick_start
   getting_started/concepts

.. toctree::
   :hidden:
   :caption: User Guide

   guide/protocol_flow
   guide/configuration

.. toctree::
   :hidden:
   :caption: API Reference

   api/index

.. toctree::
   :hidden:
   :caption: Reference

   reference/error_codes
   reference/values
   reference/glossary
   reference/links

.. toctree::
   :hidden:
   :caption: Project

   project/contributing
   project/testing
   project/changelog
