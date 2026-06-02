Quick Start
===========

This page walks through the smallest working EDHOC handshake using libedhoc.
It assumes you have already read :doc:`introduction` and want to see a few
lines of code.

A complete, ready-to-run example lives under
`sample/benchmark <https://github.com/kamil-kielbasa/libedhoc/tree/main/sample>`_
in the repository — when in doubt, refer to it.

Build libedhoc
--------------

**Linux (via the unified CI script):**

.. code-block:: bash

   git clone --recurse-submodules https://github.com/kamil-kielbasa/libedhoc.git
   cd libedhoc
   scripts/ci.sh build --gcc        # or: scripts/ci.sh build --clang

**Zephyr (west):**

.. code-block:: bash

   git clone https://github.com/kamil-kielbasa/libedhoc.git
   west init -l libedhoc
   west update --narrow -o=--depth=1
   west build -b native_sim libedhoc/sample/benchmark

See :doc:`../guide/configuration` for the full list of Kconfig/compile-time
options.

Minimal handshake skeleton
--------------------------

A typical caller initialises the :term:`context`, configures the
:term:`authentication method`\ (s) and :term:`cipher suite`\ (s), binds the
four callback interfaces, drives the messages in order and finally exports
the :term:`OSCORE` material.

.. code-block:: c

   #include <edhoc.h>

   struct edhoc_context ctx;

   /* 1. Initialise. */
   edhoc_context_init(&ctx);

   /* 2. Configure (any order). */
   edhoc_set_methods(&ctx, methods, methods_len);
   edhoc_set_cipher_suites(&ctx, suites, suites_len);
   edhoc_set_connection_id(&ctx, &conn_id);

   /* 3. Bind callbacks (any order). */
   edhoc_bind_keys(&ctx, &keys);
   edhoc_bind_crypto(&ctx, &crypto);
   edhoc_bind_credentials(&ctx, &cred);
   /* edhoc_bind_ead(&ctx, &ead); -- optional */

   /* 4. Run the handshake (Initiator side shown). */
   edhoc_message_1_compose(&ctx, msg1, sizeof(msg1), &msg1_len);
   /* send msg1 over CoAP, receive msg2 */
   edhoc_message_2_process(&ctx, msg2, msg2_len);
   edhoc_message_3_compose(&ctx, msg3, sizeof(msg3), &msg3_len);
   /* optionally exchange message_4 */

   /* 5. Export OSCORE keys and tear down. */
   edhoc_export_oscore_session(&ctx, /* ... */);
   edhoc_context_deinit(&ctx);

The full message flow with the matching CoAP exchange is illustrated on
:doc:`../guide/protocol_flow`.

Next steps
----------

* Read :doc:`concepts` for the EDHOC mental model.
* Browse the API surface starting from :doc:`../api/index`.
* When something goes wrong, check :doc:`../reference/error_codes`.
