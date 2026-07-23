Quick Start
===========

This page shows the smallest working EDHOC handshake with *libedhoc*. It assumes
you have read the :doc:`introduction`. A complete, ready-to-run example lives
in `sample/benchmark
<https://github.com/kamil-kielbasa/libedhoc/tree/main/sample>`_.

Build
-----

All builds go through the unified CI script — the same entry point every CI
job uses:

.. code-block:: bash

   scripts/ci.sh build --gcc        # or --clang

See :doc:`../guide/configuration` for the Kconfig / compile-time options and
the Zephyr (west) workflow.

Minimal handshake
-----------------

A caller allocates the opaque :term:`context`, configures the
:term:`authentication method`\ (s) and :term:`cipher suite`\ (s), binds the
callback interfaces, drives the messages in order and finally exports the
:term:`OSCORE` Security Context.

.. code-block:: c

   #include <edhoc/edhoc.h>

   /* 1. Allocate the opaque context (stack VLA shown; malloc() also works). */
   _Alignas(max_align_t) uint8_t storage[edhoc_context_size()];
   struct edhoc_context *ctx = (struct edhoc_context *)storage;
   edhoc_context_init(ctx);

   /* 2. Configure. */
   edhoc_set_methods(ctx, methods, method_count);
   edhoc_set_cipher_suites(ctx, suites, cipher_suite_count);
   edhoc_set_connection_id(ctx, &connection_id);
   edhoc_set_user_context(ctx, user_context);   /* optional */

   /* 3. Bind interfaces. */
   edhoc_bind_crypto(ctx, &crypto);
   edhoc_bind_platform(ctx, &platform);
   edhoc_bind_credentials(ctx, &credentials);
   /* edhoc_bind_ead(ctx, &ead);  -- optional */

   /* 4. Run the handshake (Initiator side shown). */
   edhoc_message_1_compose(ctx, msg1, sizeof(msg1), &msg1_len);
   /* send msg1, receive msg2 */
   edhoc_message_2_process(ctx, msg2, msg2_len);
   edhoc_message_3_compose(ctx, msg3, sizeof(msg3), &msg3_len);
   /* optionally exchange message_4 */

   /* 5. Export the OSCORE Security Context and tear down. */
   edhoc_export_oscore_context_raw(ctx, /* ... */);
   edhoc_context_deinit(ctx);

The matching CoAP exchange is illustrated on :doc:`../guide/protocol_flow`; the
per-call reference is in :doc:`../api/index`.

Next steps
----------

* :doc:`../guide/security` — how keys are held and wiped.
* :doc:`../api/index` — the complete API surface.
* :doc:`../api/errors` — decoding a failure.
