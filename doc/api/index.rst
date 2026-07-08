API Reference
=============

This section is the complete reference for the **libedhoc** C API. It is
generated from the Doxygen comments in the public headers under
``include/edhoc/`` and the reference suites under ``library/cipher_suites/``.

If you are new to libedhoc, read :doc:`../getting_started/introduction` and
:doc:`../getting_started/concepts` first; if you are about to write code,
:doc:`../getting_started/quick_start` walks through a minimal handshake.

Lifecycle
---------

The EDHOC :term:`context` must be used following a strict call order.
Deviating from this sequence results in ``EDHOC_ERROR_BAD_STATE``.

**1. Initialization**

.. code-block:: c

   struct edhoc_context ctx;
   edhoc_context_init(&ctx);

**2. Configuration** (order within this group does not matter)

.. code-block:: c

   edhoc_set_methods(&ctx, methods, methods_len);
   edhoc_set_cipher_suites(&ctx, suites, suites_len);
   edhoc_set_connection_id(&ctx, &conn_id);
   edhoc_set_user_context(&ctx, user_ctx);

**3. Bind callbacks** (order within this group does not matter)

.. code-block:: c

   edhoc_bind_keys(&ctx, &keys);
   edhoc_bind_crypto(&ctx, &crypto);
   edhoc_bind_credentials(&ctx, &cred);
   edhoc_bind_ead(&ctx, &ead);          /* optional */

**4. Message exchange** (strict order; role determines which side composes or processes)

.. code-block:: c

   /* Initiator composes, Responder processes: */
   edhoc_message_1_compose / edhoc_message_1_process
   edhoc_message_2_compose / edhoc_message_2_process
   edhoc_message_3_compose / edhoc_message_3_process
   edhoc_message_4_compose / edhoc_message_4_process  /* optional */

**5. Export and teardown**

.. code-block:: c

   edhoc_export_oscore_session(&ctx, ...);
   /* Optionally perform key update and re-export: */
   edhoc_export_key_update(&ctx, entropy, entropy_len);
   edhoc_export_oscore_session(&ctx, ...);
   edhoc_context_deinit(&ctx);

Error model
-----------

All API functions return ``EDHOC_SUCCESS`` (0) on success or a negative error
code on failure. Error codes are defined in :file:`include/edhoc/edhoc_values.h` and
listed on the :doc:`../reference/error_codes` page.

After a message-processing function fails, use :c:func:`edhoc_error_get_code`
to retrieve the EDHOC-level error code (RFC 9528, Section 6):

.. code-block:: c

   int ret = edhoc_message_1_process(&ctx, msg1, msg1_len);
   if (ret != EDHOC_SUCCESS) {
       enum edhoc_error_code err;
       edhoc_error_get_code(&ctx, &err);

       if (err == EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE) {
           /* Retrieve own and peer cipher suites for renegotiation: */
           edhoc_error_get_cipher_suites(&ctx, own, own_size, &own_len,
                                         peer, peer_size, &peer_len);
       }
   }

To send an EDHOC error message to the peer:

.. code-block:: c

   struct edhoc_error_info info = { .text_string = "details", .total_entries = 7 };
   edhoc_message_error_compose(buf, buf_size, &buf_len,
                               EDHOC_ERROR_CODE_UNSPECIFIED_ERROR, &info);

API pages
---------

.. toctree::
   :maxdepth: 1

   context
   messages
   exporters
   credentials
   crypto
   ead
   platform
   helpers
   internals
