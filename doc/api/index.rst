API Reference
=============

This section is the complete reference for the *libedhoc* C API.

Lifecycle
---------

The EDHOC :term:`context` follows a strict call order. A runnable example is in
the :doc:`../getting_started/quick_start`.

#. **Allocate and initialize** — size the opaque context with
   ``edhoc_context_size()``, then ``edhoc_context_init()``.
#. **Configure** — ``edhoc_set_methods()``, ``edhoc_set_cipher_suites()``,
   ``edhoc_set_connection_id()`` and, optionally, ``edhoc_set_user_context()``.
#. **Bind interfaces** — ``edhoc_bind_crypto()``, ``edhoc_bind_credentials()``,
   ``edhoc_bind_platform()`` and the optional ``edhoc_bind_ead()``; their
   callbacks receive the context set with ``edhoc_set_user_context()``.
#. **Exchange messages** (strict order) — ``edhoc_message_1_compose`` /
   ``_process`` through ``edhoc_message_4`` (message 4 optional); the role
   decides which side composes or processes each message.
#. **Export and tear down** — export the OSCORE Security Context, then
   ``edhoc_context_deinit()``.

Steps 2 and 3 may be interleaved in any order; all must complete before the
first message-exchange call.

Error model
-----------

All API functions return ``EDHOC_SUCCESS`` (0) on success or a negative error
code on failure. Error codes are defined in :file:`include/edhoc/values.h` and
listed on the :doc:`errors` page.

After a message-processing function fails, use :c:func:`edhoc_error_get_code`
to retrieve the EDHOC-level error code (RFC 9528, Section 6):

.. code-block:: c

   int ret = edhoc_message_1_process(ctx, msg1, msg1_len);
   if (ret != EDHOC_SUCCESS) {
       enum edhoc_error_code err;
       edhoc_error_get_code(ctx, &err);

       if (err == EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE) {
           /* Retrieve own and peer cipher suites for renegotiation: */
           edhoc_error_get_cipher_suites(ctx, own, own_size, &own_len,
                                         peer, peer_size, &peer_len);
       }
   }

To send an EDHOC error message to the peer:

.. code-block:: c

   const char text[] = "details";
   const struct edhoc_error_info info = {
       .text_string    = text,
       .entries_size   = strlen(text),
       .entries_length = strlen(text),
   };
   edhoc_message_error_compose(buf, buf_size, &buf_len,
                               EDHOC_ERROR_CODE_UNSPECIFIED_ERROR, &info);

API pages
---------

.. toctree::
   :maxdepth: 1

   context
   messages
   crypto
   credentials
   ead
   platform
   exporters
   errors
   cipher_suites
   coap
