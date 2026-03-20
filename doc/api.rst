EDHOC API & Interfaces
======================

Lifecycle
*********

The EDHOC context must be used following a strict call order. Deviating from
this sequence results in ``EDHOC_ERROR_BAD_STATE``.

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

Error handling
**************

All API functions return ``EDHOC_SUCCESS`` (0) on success or a negative error
code on failure. Error codes are defined in :file:`include/edhoc_values.h`.

After a message processing function fails, use :c:func:`edhoc_error_get_code`
to retrieve the EDHOC-level error code (RFC 9528: Section 6):

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

Main API
********

| Header file: :file:`include/edhoc.h`.

.. doxygengroup:: edhoc-api-version
   :project: libedhoc
   :members:

.. doxygengroup:: edhoc-api-setters
   :project: libedhoc
   :members:

.. doxygengroup:: edhoc-api-messages
   :project: libedhoc
   :members:

.. doxygengroup:: edhoc-api-exporters
   :project: libedhoc
   :members:

.. doxygengroup:: edhoc-api-error
   :project: libedhoc
   :members:

Authentication credentials
**************************

| Header file: :file:`include/edhoc_credentials.h`.

.. doxygengroup:: edhoc-interface-credentials
   :project: libedhoc
   :members:

Cryptographic operations
************************

| Header file: :file:`include/edhoc_crypto.h`.

.. doxygengroup:: edhoc-interface-crypto-keys
   :project: libedhoc
   :members:

.. doxygengroup:: edhoc-interface-crypto-operations
   :project: libedhoc
   :members:

External Authorization Data
***************************

| Header file: :file:`include/edhoc_ead.h`.

.. doxygengroup:: edhoc-interface-ead
   :project: libedhoc
   :members:

EDHOC context
*************

| Header file: :file:`include/edhoc_context.h`.

.. doxygengroup:: edhoc-context
   :project: libedhoc
   :members:

EDHOC common
************

| Header file: :file:`include/edhoc_common.h`.

.. doxygengroup:: edhoc-common-structures
   :project: libedhoc
   :members:

.. doxygengroup:: edhoc-common-cbor
   :project: libedhoc
   :members:

.. doxygengroup:: edhoc-common-mac-context
   :project: libedhoc
   :members:

.. doxygengroup:: edhoc-common-sign-or-mac
   :project: libedhoc
   :members:

EDHOC cipher suite 0
********************

| Header file: :file:`helpers/include/edhoc_cipher_suite_0.h`.

.. doxygengroup:: edhoc-cipher-suite-0-api
   :project: libedhoc
   :members:

EDHOC cipher suite 2
********************

| Header file: :file:`helpers/include/edhoc_cipher_suite_2.h`.

.. note::

   In the bundled reference (``helpers/src/edhoc_cipher_suite_2.c``), what would be a single
   ``psa_sign_message``-style operation is **split** into two steps—**hash, then sign**—so you can
   map each step to the crypto setup you have. That is useful when **sending a large blob for
   signing is expensive**, for example with some secure elements; the library still passes the
   **full** COSE Sign1 bytes into the ``signature`` / ``verify`` callbacks.

.. doxygengroup:: edhoc-cipher-suite-2-api
   :project: libedhoc
   :members:

EDHOC macros
************

| Header file: :file:`include/edhoc_macros.h`.

.. doxygengroup:: edhoc-macros
   :project: libedhoc
   :members:

EDHOC logging
*************

| Header file: :file:`include/edhoc_log.h`.
| Backend header: :file:`port/log/linux/edhoc_log_backend.h` (Linux) or :file:`port/log/zephyr/edhoc_log_backend.h` (Zephyr).

The logging module provides compile-time configurable log levels via ``CONFIG_LIBEDHOC_LOG_LEVEL``:

.. list-table::
   :header-rows: 1

   * - Level
     - Macro
     - Value
   * - None
     - ``EDHOC_LOG_LEVEL_NONE``
     - 0
   * - Error
     - ``EDHOC_LOG_LEVEL_ERR``
     - 1
   * - Warning
     - ``EDHOC_LOG_LEVEL_WRN``
     - 2
   * - Info
     - ``EDHOC_LOG_LEVEL_INF``
     - 3
   * - Debug
     - ``EDHOC_LOG_LEVEL_DBG``
     - 4

Set ``CONFIG_LIBEDHOC_LOG_LEVEL`` to the desired level during compilation. Each level enables all levels below it. The Linux backend outputs timestamped, color-coded messages to stdout/stderr. The Zephyr backend delegates to the Zephyr logging subsystem.

EDHOC helpers
*************

| Header file: :file:`helpers/include/edhoc_helpers.h`.

.. doxygengroup:: edhoc-api-connection-id
   :project: libedhoc
   :members:

.. doxygengroup:: edhoc-api-buffer-utils
   :project: libedhoc
   :members: