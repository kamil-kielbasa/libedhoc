EDHOC Error Codes
=================

All API functions return ``EDHOC_SUCCESS`` (``0``) on success or a negative C
error code on failure. After a message compose or process failure, call
:c:func:`edhoc_error_get_code` to retrieve the EDHOC-level error code carried
in (or to be carried in) the on-the-wire error message defined in RFC 9528,
Section 6.

| Header file: :file:`include/edhoc/values.h`

Cipher suite negotiation
------------------------

Both roles reach :c:func:`edhoc_error_get_cipher_suites` once
``EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE`` is recorded for the session.
The own list is always the one given to :c:func:`edhoc_set_cipher_suites`; the
peer list is the ``SUITES_I`` received in message 1 on the Responder, and the
``SUITES_R`` received in the error message on the Initiator.

The Responder reaches it when :c:func:`edhoc_message_1_process` rejects the
selected suite, and builds ``SUITES_R`` out of the two lists. The Initiator
reaches it after decoding that error message:

.. code-block:: c

   int32_t suites_r[8] = { 0 };
   enum edhoc_error_code err = EDHOC_ERROR_CODE_SUCCESS;
   struct edhoc_error_info info = {
       .cipher_suites  = suites_r,
       .entries_size   = sizeof(suites_r) / sizeof(*suites_r),
       .entries_length = 0,
   };

   edhoc_message_error_process(ctx, buf, buf_len, &err, &info);

   if (err == EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE) {
       edhoc_error_get_cipher_suites(ctx, own, own_size, &own_len,
                                     peer, peer_size, &peer_len);
   }

Retrying is a new EDHOC session: reinitialize the context, so that message 1 is
composed with a fresh ephemeral key pair (RFC 9528, Section 6.3.1).

Aborted and completed sessions
------------------------------

:c:func:`edhoc_message_error_compose` and :c:func:`edhoc_message_error_process`
abort the session, so any following message call returns
``EDHOC_ERROR_BAD_STATE``. A completed session is the exception: both return
``EDHOC_ERROR_BAD_STATE`` and leave the context untouched, so the exporters keep
working. An error message is not authenticated, and the session output may be
maintained even if one is received (RFC 9528, Section 5.1).

Error code enumeration
----------------------

.. doxygengroup:: edhoc-error-codes
   :project: libedhoc
   :members:

Runtime error API
-----------------

.. doxygengroup:: edhoc-api-error
   :project: libedhoc
   :members:
