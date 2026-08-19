/**
 * \file    edhoc_exporter_internal.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC exporter for PRK exporter, key update or OSCORE Security Context.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include <edhoc_config.h>
#endif

/* EDHOC public headers: */
#include <edhoc/edhoc.h>
#include <edhoc/values.h>
#include <edhoc/cipher_suite.h>
#include <edhoc/crypto.h>

/* EDHOC internal headers: */
#include "edhoc_exporter_internal.h"
#include "edhoc_context_internal.h"
#include "edhoc_key_slot_internal.h"
#include "edhoc_kdf_internal.h"
#include "edhoc_key_schedule_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_connection_id_internal.h"
#include "edhoc_backend_log.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */

/** \brief Output form produced by \ref derive_exporter_output. */
enum exporter_output_kind {
	/** Opaque key-store handle (length governed by the key usage). */
	EXPORTER_OUTPUT_HANDLE,
	/** Raw keying-material bytes. */
	EXPORTER_OUTPUT_BYTES,
};

/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Is \p label a permitted EDHOC exporter label (RFC 9528: 10.1)?
 *
 *        Permitted labels are 0 (OSCORE Master Secret), 1 (OSCORE Master Salt)
 *        and the private-use range 32768-65535.
 *
 * \param label			EDHOC exporter label.
 *
 * \return \c true when \p label is permitted.
 */
STATIC bool is_exporter_label_permitted(size_t label);

/**
 * \brief Shared exporter core: derive \p output_length bytes of keying material
 *        from PRK_exporter as a key handle or raw bytes.
 *
 *        \p output_kind selects the output form and how \p output is read:
 *        #EXPORTER_OUTPUT_HANDLE writes a key handle (governed by \p usage),
 *        #EXPORTER_OUTPUT_BYTES writes \p output_length raw bytes. On any
 *        failure the caller's \p output is scrubbed so no keying material is
 *        leaked.
 *
 * \param[in,out] ctx		EDHOC context.
 * \param label			EDHOC exporter label.
 * \param[in] context		Exporter context byte string.
 * \param context_len		Size of \p context in bytes.
 * \param usage			Key usage (key-handle form only).
 * \param output_kind		Selects handle vs. raw-bytes output.
 * \param[out] output		Key handle or raw-bytes buffer to fill.
 * \param output_length		Number of bytes to derive.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int derive_exporter_output(struct edhoc_context *ctx, size_t label,
				  const uint8_t *context, size_t context_len,
				  enum edhoc_key_usage usage,
				  enum exporter_output_kind output_kind,
				  void *output, size_t output_length);

/**
 * \brief Validate that an OSCORE Security Context export may run in the current state.
 *
 * \param[in] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int check_oscore_export(const struct edhoc_context *ctx);

/**
 * \brief Derive the OSCORE master salt and copy the sender/recipient IDs.
 *
 * \param[in,out] ctx		EDHOC context.
 * \param[out] salt		Buffer for the OSCORE master salt.
 * \param salt_len		Size of \p salt in bytes.
 * \param[out] sid		Buffer for the OSCORE sender ID.
 * \param sid_size		Size of \p sid in bytes.
 * \param[out] sid_len		On success, the sender ID length.
 * \param[out] rid		Buffer for the OSCORE recipient ID.
 * \param rid_size		Size of \p rid in bytes.
 * \param[out] rid_len		On success, the recipient ID length.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int export_oscore_salt_and_ids(struct edhoc_context *ctx, uint8_t *salt,
				      size_t salt_len, uint8_t *sid,
				      size_t sid_size, size_t *sid_len,
				      uint8_t *rid, size_t rid_size,
				      size_t *rid_len);

/* Static function definitions --------------------------------------------- */

STATIC bool is_exporter_label_permitted(size_t label)
{
	return EDHOC_EXPORTER_LABEL_OSCORE_MASTER_SECRET == label ||
	       EDHOC_EXPORTER_LABEL_OSCORE_MASTER_SALT == label ||
	       (EDHOC_PRK_EXPORTER_PRIVATE_LABEL_MINIMUM <= label &&
		label <= EDHOC_PRK_EXPORTER_PRIVATE_LABEL_MAXIMUM);
}

STATIC int derive_exporter_output(struct edhoc_context *ctx, size_t label,
				  const uint8_t *context, size_t context_len,
				  enum edhoc_key_usage usage,
				  enum exporter_output_kind output_kind,
				  void *output, size_t output_length)
{
	if (NULL == ctx || (NULL == context && 0 != context_len) ||
	    NULL == output || 0 == output_length) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* 1. Validate the exporter state and derive PRK_out if not present. */
	if (EDHOC_SM_PERSISTED < ctx->state.machine ||
	    EDHOC_PRK_STATE_4E3M > ctx->state.prk_state) {
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	if (EDHOC_PRK_STATE_4E3M == ctx->state.prk_state) {
		ret = edhoc_key_schedule_prk_out(ctx);

		if (EDHOC_SUCCESS != ret) {
			return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
		}
	}

	/* 2. Compute the transient PRK_exporter. */
	ret = edhoc_key_schedule_prk_exporter(ctx);

	if (EDHOC_SUCCESS != ret) {
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 3. Derive the keying material as a key handle or raw bytes. */
	const void *prk_exporter =
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_EXPORTER);

	switch (output_kind) {
	case EXPORTER_OUTPUT_HANDLE:
		ret = edhoc_kdf_expand(ctx, prk_exporter, (int32_t)label,
				       context, context_len, usage, output,
				       output_length);
		break;
	case EXPORTER_OUTPUT_BYTES:
		ret = edhoc_kdf_expand_raw(ctx, prk_exporter, (int32_t)label,
					   context, context_len, output,
					   output_length);
		break;
	default:
		ret = EDHOC_ERROR_NOT_SUPPORTED;
		break;
	}

	/* 4. Release the transient PRK_exporter. */
	const int destroy_ret =
		edhoc_key_slot_release(ctx, EDHOC_KEY_SLOT_PRK_EXPORTER);

	if (EDHOC_SUCCESS != ret) {
		/* Never leave derived keying material in the caller's output. */
		edhoc_zeroize(ctx, output,
			      EXPORTER_OUTPUT_HANDLE == output_kind ?
				      CONFIG_LIBEDHOC_KEY_ID_LEN :
				      output_length);

		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	if (EDHOC_SUCCESS != destroy_ret) {
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int check_oscore_export(const struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (false == ctx->is_oscore_export_allowed) {
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_SM_COMPLETED > ctx->state.machine ||
	    EDHOC_PRK_STATE_4E3M > ctx->state.prk_state) {
		return EDHOC_ERROR_BAD_STATE;
	}

	const struct connection_id *own = &ctx->negotiation.connection_id;
	const struct connection_id *peer = &ctx->negotiation.peer_connection_id;

	/* RFC 9528: 3.3.3 - C_I and C_R become the OSCORE Recipient IDs, so
	 * equal ones give both peers the same key and the same nonce. Two
	 * empty identifiers collide as well. */
	if (own->length == peer->length &&
	    0 == memcmp(own->value, peer->value, own->length)) {
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	return EDHOC_SUCCESS;
}

STATIC int export_oscore_salt_and_ids(struct edhoc_context *ctx, uint8_t *salt,
				      size_t salt_len, uint8_t *sid,
				      size_t sid_size, size_t *sid_len,
				      uint8_t *rid, size_t rid_size,
				      size_t *rid_len)
{
	if (NULL == ctx || NULL == salt || 0 == salt_len || NULL == sid ||
	    0 == sid_size || NULL == sid_len || NULL == rid || 0 == rid_size ||
	    NULL == rid_len) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* 1. Derive OSCORE master salt. */
	int ret = edhoc_exporter_export_raw(
		ctx, EDHOC_EXPORTER_LABEL_OSCORE_MASTER_SALT, NULL, 0, salt,
		salt_len);

	if (EDHOC_SUCCESS != ret) {
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 2. Copy OSCORE sender ID. RFC 9528: 3.3.3 - the OSCORE identifier is
	 * the connection identifier byte string itself. */
	if (sid_size < ctx->negotiation.peer_connection_id.length) {
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	*sid_len = ctx->negotiation.peer_connection_id.length;
	memcpy(sid, ctx->negotiation.peer_connection_id.value, *sid_len);

	/* 3. Copy OSCORE recipient ID. */
	if (rid_size < ctx->negotiation.connection_id.length) {
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	*rid_len = ctx->negotiation.connection_id.length;
	memcpy(rid, ctx->negotiation.connection_id.value, *rid_len);

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

int edhoc_exporter_export(struct edhoc_context *ctx, size_t label,
			  const uint8_t *context, size_t context_len,
			  enum edhoc_key_usage usage, void *key_id)
{
	if (NULL == ctx || (NULL == context && 0 != context_len) ||
	    NULL == key_id) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!is_exporter_label_permitted(label)) {
		EDHOC_LOG_ERR("Exporter label not permitted: %zu", label);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);

	size_t output_length = 0;

	switch (usage) {
	case EDHOC_KEY_USAGE_KDF:
		output_length = csuite->hash_length;
		break;
	case EDHOC_KEY_USAGE_AEAD:
		output_length = csuite->aead_key_length;
		break;
	default:
		EDHOC_LOG_ERR("Invalid key usage: %d", usage);
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	return derive_exporter_output(ctx, label, context, context_len, usage,
				      EXPORTER_OUTPUT_HANDLE, key_id,
				      output_length);
}

int edhoc_exporter_export_raw(struct edhoc_context *ctx, size_t label,
			      const uint8_t *context, size_t context_len,
			      uint8_t *secret, size_t secret_len)
{
	if (NULL == ctx || (NULL == context && 0 != context_len) ||
	    NULL == secret || 0 == secret_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!is_exporter_label_permitted(label)) {
		EDHOC_LOG_ERR("Exporter label not permitted: %zu", label);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	return derive_exporter_output(ctx, label, context, context_len,
				      EDHOC_KEY_USAGE_KDF,
				      EXPORTER_OUTPUT_BYTES, secret,
				      secret_len);
}

int edhoc_exporter_key_update(struct edhoc_context *ctx, const uint8_t *context,
			      size_t context_len)
{
	if (NULL == ctx || NULL == context || 0 == context_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_SM_COMPLETED > ctx->state.machine ||
	    EDHOC_PRK_STATE_4E3M > ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d", ctx->state.machine,
			      ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	const enum edhoc_state_machine status = ctx->state.machine;
	ctx->state.machine = EDHOC_SM_ABORTED;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	if (EDHOC_PRK_STATE_4E3M == ctx->state.prk_state) {
		ret = edhoc_key_schedule_prk_out(ctx);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Compute PRK_out for key update: %d",
				      ret);
			return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
		}
	}

	ret = edhoc_key_schedule_prk_out_update(ctx, context, context_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute new PRK_out: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	ctx->state.machine = status;
	ctx->is_oscore_export_allowed = true;
	return EDHOC_SUCCESS;
}

/*
 * Steps for exporting the OSCORE Security Context (master secret as a handle):
 *      1. Check that an OSCORE export may run.
 *      2. Derive OSCORE master salt and copy the sender/recipient IDs.
 *      3. Derive OSCORE master secret (caller-owned key handle).
 */
int edhoc_exporter_oscore_context(struct edhoc_context *ctx,
				  void *master_secret_key_id, uint8_t *salt,
				  size_t salt_len, uint8_t *sid,
				  size_t sid_size, size_t *sid_len,
				  uint8_t *rid, size_t rid_size,
				  size_t *rid_len)
{
	if (NULL == ctx || NULL == master_secret_key_id || NULL == salt ||
	    0 == salt_len || NULL == sid || 0 == sid_size || NULL == sid_len ||
	    NULL == rid || 0 == rid_size || NULL == rid_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = check_oscore_export(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Check OSCORE export: %d", ret);
		return ret;
	}

	const enum edhoc_state_machine status = ctx->state.machine;
	ctx->state.machine = EDHOC_SM_ABORTED;
	ctx->is_oscore_export_allowed = false;

	/* 1. Derive OSCORE master salt and copy the sender/recipient IDs. */
	ret = export_oscore_salt_and_ids(ctx, salt, salt_len, sid, sid_size,
					 sid_len, rid, rid_size, rid_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Export OSCORE salt and IDs: %d", ret);
		return ret;
	}

	/* 2. Derive OSCORE master secret (caller-owned key handle). Per RFC 9528
	 * A.1 the OSCORE Master Secret length defaults to the application AEAD
	 * key length, so it is derived as an AEAD key. The derive scrubs its own
	 * output on failure, so nothing leaks here. */
	ret = edhoc_exporter_export(ctx,
				    EDHOC_EXPORTER_LABEL_OSCORE_MASTER_SECRET,
				    NULL, 0, EDHOC_KEY_USAGE_AEAD,
				    master_secret_key_id);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Derive OSCORE master secret: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	ctx->state.machine = status;
	return EDHOC_SUCCESS;
}

/*
 * Steps for exporting the OSCORE Security Context (raw master secret):
 *      1. Check that an OSCORE export may run.
 *      2. Derive OSCORE master salt and copy the sender/recipient IDs.
 *      3. Derive OSCORE master secret (raw bytes).
 */
int edhoc_exporter_oscore_context_raw(struct edhoc_context *ctx,
				      uint8_t *secret, size_t secret_len,
				      uint8_t *salt, size_t salt_len,
				      uint8_t *sid, size_t sid_size,
				      size_t *sid_len, uint8_t *rid,
				      size_t rid_size, size_t *rid_len)
{
	if (NULL == ctx || NULL == secret || 0 == secret_len || NULL == salt ||
	    0 == salt_len || NULL == sid || 0 == sid_size || NULL == sid_len ||
	    NULL == rid || 0 == rid_size || NULL == rid_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = check_oscore_export(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Check OSCORE export: %d", ret);
		return ret;
	}

	const enum edhoc_state_machine status = ctx->state.machine;
	ctx->state.machine = EDHOC_SM_ABORTED;
	ctx->is_oscore_export_allowed = false;

	/* 1. Derive OSCORE master salt and copy the sender/recipient IDs. */
	ret = export_oscore_salt_and_ids(ctx, salt, salt_len, sid, sid_size,
					 sid_len, rid, rid_size, rid_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Export OSCORE salt and IDs: %d", ret);
		return ret;
	}

	/* 2. Derive OSCORE master secret (raw bytes). The derive scrubs its
	 * own output on failure, so nothing leaks here. */
	ret = edhoc_exporter_export_raw(
		ctx, EDHOC_EXPORTER_LABEL_OSCORE_MASTER_SECRET, NULL, 0, secret,
		secret_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Derive OSCORE master secret: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	ctx->state.machine = status;
	return EDHOC_SUCCESS;
}
