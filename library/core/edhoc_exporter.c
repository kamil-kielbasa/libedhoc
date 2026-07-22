/**
 * \file    edhoc_exporter.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC exporter for PRK exporter, key update or OSCORE session.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* EDHOC header: */
#include <edhoc/edhoc.h>
#include "edhoc_context_internal.h"
#include "edhoc_values_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_common_internal.h"
#include "edhoc_backend_log.h"
#include "edhoc_backend_memory.h"

/* Standard library headers: */
#include <string.h>
#include <stdint.h>

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_int_type_encode.h>
#include <backend_cbor_info_encode.h>

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
 * \brief Compute output pseudo random key (PRK_out).
 *
 * \param[in] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int compute_prk_out(struct edhoc_context *ctx);

/**
 * \brief Compute a new output pseudo random key (PRK_out) for KeyUpdate.
 *
 * \param[in,out] ctx		EDHOC context.
 * \param[in] context		KeyUpdate context byte string.
 * \param context_len		Size of \p context in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int compute_new_prk_out(struct edhoc_context *ctx,
			       const uint8_t *context, size_t context_len);

/**
 * \brief Compute exporter pseudo random key (PRK_exporter) into its key slot.
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int compute_prk_exporter(struct edhoc_context *ctx);

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
 * \brief Validate that an OSCORE session export may run in the current state.
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
	return OSCORE_EXTRACT_LABEL_MASTER_SECRET == label ||
	       OSCORE_EXTRACT_LABEL_MASTER_SALT == label ||
	       (EDHOC_PRK_EXPORTER_PRIVATE_LABEL_MINIMUM <= label &&
		label <= EDHOC_PRK_EXPORTER_PRIVATE_LABEL_MAXIMUM);
}

STATIC int compute_prk_out(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_4 != ctx->state.th.stage ||
	    EDHOC_PRK_STATE_4E3M != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d", ctx->state.th.stage,
			      ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);

	/* Calculate struct info cbor overhead. */
	size_t len = 0;
	len += edhoc_cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_PRK_OUT);
	len += ctx->state.th.length + edhoc_cbor_bstr_oh(ctx->state.th.length);
	len += edhoc_cbor_int_mem_req((int32_t)csuite->hash_length);

	EDHOC_MEM_ALLOC(uint8_t, info, len);
	if (NULL == info) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	/* Generate PRK_out. */
	const struct info input_info = {
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_PRK_OUT,
		.info_context.value = ctx->state.th.value,
		.info_context.len = ctx->state.th.length,
		.info_length = (uint32_t)csuite->hash_length,
	};

	len = 0;
	ret = cbor_encode_info(info, EDHOC_MEM_ALLOC_SIZE(info), &input_info,
			       &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc PRK_out info: %d", ret);
		EDHOC_MEM_FREE(info);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* EDHOC_Expand(PRK_4e3m, info) -> PRK_out (KDF key handle). */
	ret = edhoc_crypto(ctx)->expand(
		ctx->user_context,
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_4E3M), info, len,
		EDHOC_KEY_USAGE_KDF,
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_OUT));
	EDHOC_MEM_FREE(info);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Expand PRK_out: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	edhoc_key_slot_mark_present(ctx, EDHOC_KEY_SLOT_PRK_OUT);

	/* PRK_4e3m is spent; release it. After the handshake messages have
	 * freed their secrets it is the only live slot below PRK_out, so the
	 * prefix release destroys exactly that handle. */
	ret = edhoc_key_slot_release_up_to(ctx, EDHOC_KEY_SLOT_PRK_OUT);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Release spent key slots: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ctx->state.prk_state = EDHOC_PRK_STATE_OUT;
	return EDHOC_SUCCESS;
}

STATIC int compute_new_prk_out(struct edhoc_context *ctx,
			       const uint8_t *context, size_t context_len)
{
	if (NULL == ctx || (NULL == context && 0 != context_len)) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_PRK_STATE_OUT != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad state: %d", ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);

	/* Calculate struct info cbor overhead. */
	size_t len = 0;
	len += edhoc_cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_NEW_PRK_OUT);
	len += context_len + edhoc_cbor_bstr_oh(context_len);
	len += edhoc_cbor_int_mem_req((int32_t)csuite->hash_length);

	EDHOC_MEM_ALLOC(uint8_t, info, len);
	if (NULL == info) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	/* Generate PRK_out. */
	const struct info input_info = {
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_NEW_PRK_OUT,
		.info_context.value = context,
		.info_context.len = context_len,
		.info_length = (uint32_t)csuite->hash_length,
	};

	len = 0;
	ret = cbor_encode_info(info, EDHOC_MEM_ALLOC_SIZE(info), &input_info,
			       &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc new PRK_out info: %d", ret);
		EDHOC_MEM_FREE(info);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* new PRK_out = EDHOC_Expand(PRK_out, info(context)). The old PRK_out
	 * handle is taken from a local copy so the derivation can write the new
	 * handle straight into the PRK_out slot; the old handle is destroyed
	 * afterwards. */
	uint8_t old_prk_out[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	edhoc_key_slot_snapshot(ctx, EDHOC_KEY_SLOT_PRK_OUT, old_prk_out);

	ret = edhoc_crypto(ctx)->expand(
		ctx->user_context, old_prk_out, info, len, EDHOC_KEY_USAGE_KDF,
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_OUT));
	EDHOC_MEM_FREE(info);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Expand new PRK_out: %d", ret);
		/* Restore the old PRK_out handle so the slot stays valid. */
		edhoc_key_slot_restore(ctx, EDHOC_KEY_SLOT_PRK_OUT,
				       old_prk_out);
		edhoc_zeroize(ctx, old_prk_out, sizeof(old_prk_out));
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* The new PRK_out handle now owns the slot; destroy the old one. */
	ret = edhoc_key_destroy(ctx, old_prk_out);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Destroy old PRK_out: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int compute_prk_exporter(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_PRK_STATE_OUT != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad state: %d", ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);

	size_t len = 0;
	len += edhoc_cbor_int_mem_req(
		EDHOC_EXTRACT_PRK_INFO_LABEL_PRK_EXPORTER);
	len += edhoc_cbor_bstr_oh(0); /* cbor empty byte string. */
	len += edhoc_cbor_int_mem_req((int32_t)csuite->hash_length);

	EDHOC_MEM_ALLOC(uint8_t, info, len);
	if (NULL == info) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	const struct info input_info = {
		.info_label =
			(int32_t)EDHOC_EXTRACT_PRK_INFO_LABEL_PRK_EXPORTER,
		.info_context.value = NULL,
		.info_context.len = 0,
		.info_length = (uint32_t)csuite->hash_length,
	};

	len = 0;
	ret = cbor_encode_info(info, EDHOC_MEM_ALLOC_SIZE(info), &input_info,
			       &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc PRK_exporter info: %d", ret);
		EDHOC_MEM_FREE(info);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* EDHOC_Expand(PRK_out, info) -> PRK_exporter (KDF key handle). */
	ret = edhoc_crypto(ctx)->expand(
		ctx->user_context,
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_OUT), info, len,
		EDHOC_KEY_USAGE_KDF,
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_EXPORTER));
	EDHOC_MEM_FREE(info);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Expand PRK_exporter: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	edhoc_key_slot_mark_present(ctx, EDHOC_KEY_SLOT_PRK_EXPORTER);
	return EDHOC_SUCCESS;
}

STATIC int derive_exporter_output(struct edhoc_context *ctx, size_t label,
				  const uint8_t *context, size_t context_len,
				  enum edhoc_key_usage usage,
				  enum exporter_output_kind output_kind,
				  void *output, size_t output_length)
{
	if (NULL == ctx || (NULL == context && 0 != context_len) ||
	    NULL == output || 0 == output_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* 1. Validate the exporter state and derive PRK_out if not present. */
	if (EDHOC_SM_PERSISTED < ctx->state.machine ||
	    EDHOC_PRK_STATE_4E3M > ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d", ctx->state.machine,
			      ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	if (EDHOC_PRK_STATE_4E3M == ctx->state.prk_state) {
		ret = compute_prk_out(ctx);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Compute PRK_out: %d", ret);
			return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
		}
	}

	/* 2. Cborise the exporter info (label, context, output length). */
	size_t len = 0;
	len += edhoc_cbor_int_mem_req((int32_t)label);
	len += context_len + edhoc_cbor_bstr_oh(context_len);
	len += edhoc_cbor_int_mem_req((int32_t)output_length);

	EDHOC_MEM_ALLOC(uint8_t, info, len);
	if (NULL == info) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	const struct info input_info = (struct info){
		.info_label = (int32_t)label,
		.info_context.value = context,
		.info_context.len = context_len,
		.info_length = (uint32_t)output_length,
	};

	len = 0;
	ret = cbor_encode_info(info, EDHOC_MEM_ALLOC_SIZE(info), &input_info,
			       &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc exporter info: %d", ret);
		EDHOC_MEM_FREE(info);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* 3. Compute the transient PRK_exporter. */
	ret = compute_prk_exporter(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_exporter: %d", ret);
		EDHOC_MEM_FREE(info);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 4. Derive the keying material as a key handle or raw bytes. */
	const void *prk_exporter =
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_EXPORTER);

	switch (output_kind) {
	case EXPORTER_OUTPUT_HANDLE:
		ret = edhoc_crypto(ctx)->expand(ctx->user_context, prk_exporter,
						info, len, usage, output);
		break;
	case EXPORTER_OUTPUT_BYTES:
		ret = edhoc_crypto(ctx)->expand_raw(ctx->user_context,
						    prk_exporter, info, len,
						    output, output_length);
		break;
	}
	EDHOC_MEM_FREE(info);

	/* 5. Release the transient PRK_exporter. */
	const int destroy_ret =
		edhoc_key_slot_release(ctx, EDHOC_KEY_SLOT_PRK_EXPORTER);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Expand exporter output: %d", ret);
		/* Never leave derived keying material in the caller's output. */
		switch (output_kind) {
		case EXPORTER_OUTPUT_HANDLE:
			edhoc_zeroize(ctx, output, CONFIG_LIBEDHOC_KEY_ID_LEN);
			break;
		case EXPORTER_OUTPUT_BYTES:
			edhoc_zeroize(ctx, output, output_length);
			break;
		}

		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	if (EDHOC_SUCCESS != destroy_ret) {
		EDHOC_LOG_ERR("Release PRK_exporter: %d", destroy_ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int check_oscore_export(const struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (false == ctx->is_oscore_export_allowed) {
		EDHOC_LOG_ERR(
			"OSCORE export not allowed in current context state");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_SM_COMPLETED > ctx->state.machine ||
	    EDHOC_PRK_STATE_4E3M > ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d", ctx->state.machine,
			      ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
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
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* 1. Derive OSCORE master salt. */
	int ret = edhoc_export_raw(ctx, OSCORE_EXTRACT_LABEL_MASTER_SALT, NULL,
				   0, salt, salt_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Derive OSCORE master salt: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 2. Copy OSCORE sender ID. */
	switch (ctx->negotiation.peer_connection_id.encode_type) {
	case EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER: {
		/* See RFC9528 section 3.3.3 */
		/* NOLINTNEXTLINE(bugprone-signed-char-misuse,cert-str34-c) */
		int32_t int_value =
			ctx->negotiation.peer_connection_id.int_value;
		ret = cbor_encode_integer_type_int_type(sid, sid_size,
							&int_value, sid_len);
		if (ZCBOR_SUCCESS != ret) {
			EDHOC_LOG_ERR("CBOR encode OSCORE SID: %d", ret);
			return EDHOC_ERROR_CBOR_FAILURE;
		}
		break;
	}
	case EDHOC_CONNECTION_ID_TYPE_BYTE_STRING:
		if (sid_size <
		    ctx->negotiation.peer_connection_id.bstr_length) {
			EDHOC_LOG_ERR(
				"Buffer too small for OSCORE SID: %zu, %zu",
				sid_size,
				ctx->negotiation.peer_connection_id.bstr_length);
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		*sid_len = ctx->negotiation.peer_connection_id.bstr_length;
		memcpy(sid, ctx->negotiation.peer_connection_id.bstr_value,
		       ctx->negotiation.peer_connection_id.bstr_length);
		break;
	default:
		EDHOC_LOG_ERR("Invalid peer CID enc type: %d",
			      ctx->negotiation.peer_connection_id.encode_type);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	switch (ctx->negotiation.peer_connection_id.encode_type) {
	case EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER:
		EDHOC_LOG_HEXDUMP_DBG(
			(const uint8_t *)&ctx->negotiation.peer_connection_id
				.int_value,
			sizeof(ctx->negotiation.peer_connection_id.int_value),
			"OSCORE sender ID");
		break;
	case EDHOC_CONNECTION_ID_TYPE_BYTE_STRING:
		EDHOC_LOG_HEXDUMP_DBG(
			ctx->negotiation.peer_connection_id.bstr_value,
			ctx->negotiation.peer_connection_id.bstr_length,
			"OSCORE sender ID");
		break;
	default:
		EDHOC_LOG_ERR("Invalid peer CID enc type: %d",
			      ctx->negotiation.peer_connection_id.encode_type);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	/* 3. Copy OSCORE recipient ID. */
	switch (ctx->negotiation.connection_id.encode_type) {
	case EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER: {
		/* See RFC9528 section 3.3.3 */
		/* NOLINTNEXTLINE(bugprone-signed-char-misuse,cert-str34-c) */
		int32_t int_value = ctx->negotiation.connection_id.int_value;
		ret = cbor_encode_integer_type_int_type(rid, rid_size,
							&int_value, rid_len);
		if (ZCBOR_SUCCESS != ret) {
			EDHOC_LOG_ERR("CBOR encode OSCORE RID: %d", ret);
			return EDHOC_ERROR_CBOR_FAILURE;
		}
		break;
	}
	case EDHOC_CONNECTION_ID_TYPE_BYTE_STRING:
		if (rid_size < ctx->negotiation.connection_id.bstr_length) {
			EDHOC_LOG_ERR(
				"Buffer too small for OSCORE RID: %zu, %zu",
				rid_size,
				ctx->negotiation.connection_id.bstr_length);
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		*rid_len = ctx->negotiation.connection_id.bstr_length;
		memcpy(rid, ctx->negotiation.connection_id.bstr_value,
		       ctx->negotiation.connection_id.bstr_length);
		break;
	default:
		EDHOC_LOG_ERR("Invalid OSCORE RID enc type: %d",
			      ctx->negotiation.connection_id.encode_type);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	switch (ctx->negotiation.connection_id.encode_type) {
	case EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER:
		EDHOC_LOG_HEXDUMP_DBG(
			(const uint8_t *)&ctx->negotiation.connection_id
				.int_value,
			sizeof(ctx->negotiation.connection_id.int_value),
			"OSCORE recipient ID");
		break;
	case EDHOC_CONNECTION_ID_TYPE_BYTE_STRING:
		EDHOC_LOG_HEXDUMP_DBG(
			ctx->negotiation.connection_id.bstr_value,
			ctx->negotiation.connection_id.bstr_length,
			"OSCORE recipient ID");
		break;

	default:
		EDHOC_LOG_ERR("Invalid OSCORE RID enc type: %d",
			      ctx->negotiation.connection_id.encode_type);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

int edhoc_export(struct edhoc_context *ctx, size_t label,
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

int edhoc_export_raw(struct edhoc_context *ctx, size_t label,
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

int edhoc_export_key_update(struct edhoc_context *ctx, const uint8_t *context,
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
		ret = compute_prk_out(ctx);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Compute PRK_out for key update: %d",
				      ret);
			return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
		}
	}

	ret = compute_new_prk_out(ctx, context, context_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute new PRK_out: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	ctx->state.machine = status;
	ctx->is_oscore_export_allowed = true;
	return EDHOC_SUCCESS;
}

/*
 * Steps for exporting the OSCORE session (master secret as a handle):
 *      1. Check that an OSCORE export may run.
 *      2. Derive OSCORE master salt and copy the sender/recipient IDs.
 *      3. Derive OSCORE master secret (caller-owned key handle).
 */
int edhoc_export_oscore_session(struct edhoc_context *ctx,
				void *master_secret_key_id, uint8_t *salt,
				size_t salt_len, uint8_t *sid, size_t sid_size,
				size_t *sid_len, uint8_t *rid, size_t rid_size,
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
	ret = edhoc_export(ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL, 0,
			   EDHOC_KEY_USAGE_AEAD, master_secret_key_id);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Derive OSCORE master secret: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	ctx->state.machine = status;
	return EDHOC_SUCCESS;
}

/*
 * Steps for exporting the OSCORE session (raw master secret):
 *      1. Check that an OSCORE export may run.
 *      2. Derive OSCORE master salt and copy the sender/recipient IDs.
 *      3. Derive OSCORE master secret (raw bytes).
 */
int edhoc_export_oscore_session_raw(struct edhoc_context *ctx, uint8_t *secret,
				    size_t secret_len, uint8_t *salt,
				    size_t salt_len, uint8_t *sid,
				    size_t sid_size, size_t *sid_len,
				    uint8_t *rid, size_t rid_size,
				    size_t *rid_len)
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
	ret = edhoc_export_raw(ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL, 0,
			       secret, secret_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Derive OSCORE master secret: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	ctx->state.machine = status;
	return EDHOC_SUCCESS;
}
