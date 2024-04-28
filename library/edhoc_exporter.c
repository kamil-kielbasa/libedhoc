/**
 * \file    edhoc_exporter.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC exporter for key update or OSCORE session.
 * \version 0.2
 * \date    2024-01-01
 *
 * \copyright Copyright (c) 2024
 *
 */

/* Include files ----------------------------------------------------------- */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include "edhoc.h"
#include <string.h>
#include <stdint.h>

#include <zcbor_common.h>
#include <backend_cbor_info_encode.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/** 
 * \brief CBOR integer memory requirements.
 *
 * \param val                   Raw integer value.
 *
 * \return Number of bytes.
 */
static inline size_t cbor_int_mem_req(int32_t val);

/**
 * \brief CBOR byte stream overhead.
 *
 * \param len                   Length of buffer to CBOR as bstr.
 *
 * \return Number of bytes.
 */
static inline size_t cbor_bstr_overhead(size_t len);

/**
 * \brief Compute output pseudo random key (PRK_out).
 *
 * \param[in] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_prk_out(struct edhoc_context *ctx);

/**
 * \brief Compute output pseudo random key (PRK_out).
 *
 * \param[in] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_new_prk_out(struct edhoc_context *ctx,
			       const uint8_t *entropy, size_t entropy_len);

/**
 * \brief Compute exporter pseudo random key (PRK_exporter).
 *
 * \param[in] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_prk_exporter(const struct edhoc_context *ctx,
				uint8_t *prk_exp, size_t prk_exp_len);

/* Static function definitions --------------------------------------------- */

static inline size_t cbor_int_mem_req(int32_t val)
{
	if (val >= ONE_BYTE_CBOR_INT_MIN_VALUE &&
	    val <= ONE_BYTE_CBOR_INT_MAX_VALUE) {
		return 1;
	} else if (val >= -(UINT8_MAX + 1) && val <= UINT8_MAX) {
		return 2;
	} else if (val >= -(UINT16_MAX + 1) && val <= UINT16_MAX) {
		return 3;
	} else {
		return 4;
	}
}

static inline size_t cbor_bstr_overhead(size_t len)
{
	if (len <= 23) {
		return 1;
	} else if (len <= UINT8_MAX) {
		return 2;
	} else if (len <= UINT16_MAX) {
		return 3;
	} else if (len <= UINT32_MAX) {
		return 4;
	} else {
		return 5;
	}
}

static int compute_prk_out(struct edhoc_context *ctx)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_4 != ctx->th_state ||
	    EDHOC_PRK_STATE_4E3M != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* Calculate struct info cbor overhead. */
	size_t len = 0;
	len += cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_IV_3);
	len += ctx->th_len + cbor_bstr_overhead(ctx->th_len);
	len += cbor_int_mem_req(csuite.hash_length);

	uint8_t info[len];
	memset(info, 0, sizeof(info));

	/* Generate PRK_out. */
	struct info input_info = {
		._info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_PRK_OUT,
		._info_context.value = ctx->th,
		._info_context.len = ctx->th_len,
		._info_length = csuite.hash_length,
	};

	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys.generate_key(EDHOC_KT_EXPAND, ctx->prk, ctx->prk_len,
				     key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.expand(key_id, info, len, ctx->prk, ctx->prk_len);
	ctx->keys.destroy_key(key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_out", ctx->prk, ctx->prk_len);

	ctx->prk_state = EDHOC_PRK_STATE_OUT;
	return EDHOC_SUCCESS;
}

static int compute_new_prk_out(struct edhoc_context *ctx,
			       const uint8_t *entropy, size_t entropy_len)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_PRK_STATE_OUT != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* Calculate struct info cbor overhead. */
	size_t len = 0;
	len += cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_NEW_PRK_OUT);
	len += entropy_len + cbor_bstr_overhead(entropy_len);
	len += cbor_int_mem_req(csuite.hash_length);

	uint8_t info[len];
	memset(info, 0, sizeof(info));

	/* Generate PRK_out. */
	struct info input_info = {
		._info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_NEW_PRK_OUT,
		._info_context.value = entropy,
		._info_context.len = entropy_len,
		._info_length = csuite.hash_length,
	};

	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys.generate_key(EDHOC_KT_EXPAND, ctx->prk, ctx->prk_len,
				     key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.expand(key_id, info, len, ctx->prk, ctx->prk_len);
	ctx->keys.destroy_key(key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->prk_state = EDHOC_PRK_STATE_OUT;
	return EDHOC_SUCCESS;
}

static int compute_prk_exporter(const struct edhoc_context *ctx,
				uint8_t *prk_exp, size_t prk_exp_len)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_PRK_STATE_OUT != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	size_t len = 0;
	len += cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_PRK_EXPORTER);
	len += 1 + cbor_bstr_overhead(0); /* cbor empty byte string. */
	len += cbor_int_mem_req(csuite.hash_length);

	uint8_t info[len];
	memset(info, 0, sizeof(info));

	struct info input_info = {
		._info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_PRK_EXPORTER,
		._info_context.value = NULL,
		._info_context.len = 0,
		._info_length = csuite.hash_length,
	};

	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys.generate_key(EDHOC_KT_EXPAND, ctx->prk, ctx->prk_len,
				     key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.expand(key_id, info, len, prk_exp, prk_exp_len);
	ctx->keys.destroy_key(key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_exporter", prk_exp,
			    prk_exp_len);

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

int edhoc_export_key_update(struct edhoc_context *ctx, const uint8_t *entropy,
			    size_t entropy_len)
{
	if (NULL == ctx || NULL == entropy || 0 == entropy_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_SM_COMPLETED > ctx->status ||
	    EDHOC_PRK_STATE_4E3M > ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	const enum edhoc_state_machine status = ctx->status;
	ctx->status = EDHOC_SM_ABORTED;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	if (EDHOC_PRK_STATE_4E3M == ctx->prk_state) {
		ret = compute_prk_out(ctx);

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	ret = compute_new_prk_out(ctx, entropy, entropy_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "new PRK_out", ctx->prk,
			    ctx->prk_len);

	ctx->status = status;
	ctx->is_oscore_export_allowed = true;
	return EDHOC_SUCCESS;
}

/**
 * Steps for exporting secrets:
 *      1. Compute pseudorandom key output if needed (PRK_out).
 *      2. Choose most preferred cipher suite.
 *      3. Compute pseudo random key exporter (PRK_exporter).
 *      4. Derive OSCORE master secret.
 *      5. Derive OSCORE master salt.
 *      6. Copy OSCORE sender ID.
 *      7. Copy OSCORE recipient ID.
 */
int edhoc_export_oscore_session(struct edhoc_context *ctx,
				uint8_t *restrict secret, size_t secret_len,
				uint8_t *restrict salt, size_t salt_len,
				uint8_t *restrict sid, size_t sid_size,
				size_t *restrict sid_len, uint8_t *restrict rid,
				size_t rid_size, size_t *restrict rid_len)
{
	if (NULL == ctx || NULL == secret || 0 == secret_len || NULL == salt ||
	    0 == salt_len || NULL == sid || 0 == sid_size || NULL == sid_len ||
	    NULL == rid || 0 == rid_size || NULL == rid_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (false == ctx->is_oscore_export_allowed)
		return EDHOC_ERROR_BAD_STATE;

	if (EDHOC_SM_COMPLETED > ctx->status ||
	    EDHOC_PRK_STATE_4E3M > ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	const enum edhoc_state_machine status = ctx->status;
	ctx->status = EDHOC_SM_ABORTED;
	ctx->is_oscore_export_allowed = false;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Compute pseudorandom key output if needed (PRK_out). */
	if (EDHOC_PRK_STATE_4E3M == ctx->prk_state) {
		ret = compute_prk_out(ctx);

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	struct info input_info = { 0 };
	uint8_t key_id[EDHOC_KID_LEN] = { 0 };

	/* 2. Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* 3. Compute pseudo random key exporter (PRK_exporter). */
	uint8_t prk_exporter[csuite.hash_length];
	memset(prk_exporter, 0, sizeof(prk_exporter));

	ret = compute_prk_exporter(ctx, prk_exporter, ARRAY_SIZE(prk_exporter));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	/* 4. Derive OSCORE master secret. */
	size_t len = 0;
	len += cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_PRK_EXPORTER);
	len += 1 + cbor_bstr_overhead(0); /* cbor empty byte string. */
	len += cbor_int_mem_req(csuite.hash_length);

	uint8_t info[len];
	memset(info, 0, sizeof(info));

	input_info = (struct info){
		._info_label = OSCORE_EXTRACT_LABEL_MASTER_SECRET,
		._info_context.value = NULL,
		._info_context.len = 0,
		._info_length = secret_len,
	};

	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	ret = ctx->keys.generate_key(EDHOC_KT_EXPAND, prk_exporter,
				     ARRAY_SIZE(prk_exporter), key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.expand(key_id, info, len, secret, secret_len);
	ctx->keys.destroy_key(key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "OSCORE master secret", secret,
			    secret_len);

	/* 5. Derive OSCORE master salt. */
	input_info = (struct info){
		._info_label = OSCORE_EXTRACT_LABEL_MASTER_SALT,
		._info_context.value = NULL,
		._info_context.len = 0,
		._info_length = salt_len,
	};

	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	ret = ctx->keys.generate_key(EDHOC_KT_EXPAND, prk_exporter,
				     ARRAY_SIZE(prk_exporter), key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.expand(key_id, info, len, salt, salt_len);
	ctx->keys.destroy_key(key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "OSCORE master salt", salt,
			    salt_len);

	/* 6. Copy OSCORE sender ID. */
	switch (ctx->peer_cid.encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
		*sid_len = sizeof(ctx->peer_cid.int_value);
		memcpy(sid, &ctx->peer_cid.int_value,
		       sizeof(ctx->peer_cid.int_value));
		break;
	case EDHOC_CID_TYPE_BYTE_STRING:
		if (sid_size < ctx->peer_cid.bstr_length)
			return EDHOC_ERROR_BUFFER_TOO_SMALL;

		*sid_len = ctx->peer_cid.bstr_length;
		memcpy(sid, ctx->peer_cid.bstr_value,
		       ctx->peer_cid.bstr_length);
		break;
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (NULL != ctx->logger) {
		switch (ctx->peer_cid.encode_type) {
		case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
			ctx->logger(ctx->user_ctx, "OSCORE sender ID",
				    (const uint8_t *)&ctx->peer_cid.int_value,
				    sizeof(ctx->peer_cid.int_value));
			break;
		case EDHOC_CID_TYPE_BYTE_STRING:
			ctx->logger(ctx->user_ctx, "OSCORE sender ID",
				    ctx->peer_cid.bstr_value,
				    ctx->peer_cid.bstr_length);
			break;

		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	/* 7. Copy OSCORE recipient ID. */
	switch (ctx->cid.encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
		*rid_len = sizeof(ctx->cid.int_value);
		memcpy(rid, &ctx->cid.int_value, sizeof(ctx->cid.int_value));
		break;
	case EDHOC_CID_TYPE_BYTE_STRING:
		if (rid_size < ctx->cid.bstr_length)
			return EDHOC_ERROR_BUFFER_TOO_SMALL;

		*rid_len = ctx->cid.bstr_length;
		memcpy(rid, ctx->cid.bstr_value, ctx->cid.bstr_length);
		break;
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (NULL != ctx->logger) {
		switch (ctx->cid.encode_type) {
		case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
			ctx->logger(ctx->user_ctx, "OSCORE sender ID",
				    (const uint8_t *)&ctx->cid.int_value,
				    sizeof(ctx->cid.int_value));
			break;
		case EDHOC_CID_TYPE_BYTE_STRING:
			ctx->logger(ctx->user_ctx, "OSCORE sender ID",
				    ctx->cid.bstr_value, ctx->cid.bstr_length);
			break;

		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	ctx->status = status;
	return EDHOC_SUCCESS;
}
