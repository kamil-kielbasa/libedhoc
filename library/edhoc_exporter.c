/**
 * \file    edhoc_exporter.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC exporter for OSCORE key and salt.
 * \version 0.1
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */
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
 * \brief CBOR integer overhead.
 *
 * \param val                   Length of buffer to CBOR as int.
 *
 * \return Number of bytes.
 */
static inline size_t cbor_int_overhead(int32_t val);

/** 
 * \brief CBOR byte stream overhead.
 *
 * \param len                   Length of buffer to CBOR as bstr.
 *
 * \return Number of bytes.
 */
static inline size_t cbor_bstr_overhead(size_t len);

/* Static function definitions --------------------------------------------- */

#ifdef DEBUG_LOGS
#include <stdio.h>
static inline void print_array(const char *name, const uint8_t *array,
			       size_t array_length)
{
	printf("%s:\tLEN( %zu )\n", name, array_length);

	for (size_t i = 0; i < array_length; ++i) {
		if (0 == i % 16 && i > 0) {
			printf("\n");
		}

		printf("%02x ", array[i]);
	}

	printf("\n\n");
}
#define LOG(name, arr, len) print_array(name, arr, len)
#else
#define LOG(name, arr, len) \
	do {                \
		(void)name; \
		(void)arr;  \
		(void)len;  \
	} while (0)
#endif

static inline size_t cbor_int_overhead(int32_t val)
{
	if (val >= ONE_BYTE_CBOR_INT_MIN_VALUE &&
	    val <= ONE_BYTE_CBOR_INT_MAX_VALUE)
		return 1;

	if (val >= -256 && val <= 255)
		return 2;

	return 3;
}

static inline size_t cbor_bstr_overhead(size_t len)
{
	if (len == 0)
		return 0;
	if (len <= 5)
		return 1;
	if (len <= UINT8_MAX)
		return 2;
	if (len <= UINT16_MAX)
		return 3;
	return 5;
}

/* Module interface function definitions ----------------------------------- */

/**
 * Steps for exporting secrets:
 *      1. Choose most preferred cipher suite.
 *      2. Calculate pseudo random key exporter (PRK_exporter).
 *      3. Derive OSCORE master secret.
 *      4. Derive OSCORE master salt.
 */
int edhoc_export_secret_and_salt(struct edhoc_context *ctx, uint8_t *secret,
				 size_t secret_len, uint8_t *salt,
				 size_t salt_len)
{
	if (NULL == ctx || NULL == secret || 0 == secret_len || NULL == salt ||
	    0 == salt_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (COMPLETED != ctx->status)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;
	struct info input_info = { 0 };
	uint8_t key_id[EDHOC_KID_LEN] = { 0 };

	/* 1. Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* 2. Calculate pseudo random key exporter (PRK_exporter). */
	len = 0;
	len += cbor_int_overhead(EDHOC_EXTRACT_PRK_INFO_LABEL_PRK_EXPORTER);
	len += 1 + cbor_bstr_overhead(0); /* cbor empty byte string. */
	len += cbor_int_overhead(csuite.hash_len);

	uint8_t info[len];
	memset(info, 0, sizeof(info));

	input_info = (struct info){
		._info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_PRK_EXPORTER,
		._info_context.value = NULL,
		._info_context.len = 0,
		._info_length = csuite.hash_len,
	};

	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	ret = ctx->keys_cb.generate_key(EDHOC_KT_EXPAND, ctx->prk, ctx->prk_len,
					key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	memset(ctx->prk, 0, sizeof(ctx->prk));
	ctx->prk_len = csuite.hash_len;
	ret = ctx->crypto_cb.expand(key_id, info, len, ctx->prk, ctx->prk_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->keys_cb.destroy_key(key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->prk_state = EDHOC_PRK_STATE_EXPORTER;
	LOG("PRK_exporter", ctx->prk, ctx->prk_len);

	/* 3. Derive OSCORE master secret. */
	input_info = (struct info){
		._info_label = OSCORE_EXTRACT_LABEL_MASTER_SECRET,
		._info_context.value = NULL,
		._info_context.len = 0,
		._info_length = secret_len,
	};

	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret) {
		ctx->prk_state = EDHOC_PRK_STATE_INVALID;
		ctx->prk_len = 0;
		memset(ctx->prk, 0, sizeof(ctx->prk));
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	ret = ctx->keys_cb.generate_key(EDHOC_KT_EXPAND, ctx->prk, ctx->prk_len,
					key_id);

	if (EDHOC_SUCCESS != ret) {
		ctx->prk_state = EDHOC_PRK_STATE_INVALID;
		ctx->prk_len = 0;
		memset(ctx->prk, 0, sizeof(ctx->prk));
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ret = ctx->crypto_cb.expand(key_id, info, len, secret, secret_len);

	if (EDHOC_SUCCESS != ret) {
		ctx->prk_state = EDHOC_PRK_STATE_INVALID;
		ctx->prk_len = 0;
		memset(ctx->prk, 0, sizeof(ctx->prk));
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ret = ctx->keys_cb.destroy_key(key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret) {
		ctx->prk_state = EDHOC_PRK_STATE_INVALID;
		ctx->prk_len = 0;
		memset(ctx->prk, 0, sizeof(ctx->prk));
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	LOG("OSCORE master secret", secret, secret_len);

	/* 4. Derive OSCORE master salt. */
	input_info = (struct info){
		._info_label = OSCORE_EXTRACT_LABEL_MASTER_SALT,
		._info_context.value = NULL,
		._info_context.len = 0,
		._info_length = salt_len,
	};

	len = 0;
	ret = cbor_encode_info(info, ARRAY_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret) {
		ctx->prk_state = EDHOC_PRK_STATE_INVALID;
		ctx->prk_len = 0;
		memset(ctx->prk, 0, sizeof(ctx->prk));
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	ret = ctx->keys_cb.generate_key(EDHOC_KT_EXPAND, ctx->prk, ctx->prk_len,
					key_id);

	if (EDHOC_SUCCESS != ret) {
		memset(ctx->prk, 0, sizeof(ctx->prk));
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ret = ctx->crypto_cb.expand(key_id, info, len, salt, salt_len);

	if (EDHOC_SUCCESS != ret) {
		memset(ctx->prk, 0, sizeof(ctx->prk));
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ret = ctx->keys_cb.destroy_key(key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret) {
		memset(ctx->prk, 0, sizeof(ctx->prk));
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	LOG("OSCORE master salt", salt, salt_len);

	memset(ctx->prk, 0, sizeof(ctx->prk));
	return EDHOC_SUCCESS;
}