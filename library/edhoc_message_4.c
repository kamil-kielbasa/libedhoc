/**
 * \file    edhoc_message_4.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message 4 compose & process.
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include "edhoc.h"
#include "edhoc_common.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
#pragma clang diagnostic ignored "-Wreserved-identifier"
#pragma clang diagnostic ignored "-Wpadded"
#pragma clang diagnostic ignored "-Wdocumentation"
#endif

/* CBOR headers: */
#include <backend_cbor_info_encode.h>
#include <backend_cbor_enc_structure_encode.h>
#include <backend_cbor_enc_structure_decode.h>
#include <backend_cbor_plaintext_4_encode.h>
#include <backend_cbor_plaintext_4_decode.h>
#include <backend_cbor_message_4_encode.h>
#include <backend_cbor_message_4_decode.h>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Compute PLAINTEXT_4 length.
 *
 * \param[in] edhoc_context		EDHOC context.
 * \param[out] plaintext_4_length       Length of PLAINTEXT_4.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_plaintext_4_length(const struct edhoc_context *edhoc_context,
				      size_t *plaintext_4_length);

/**
 * \brief Prepare PLAINTEXT_4.
 *
 * \param[in] edhoc_context	        EDHOC context.
 * \param[out] plaintext_4	        Buffer where the generated plaintext 4 is to be written.
 * \param plaintext_4_size             	Size of the \p plaintext_4 buffer in bytes.
 * \param plaintext_4_length	        On success, the number of bytes that make up the plaintext 4.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int prepare_plaintext_4(const struct edhoc_context *edhoc_context,
			       uint8_t *plaintext_4, size_t plaintext_4_size,
			       size_t *plaintext_4_length);

/**
 * \brief Compute required length in bytes for AAD_4.
 *
 * \param[in] edhoc_context		EDHOC context.
 *
 * \retval Value different than 0 is success, otherwise failure.
 */
static size_t compute_aad_4_length(const struct edhoc_context *edhoc_context);

/**
 * \brief Compute K_4, IV_4 and AAD_4.
 *
 * \param[in] edhoc_context	        EDHOC context.
 * \param[out] key			Buffer where the generated K_4 is to be written.
 * \param key_length	        	Size of the \p key buffer in bytes.
 * \param[out] iv	        	Buffer where the generated IV_4 is to be written.
 * \param iv_length                	Size of the \p iv buffer in bytes.
 * \param[out] aad	        	Buffer where the generated AAD_4 is to be written.
 * \param aad_size               	Size of the \p aad buffer in bytes.
 * \param[out] aad_length		On success, the number of bytes that make up the AAD_4.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_key_iv_aad(const struct edhoc_context *edhoc_context,
			      uint8_t *key, size_t key_length, uint8_t *iv,
			      size_t iv_length, uint8_t *aad, size_t aad_size,
			      size_t *aad_length);

/**
 * \brief Compute CIPHERTEXT_4.
 *
 * \param[in] edhoc_context	        EDHOC context.
 * \param[in] key			Buffer containing the K_4.
 * \param key_length	        	Size of the \p key buffer in bytes.
 * \param[in] iv	        	Buffer containing the IV_4.
 * \param iv_length                	Size of the \p iv buffer in bytes.
 * \param[in] aad	        	Buffer containing the AAD_4.
 * \param aad_length               	Size of the \p aad buffer in bytes.
 * \param[in] plaintext_4	        Buffer containing the PLAINTEXT_4.
 * \param plaintext_4_length            Size of the \p plaintext_4 buffer in bytes.
 * \param[out] ciphertext_4	        Buffer where the generated CIPHERTEXT_4 is to be written.
 * \param ciphertext_4_size	        Size of the \p ciphertext_4 buffer in bytes.
 * \param[out] ciphertext_4_length      On success, the number of bytes that make up the CIPHERTEXT_4.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_ciphertext_4(const struct edhoc_context *edhoc_context,
				const uint8_t *key, size_t key_length,
				const uint8_t *iv, size_t iv_length,
				const uint8_t *aad, size_t aad_length,
				const uint8_t *plaintext_4,
				size_t plaintext_4_length,
				uint8_t *ciphertext_4, size_t ciphertext_4_size,
				size_t *ciphertext_4_length);

/**
 * \brief Generate edhoc message 4.
 *
 * \param[in] ciphertext_4	        Buffer continas the ciphertext 4.
 * \param ciphertext_4_length	        Size of the \p ciphertext_4 buffer in bytes.
 * \param[out] message_4            	Buffer where the generated message 4 is to be written.
 * \param message_4_size            	Size of the \p message_4 buffer in bytes.
 * \param[out] message_4_length        	On success, the number of bytes that make up the message 4.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int generate_message_4(const uint8_t *ciphertext_4,
			      size_t ciphertext_4_length, uint8_t *message_4,
			      size_t message_4_size, size_t *message_4_length);

/**
 * \brief CBOR decode message 4 and save address and length for CIPHERTEXT_4.
 *
 * \param[in] message_4     		Buffer containing the message 4.
 * \param message_4_length     		Size of the \p message_4 buffer in bytes.
 * \param[out] ciphertext_4	        Pointer to buffer containing the CIPHERTEXT_4.
 * \param[out] ciphertext_4_length	Size of the \p ciphertext_4 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int parse_message_4(const uint8_t *message_4, size_t message_4_length,
			   const uint8_t **ciphertext_4,
			   size_t *ciphertext_4_length);

/**
 * \brief Decrypt CIPHERTEXT_4.
 *
 * \param[in] edhoc_context		EDHOC context.
 * \param[in] key			Buffer containing the K_4.
 * \param key_length	        	Size of the \p key buffer in bytes.
 * \param[in] iv	        	Buffer containing the IV_4.
 * \param iv_length                	Size of the \p iv buffer in bytes.
 * \param[in] aad	        	Buffer containing the AAD_4.
 * \param aad_length               	Size of the \p aad buffer in bytes.
 * \param[in] ciphertext_4	        Pointer to buffer containing the CIPHERTEXT_4.
 * \param ciphertext_4_length	        Size of the \p ctxt_4 buffer in bytes.
 * \param[out] plaintext_4	        Buffer where the decrypted PLAINTEXT_4 is to be written.
 * \param plaintext_4_length	        Size of the \p ptxt_4 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int
decrypt_ciphertext_4(const struct edhoc_context *edhoc_context,
		     const uint8_t *key, size_t key_length, const uint8_t *iv,
		     size_t iv_length, const uint8_t *aad, size_t aad_length,
		     const uint8_t *ciphertext_4, size_t ciphertext_4_length,
		     uint8_t *plaintext_4, size_t plaintext_4_length);

/**
 * \brief Parsed cborised PLAINTEXT_4.
 *
 * \param[in] edhoc_context		EDHOC context.
 * \param[in] plaintext_4		Buffer containing the PLAINTEXT_4.
 * \param plaintext_4_length            Size of the \p plaintext_4 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int parse_plaintext_4(struct edhoc_context *edhoc_context,
			     const uint8_t *plaintext_4,
			     size_t plaintext_4_length);

/* Static function definitions --------------------------------------------- */

static int compute_plaintext_4_length(const struct edhoc_context *ctx,
				      size_t *ptxt_4_len)
{
	if (NULL == ctx || NULL == ptxt_4_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	size_t len = 0;

	for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
		len += edhoc_cbor_int_mem_req(ctx->ead_token[i].label);
		len += ctx->ead_token[i].value_len + 1;
		len += edhoc_cbor_bstr_oh(ctx->ead_token[i].value_len);
	}

	*ptxt_4_len = len;
	return EDHOC_SUCCESS;
}

static int prepare_plaintext_4(const struct edhoc_context *ctx, uint8_t *ptxt_4,
			       size_t ptxt_4_size, size_t *ptxt_4_len)
{
	if (NULL == ctx || NULL == ptxt_4 || NULL == ptxt_4_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	struct plaintext_4 ead_4 = { .plaintext_4_present = false };

	if (ARRAY_SIZE(ead_4.plaintext_4.EAD_4) < ctx->nr_of_ead_tokens)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	if (0 != ctx->nr_of_ead_tokens) {
		ead_4.plaintext_4_present = true;
		ead_4.plaintext_4.EAD_4_count = ctx->nr_of_ead_tokens;

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			ead_4.plaintext_4.EAD_4[i].ead_y_ead_label =
				ctx->ead_token[i].label;
			ead_4.plaintext_4.EAD_4[i].ead_y_ead_value.value =
				ctx->ead_token[i].value;
			ead_4.plaintext_4.EAD_4[i].ead_y_ead_value.len =
				ctx->ead_token[i].value_len;
			ead_4.plaintext_4.EAD_4[i].ead_y_ead_value_present =
				(NULL != ctx->ead_token[i].value);
		}
	} else {
		ead_4.plaintext_4_present = false;
	}

	ret = cbor_encode_plaintext_4(ptxt_4, ptxt_4_size, &ead_4, ptxt_4_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	return EDHOC_SUCCESS;
}

static size_t compute_aad_4_length(const struct edhoc_context *ctx)
{
	size_t len = 0;

	len += sizeof("Encrypt0") + edhoc_cbor_tstr_oh(sizeof("Encrypt0"));
	len += 0 + edhoc_cbor_bstr_oh(0);
	len += ctx->th_len + edhoc_cbor_bstr_oh(ctx->th_len);

	return len;
}

static int compute_key_iv_aad(const struct edhoc_context *ctx, uint8_t *key,
			      size_t key_len, uint8_t *iv, size_t iv_len,
			      uint8_t *aad, size_t aad_size, size_t *aad_len)
{
	if (NULL == ctx || NULL == key || 0 == key_len || NULL == iv ||
	    0 == iv_len || NULL == aad || 0 == aad_size || NULL == aad_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_4 != ctx->th_state ||
	    EDHOC_PRK_STATE_4E3M != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	struct info input_info = { 0 };

	/* Calculate struct info cbor overhead. */
	size_t len = 0;
	len += edhoc_cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_IV_3);
	len += ctx->th_len + edhoc_cbor_bstr_oh(ctx->th_len);
	len += edhoc_cbor_int_mem_req((int32_t)csuite.aead_key_length);

	VLA_ALLOC(uint8_t, info, len);
	memset(info, 0, VLA_SIZEOF(info));

	/* Generate K_3. */
	input_info = (struct info){
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_K_4,
		.info_context.value = ctx->th,
		.info_context.len = ctx->th_len,
		.info_length = (uint32_t)csuite.aead_key_length,
	};

	memset(info, 0, VLA_SIZEOF(info));
	len = 0;
	ret = cbor_encode_info(info, VLA_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_EXPAND, ctx->prk,
				   ctx->prk_len, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.expand(ctx->user_ctx, key_id, info, len, key,
				 key_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	/* Generate IV_3. */
	input_info = (struct info){
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_IV_4,
		.info_context.value = ctx->th,
		.info_context.len = ctx->th_len,
		.info_length = (uint32_t)csuite.aead_iv_length,
	};

	memset(info, 0, VLA_SIZEOF(info));
	len = 0;
	ret = cbor_encode_info(info, VLA_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_EXPAND, ctx->prk,
				   ctx->prk_len, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.expand(ctx->user_ctx, key_id, info, len, iv, iv_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	/* Generate AAD_3. */
	struct enc_structure cose_enc_0 = {
		.enc_structure_protected.value = NULL,
		.enc_structure_protected.len = 0,
		.enc_structure_external_aad.value = ctx->th,
		.enc_structure_external_aad.len = ctx->th_len,
	};

	ret = cbor_encode_enc_structure(aad, aad_size, &cose_enc_0, aad_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	return EDHOC_SUCCESS;
}

static int compute_ciphertext_4(const struct edhoc_context *ctx,
				const uint8_t *key, size_t key_len,
				const uint8_t *iv, size_t iv_len,
				const uint8_t *aad, size_t aad_len,
				const uint8_t *ptxt_4, size_t ptxt_4_len,
				uint8_t *ctxt_4, size_t ctxt_4_size,
				size_t *ctxt_4_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_ENCRYPT, key,
				   key_len, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.encrypt(ctx->user_ctx, key_id, iv, iv_len, aad,
				  aad_len, ptxt_4, ptxt_4_len, ctxt_4,
				  ctxt_4_size, ctxt_4_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int generate_message_4(const uint8_t *ctxt_4, size_t ctxt_4_len,
			      uint8_t *msg_4, size_t msg_4_size,
			      size_t *msg_4_len)
{
	if (NULL == ctxt_4 || 0 == ctxt_4_len || NULL == msg_4 ||
	    0 == msg_4_size || NULL == msg_4_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct zcbor_string input_bstr = {
		.value = ctxt_4,
		.len = ctxt_4_len,
	};

	ret = cbor_encode_message_4_CIPHERTEXT_4(msg_4, msg_4_size, &input_bstr,
						 msg_4_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	return EDHOC_SUCCESS;
}

static int parse_message_4(const uint8_t *msg_4, size_t msg_4_len,
			   const uint8_t **ctxt_4, size_t *ctxt_4_len)
{
	if (NULL == msg_4 || 0 == msg_4_len || NULL == ctxt_4 ||
	    NULL == ctxt_4_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t len = 0;
	struct zcbor_string dec_msg_4 = { 0 };
	ret = cbor_decode_message_4_CIPHERTEXT_4(msg_4, msg_4_len, &dec_msg_4,
						 &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	*ctxt_4 = dec_msg_4.value;
	*ctxt_4_len = dec_msg_4.len;

	return EDHOC_SUCCESS;
}

static int decrypt_ciphertext_4(const struct edhoc_context *ctx,
				const uint8_t *key, size_t key_len,
				const uint8_t *iv, size_t iv_len,
				const uint8_t *aad, size_t aad_len,
				const uint8_t *ctxt_4, size_t ctxt_4_len,
				uint8_t *ptxt_4, size_t ptxt_4_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_DECRYPT, key,
				   key_len, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	size_t len = 0;
	ret = ctx->crypto.decrypt(ctx->user_ctx, key_id, iv, iv_len, aad,
				  aad_len, ctxt_4, ctxt_4_len, ptxt_4,
				  ptxt_4_len, &len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret || ptxt_4_len != len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int parse_plaintext_4(struct edhoc_context *ctx, const uint8_t *ptxt_4,
			     size_t ptxt_4_len)
{
	if (NULL == ctx || NULL == ptxt_4)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t len = 0;
	struct plaintext_4 ead_4 = { 0 };
	ret = cbor_decode_plaintext_4(ptxt_4, ptxt_4_len, &ead_4, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	ctx->nr_of_ead_tokens = ead_4.plaintext_4.EAD_4_count;
	for (size_t i = 0; i < ead_4.plaintext_4.EAD_4_count; ++i) {
		ctx->ead_token[i].label =
			ead_4.plaintext_4.EAD_4[i].ead_y_ead_label;
		ctx->ead_token[i].value =
			ead_4.plaintext_4.EAD_4[i].ead_y_ead_value.value;
		ctx->ead_token[i].value_len =
			ead_4.plaintext_4.EAD_4[i].ead_y_ead_value.len;
	}

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

/**
 * Steps for composition of message 4:
 *      1.  Choose most preferred cipher suite.
 *      2.  Compose EAD_4 if present.
 *      3a. Compute ptxt_4 length (PLAINTEXT_4).
 *      3b. Prepare ptxt_4 (PLAINTEXT_4).
 *      4.  Compute K_4, IV_4 and AAD_4.
 *      5.  Compute ctxt_4.
 *      6.  Generate edhoc message 4.
 */
int edhoc_message_4_compose(struct edhoc_context *ctx, uint8_t *msg_4,
			    size_t msg_4_size, size_t *msg_4_len)
{
	if (NULL == ctx || NULL == msg_4 || 0 == msg_4_size ||
	    NULL == msg_4_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_SM_COMPLETED != ctx->status ||
	    EDHOC_TH_STATE_4 != ctx->th_state ||
	    EDHOC_PRK_STATE_4E3M != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_4;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* 2. Compose EAD_4 if present. */
	if (NULL != ctx->ead.compose && 0 != ARRAY_SIZE(ctx->ead_token) - 1) {
		ret = ctx->ead.compose(ctx->user_ctx, ctx->message,
				       ctx->ead_token,
				       ARRAY_SIZE(ctx->ead_token) - 1,
				       &ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret ||
		    ARRAY_SIZE(ctx->ead_token) - 1 < ctx->nr_of_ead_tokens)
			return EDHOC_ERROR_EAD_COMPOSE_FAILURE;

		if (NULL != ctx->logger) {
			for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
				ctx->logger(ctx->user_ctx,
					    "EAD_4 compose label",
					    (const uint8_t *)&ctx->ead_token[i]
						    .label,
					    sizeof(ctx->ead_token[i].label));

				if (0 != ctx->ead_token[i].value_len)
					ctx->logger(
						ctx->user_ctx,
						"EAD_4 compose value",
						ctx->ead_token[i].value,
						ctx->ead_token[i].value_len);
			}
		}
	}

	/* 3a. Compute ptxt_4 length (PLAINTEXT_4). */
	size_t ptxt_4_len = 0;
	ret = compute_plaintext_4_length(ctx, &ptxt_4_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	VLA_ALLOC(uint8_t, ptxt_4, ptxt_4_len);
	memset(ptxt_4, 0, VLA_SIZEOF(ptxt_4));

	/* 3b. Prepare ptxt_4 (PLAINTEXT_4). */
	ret = prepare_plaintext_4(ctx, ptxt_4, VLA_SIZE(ptxt_4), &ptxt_4_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PLAINTEXT_4", ptxt_4, ptxt_4_len);

	/* 4. Compute K_4, IV_4 and AAD_4. */
	VLA_ALLOC(uint8_t, key, csuite.aead_key_length);
	memset(key, 0, VLA_SIZEOF(key));

	VLA_ALLOC(uint8_t, iv, csuite.aead_iv_length);
	memset(iv, 0, VLA_SIZEOF(iv));

	size_t aad_len = compute_aad_4_length(ctx);
	VLA_ALLOC(uint8_t, aad, aad_len);
	memset(aad, 0, VLA_SIZEOF(aad));

	aad_len = 0;
	ret = compute_key_iv_aad(ctx, key, VLA_SIZE(key), iv, VLA_SIZE(iv), aad,
				 VLA_SIZE(aad), &aad_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger) {
		ctx->logger(ctx->user_ctx, "K_4", key, VLA_SIZE(key));
		ctx->logger(ctx->user_ctx, "IV_4", iv, VLA_SIZE(iv));
		ctx->logger(ctx->user_ctx, "AAD_4", aad, aad_len);
	}

	/* 5. Compute ctxt_4. */
	size_t ctxt_4_len = 0;
	VLA_ALLOC(uint8_t, ctxt_4, VLA_SIZE(ptxt_4) + csuite.aead_tag_length);
	memset(ctxt_4, 0, VLA_SIZEOF(ctxt_4));

	ret = compute_ciphertext_4(ctx, key, VLA_SIZE(key), iv, VLA_SIZE(iv),
				   aad, aad_len, ptxt_4, ptxt_4_len, ctxt_4,
				   VLA_SIZE(ctxt_4), &ctxt_4_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "CIPHERTEXT_4", ctxt_4, ctxt_4_len);

	/* 6. Generate edhoc message 4. */
	ret = generate_message_4(ctxt_4, ctxt_4_len, msg_4, msg_4_size,
				 msg_4_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "message_4", msg_4, *msg_4_len);

	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->status = EDHOC_SM_PERSISTED;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}

/**
 * Steps for processing of message 4:
 *      1. Choose most preferred cipher suite.
 *      2. CBOR decode message 3.
 *      3. Compute K_4, IV_4 and AAD_4.
 *      4. Decrypt ctxt_4.
 *      5. Parse CBOR ptxt_4 (PLAINTEXT_4).
 *      6. Process EAD_4 if present.
 */
int edhoc_message_4_process(struct edhoc_context *ctx, const uint8_t *msg_4,
			    size_t msg_4_len)
{
	if (NULL == ctx || NULL == msg_4 || 0 == msg_4_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_SM_COMPLETED != ctx->status ||
	    EDHOC_TH_STATE_4 != ctx->th_state ||
	    EDHOC_PRK_STATE_4E3M != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_4;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* 2. CBOR decode message 3. */
	const uint8_t *ctxt_4 = NULL;
	size_t ctxt_4_len = 0;

	ret = parse_message_4(msg_4, msg_4_len, &ctxt_4, &ctxt_4_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_MSG_4_PROCESS_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "CIPHERTEXT_4", ctxt_4, ctxt_4_len);

	/* 3. Compute K_4, IV_4 and AAD_4. */
	VLA_ALLOC(uint8_t, key, csuite.aead_key_length);
	memset(key, 0, VLA_SIZEOF(key));

	VLA_ALLOC(uint8_t, iv, csuite.aead_iv_length);
	memset(iv, 0, VLA_SIZEOF(iv));

	size_t aad_len = compute_aad_4_length(ctx);
	VLA_ALLOC(uint8_t, aad, aad_len);
	memset(aad, 0, VLA_SIZEOF(aad));

	aad_len = 0;
	ret = compute_key_iv_aad(ctx, key, VLA_SIZE(key), iv, VLA_SIZE(iv), aad,
				 VLA_SIZE(aad), &aad_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger) {
		ctx->logger(ctx->user_ctx, "K_4", key, VLA_SIZE(key));
		ctx->logger(ctx->user_ctx, "IV_4", iv, VLA_SIZE(iv));
		ctx->logger(ctx->user_ctx, "AAD_4", aad, aad_len);
	}

	/* 4. Decrypt ctxt_4. */
	VLA_ALLOC(uint8_t, ptxt_4, ctxt_4_len - csuite.aead_tag_length);
	memset(ptxt_4, 0, VLA_SIZEOF(ptxt_4));

	ret = decrypt_ciphertext_4(ctx, key, VLA_SIZE(key), iv, VLA_SIZE(iv),
				   aad, aad_len, ctxt_4, ctxt_4_len, ptxt_4,
				   VLA_SIZE(ptxt_4));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PLAINTEXT_4", ptxt_4,
			    VLA_SIZE(ptxt_4));

	/* 5. Parse CBOR ptxt_4 (PLAINTEXT_4). */
	ret = parse_plaintext_4(ctx, ptxt_4, VLA_SIZE(ptxt_4));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	/* 6. Process EAD_4 if present. */
	if (NULL != ctx->ead.process && 0 != ARRAY_SIZE(ctx->ead_token) - 1 &&
	    0 != ctx->nr_of_ead_tokens) {
		ret = ctx->ead.process(ctx->user_ctx, ctx->message,
				       ctx->ead_token, ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;

		if (NULL != ctx->logger) {
			for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
				ctx->logger(ctx->user_ctx,
					    "EAD_4 process label",
					    (const uint8_t *)&ctx->ead_token[i]
						    .label,
					    sizeof(ctx->ead_token[i].label));

				if (0 != ctx->ead_token[i].value_len)
					ctx->logger(
						ctx->user_ctx,
						"EAD_4 process value",
						ctx->ead_token[i].value,
						ctx->ead_token[i].value_len);
			}
		}
	}

	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->status = EDHOC_SM_PERSISTED;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}
