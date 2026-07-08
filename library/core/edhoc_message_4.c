/**
 * \file    edhoc_message_4.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message 4 compose & process.
 * 
 * \copyright Copyright (c) 2025
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
#include "edhoc_common_internal.h"
#include "edhoc_backend_log.h"
#include "edhoc_backend_memory.h"

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
 * \param[in] ctx	        EDHOC context.
 * \param[out] ptxt_4_len       Length of PLAINTEXT_4.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int compute_plaintext_4_len(const struct edhoc_context *ctx,
				   size_t *ptxt_4_len);

/**
 * \brief Prepare PLAINTEXT_4.
 *
 * \param[in] ctx	        EDHOC context.
 * \param[out] ptxt	        Buffer where the generated plaintext is to be written.
 * \param ptxt_size             Size of the \p ptxt buffer in bytes.
 * \param ptxt_len	        On success, the number of bytes that make up the plaintext.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int prepare_plaintext_4(const struct edhoc_context *ctx, uint8_t *ptxt,
			       size_t ptxt_size, size_t *ptxt_len);

/**
 * \brief Compute required length in bytes for AAD_4.
 *
 * \param[in] ctx	        EDHOC context.
 *
 * \retval Value different than 0 is success, otherwise failure.
 */
STATIC size_t compute_aad_4_len(const struct edhoc_context *ctx);

/**
 * \brief Compute K_4, IV_4 and AAD_4.
 *
 * \param[in] ctx	        EDHOC context.
 * \param[out] key		Buffer where the generated K_4 is to be written.
 * \param key_len	        Size of the \p key buffer in bytes.
 * \param[out] iv	        Buffer where the generated IV_4 is to be written.
 * \param iv_len                Size of the \p iv buffer in bytes.
 * \param[out] aad	        Buffer where the generated AAD_4 is to be written.
 * \param aad_len               Size of the \p aad buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int compute_key_iv_aad_4(const struct edhoc_context *ctx, uint8_t *key,
				size_t key_len, uint8_t *iv, size_t iv_len,
				uint8_t *aad, size_t aad_len);

/**
 * \brief Compute CIPHERTEXT_4.
 *
 * \param[in] ctx	        EDHOC context.
 * \param[in] key		Buffer containing the K_4.
 * \param key_len	        Size of the \p key buffer in bytes.
 * \param[in] iv	        Buffer containing the IV_4.
 * \param iv_len                Size of the \p iv buffer in bytes.
 * \param[in] aad	        Buffer containing the AAD_4.
 * \param aad_len               Size of the \p aad buffer in bytes.
 * \param[in] ptxt	        Buffer containing the PLAINTEXT_4.
 * \param ptxt_len              Size of the \p ptxt buffer in bytes.
 * \param[out] ctxt	        Buffer where the generated ciphertext is to be written.
 * \param ctxt_size	        Size of the \p ctxt buffer in bytes.
 * \param[out] ctxt_len         On success, the number of bytes that make up the CIPHERTEXT_4.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int compute_ciphertext(const struct edhoc_context *ctx,
			      const uint8_t *key, size_t key_len,
			      const uint8_t *iv, size_t iv_len,
			      const uint8_t *aad, size_t aad_len,
			      const uint8_t *ptxt, size_t ptxt_len,
			      uint8_t *ctxt, size_t ctxt_size,
			      size_t *ctxt_len);

/**
 * \brief Generate edhoc message 4.
 *
 * \param[in] ctxt	        Buffer continas the ciphertext.
 * \param ctxt_len	        Size of the \p ctxt buffer in bytes.
 * \param[out] msg_4            Buffer where the generated message 4 is to be written.
 * \param msg_4_size            Size of the \p msg_4 buffer in bytes.
 * \param[out] msg_4_len        On success, the number of bytes that make up the message 4.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int gen_msg_4(const uint8_t *ctxt, size_t ctxt_len, uint8_t *msg_4,
		     size_t msg_4_size, size_t *msg_4_len);

/**
 * \brief CBOR decode message 4 and save address and length for CIPHERTEXT_4.
 *
 * \param[in] msg_4     	Buffer containing the message 4.
 * \param msg_4_len     	Size of the \p msg_4 buffer in bytes.
 * \param[out] ctxt_4	        Pointer to buffer containing the CIPHERTEXT_4.
 * \param[out] ctxt_4_len	Size of the \p ctxctxt_4t buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int parse_msg_4(const uint8_t *msg_4, size_t msg_4_len,
		       const uint8_t **ctxt_4, size_t *ctxt_4_len);

/**
 * \brief Decrypt CIPHERTEXT_4.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] key		Buffer containing the K_4.
 * \param key_len	        Size of the \p key buffer in bytes.
 * \param[in] iv	        Buffer containing the IV_4.
 * \param iv_len                Size of the \p iv buffer in bytes.
 * \param[in] aad	        Buffer containing the AAD_4.
 * \param aad_len               Size of the \p aad buffer in bytes.
 * \param[in] ctxt	        Pointer to buffer containing the CIPHERTEXT_4.
 * \param ctxt_len	        Size of the \p ctxt buffer in bytes.
 * \param[out] ptxt	        Buffer where the decrypted PLAINTEXT_4 is to be written.
 * \param ptxt_len	        Size of the \p ptxt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int decrypt_ciphertext_4(const struct edhoc_context *ctx,
				const uint8_t *key, size_t key_len,
				const uint8_t *iv, size_t iv_len,
				const uint8_t *aad, size_t aad_len,
				const uint8_t *ctxt, size_t ctxt_len,
				uint8_t *ptxt, size_t ptxt_len);

/**
 * \brief Parsed cborised PLAINTEXT_4.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] ptxt		Buffer containing the PLAINTEXT_4.
 * \param ptxt_len              Size of the \p ptxt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int parse_plaintext_4(struct edhoc_context *ctx, const uint8_t *ptxt,
			     size_t ptxt_len);

/* Static function definitions --------------------------------------------- */

STATIC int compute_plaintext_4_len(const struct edhoc_context *ctx,
				   size_t *ptxt_4_len)
{
	if (NULL == ctx || NULL == ptxt_4_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	size_t len = 0;

	for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
		len += edhoc_cbor_int_mem_req(ctx->ead_token[i].label);
		len += ctx->ead_token[i].value_len;
		len += edhoc_cbor_bstr_oh(ctx->ead_token[i].value_len);
	}

	*ptxt_4_len = len;
	return EDHOC_SUCCESS;
}

STATIC int prepare_plaintext_4(const struct edhoc_context *ctx, uint8_t *ptxt,
			       size_t ptxt_size, size_t *ptxt_len)
{
	if (NULL == ctx || NULL == ptxt || NULL == ptxt_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	struct plaintext_4 ead_4 = { .plaintext_4_present = false };

	if (ARRAY_SIZE(ead_4.plaintext_4.EAD_4) < ctx->nr_of_ead_tokens) {
		EDHOC_LOG_ERR("EAD_4 buffer too small: %zu",
			      ctx->nr_of_ead_tokens);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

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

	ret = cbor_encode_plaintext_4(ptxt, ptxt_size, &ead_4, ptxt_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc PLAINTEXT_4: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC size_t compute_aad_4_len(const struct edhoc_context *ctx)
{
	size_t len = 0;

	len += sizeof("Encrypt0") + edhoc_cbor_tstr_oh(sizeof("Encrypt0"));
	len += edhoc_cbor_bstr_oh(0);
	len += ctx->th_len + edhoc_cbor_bstr_oh(ctx->th_len);

	return len;
}

STATIC int compute_key_iv_aad_4(const struct edhoc_context *ctx, uint8_t *key,
				size_t key_len, uint8_t *iv, size_t iv_len,
				uint8_t *aad, size_t aad_len)
{
	if (NULL == ctx || NULL == key || 0 == key_len || NULL == iv ||
	    0 == iv_len || NULL == aad || 0 == aad_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_4 != ctx->th_state ||
	    EDHOC_PRK_STATE_4E3M != ctx->prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d", ctx->th_state,
			      ctx->prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

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

	EDHOC_MEM_ALLOC(uint8_t, info, len);
	if (NULL == info) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	/* Generate K_3. */
	input_info = (struct info){
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_K_4,
		.info_context.value = ctx->th,
		.info_context.len = ctx->th_len,
		.info_length = (uint32_t)csuite.aead_key_length,
	};

	len = 0;
	ret = cbor_encode_info(info, EDHOC_MEM_ALLOC_SIZE(info), &input_info,
			       &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc info for K_4: %d", ret);
		EDHOC_MEM_FREE(info);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_EXPAND, ctx->prk,
				   ctx->prk_len, key_id);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Import key for K_4: %d", ret);
		EDHOC_MEM_FREE(info);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ret = ctx->crypto.expand(ctx->user_ctx, key_id, info, len, key,
				 key_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);
	ctx->platform.zeroize(key_id, sizeof(key_id));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Expand K_4: %d", ret);
		EDHOC_MEM_FREE(info);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* Generate IV_3. */
	input_info = (struct info){
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_IV_4,
		.info_context.value = ctx->th,
		.info_context.len = ctx->th_len,
		.info_length = (uint32_t)csuite.aead_iv_length,
	};

	memset(info, 0, EDHOC_MEM_ALLOC_SIZEOF(info));
	len = 0;
	ret = cbor_encode_info(info, EDHOC_MEM_ALLOC_SIZE(info), &input_info,
			       &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc info for IV_4: %d", ret);
		EDHOC_MEM_FREE(info);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_EXPAND, ctx->prk,
				   ctx->prk_len, key_id);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Import key for IV_4: %d", ret);
		EDHOC_MEM_FREE(info);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ret = ctx->crypto.expand(ctx->user_ctx, key_id, info, len, iv, iv_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);
	ctx->platform.zeroize(key_id, sizeof(key_id));
	EDHOC_MEM_FREE(info);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Expand IV_4: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* Generate AAD_4. */
	struct enc_structure cose_enc_0 = {
		.enc_structure_protected.value = NULL,
		.enc_structure_protected.len = 0,
		.enc_structure_external_aad.value = ctx->th,
		.enc_structure_external_aad.len = ctx->th_len,
	};

	len = 0;
	ret = cbor_encode_enc_structure(aad, aad_len, &cose_enc_0, &len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc AAD_4: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int compute_ciphertext(const struct edhoc_context *ctx,
			      const uint8_t *key, size_t key_len,
			      const uint8_t *iv, size_t iv_len,
			      const uint8_t *aad, size_t aad_len,
			      const uint8_t *ptxt, size_t ptxt_len,
			      uint8_t *ctxt, size_t ctxt_size, size_t *ctxt_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_ENCRYPT, key,
				   key_len, key_id);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Import key for encryption: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ret = ctx->crypto.encrypt(ctx->user_ctx, key_id, iv, iv_len, aad,
				  aad_len, ptxt, ptxt_len, ctxt, ctxt_size,
				  ctxt_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);
	ctx->platform.zeroize(key_id, sizeof(key_id));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Encrypt CIPHERTEXT_4: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int gen_msg_4(const uint8_t *ctxt, size_t ctxt_len, uint8_t *msg_4,
		     size_t msg_4_size, size_t *msg_4_len)
{
	if (NULL == ctxt || 0 == ctxt_len || NULL == msg_4 || 0 == msg_4_size ||
	    NULL == msg_4_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct zcbor_string input_bstr = {
		.value = ctxt,
		.len = ctxt_len,
	};

	ret = cbor_encode_message_4_CIPHERTEXT_4(msg_4, msg_4_size, &input_bstr,
						 msg_4_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc msg4: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int parse_msg_4(const uint8_t *msg_4, size_t msg_4_len,
		       const uint8_t **ctxt_4, size_t *ctxt_4_len)
{
	if (NULL == msg_4 || 0 == msg_4_len || NULL == ctxt_4 ||
	    NULL == ctxt_4_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t len = 0;
	struct zcbor_string dec_msg_4 = { 0 };
	ret = cbor_decode_message_4_CIPHERTEXT_4(msg_4, msg_4_len, &dec_msg_4,
						 &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR dec msg4: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	*ctxt_4 = dec_msg_4.value;
	*ctxt_4_len = dec_msg_4.len;

	return EDHOC_SUCCESS;
}

STATIC int decrypt_ciphertext_4(const struct edhoc_context *ctx,
				const uint8_t *key, size_t key_len,
				const uint8_t *iv, size_t iv_len,
				const uint8_t *aad, size_t aad_len,
				const uint8_t *ctxt, size_t ctxt_len,
				uint8_t *ptxt, size_t ptxt_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_DECRYPT, key,
				   key_len, key_id);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Import key for decryption: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	size_t len = 0;
	ret = ctx->crypto.decrypt(ctx->user_ctx, key_id, iv, iv_len, aad,
				  aad_len, ctxt, ctxt_len, ptxt, ptxt_len,
				  &len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);
	ctx->platform.zeroize(key_id, sizeof(key_id));

	if (EDHOC_SUCCESS != ret || ptxt_len != len) {
		EDHOC_LOG_ERR("Decrypt CIPHERTEXT_4: %d, %zu, %zu", ret,
			      ptxt_len, len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int parse_plaintext_4(struct edhoc_context *ctx, const uint8_t *ptxt,
			     size_t ptxt_len)
{
	if (NULL == ctx || NULL == ptxt) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t len = 0;
	struct plaintext_4 ead_4 = { 0 };
	ret = cbor_decode_plaintext_4(ptxt, ptxt_len, &ead_4, &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR dec PLAINTEXT_4: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

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
 *      3a. Compute plaintext length (PLAINTEXT_4).
 *      3b. Prepare plaintext (PLAINTEXT_4).
 *      4.  Compute K_4, IV_4 and AAD_4.
 *      5.  Compute ciphertext.
 *      6.  Generate edhoc message 4.
 */
int edhoc_message_4_compose(struct edhoc_context *ctx, uint8_t *msg_4,
			    size_t msg_4_size, size_t *msg_4_len)
{
	EDHOC_LOG_INF("Compose msg4 start");

	if (NULL == ctx || NULL == msg_4 || 0 == msg_4_size ||
	    NULL == msg_4_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_context_configured(ctx)) {
		EDHOC_LOG_ERR("Context not fully configured");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_SM_COMPLETED != ctx->status ||
	    EDHOC_TH_STATE_4 != ctx->th_state ||
	    EDHOC_PRK_STATE_4E3M != ctx->prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d, %d", ctx->status,
			      ctx->th_state, ctx->prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_4;
	ctx->role = EDHOC_RESPONDER;

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
		    ARRAY_SIZE(ctx->ead_token) - 1 < ctx->nr_of_ead_tokens) {
			EDHOC_LOG_ERR("Compose EAD_4: %d, %zu, %zu", ret,
				      ARRAY_SIZE(ctx->ead_token) - 1,
				      ctx->nr_of_ead_tokens);
			return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
		}

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			EDHOC_LOG_HEXDUMP_DBG(
				(const uint8_t *)&ctx->ead_token[i].label,
				sizeof(ctx->ead_token[i].label),
				"EAD_4 compose label");
			if (0 != ctx->ead_token[i].value_len) {
				EDHOC_LOG_HEXDUMP_DBG(
					ctx->ead_token[i].value,
					ctx->ead_token[i].value_len,
					"EAD_4 compose value");
			}
		}
	}

	/* 3a. Compute plaintext length (PLAINTEXT_4). */
	size_t plaintext_len = 0;
	ret = compute_plaintext_4_len(ctx, &plaintext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PLAINTEXT_4 length: %d", ret);
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* NOLINTNEXTLINE(clang-analyzer-core.VLASize) */
	EDHOC_MEM_ALLOC(uint8_t, plaintext, plaintext_len);
	if (NULL == plaintext) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	/* 3b. Prepare plaintext (PLAINTEXT_4). */
	ret = prepare_plaintext_4(ctx, plaintext,
				  EDHOC_MEM_ALLOC_SIZE(plaintext),
				  &plaintext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Prepare PLAINTEXT_4: %d", ret);
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(plaintext, plaintext_len, "PLAINTEXT_4");

	/* 4. Compute K_4, IV_4 and AAD_4. */
	EDHOC_MEM_ALLOC(uint8_t, key, csuite.aead_key_length);
	if (NULL == key) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	EDHOC_MEM_ALLOC(uint8_t, iv, csuite.aead_iv_length);
	if (NULL == iv) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(key);
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	const size_t aad_len = compute_aad_4_len(ctx);
	EDHOC_MEM_ALLOC(uint8_t, aad, aad_len);
	if (NULL == aad) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(iv);
		EDHOC_MEM_FREE(key);
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = compute_key_iv_aad_4(ctx, key, EDHOC_MEM_ALLOC_SIZE(key), iv,
				   EDHOC_MEM_ALLOC_SIZE(iv), aad,
				   EDHOC_MEM_ALLOC_SIZE(aad));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute K_4/IV_4/AAD_4: %d", ret);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		EDHOC_MEM_FREE(key);
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(key, EDHOC_MEM_ALLOC_SIZE(key), "K_4");
	EDHOC_LOG_HEXDUMP_DBG(iv, EDHOC_MEM_ALLOC_SIZE(iv), "IV_4");
	EDHOC_LOG_HEXDUMP_DBG(aad, EDHOC_MEM_ALLOC_SIZE(aad), "AAD_4");

	/* 5. Compute ciphertext. */
	size_t ciphertext_len = 0;
	EDHOC_MEM_ALLOC(uint8_t, ciphertext,
			EDHOC_MEM_ALLOC_SIZE(plaintext) +
				csuite.aead_tag_length);
	if (NULL == ciphertext) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		EDHOC_MEM_FREE(key);
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = compute_ciphertext(ctx, key, EDHOC_MEM_ALLOC_SIZE(key), iv,
				 EDHOC_MEM_ALLOC_SIZE(iv), aad,
				 EDHOC_MEM_ALLOC_SIZE(aad), plaintext,
				 plaintext_len, ciphertext,
				 EDHOC_MEM_ALLOC_SIZE(ciphertext),
				 &ciphertext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute CIPHERTEXT_4: %d", ret);
		EDHOC_MEM_FREE(ciphertext);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		EDHOC_MEM_FREE(key);
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_MEM_FREE(aad);
	EDHOC_MEM_FREE(iv);
	EDHOC_MEM_FREE(key);
	EDHOC_MEM_FREE(plaintext);

	EDHOC_LOG_HEXDUMP_DBG(ciphertext, ciphertext_len, "CIPHERTEXT_4");

	/* 6. Generate edhoc message 4. */
	ret = gen_msg_4(ciphertext, ciphertext_len, msg_4, msg_4_size,
			msg_4_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Generate message_4: %d", ret);
		EDHOC_MEM_FREE(ciphertext);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_MEM_FREE(ciphertext);

	EDHOC_LOG_HEXDUMP_DBG(msg_4, *msg_4_len, "message_4");
	EDHOC_LOG_INF("Compose msg4 end");

	ctx->nr_of_ead_tokens = 0;
	ctx->platform.zeroize(ctx->ead_token, sizeof(ctx->ead_token));

	ctx->status = EDHOC_SM_PERSISTED;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}

/**
 * Steps for processing of message 4:
 *      1. Choose most preferred cipher suite.
 *      2. CBOR decode message 3.
 *      3. Compute K_4, IV_4 and AAD_4.
 *      4. Decrypt ciphertext.
 *      5. Parse CBOR plaintext (PLAINTEXT_4).
 *      6. Process EAD_4 if present.
 */
int edhoc_message_4_process(struct edhoc_context *ctx, const uint8_t *msg_4,
			    size_t msg_4_len)
{
	EDHOC_LOG_INF("Process msg4 start");

	if (NULL == ctx || NULL == msg_4 || 0 == msg_4_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_context_configured(ctx)) {
		EDHOC_LOG_ERR("Context not fully configured");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_SM_COMPLETED != ctx->status ||
	    EDHOC_TH_STATE_4 != ctx->th_state ||
	    EDHOC_PRK_STATE_4E3M != ctx->prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d, %d", ctx->status,
			      ctx->th_state, ctx->prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_4;
	ctx->role = EDHOC_INITIATOR;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* 2. CBOR decode message 3. */
	const uint8_t *ctxt = NULL;
	size_t ctxt_len = 0;

	ret = parse_msg_4(msg_4, msg_4_len, &ctxt, &ctxt_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse message_4: %d", ret);
		return EDHOC_ERROR_MSG_4_PROCESS_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctxt, ctxt_len, "CIPHERTEXT_4");

	/* 3. Compute K_4, IV_4 and AAD_4. */
	EDHOC_MEM_ALLOC(uint8_t, key, csuite.aead_key_length);
	if (NULL == key) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	EDHOC_MEM_ALLOC(uint8_t, iv, csuite.aead_iv_length);
	if (NULL == iv) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(key);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	const size_t aad_len = compute_aad_4_len(ctx);
	EDHOC_MEM_ALLOC(uint8_t, aad, aad_len);
	if (NULL == aad) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(iv);
		EDHOC_MEM_FREE(key);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = compute_key_iv_aad_4(ctx, key, EDHOC_MEM_ALLOC_SIZE(key), iv,
				   EDHOC_MEM_ALLOC_SIZE(iv), aad,
				   EDHOC_MEM_ALLOC_SIZE(aad));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute K_4/IV_4/AAD_4: %d", ret);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		EDHOC_MEM_FREE(key);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(key, EDHOC_MEM_ALLOC_SIZE(key), "K_4");
	EDHOC_LOG_HEXDUMP_DBG(iv, EDHOC_MEM_ALLOC_SIZE(iv), "IV_4");
	EDHOC_LOG_HEXDUMP_DBG(aad, EDHOC_MEM_ALLOC_SIZE(aad), "AAD_4");

	/* 4. Decrypt ciphertext. */
	EDHOC_MEM_ALLOC(uint8_t, ptxt, ctxt_len - csuite.aead_tag_length);
	if (NULL == ptxt) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		EDHOC_MEM_FREE(key);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = decrypt_ciphertext_4(ctx, key, EDHOC_MEM_ALLOC_SIZE(key), iv,
				   EDHOC_MEM_ALLOC_SIZE(iv), aad,
				   EDHOC_MEM_ALLOC_SIZE(aad), ctxt, ctxt_len,
				   ptxt, EDHOC_MEM_ALLOC_SIZE(ptxt));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Decrypt CIPHERTEXT_4: %d", ret);
		EDHOC_MEM_FREE(ptxt);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		EDHOC_MEM_FREE(key);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_MEM_FREE(aad);
	EDHOC_MEM_FREE(iv);
	EDHOC_MEM_FREE(key);

	EDHOC_LOG_HEXDUMP_DBG(ptxt, EDHOC_MEM_ALLOC_SIZE(ptxt), "PLAINTEXT_4");

	/* 5. Parse CBOR plaintext (PLAINTEXT_4). */
	ret = parse_plaintext_4(ctx, ptxt, EDHOC_MEM_ALLOC_SIZE(ptxt));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse PLAINTEXT_4: %d", ret);
		EDHOC_MEM_FREE(ptxt);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* 6. Process EAD_4 if present.
	 *
	 * NOTE: ctx->ead_token[].value are zero-copy pointers into the
	 * plaintext buffer, so it must remain allocated until the EAD process
	 * callback has consumed the tokens.
	 */
	if (NULL != ctx->ead.process && 0 != ARRAY_SIZE(ctx->ead_token) - 1 &&
	    0 != ctx->nr_of_ead_tokens) {
		ret = ctx->ead.process(ctx->user_ctx, ctx->message,
				       ctx->ead_token, ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Process EAD_4: %d", ret);
			EDHOC_MEM_FREE(ptxt);
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;
		}

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			EDHOC_LOG_HEXDUMP_DBG(
				(const uint8_t *)&ctx->ead_token[i].label,
				sizeof(ctx->ead_token[i].label),
				"EAD_4 process label");

			if (0 != ctx->ead_token[i].value_len) {
				EDHOC_LOG_HEXDUMP_DBG(
					ctx->ead_token[i].value,
					ctx->ead_token[i].value_len,
					"EAD_4 process value");
			}
		}
	}

	EDHOC_MEM_FREE(ptxt);

	EDHOC_LOG_INF("Process msg4 end");

	ctx->nr_of_ead_tokens = 0;
	ctx->platform.zeroize(ctx->ead_token, sizeof(ctx->ead_token));

	ctx->status = EDHOC_SM_PERSISTED;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}
