/**
 * \file    edhoc_message_3.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message 3.
 * \version 0.6
 * \date    2024-08-05
 *
 * \copyright Copyright (c) 2024
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
#include <zcbor_common.h>
#include <backend_cbor_message_3_encode.h>
#include <backend_cbor_message_3_decode.h>
#include <backend_cbor_bstr_type_encode.h>
#include <backend_cbor_bstr_type_decode.h>
#include <backend_cbor_int_type_encode.h>
#include <backend_cbor_int_type_decode.h>
#include <backend_cbor_id_cred_x_encode.h>
#include <backend_cbor_id_cred_x_decode.h>
#include <backend_cbor_sig_structure_encode.h>
#include <backend_cbor_info_encode.h>
#include <backend_cbor_plaintext_3_decode.h>
#include <backend_cbor_enc_structure_encode.h>
#include <backend_cbor_enc_structure_decode.h>
#include <backend_cbor_ead_encode.h>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Compute psuedo random key (PRK_4e3m).
 *
 * \param[in,out] ctx		EDHOC context.
 * \param[in] auth_cred         Authentication credentials.
 * \param[in] pub_key           Peer public static DH key. 
 * \param pub_key_len           Size of the \p pub_key buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_prk_4e3m(struct edhoc_context *ctx,
			 const struct edhoc_auth_creds *auth_cred,
			 const uint8_t *pub_key, size_t pub_key_len);

/**
 * \brief Compute memory required for PLAINTEXT_3. 
 * 
 * \param[in] ctx               EDHOC context.
 * \param[in] mac_ctx        	MAC context.
 * \param sign_len              Size of the signature buffer in bytes.
 * \param[out] plaintext_3_len  On success, length of PLAINTEXT_3.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_plaintext_3_len(const struct edhoc_context *ctx,
				const struct mac_context *mac_ctx,
				size_t sign_len, size_t *plaintext_3_len);

/**
 * \brief Prepare PLAINTEXT_3.
 *
 * \param[in] mac_ctx		MAC context.
 * \param[in] sign		Buffer containing the signature.
 * \param sign_len		Size of the \p sign buffer in bytes.
 * \param[out] ptxt	        Buffer where the generated plaintext is to be written.
 * \param ptxt_size	        Size of the \p ptxt buffer in bytes.
 * \param[out] ptxt_len		On success, the number of bytes that make up the PLAINTEXT_2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int prepare_plaintext_3(const struct mac_context *mac_ctx,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt, size_t ptxt_size,
			       size_t *ptxt_len);

/**
 * \brief Compute required length in bytes for AAD_3.
 *
 * \param[in] ctx	        EDHOC context.
 * \param[out] aad_3_len        On success, length of AAD_3.
 *
 * \retval EDHOC_SUCCESS on success, otherwise failure.s
 */
static int32_t comp_aad_3_len(const struct edhoc_context *ctx,
			      size_t *aad_3_len);

/**
 * \brief Compute K_3, IV_3 and AAD_3.
 *
 * \param[in] ctx	        EDHOC context.
 * \param[out] key		Buffer where the generated K_3 is to be written.
 * \param key_len	        Size of the \p key buffer in bytes.
 * \param[out] iv	        Buffer where the generated IV_3 is to be written.
 * \param iv_len                Size of the \p iv buffer in bytes.
 * \param[out] aad	        Buffer where the generated AAD_3 is to be written.
 * \param aad_len               Size of the \p aad buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_key_iv_aad(const struct edhoc_context *ctx, uint8_t *key,
			   size_t key_len, uint8_t *iv, size_t iv_len,
			   uint8_t *aad, size_t aad_len);

/**
 * \brief Compute CIPHERTEXT_3.
 *
 * \param[in] ctx	        EDHOC context.
 * \param[in] key		Buffer containing the K_3.
 * \param key_len	        Size of the \p key buffer in bytes.
 * \param[in] iv	        Buffer containing the IV_3.
 * \param iv_len                Size of the \p iv buffer in bytes.
 * \param[in] aad	        Buffer containing the AAD_3.
 * \param aad_len               Size of the \p aad buffer in bytes.
 * \param[in] ptxt	        Buffer containing the PLAINTEXT_3.
 * \param ptxt_len              Size of the \p ptxt buffer in bytes.
 * \param[out] ctxt	        Buffer where the generated ciphertext is to be written.
 * \param ctxt_size	        Size of the \p ctxt buffer in bytes.
 * \param[out] ctxt_len         On success, the number of bytes that make up the CIPHERTEXT_3.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_ciphertext(const struct edhoc_context *ctx, const uint8_t *key,
			   size_t key_len, const uint8_t *iv, size_t iv_len,
			   const uint8_t *aad, size_t aad_len,
			   const uint8_t *ptxt, size_t ptxt_len, uint8_t *ctxt,
			   size_t ctxt_size, size_t *ctxt_len);

/**
 * \brief Compute transcript hash 4.
 *
 * \param[in,out] ctx		EDHOC context.
 * \param[in] mac_ctx        	MAC context.
 * \param[in] ptxt		Buffer containing the PLAINTEXT_3.
 * \param ptxt_len              Size of the \p ptxt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_th_4(struct edhoc_context *ctx,
		     const struct mac_context *mac_ctx, const uint8_t *ptxt,
		     size_t ptxt_len);

/**
 * \brief Generate edhoc message 3.
 *
 * \param[in] ctxt	        Buffer continas the ciphertext.
 * \param ctxt_len	        Size of the \p ctxt buffer in bytes.
 * \param[out] msg_3            Buffer where the generated message 3 is to be written.
 * \param msg_3_size            Size of the \p msg_3 buffer in bytes.
 * \param[out] msg_3_len        On success, the number of bytes that make up the message 3.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int gen_msg_3(const uint8_t *ctxt, size_t ctxt_len, uint8_t *msg_3,
		     size_t msg_3_size, size_t *msg_3_len);

/**
 * \brief CBOR decode message 3 and save address and length for CIPHERTEXT_3.
 *
 * \param[in] msg_3     	Buffer containing the message 3.
 * \param msg_3_len     	Size of the \p msg_3 buffer in bytes.
 * \param[out] ctxt_3	        Pointer to buffer containing the CIPHERTEXT_3.
 * \param[out] ctxt_3_len	Size of the \p ctxt_3 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int parse_msg_3(const uint8_t *msg_3, size_t msg_3_len,
		       const uint8_t **ctxt_3, size_t *ctxt_3_len);

/**
 * \brief Decrypt CIPHERTEXT_3.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] key		Buffer containing the K_3.
 * \param key_len	        Size of the \p key buffer in bytes.
 * \param[in] iv	        Buffer containing the IV_3.
 * \param iv_len                Size of the \p iv buffer in bytes.
 * \param[in] aad	        Buffer containing the AAD_3.
 * \param aad_len               Size of the \p aad buffer in bytes.
 * \param[in] ctxt	        Pointer to buffer containing the CIPHERTEXT_3.
 * \param ctxt_len	        Size of the \p ctxt buffer in bytes.
 * \param[out] ptxt	        Buffer where the decrypted PLAINTEXT_3 is to be written.
 * \param ptxt_len	        Size of the \p ptxt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int decrypt_ciphertext(const struct edhoc_context *ctx,
			      const uint8_t *key, size_t key_len,
			      const uint8_t *iv, size_t iv_len,
			      const uint8_t *aad, size_t aad_len,
			      const uint8_t *ctxt, size_t ctxt_len,
			      uint8_t *ptxt, size_t ptxt_len);

/**
 * \brief Parsed cborised PLAINTEXT_3 for separate buffers.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] ptxt		Buffer containing the PLAINTEXT_3.
 * \param ptxt_len              Size of the \p ptxt buffer in bytes.
 * \param[out] parsed_ptxt     	Structure where parsed PLAINTEXT_3 is to be written.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int parse_plaintext(struct edhoc_context *ctx, const uint8_t *ptxt,
			   size_t ptxt_len, struct plaintext *parsed_ptxt);

/**
 * \brief Compute SALT_4e3m.
 * 
 * \param[in] ctx               EDHOC context.
 * \param[out] salt             Buffer where the generated salt is to be written.
 * \param salt_len              Size of the \p salt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_salt_4e3m(const struct edhoc_context *ctx, uint8_t *salt,
			  size_t salt_len);

/**
 * \brief Compute G_IY for PRK_4e3m.
 * 
 * \param[in,out] ctx           EDHOC context.
 * \param[in] auth_cred         Authentication credentials.
 * \param[in] pub_key           Peer public key.
 * \param pub_key_len           Peer public key length.
 * \param[out] giy              Buffer where the generated G_IY is to be written.
 * \param giy_len               Size of the \p giy buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_giy(struct edhoc_context *ctx,
		    const struct edhoc_auth_creds *auth_cred,
		    const uint8_t *pub_key, size_t pub_key_len, uint8_t *giy,
		    size_t giy_len);

/* Static function definitions --------------------------------------------- */

static int comp_prk_4e3m(struct edhoc_context *ctx,
			 const struct edhoc_auth_creds *auth_cred,
			 const uint8_t *pub_key, size_t pub_key_len)
{
	if (NULL == ctx || NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_PRK_STATE_3E2M != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	switch (ctx->chosen_method) {
	case EDHOC_METHOD_0:
	case EDHOC_METHOD_1:
		ctx->prk_state = EDHOC_PRK_STATE_4E3M;
		return EDHOC_SUCCESS;

	case EDHOC_METHOD_2:
	case EDHOC_METHOD_3: {
		const size_t hash_len =
			ctx->csuite[ctx->chosen_csuite_idx].hash_length;

		VLA_ALLOC(uint8_t, salt_4e3m, hash_len);
		memset(salt_4e3m, 0, VLA_SIZEOF(salt_4e3m));

		int ret = comp_salt_4e3m(ctx, salt_4e3m, VLA_SIZE(salt_4e3m));

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		if (NULL != ctx->logger)
			ctx->logger(ctx->user_ctx, "SALT_4e3m", salt_4e3m,
				    VLA_SIZE(salt_4e3m));

		const size_t ecc_key_len =
			ctx->csuite[ctx->chosen_csuite_idx].ecc_key_length;

		VLA_ALLOC(uint8_t, giy, ecc_key_len);
		memset(giy, 0, VLA_SIZEOF(giy));

		ret = comp_giy(ctx, auth_cred, pub_key, pub_key_len, giy,
			       VLA_SIZE(giy));

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		if (NULL != ctx->logger)
			ctx->logger(ctx->user_ctx, "G_IY", giy, VLA_SIZE(giy));

		ctx->prk_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

		uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
		ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_EXTRACT, giy,
					   VLA_SIZE(giy), key_id);
		memset(giy, 0, VLA_SIZEOF(giy));

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		size_t out_len = 0;
		ret = ctx->crypto.extract(ctx->user_ctx, key_id, salt_4e3m,
					  VLA_SIZE(salt_4e3m), ctx->prk,
					  ctx->prk_len, &out_len);
		ctx->keys.destroy_key(ctx->user_ctx, key_id);

		if (EDHOC_SUCCESS != ret || ctx->prk_len != out_len)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		ctx->prk_state = EDHOC_PRK_STATE_4E3M;
		return EDHOC_SUCCESS;
	}
	case EDHOC_METHOD_MAX:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	return EDHOC_ERROR_NOT_PERMITTED;
}

static int comp_plaintext_3_len(const struct edhoc_context *ctx,
				const struct mac_context *mac_ctx,
				size_t sign_len, size_t *plaintext_3_len)
{
	if (NULL == ctx || NULL == mac_ctx || 0 == sign_len ||
	    NULL == plaintext_3_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	size_t len = 0;

	switch (ctx->cid.encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
		len += edhoc_cbor_int_mem_req(ctx->cid.int_value);
		break;
	case EDHOC_CID_TYPE_BYTE_STRING:
		len += ctx->cid.bstr_length;
		len += edhoc_cbor_bstr_oh(ctx->cid.bstr_length);
		break;
	}

	if (true == mac_ctx->id_cred_is_comp_enc) {
		switch (mac_ctx->id_cred_enc_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			len += edhoc_cbor_int_mem_req(mac_ctx->id_cred_int);
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			len += mac_ctx->id_cred_bstr_len;
			len += edhoc_cbor_bstr_oh(mac_ctx->id_cred_bstr_len);
			break;
		}
	} else {
		len += mac_ctx->id_cred_len;
	}

	len += sign_len;
	len += edhoc_cbor_bstr_oh(sign_len);
	len += mac_ctx->ead_len;

	*plaintext_3_len = len;
	return EDHOC_SUCCESS;
}

static int prepare_plaintext_3(const struct mac_context *mac_ctx,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt, size_t ptxt_size,
			       size_t *ptxt_len)
{
	if (NULL == mac_ctx || NULL == sign || 0 == sign_len || NULL == ptxt ||
	    0 == ptxt_size || NULL == ptxt_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t offset = 0;

	/* ID_CRED_I. */
	if (mac_ctx->id_cred_is_comp_enc) {
		switch (mac_ctx->id_cred_enc_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			memcpy(&ptxt[offset], &mac_ctx->id_cred_int, 1);
			offset += 1;
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			memcpy(&ptxt[offset], &mac_ctx->id_cred_bstr,
			       mac_ctx->id_cred_bstr_len);
			offset += mac_ctx->id_cred_bstr_len;
			break;
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	} else {
		memcpy(&ptxt[offset], mac_ctx->id_cred, mac_ctx->id_cred_len);
		offset += mac_ctx->id_cred_len;
	}
	const struct zcbor_string cbor_sign_or_mac_3 = {
		.value = sign,
		.len = sign_len,
	};

	size_t len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		&ptxt[offset], sign_len + edhoc_cbor_bstr_oh(sign_len),
		&cbor_sign_or_mac_3, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	offset += len;

	/* EAD_3 if present. */
	if (mac_ctx->is_ead) {
		memcpy(&ptxt[offset], mac_ctx->ead, mac_ctx->ead_len);
		offset += mac_ctx->ead_len;
	}

	if (offset > ptxt_size)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	*ptxt_len = offset;

	return EDHOC_SUCCESS;
}

static int comp_aad_3_len(const struct edhoc_context *ctx, size_t *aad_3_len)
{
	if (NULL == ctx || NULL == aad_3_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	size_t len = 0;

	len += sizeof("Encrypt0") + edhoc_cbor_tstr_oh(sizeof("Encrypt0"));
	len += 1; /* One byte for cbor bstr with 0 value. */
	len += ctx->th_len + edhoc_cbor_bstr_oh(ctx->th_len);

	*aad_3_len = len;
	return EDHOC_SUCCESS;
}

static int comp_key_iv_aad(const struct edhoc_context *ctx, uint8_t *key,
			   size_t key_len, uint8_t *iv, size_t iv_len,
			   uint8_t *aad, size_t aad_len)
{
	if (NULL == ctx || NULL == key || 0 == key_len || NULL == iv ||
	    0 == iv_len || NULL == aad || 0 == aad_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_3 != ctx->th_state)
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
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_K_3,
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
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_IV_3,
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

	len = 0;
	ret = cbor_encode_enc_structure(aad, aad_len, &cose_enc_0, &len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	return EDHOC_SUCCESS;
}

static int comp_ciphertext(const struct edhoc_context *ctx, const uint8_t *key,
			   size_t key_len, const uint8_t *iv, size_t iv_len,
			   const uint8_t *aad, size_t aad_len,
			   const uint8_t *ptxt, size_t ptxt_len, uint8_t *ctxt,
			   size_t ctxt_size, size_t *ctxt_len)
{
	if (NULL == ctx || NULL == key || 0 == key_len || NULL == iv ||
	    0 == iv_len || NULL == aad || 0 == aad_len || NULL == ptxt ||
	    0 == ptxt_len || NULL == ctxt || 0 == ctxt_size || NULL == ctxt_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_ENCRYPT, key,
				   key_len, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.encrypt(ctx->user_ctx, key_id, iv, iv_len, aad,
				  aad_len, ptxt, ptxt_len, ctxt, ctxt_size,
				  ctxt_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int comp_th_4(struct edhoc_context *ctx,
		     const struct mac_context *mac_ctx, const uint8_t *ptxt,
		     size_t ptxt_len)
{
	if (NULL == ctx || NULL == mac_ctx || NULL == ptxt || 0 == ptxt_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_3 != ctx->th_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;
	size_t offset = 0;

	/* Calculate required buffer length for TH_4. */
	len = 0;
	len += ctx->th_len + edhoc_cbor_bstr_oh(ctx->th_len);
	len += ptxt_len;
	len += mac_ctx->cred_len;

	VLA_ALLOC(uint8_t, th_4, len);
	memset(th_4, 0, VLA_SIZEOF(th_4));

	/* TH_3. */
	const struct zcbor_string cbor_th_3 = {
		.value = ctx->th,
		.len = ctx->th_len,
	};

	len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		&th_4[offset], VLA_SIZE(th_4), &cbor_th_3, &len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	offset += len;

	/* PLAINTEXT_3. */
	memcpy(&th_4[offset], ptxt, ptxt_len);
	offset += ptxt_len;

	/* CRED_I. */
	memcpy(&th_4[offset], mac_ctx->cred, mac_ctx->cred_len);
	offset += mac_ctx->cred_len;

	if (VLA_SIZE(th_4) < offset)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	/* Calculate TH_4. */
	ctx->th_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

	size_t hash_length = 0;
	ret = ctx->crypto.hash(ctx->user_ctx, th_4, VLA_SIZE(th_4), ctx->th,
			       ctx->th_len, &hash_length);

	if (EDHOC_SUCCESS != ret || ctx->th_len != hash_length)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->th_state = EDHOC_TH_STATE_4;
	return EDHOC_SUCCESS;
}

static int gen_msg_3(const uint8_t *ctxt, size_t ctxt_len, uint8_t *msg_3,
		     size_t msg_3_size, size_t *msg_3_len)
{
	if (NULL == ctxt || 0 == ctxt_len || NULL == msg_3 || 0 == msg_3_size ||
	    NULL == msg_3_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct zcbor_string input_bstr = {
		.value = ctxt,
		.len = ctxt_len,
	};

	ret = cbor_encode_message_3_CIPHERTEXT_3(msg_3, msg_3_size + 1,
						 &input_bstr, msg_3_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	return EDHOC_SUCCESS;
}

static int parse_msg_3(const uint8_t *msg_3, size_t msg_3_len,
		       const uint8_t **ctxt_3, size_t *ctxt_3_len)
{
	if (NULL == msg_3 || 0 == msg_3_len || NULL == ctxt_3 ||
	    NULL == ctxt_3_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t len = 0;
	struct zcbor_string dec_msg_3 = { 0 };
	ret = cbor_decode_message_3_CIPHERTEXT_3(msg_3, msg_3_len, &dec_msg_3,
						 &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	*ctxt_3 = dec_msg_3.value;
	*ctxt_3_len = dec_msg_3.len;

	return EDHOC_SUCCESS;
}

static int decrypt_ciphertext(const struct edhoc_context *ctx,
			      const uint8_t *key, size_t key_len,
			      const uint8_t *iv, size_t iv_len,
			      const uint8_t *aad, size_t aad_len,
			      const uint8_t *ctxt, size_t ctxt_len,
			      uint8_t *ptxt, size_t ptxt_len)
{
	if (NULL == ctx || NULL == key || 0 == key_len || NULL == iv ||
	    0 == iv_len || NULL == aad || 0 == aad_len || 0 == ctxt_len ||
	    NULL == ptxt || 0 == ptxt_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_DECRYPT, key,
				   key_len, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	size_t len = 0;
	ret = ctx->crypto.decrypt(ctx->user_ctx, key_id, iv, iv_len, aad,
				  aad_len, ctxt, ctxt_len, ptxt, ptxt_len,
				  &len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret || ptxt_len != len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int parse_plaintext(struct edhoc_context *ctx, const uint8_t *ptxt,
			   size_t ptxt_len, struct plaintext *parsed_ptxt)
{
	if (NULL == ctx || NULL == ptxt || 0 == ptxt_len || NULL == parsed_ptxt)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct plaintext_3 cbor_ptxt_3 = { 0 };
	ret = cbor_decode_plaintext_3(ptxt, ptxt_len, &cbor_ptxt_3, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	/* ID_CRED_I */
	switch (cbor_ptxt_3.plaintext_3_ID_CRED_I_choice) {
	case plaintext_3_ID_CRED_I_int_c: {
		parsed_ptxt->auth_cred.label = EDHOC_COSE_HEADER_KID;
		parsed_ptxt->auth_cred.key_id.encode_type =
			EDHOC_ENCODE_TYPE_INTEGER;
		parsed_ptxt->auth_cred.key_id.key_id_int =
			cbor_ptxt_3.plaintext_3_ID_CRED_I_int;
		break;
	}

	case plaintext_3_ID_CRED_I_bstr_c:
		parsed_ptxt->auth_cred.label = EDHOC_COSE_HEADER_KID;
		parsed_ptxt->auth_cred.key_id.encode_type =
			EDHOC_ENCODE_TYPE_BYTE_STRING;
		parsed_ptxt->auth_cred.key_id.key_id_bstr_length =
			cbor_ptxt_3.plaintext_3_ID_CRED_I_bstr.len;
		memcpy(parsed_ptxt->auth_cred.key_id.key_id_bstr,
		       cbor_ptxt_3.plaintext_3_ID_CRED_I_bstr.value,
		       cbor_ptxt_3.plaintext_3_ID_CRED_I_bstr.len);
		break;

	case plaintext_3_ID_CRED_I_map_m_c: {
		const struct map *cbor_map =
			&cbor_ptxt_3.plaintext_3_ID_CRED_I_map_m;

		if (cbor_map->map_x5chain_present) {
			const struct COSE_X509_r *cose_x509 =
				&cbor_map->map_x5chain.map_x5chain;

			parsed_ptxt->auth_cred.label =
				EDHOC_COSE_HEADER_X509_CHAIN;

			switch (cose_x509->COSE_X509_choice) {
			case COSE_X509_bstr_c:
				parsed_ptxt->auth_cred.x509_chain.nr_of_certs =
					1;
				parsed_ptxt->auth_cred.x509_chain.cert[0] =
					cose_x509->COSE_X509_bstr.value;
				parsed_ptxt->auth_cred.x509_chain.cert_len[0] =
					cose_x509->COSE_X509_bstr.len;
				break;

			case COSE_X509_certs_l_c: {
				parsed_ptxt->auth_cred.x509_chain.nr_of_certs =
					cose_x509->COSE_X509_certs_l_certs_count;

				if (ARRAY_SIZE(parsed_ptxt->auth_cred.x509_chain
						       .cert) <
				    cose_x509->COSE_X509_certs_l_certs_count)
					return EDHOC_ERROR_BUFFER_TOO_SMALL;

				for (size_t i = 0;
				     i <
				     cose_x509->COSE_X509_certs_l_certs_count;
				     ++i) {
					parsed_ptxt->auth_cred.x509_chain
						.cert[i] =
						cose_x509
							->COSE_X509_certs_l_certs
								[i]
							.value;
					parsed_ptxt->auth_cred.x509_chain
						.cert_len[i] =
						cose_x509
							->COSE_X509_certs_l_certs
								[i]
							.len;
				}

				break;
			}
			}

			break;
		}

		if (cbor_map->map_x5t_present) {
			parsed_ptxt->auth_cred.label =
				EDHOC_COSE_HEADER_X509_HASH;

			const struct COSE_CertHash *cose_x509 =
				&cbor_map->map_x5t.map_x5t;

			parsed_ptxt->auth_cred.x509_hash.cert_fp =
				cose_x509->COSE_CertHash_hashValue.value;
			parsed_ptxt->auth_cred.x509_hash.cert_fp_len =
				cose_x509->COSE_CertHash_hashValue.len;

			switch (cose_x509->COSE_CertHash_hashAlg_choice) {
			case COSE_CertHash_hashAlg_int_c:
				parsed_ptxt->auth_cred.x509_hash.encode_type =
					EDHOC_ENCODE_TYPE_INTEGER;
				parsed_ptxt->auth_cred.x509_hash.alg_int =
					cose_x509->COSE_CertHash_hashAlg_int;
				break;
			case COSE_CertHash_hashAlg_tstr_c:
				if (ARRAY_SIZE(parsed_ptxt->auth_cred.x509_hash
						       .alg_bstr) <
				    cose_x509->COSE_CertHash_hashAlg_tstr.len)
					return EDHOC_ERROR_BUFFER_TOO_SMALL;

				parsed_ptxt->auth_cred.x509_hash.encode_type =
					EDHOC_ENCODE_TYPE_BYTE_STRING;
				parsed_ptxt->auth_cred.x509_hash
					.alg_bstr_length =
					cose_x509->COSE_CertHash_hashAlg_tstr
						.len;
				memcpy(parsed_ptxt->auth_cred.x509_hash.alg_bstr,
				       cose_x509->COSE_CertHash_hashAlg_tstr
					       .value,
				       cose_x509->COSE_CertHash_hashAlg_tstr
					       .len);
				break;
			default:
				return EDHOC_ERROR_NOT_PERMITTED;
			}

			break;
		}
	}
	}

	/* Sign_or_MAC_3 */
	parsed_ptxt->sign_or_mac =
		cbor_ptxt_3.plaintext_3_Signature_or_MAC_3.value;
	parsed_ptxt->sign_or_mac_len =
		cbor_ptxt_3.plaintext_3_Signature_or_MAC_3.len;

	/* EAD_3 if present */
	if (cbor_ptxt_3.plaintext_3_EAD_3_m_present) {
		ctx->nr_of_ead_tokens =
			cbor_ptxt_3.plaintext_3_EAD_3_m.EAD_3_count;

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			ctx->ead_token[i].label =
				cbor_ptxt_3.plaintext_3_EAD_3_m.EAD_3[i]
					.ead_y_ead_label;
			ctx->ead_token[i].value =
				cbor_ptxt_3.plaintext_3_EAD_3_m.EAD_3[i]
					.ead_y_ead_value.value;
			ctx->ead_token[i].value_len =
				cbor_ptxt_3.plaintext_3_EAD_3_m.EAD_3[i]
					.ead_y_ead_value.len;
		}
	}

	return EDHOC_SUCCESS;
}

static int comp_salt_4e3m(const struct edhoc_context *ctx, uint8_t *salt,
			  size_t salt_len)
{
	if (NULL == ctx || NULL == salt || 0 == salt_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_3 != ctx->th_state ||
	    EDHOC_PRK_STATE_3E2M != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	const size_t hash_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

	const struct info input_info = {
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_SALT_4E3M,
		.info_context.value = ctx->th,
		.info_context.len = ctx->th_len,
		.info_length = (uint32_t)hash_len,
	};

	size_t len = 0;
	len += edhoc_cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_SALT_4E3M);
	len += ctx->th_len + edhoc_cbor_bstr_oh(ctx->th_len);
	len += edhoc_cbor_int_mem_req((int32_t)hash_len);

	VLA_ALLOC(uint8_t, info, len);
	memset(info, 0, VLA_SIZEOF(info));

	len = 0;
	ret = cbor_encode_info(info, VLA_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret || VLA_SIZE(info) != len)
		return EDHOC_ERROR_CBOR_FAILURE;

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_EXPAND, ctx->prk,
				   ctx->prk_len, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.expand(ctx->user_ctx, key_id, info, VLA_SIZE(info),
				 salt, salt_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int comp_giy(struct edhoc_context *ctx,
		    const struct edhoc_auth_creds *auth_cred,
		    const uint8_t *pub_key, size_t pub_key_len, uint8_t *giy,
		    size_t giy_len)
{
	if (NULL == ctx || NULL == auth_cred || NULL == giy || 0 == giy_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	switch (ctx->role) {
	case EDHOC_INITIATOR: {
		size_t secret_len = 0;
		ret = ctx->crypto.key_agreement(ctx->user_ctx,
						auth_cred->priv_key_id,
						ctx->dh_peer_pub_key,
						ctx->dh_peer_pub_key_len, giy,
						giy_len, &secret_len);

		if (EDHOC_SUCCESS != ret || secret_len != giy_len)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		return EDHOC_SUCCESS;
	}

	case EDHOC_RESPONDER: {
		uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
		ret = ctx->keys.import_key(ctx->user_ctx,
					   EDHOC_KT_KEY_AGREEMENT,
					   ctx->dh_priv_key,
					   ctx->dh_priv_key_len, key_id);
		ctx->dh_priv_key_len = 0;
		memset(ctx->dh_priv_key, 0, ARRAY_SIZE(ctx->dh_priv_key));

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		size_t secret_len = 0;
		ret = ctx->crypto.key_agreement(ctx->user_ctx, key_id, pub_key,
						pub_key_len, giy, giy_len,
						&secret_len);

		ctx->keys.destroy_key(ctx->user_ctx, key_id);
		memset(key_id, 0, sizeof(key_id));

		if (EDHOC_SUCCESS != ret || secret_len != giy_len)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		return EDHOC_SUCCESS;
	}

	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
}

/* Module interface function definitions ----------------------------------- */

/**
 * Steps for composition of message 3:
 *      1.  Choose most preferred cipher suite.
 *      2.  Compose EAD_3 if present.
 *      3.  Fetch authentication credentials.
 *      4.  Compute K_3, IV_3 and AAD_3.
 *      5.  Compute PRK_4e3m.
 *      6a. Compute required buffer length for context_3.
 *      6b. Cborise items required by context_3.
 *      6c. Compute Message Authentication Code (MAC_3).
 *      7.  Compute signature if needed (Signature_or_MAC_3).
 *      8.  Prepare plaintext (PLAINTEXT_3).
 *      9.  Compute ciphertext.
 *      10. Compute transcript hash 4.
 *      11. Generate edhoc message 3.
 *      12. Clean-up EAD tokens.
 */
int edhoc_message_3_compose(struct edhoc_context *ctx, uint8_t *msg_3,
			    size_t msg_3_size, size_t *msg_3_len)
{
	if (NULL == ctx || NULL == msg_3 || 0 == msg_3_size ||
	    NULL == msg_3_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_SM_VERIFIED_M2 != ctx->status ||
	    EDHOC_TH_STATE_3 != ctx->th_state ||
	    EDHOC_PRK_STATE_3E2M != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_3;
	ctx->role = EDHOC_INITIATOR;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* 2. Compose EAD_3 if present. */
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
					    "EAD_3 compose label",
					    (const uint8_t *)&ctx->ead_token[i]
						    .label,
					    sizeof(ctx->ead_token[i].label));

				if (0 != ctx->ead_token[i].value_len)
					ctx->logger(
						ctx->user_ctx,
						"EAD_3 compose value",
						ctx->ead_token[i].value,
						ctx->ead_token[i].value_len);
			}
		}
	}

	/* 3. Fetch authentication credentials. */
	struct edhoc_auth_creds auth_creds = { 0 };
	ret = ctx->cred.fetch(ctx->user_ctx, &auth_creds);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/* 4. Compute K_3, IV_3 and AAD_3. */
	VLA_ALLOC(uint8_t, key, csuite.aead_key_length);
	memset(key, 0, VLA_SIZEOF(key));

	VLA_ALLOC(uint8_t, iv, csuite.aead_iv_length);
	memset(iv, 0, VLA_SIZEOF(iv));

	size_t aad_len = 0;
	ret = comp_aad_3_len(ctx, &aad_len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	VLA_ALLOC(uint8_t, aad, aad_len);
	memset(aad, 0, VLA_SIZEOF(aad));

	ret = comp_key_iv_aad(ctx, key, VLA_SIZE(key), iv, VLA_SIZE(iv), aad,
			      VLA_SIZE(aad));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger) {
		ctx->logger(ctx->user_ctx, "K_3", key, VLA_SIZE(key));
		ctx->logger(ctx->user_ctx, "IV_3", iv, VLA_SIZE(iv));
		ctx->logger(ctx->user_ctx, "AAD_3", aad, VLA_SIZE(aad));
	}

	/* 5. Compute PRK_4e3m. */
	ret = comp_prk_4e3m(ctx, &auth_creds, NULL, 0);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_4e3m", ctx->prk, ctx->prk_len);

	size_t mac_context_length = 0;
	ret = edhoc_comp_mac_context_length(ctx, &auth_creds,
					    &mac_context_length);

	if (EDHOC_SUCCESS != ret)
		return ret;

	/* 6b. Cborise items required by context_3. */
	VLA_ALLOC(uint8_t, mac_3_context_buf,
		  sizeof(struct mac_context) + mac_context_length);
	memset(mac_3_context_buf, 0, VLA_SIZEOF(mac_3_context_buf));

	struct mac_context *mac_context = (void *)mac_3_context_buf;
	mac_context->buf_len = mac_context_length;

	ret = edhoc_comp_mac_context(ctx, &auth_creds, mac_context);
	if (EDHOC_SUCCESS != ret)
		return ret;

	if (NULL != ctx->logger) {
		ctx->logger(ctx->user_ctx, "ID_CRED_I", mac_context->id_cred,
			    mac_context->id_cred_len);
		ctx->logger(ctx->user_ctx, "TH_3", mac_context->th,
			    mac_context->th_len);
		ctx->logger(ctx->user_ctx, "CRED_I", mac_context->cred,
			    mac_context->cred_len);
		ctx->logger(ctx->user_ctx, "context_3", mac_context->buf,
			    mac_context->buf_len);
	}

	/* 6c. Compute Message Authentication Code (MAC_3). */
	size_t mac_length = 0;
	ret = edhoc_comp_mac_length(ctx, &mac_length);
	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_3;

	VLA_ALLOC(uint8_t, mac_buf, mac_length);
	memset(mac_buf, 0, VLA_SIZEOF(mac_buf));
	ret = edhoc_comp_mac(ctx, mac_context, mac_buf, mac_length);
	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_3;

	/* 7. Compute signature if needed (Signature_or_MAC_3). */
	size_t sign_or_mac_length = 0;
	ret = edhoc_comp_sign_or_mac_length(ctx, &sign_or_mac_length);
	if (EDHOC_SUCCESS != ret)
		return ret;

	size_t signature_length = 0;
	VLA_ALLOC(uint8_t, signature, sign_or_mac_length);
	memset(signature, 0, VLA_SIZEOF(signature));
	ret = edhoc_comp_sign_or_mac(ctx, &auth_creds, mac_context, mac_buf,
				     mac_length, signature, VLA_SIZE(signature),
				     &signature_length);
	if (EDHOC_SUCCESS != ret)
		return ret;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "Signature_or_MAC_3", signature,
			    signature_length);

	/* 8. Prepare plaintext (PLAINTEXT_3). */
	size_t plaintext_len = 0;
	ret = comp_plaintext_3_len(ctx, mac_context, signature_length,
				   &plaintext_len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	VLA_ALLOC(uint8_t, plaintext, plaintext_len);
	memset(plaintext, 0, VLA_SIZEOF(plaintext));

	plaintext_len = 0;
	ret = prepare_plaintext_3(mac_context, signature, signature_length,
				  plaintext, VLA_SIZE(plaintext),
				  &plaintext_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PLAINTEXT_3", plaintext,
			    plaintext_len);

	/* 9. Compute ciphertext. */
	size_t ciphertext_len = 0;
	VLA_ALLOC(uint8_t, ciphertext, plaintext_len + csuite.aead_tag_length);
	memset(ciphertext, 0, VLA_SIZEOF(ciphertext));

	ret = comp_ciphertext(ctx, key, VLA_SIZE(key), iv, VLA_SIZE(iv), aad,
			      VLA_SIZE(aad), plaintext, plaintext_len,
			      ciphertext, VLA_SIZE(ciphertext),
			      &ciphertext_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "CIPHERTEXT_3", ciphertext,
			    ciphertext_len);

	/* 10. Compute transcript hash 4. */
	ret = comp_th_4(ctx, mac_context, plaintext, plaintext_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_4", ctx->th, ctx->th_len);

	/* 11. Generate edhoc message 3. */
	ret = gen_msg_3(ciphertext, ciphertext_len, msg_3, msg_3_size,
			msg_3_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "message_3", msg_3, *msg_3_len);

	/* 12. Clean-up EAD tokens. */
	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->is_oscore_export_allowed = true;
	ctx->status = EDHOC_SM_COMPLETED;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}

/**
 * Steps for processing of message 3:
 *      1.  Choose most preferred cipher suite.
 *      2.  CBOR decode message 3.
 *      3.  Compute K_3, IV_3 and AAD_3.
 *      4.  Decrypt ciphertext.
 *      5.  Parse CBOR plaintext (PLAINTEXT_3).
 *      6.  Process EAD_3 if present.
 *      7.  Verify if credentials from peer are trusted.
 *      8.  Compute PRK_4e3m.
 *      9a. Compute required buffer length for context_3.
 *      9b. Cborise items required by context_3.
 *      9c. Compute Message Authentication Code (MAC_3).
 *      10. Verify Signature_or_MAC_3.
 *      11. Compute transcript hash 4.
 *      12. Clean-up EAD tokens.
 */
int edhoc_message_3_process(struct edhoc_context *ctx, const uint8_t *msg_3,
			    size_t msg_3_len)
{
	if (NULL == ctx || NULL == msg_3 || 0 == msg_3_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_SM_WAIT_M3 != ctx->status ||
	    EDHOC_TH_STATE_3 != ctx->th_state ||
	    EDHOC_PRK_STATE_3E2M != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_3;
	ctx->role = EDHOC_RESPONDER;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* 2. CBOR decode message 3. */
	const uint8_t *ctxt = NULL;
	size_t ctxt_len = 0;

	ret = parse_msg_3(msg_3, msg_3_len, &ctxt, &ctxt_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_MSG_3_PROCESS_FAILURE;

	/* 3. Compute K_3, IV_3 and AAD_3. */
	VLA_ALLOC(uint8_t, key, csuite.aead_key_length);
	memset(key, 0, VLA_SIZEOF(key));

	VLA_ALLOC(uint8_t, iv, csuite.aead_iv_length);
	memset(iv, 0, VLA_SIZEOF(iv));

	size_t aad_len = 0;
	ret = comp_aad_3_len(ctx, &aad_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	VLA_ALLOC(uint8_t, aad, aad_len);
	memset(aad, 0, VLA_SIZEOF(aad));

	ret = comp_key_iv_aad(ctx, key, VLA_SIZE(key), iv, VLA_SIZE(iv), aad,
			      VLA_SIZE(aad));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger) {
		ctx->logger(ctx->user_ctx, "K_3", key, VLA_SIZE(key));
		ctx->logger(ctx->user_ctx, "IV_3", iv, VLA_SIZE(iv));
		ctx->logger(ctx->user_ctx, "AAD_3", aad, VLA_SIZE(aad));
	}

	/* 4. Decrypt ciphertext. */
	VLA_ALLOC(uint8_t, ptxt, ctxt_len - csuite.aead_tag_length);
	memset(ptxt, 0, VLA_SIZEOF(ptxt));

	ret = decrypt_ciphertext(ctx, key, VLA_SIZE(key), iv, VLA_SIZE(iv), aad,
				 VLA_SIZE(aad), ctxt, ctxt_len, ptxt,
				 VLA_SIZE(ptxt));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PLAINTEXT_3", ptxt, VLA_SIZE(ptxt));

	/* 5. Parse CBOR plaintext (PLAINTEXT_3). */
	struct plaintext parsed_ptxt = { 0 };
	ret = parse_plaintext(ctx, ptxt, VLA_SIZE(ptxt), &parsed_ptxt);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	/* 6. Process EAD_3 if present. */
	if (NULL != ctx->ead.process && 0 != ARRAY_SIZE(ctx->ead_token) - 1 &&
	    0 != ctx->nr_of_ead_tokens) {
		ret = ctx->ead.process(ctx->user_ctx, ctx->message,
				       ctx->ead_token, ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;

		if (NULL != ctx->logger) {
			for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
				ctx->logger(ctx->user_ctx,
					    "EAD_3 process label",
					    (const uint8_t *)&ctx->ead_token[i]
						    .label,
					    sizeof(ctx->ead_token[i].label));

				if (0 != ctx->ead_token[i].value_len)
					ctx->logger(
						ctx->user_ctx,
						"EAD_3 process value",
						ctx->ead_token[i].value,
						ctx->ead_token[i].value_len);
			}
		}
	}

	/* 7. Verify if credentials from peer are trusted. */
	const uint8_t *pub_key = NULL;
	size_t pub_key_len = 0;
	ret = ctx->cred.verify(ctx->user_ctx, &parsed_ptxt.auth_cred, &pub_key,
			       &pub_key_len);

	if (EDHOC_SUCCESS != ret) {
		ctx->error_code =
			EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	/* 8. Compute PRK_4e3m. */
	ret = comp_prk_4e3m(ctx, &parsed_ptxt.auth_cred, pub_key, pub_key_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	/* 9a. Compute required buffer length for context_3. */
	size_t mac_context_len = 0;
	ret = edhoc_comp_mac_context_length(ctx, &parsed_ptxt.auth_cred,
					    &mac_context_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_3;

	/* 9b. Cborise items required by context_3. */
	VLA_ALLOC(uint8_t, mac_3_context_buf,
		  sizeof(struct mac_context) + mac_context_len);
	memset(mac_3_context_buf, 0, VLA_SIZEOF(mac_3_context_buf));

	struct mac_context *mac_context = (void *)mac_3_context_buf;
	mac_context->buf_len = mac_context_len;

	ret = edhoc_comp_mac_context(ctx, &parsed_ptxt.auth_cred, mac_context);
	if (EDHOC_SUCCESS != ret)
		return ret;

	if (NULL != ctx->logger) {
		ctx->logger(ctx->user_ctx, "C_I", mac_context->conn_id,
			    mac_context->conn_id_len);
		ctx->logger(ctx->user_ctx, "ID_CRED_I", mac_context->id_cred,
			    mac_context->id_cred_len);
		ctx->logger(ctx->user_ctx, "TH_3", mac_context->th,
			    mac_context->th_len);
		ctx->logger(ctx->user_ctx, "CRED_I", mac_context->cred,
			    mac_context->cred_len);
		ctx->logger(ctx->user_ctx, "context_3", mac_context->buf,
			    mac_context->buf_len);
	}

	/* 9c. Compute Message Authentication Code (MAC_3). */
	size_t mac_length = 0;
	ret = edhoc_comp_mac_length(ctx, &mac_length);
	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_3;

	VLA_ALLOC(uint8_t, mac_buf, mac_length);
	memset(mac_buf, 0, VLA_SIZEOF(mac_buf));
	ret = edhoc_comp_mac(ctx, mac_context, mac_buf, mac_length);
	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_3;

	/* 10. Verify Signature_or_MAC_3. */
	ret = edhoc_verify_sign_or_mac(ctx, mac_context, pub_key, pub_key_len,
				       parsed_ptxt.sign_or_mac,
				       parsed_ptxt.sign_or_mac_len, mac_buf,
				       mac_length);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_SIGN_OR_MAC_2;

	/* 11. Compute transcript hash 4. */
	ret = comp_th_4(ctx, mac_context, ptxt, VLA_SIZE(ptxt));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	/* 12. Clean-up EAD tokens. */
	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->is_oscore_export_allowed = true;
	ctx->status = EDHOC_SM_COMPLETED;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}
