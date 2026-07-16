/**
 * \file    edhoc_message_3.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message 3 compose & process.
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
 * \brief Compute pseudorandom key (PRK_4e3m).
 *
 * \param[in,out] ctx		EDHOC context.
 * \param[in] auth_cred         Authentication credentials.
 * \param[in] pub_key           Peer public static DH key. 
 * \param pub_key_len           Size of the \p pub_key buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_prk_4e3m(struct edhoc_context *ctx,
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
STATIC int comp_plaintext_3_len(const struct edhoc_context *ctx,
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
STATIC int prepare_plaintext_3(const struct mac_context *mac_ctx,
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
STATIC int comp_aad_3_len(const struct edhoc_context *ctx, size_t *aad_3_len);

/**
 * \brief Compute K_3 (AEAD key handle), IV_3 and AAD_3.
 *
 * \param[in,out] ctx	        EDHOC context.
 * \param[out] iv	        Buffer where the generated IV_3 is to be written.
 * \param iv_len                Size of the \p iv buffer in bytes.
 * \param[out] aad	        Buffer where the generated AAD_3 is to be written.
 * \param aad_len               Size of the \p aad buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_key_iv_aad_3(struct edhoc_context *ctx, uint8_t *iv,
			     size_t iv_len, uint8_t *aad, size_t aad_len);

/**
 * \brief Compute CIPHERTEXT_3.
 *
 * \param[in] ctx	        EDHOC context.
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
STATIC int comp_ciphertext(const struct edhoc_context *ctx, const uint8_t *iv,
			   size_t iv_len, const uint8_t *aad, size_t aad_len,
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
STATIC int comp_th_4(struct edhoc_context *ctx,
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
STATIC int gen_msg_3(const uint8_t *ctxt, size_t ctxt_len, uint8_t *msg_3,
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
STATIC int parse_msg_3(const uint8_t *msg_3, size_t msg_3_len,
		       const uint8_t **ctxt_3, size_t *ctxt_3_len);

/**
 * \brief Decrypt CIPHERTEXT_3.
 *
 * \param[in] ctx		EDHOC context.
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
STATIC int decrypt_ciphertext_3(const struct edhoc_context *ctx,
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
STATIC int parse_plaintext_3(struct edhoc_context *ctx, const uint8_t *ptxt,
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
STATIC int comp_salt_4e3m(const struct edhoc_context *ctx, uint8_t *salt,
			  size_t salt_len);

/**
 * \brief Compute G_IY for PRK_4e3m into the G_IY key slot.
 * 
 * \param[in,out] ctx           EDHOC context.
 * \param[in] auth_cred         Authentication credentials.
 * \param[in] pub_key           Peer public key.
 * \param pub_key_len           Peer public key length.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_giy(struct edhoc_context *ctx,
		    const struct edhoc_auth_creds *auth_cred,
		    const uint8_t *pub_key, size_t pub_key_len);

/* Static function definitions --------------------------------------------- */

STATIC int comp_prk_4e3m(struct edhoc_context *ctx,
			 const struct edhoc_auth_creds *auth_cred,
			 const uint8_t *pub_key, size_t pub_key_len)
{
	if (NULL == ctx || NULL == auth_cred) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_PRK_STATE_3E2M != ctx->prk_state) {
		EDHOC_LOG_ERR("Bad PRK state: %d", ctx->prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	switch (ctx->chosen_method) {
	case EDHOC_METHOD_0:
	case EDHOC_METHOD_1:
		/* PRK_4e3m == PRK_3e2m: move PRK_3e2m's slot into PRK_4e3m so
		 * the key is owned by a single handle that lives on for PRK_out
		 * (and message 4). */
		edhoc_key_slot_move(ctx, EDHOC_KEY_SLOT_PRK_4E3M,
				    EDHOC_KEY_SLOT_PRK_3E2M);
		ctx->prk_state = EDHOC_PRK_STATE_4E3M;
		return EDHOC_SUCCESS;

	case EDHOC_METHOD_2:
	case EDHOC_METHOD_3: {
		const size_t hash_len =
			ctx->csuite[ctx->chosen_csuite_idx].hash_length;

		EDHOC_MEM_ALLOC(uint8_t, salt_4e3m, hash_len);
		if (NULL == salt_4e3m) {
			EDHOC_LOG_ERR("Memory allocation failed");
			return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
		}

		int ret = comp_salt_4e3m(ctx, salt_4e3m,
					 EDHOC_MEM_ALLOC_SIZE(salt_4e3m));

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Compute SALT_4e3m: %d", ret);
			EDHOC_MEM_FREE(salt_4e3m);
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		EDHOC_LOG_HEXDUMP_DBG(salt_4e3m,
				      EDHOC_MEM_ALLOC_SIZE(salt_4e3m),
				      "SALT_4e3m");

		/* G_IY is a static-DH shared secret produced into its context
		 * slot; it is the IKM for EDHOC_Extract and is released with the
		 * other message 3 secrets (or by deinit on an error path). */
		ret = comp_giy(ctx, auth_cred, pub_key, pub_key_len);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Compute G_IY: %d", ret);
			EDHOC_MEM_FREE(salt_4e3m);
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		/* EDHOC_Extract(salt = SALT_4e3m, IKM = G_IY) -> PRK_4e3m in its
		 * own dedicated handle. SALT_4e3m is spent afterwards. */
		ret = ctx->itf.crypto.extract(
			ctx->user_ctx,
			edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_G_IY), salt_4e3m,
			EDHOC_MEM_ALLOC_SIZE(salt_4e3m),
			edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_4E3M));

		ctx->itf.platform.zeroize(salt_4e3m,
					  EDHOC_MEM_ALLOC_SIZE(salt_4e3m));
		EDHOC_MEM_FREE(salt_4e3m);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Extract PRK_4e3m: %d", ret);
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		edhoc_key_slot_mark_present(ctx, EDHOC_KEY_SLOT_PRK_4E3M);
		ctx->prk_state = EDHOC_PRK_STATE_4E3M;
		return EDHOC_SUCCESS;
	}
	case EDHOC_METHOD_MAX:
		EDHOC_LOG_ERR("Invalid method");
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	EDHOC_LOG_ERR("Unsupported method: %d", ctx->chosen_method);
	return EDHOC_ERROR_NOT_PERMITTED;
}

STATIC int comp_plaintext_3_len(const struct edhoc_context *ctx,
				const struct mac_context *mac_ctx,
				size_t sign_len, size_t *plaintext_3_len)
{
	if (NULL == ctx || NULL == mac_ctx || 0 == sign_len ||
	    NULL == plaintext_3_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

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

STATIC int prepare_plaintext_3(const struct mac_context *mac_ctx,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt, size_t ptxt_size,
			       size_t *ptxt_len)
{
	if (NULL == mac_ctx || NULL == sign || 0 == sign_len || NULL == ptxt ||
	    0 == ptxt_size || NULL == ptxt_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

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
			EDHOC_LOG_ERR("Invalid ID_CRED_I enc type: %d",
				      mac_ctx->id_cred_enc_type);
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

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc Signature_or_MAC_3: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	offset += len;

	/* EAD_3 if present. */
	if (mac_ctx->is_ead) {
		memcpy(&ptxt[offset], mac_ctx->ead, mac_ctx->ead_len);
		offset += mac_ctx->ead_len;
	}

	if (offset > ptxt_size) {
		EDHOC_LOG_ERR("Buffer too small for plaintext_3: %zu, %zu",
			      offset, ptxt_size);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	*ptxt_len = offset;

	return EDHOC_SUCCESS;
}

STATIC int comp_aad_3_len(const struct edhoc_context *ctx, size_t *aad_3_len)
{
	if (NULL == ctx || NULL == aad_3_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	size_t len = 0;

	len += sizeof("Encrypt0") + edhoc_cbor_tstr_oh(sizeof("Encrypt0"));
	len += 1; /* One byte for cbor bstr with 0 value. */
	len += ctx->th_len + edhoc_cbor_bstr_oh(ctx->th_len);

	*aad_3_len = len;
	return EDHOC_SUCCESS;
}

STATIC int comp_key_iv_aad_3(struct edhoc_context *ctx, uint8_t *iv,
			     size_t iv_len, uint8_t *aad, size_t aad_len)
{
	if (NULL == ctx || NULL == iv || 0 == iv_len || NULL == aad ||
	    0 == aad_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_3 != ctx->th_state) {
		EDHOC_LOG_ERR("Invalid TH state: %d, %d", ctx->th_state,
			      EDHOC_TH_STATE_3);
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

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

	/* Generate K_3 as an AEAD key handle (its own context slot). */
	input_info = (struct info){
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_K_3,
		.info_context.value = ctx->th,
		.info_context.len = ctx->th_len,
		.info_length = (uint32_t)csuite.aead_key_length,
	};

	len = 0;
	ret = cbor_encode_info(info, EDHOC_MEM_ALLOC_SIZE(info), &input_info,
			       &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR encode info for K_3: %d", ret);
		EDHOC_MEM_FREE(info);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* EDHOC_Expand(PRK_3e2m, info) -> K_3 (AEAD key handle). */
	ret = ctx->itf.crypto.expand(
		ctx->user_ctx, edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_3E2M),
		info, len, EDHOC_KEY_USAGE_AEAD,
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_K_3));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Expand K_3: %d", ret);
		EDHOC_MEM_FREE(info);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	edhoc_key_slot_mark_present(ctx, EDHOC_KEY_SLOT_K_3);

	/* Generate IV_3 (raw). */
	input_info = (struct info){
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_IV_3,
		.info_context.value = ctx->th,
		.info_context.len = ctx->th_len,
		.info_length = (uint32_t)csuite.aead_iv_length,
	};

	memset(info, 0, EDHOC_MEM_ALLOC_SIZEOF(info));
	len = 0;
	ret = cbor_encode_info(info, EDHOC_MEM_ALLOC_SIZE(info), &input_info,
			       &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc info for IV_3: %d", ret);
		EDHOC_MEM_FREE(info);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* EDHOC_Expand(PRK_3e2m, info) -> IV_3 (raw). */
	ret = ctx->itf.crypto.expand_raw(
		ctx->user_ctx, edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_3E2M),
		info, len, iv, iv_len);
	EDHOC_MEM_FREE(info);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Expand IV_3: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* Generate AAD_3. */
	struct enc_structure cose_enc_0 = {
		.enc_structure_protected.value = NULL,
		.enc_structure_protected.len = 0,
		.enc_structure_external_aad.value = ctx->th,
		.enc_structure_external_aad.len = ctx->th_len,
	};

	len = 0;
	ret = cbor_encode_enc_structure(aad, aad_len, &cose_enc_0, &len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc AAD_3: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int comp_ciphertext(const struct edhoc_context *ctx, const uint8_t *iv,
			   size_t iv_len, const uint8_t *aad, size_t aad_len,
			   const uint8_t *ptxt, size_t ptxt_len, uint8_t *ctxt,
			   size_t ctxt_size, size_t *ctxt_len)
{
	if (NULL == ctx || NULL == iv || 0 == iv_len || NULL == aad ||
	    0 == aad_len || NULL == ptxt || 0 == ptxt_len || NULL == ctxt ||
	    0 == ctxt_size || NULL == ctxt_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* AEAD-encrypt PLAINTEXT_3 under K_3 (its context slot handle), with
	 * IV_3 as the nonce and AAD_3 as associated data. */
	const int ret = ctx->itf.crypto.aead_encrypt(
		ctx->user_ctx, edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_K_3), iv,
		iv_len, aad, aad_len, ptxt, ptxt_len, ctxt, ctxt_size,
		ctxt_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Encrypt ciphertext_3: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int comp_th_4(struct edhoc_context *ctx,
		     const struct mac_context *mac_ctx, const uint8_t *ptxt,
		     size_t ptxt_len)
{
	if (NULL == ctx || NULL == mac_ctx || NULL == ptxt || 0 == ptxt_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_3 != ctx->th_state) {
		EDHOC_LOG_ERR("Invalid TH state: %d", ctx->th_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	/* TH_4 = H(TH_3, PLAINTEXT_3, CRED_I) streamed as:
	 * bstr(TH_3) || PLAINTEXT_3 || CRED_I. ctx->th holds TH_3 on input and
	 * receives TH_4 on output; the multipart update consumes it before
	 * hash_finish overwrites it. */
	const size_t th_3_len = ctx->th_len;

	uint8_t th_3_hdr[EDHOC_CBOR_BSTR_HEADER_MAX_LEN] = { 0 };

	const struct hash_segment segments[] = {
		{ th_3_hdr, edhoc_cbor_bstr_header(th_3_hdr, th_3_len) },
		{ ctx->th, th_3_len },
		{ ptxt, ptxt_len },
		{ mac_ctx->cred, mac_ctx->cred_len },
	};

	ctx->th_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

	size_t hash_len = 0;
	const int ret = edhoc_comp_hash(ctx, segments, ARRAY_SIZE(segments),
					ctx->th, ctx->th_len, &hash_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Hash TH_4: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ctx->th_state = EDHOC_TH_STATE_4;
	return EDHOC_SUCCESS;
}

STATIC int gen_msg_3(const uint8_t *ctxt, size_t ctxt_len, uint8_t *msg_3,
		     size_t msg_3_size, size_t *msg_3_len)
{
	if (NULL == ctxt || 0 == ctxt_len || NULL == msg_3 || 0 == msg_3_size ||
	    NULL == msg_3_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct zcbor_string input_bstr = {
		.value = ctxt,
		.len = ctxt_len,
	};

	ret = cbor_encode_message_3_CIPHERTEXT_3(msg_3, msg_3_size + 1,
						 &input_bstr, msg_3_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc msg3: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int parse_msg_3(const uint8_t *msg_3, size_t msg_3_len,
		       const uint8_t **ctxt_3, size_t *ctxt_3_len)
{
	if (NULL == msg_3 || 0 == msg_3_len || NULL == ctxt_3 ||
	    NULL == ctxt_3_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t len = 0;
	struct zcbor_string dec_msg_3 = { 0 };
	ret = cbor_decode_message_3_CIPHERTEXT_3(msg_3, msg_3_len, &dec_msg_3,
						 &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR dec msg3: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	*ctxt_3 = dec_msg_3.value;
	*ctxt_3_len = dec_msg_3.len;

	return EDHOC_SUCCESS;
}

STATIC int decrypt_ciphertext_3(const struct edhoc_context *ctx,
				const uint8_t *iv, size_t iv_len,
				const uint8_t *aad, size_t aad_len,
				const uint8_t *ctxt, size_t ctxt_len,
				uint8_t *ptxt, size_t ptxt_len)
{
	if (NULL == ctx || NULL == iv || 0 == iv_len || NULL == aad ||
	    0 == aad_len || 0 == ctxt_len || NULL == ptxt || 0 == ptxt_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* AEAD-decrypt CIPHERTEXT_3 under K_3 (its context slot handle), with
	 * IV_3 as the nonce and AAD_3 as associated data. */
	size_t len = 0;
	const int ret = ctx->itf.crypto.aead_decrypt(
		ctx->user_ctx, edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_K_3), iv,
		iv_len, aad, aad_len, ctxt, ctxt_len, ptxt, ptxt_len, &len);

	if (EDHOC_SUCCESS != ret || ptxt_len != len) {
		EDHOC_LOG_ERR("Decrypt ciphertext_3: %d, %zu, %zu", ret,
			      ptxt_len, len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int parse_plaintext_3(struct edhoc_context *ctx, const uint8_t *ptxt,
			     size_t ptxt_len, struct plaintext *parsed_ptxt)
{
	if (NULL == ctx || NULL == ptxt || 0 == ptxt_len ||
	    NULL == parsed_ptxt) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct plaintext_3 cbor_ptxt_3 = { 0 };
	ret = cbor_decode_plaintext_3(ptxt, ptxt_len, &cbor_ptxt_3, &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR dec plaintext_3: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

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
				    cose_x509->COSE_X509_certs_l_certs_count) {
					EDHOC_LOG_ERR(
						"X.509 certificate chain too large: %zu",
						cose_x509
							->COSE_X509_certs_l_certs_count);
					return EDHOC_ERROR_BUFFER_TOO_SMALL;
				}

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
				    cose_x509->COSE_CertHash_hashAlg_tstr.len) {
					EDHOC_LOG_ERR(
						"X.509 hash algorithm string too large: %zu",
						cose_x509
							->COSE_CertHash_hashAlg_tstr
							.len);
					return EDHOC_ERROR_BUFFER_TOO_SMALL;
				}

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
				EDHOC_LOG_ERR(
					"Invalid COSE_CertHash_hashAlg choice: %d",
					cose_x509->COSE_CertHash_hashAlg_choice);
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

STATIC int comp_salt_4e3m(const struct edhoc_context *ctx, uint8_t *salt,
			  size_t salt_len)
{
	if (NULL == ctx || NULL == salt || 0 == salt_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_3 != ctx->th_state ||
	    EDHOC_PRK_STATE_3E2M != ctx->prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d", ctx->th_state,
			      ctx->prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

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

	EDHOC_MEM_ALLOC(uint8_t, info, len);
	if (NULL == info) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	len = 0;
	ret = cbor_encode_info(info, EDHOC_MEM_ALLOC_SIZE(info), &input_info,
			       &len);

	if (ZCBOR_SUCCESS != ret || EDHOC_MEM_ALLOC_SIZE(info) != len) {
		EDHOC_LOG_ERR("CBOR enc info for salt_4e3m: %d, %zu, %zu", ret,
			      EDHOC_MEM_ALLOC_SIZE(info), len);
		EDHOC_MEM_FREE(info);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* EDHOC_Expand(PRK_3e2m, info) -> SALT_4e3m (raw). */
	ret = ctx->itf.crypto.expand_raw(
		ctx->user_ctx, edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_3E2M),
		info, EDHOC_MEM_ALLOC_SIZE(info), salt, salt_len);
	EDHOC_MEM_FREE(info);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Expand salt_4e3m: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int comp_giy(struct edhoc_context *ctx,
		    const struct edhoc_auth_creds *auth_cred,
		    const uint8_t *pub_key, size_t pub_key_len)
{
	if (NULL == ctx || NULL == auth_cred) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	void *giy_key_id = edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_G_IY);
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	switch (ctx->role) {
	case EDHOC_INITIATOR:
		/* G_IY = key_agreement(I's static private key, R's ephemeral
		 * public key G_Y). The shared secret is produced as a handle. */
		ret = ctx->itf.crypto.key_agreement(ctx->user_ctx,
						    auth_cred->priv_key_id,
						    ctx->peer_pub_eph_key,
						    ctx->peer_pub_eph_key_len,
						    giy_key_id);
		break;

	case EDHOC_RESPONDER:
		/* G_IY = key_agreement(R's ephemeral private key, I's static
		 * public key). The Responder's ephemeral private key was
		 * retained by the KEM encapsulation in message 2. */
		ret = ctx->itf.crypto.key_agreement(
			ctx->user_ctx,
			edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_EPHEMERAL),
			pub_key, pub_key_len, giy_key_id);
		break;

	default:
		EDHOC_LOG_ERR("Invalid role: %d", ctx->role);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Key agreement for G_IY: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	edhoc_key_slot_mark_present(ctx, EDHOC_KEY_SLOT_G_IY);
	return EDHOC_SUCCESS;
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
 *      12. Release the message-3 scoped secrets (PRK_4e3m lives on).
 *      13. Clean-up EAD tokens.
 */
int edhoc_message_3_compose(struct edhoc_context *ctx, uint8_t *msg_3,
			    size_t msg_3_size, size_t *msg_3_len)
{
	EDHOC_LOG_INF("Compose msg3 start");

	if (NULL == ctx || NULL == msg_3 || 0 == msg_3_size ||
	    NULL == msg_3_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_context_configured(ctx)) {
		EDHOC_LOG_ERR("Context not fully configured");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_SM_VERIFIED_M2 != ctx->status ||
	    EDHOC_TH_STATE_3 != ctx->th_state ||
	    EDHOC_PRK_STATE_3E2M != ctx->prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d, %d", ctx->status,
			      ctx->th_state, ctx->prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_3;
	ctx->role = EDHOC_INITIATOR;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* 2. Compose EAD_3 if present. */
	if (NULL != ctx->itf.ead.compose &&
	    0 != ARRAY_SIZE(ctx->ead_token) - 1) {
		ret = ctx->itf.ead.compose(ctx->user_ctx, ctx->message,
					   ctx->ead_token,
					   ARRAY_SIZE(ctx->ead_token) - 1,
					   &ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret ||
		    ARRAY_SIZE(ctx->ead_token) - 1 < ctx->nr_of_ead_tokens) {
			EDHOC_LOG_ERR("Compose EAD_3: %d, %zu, %zu", ret,
				      ARRAY_SIZE(ctx->ead_token) - 1,
				      ctx->nr_of_ead_tokens);
			return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
		}

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			EDHOC_LOG_HEXDUMP_DBG(
				(const uint8_t *)&ctx->ead_token[i].label,
				sizeof(ctx->ead_token[i].label),
				"EAD_3 token label:");

			if (0 != ctx->ead_token[i].value_len) {
				EDHOC_LOG_HEXDUMP_DBG(
					ctx->ead_token[i].value,
					ctx->ead_token[i].value_len,
					"EAD_3 token value:");
			}
		}
	}

	/* 3. Fetch authentication credentials. */
	struct edhoc_auth_creds auth_creds = { 0 };
	ret = ctx->itf.cred.fetch(ctx->user_ctx, &auth_creds);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Fetch credentials: %d", ret);
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	/* 4. Compute IV_3 and AAD_3 (K_3 is produced into its context slot). */
	EDHOC_MEM_ALLOC(uint8_t, iv, csuite.aead_iv_length);
	if (NULL == iv) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	size_t aad_len = 0;
	ret = comp_aad_3_len(ctx, &aad_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute AAD_3 length: %d", ret);
		EDHOC_MEM_FREE(iv);
		return ret;
	}

	EDHOC_MEM_ALLOC(uint8_t, aad, aad_len);
	if (NULL == aad) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = comp_key_iv_aad_3(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv), aad,
				EDHOC_MEM_ALLOC_SIZE(aad));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute K_3: %d", ret);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(iv, EDHOC_MEM_ALLOC_SIZE(iv), "IV_3");
	EDHOC_LOG_HEXDUMP_DBG(aad, EDHOC_MEM_ALLOC_SIZE(aad), "AAD_3");

	/* 5. Compute PRK_4e3m. */
	ret = comp_prk_4e3m(ctx, &auth_creds, NULL, 0);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_4e3m: %d", ret);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	size_t mac_context_length = 0;
	ret = edhoc_comp_mac_context_length(ctx, &auth_creds,
					    &mac_context_length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute MAC context length: %d", ret);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return ret;
	}

	/* 6b. Cborise items required by context_3. */
	EDHOC_MEM_ALLOC(uint8_t, mac_3_context_buf,
			sizeof(struct mac_context) + mac_context_length);
	if (NULL == mac_3_context_buf) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	struct mac_context *mac_context = (void *)mac_3_context_buf;
	mac_context->buf_len = mac_context_length;

	ret = edhoc_comp_mac_context(ctx, &auth_creds, mac_context);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute MAC context: %d", ret);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return ret;
	}

	EDHOC_LOG_HEXDUMP_DBG(mac_context->id_cred, mac_context->id_cred_len,
			      "ID_CRED_I");
	EDHOC_LOG_HEXDUMP_DBG(mac_context->th, mac_context->th_len, "TH_3");
	EDHOC_LOG_HEXDUMP_DBG(mac_context->cred, mac_context->cred_len,
			      "CRED_I");
	EDHOC_LOG_HEXDUMP_DBG(mac_context->buf, mac_context->buf_len,
			      "context_3");

	/* 6c. Compute Message Authentication Code (MAC_3). */
	size_t mac_length = 0;
	ret = edhoc_comp_mac_length(ctx, &mac_length);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute MAC_3 length: %d", ret);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_INVALID_MAC_3;
	}

	EDHOC_MEM_ALLOC(uint8_t, mac_buf, mac_length);
	if (NULL == mac_buf) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}
	ret = edhoc_comp_mac(ctx, mac_context, mac_buf, mac_length);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute MAC_3: %d", ret);
		EDHOC_MEM_FREE(mac_buf);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_INVALID_MAC_3;
	}

	/* 7. Compute signature if needed (Signature_or_MAC_3). */
	size_t sign_or_mac_length = 0;
	ret = edhoc_comp_sign_or_mac_length(ctx, &sign_or_mac_length);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute Signature_or_MAC_3 length: %d", ret);
		EDHOC_MEM_FREE(mac_buf);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return ret;
	}

	size_t signature_length = 0;
	EDHOC_MEM_ALLOC(uint8_t, signature, sign_or_mac_length);
	if (NULL == signature) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(mac_buf);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}
	ret = edhoc_comp_sign_or_mac(ctx, &auth_creds, mac_context, mac_buf,
				     mac_length, signature,
				     EDHOC_MEM_ALLOC_SIZE(signature),
				     &signature_length);
	EDHOC_MEM_FREE(mac_buf);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute Signature_or_MAC_3: %d", ret);
		EDHOC_MEM_FREE(signature);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return ret;
	}

	EDHOC_LOG_HEXDUMP_DBG(signature, signature_length,
			      "Signature_or_MAC_3");

	/* 8. Prepare plaintext (PLAINTEXT_3). */
	size_t plaintext_len = 0;
	ret = comp_plaintext_3_len(ctx, mac_context, signature_length,
				   &plaintext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PLAINTEXT_3 length: %d", ret);
		EDHOC_MEM_FREE(signature);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return ret;
	}

	EDHOC_MEM_ALLOC(uint8_t, plaintext, plaintext_len);
	if (NULL == plaintext) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(signature);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	plaintext_len = 0;
	ret = prepare_plaintext_3(mac_context, signature, signature_length,
				  plaintext, EDHOC_MEM_ALLOC_SIZE(plaintext),
				  &plaintext_len);
	EDHOC_MEM_FREE(signature);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Prepare PLAINTEXT_3: %d", ret);
		EDHOC_MEM_FREE(plaintext);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(plaintext, plaintext_len, "PLAINTEXT_3");

	/* 9. Compute ciphertext. */
	size_t ciphertext_len = 0;
	EDHOC_MEM_ALLOC(uint8_t, ciphertext,
			plaintext_len + csuite.aead_tag_length);
	if (NULL == ciphertext) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(plaintext);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = comp_ciphertext(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv), aad,
			      EDHOC_MEM_ALLOC_SIZE(aad), plaintext,
			      plaintext_len, ciphertext,
			      EDHOC_MEM_ALLOC_SIZE(ciphertext),
			      &ciphertext_len);
	EDHOC_MEM_FREE(aad);
	EDHOC_MEM_FREE(iv);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute CIPHERTEXT_3: %d", ret);
		EDHOC_MEM_FREE(ciphertext);
		EDHOC_MEM_FREE(plaintext);
		EDHOC_MEM_FREE(mac_3_context_buf);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ciphertext, ciphertext_len, "CIPHERTEXT_3");

	/* 10. Compute transcript hash 4. */
	ret = comp_th_4(ctx, mac_context, plaintext, plaintext_len);
	EDHOC_MEM_FREE(plaintext);
	EDHOC_MEM_FREE(mac_3_context_buf);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_4: %d", ret);
		EDHOC_MEM_FREE(ciphertext);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->th, ctx->th_len, "TH_4");

	/* 11. Generate edhoc message 3. */
	ret = gen_msg_3(ciphertext, ciphertext_len, msg_3, msg_3_size,
			msg_3_len);
	EDHOC_MEM_FREE(ciphertext);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Generate message_3: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(msg_3, *msg_3_len, "message_3");
	EDHOC_LOG_INF("Compose msg3 end");

	/* 12. Release the message-3 scoped secrets (PRK_4e3m lives on). */
	ret = edhoc_key_slot_release_up_to(ctx, EDHOC_KEY_SLOT_PRK_4E3M);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Release message 3 secrets: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* 13. Clean-up EAD tokens. */
	ctx->nr_of_ead_tokens = 0;
	ctx->itf.platform.zeroize(ctx->ead_token, sizeof(ctx->ead_token));

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
 *      12. Release the message-3 scoped secrets (PRK_4e3m lives on).
 *      13. Clean-up EAD tokens.
 */
int edhoc_message_3_process(struct edhoc_context *ctx, const uint8_t *msg_3,
			    size_t msg_3_len)
{
	EDHOC_LOG_INF("Process msg3 start");

	if (NULL == ctx || NULL == msg_3 || 0 == msg_3_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_context_configured(ctx)) {
		EDHOC_LOG_ERR("Context not fully configured");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_SM_WAIT_M3 != ctx->status ||
	    EDHOC_TH_STATE_3 != ctx->th_state ||
	    EDHOC_PRK_STATE_3E2M != ctx->prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d, %d", ctx->status,
			      ctx->th_state, ctx->prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

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

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse msg3: %d", ret);
		return EDHOC_ERROR_MSG_3_PROCESS_FAILURE;
	}

	if (ctxt_len < csuite.aead_tag_length) {
		EDHOC_LOG_ERR("CIPHERTEXT_3 shorter than the AEAD tag: %zu",
			      ctxt_len);
		return EDHOC_ERROR_MSG_3_PROCESS_FAILURE;
	}

	/* 3. Compute IV_3 and AAD_3 (K_3 is produced into its context slot). */
	EDHOC_MEM_ALLOC(uint8_t, iv, csuite.aead_iv_length);
	if (NULL == iv) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	size_t aad_len = 0;
	ret = comp_aad_3_len(ctx, &aad_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute AAD_3 length: %d", ret);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	EDHOC_MEM_ALLOC(uint8_t, aad, aad_len);
	if (NULL == aad) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = comp_key_iv_aad_3(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv), aad,
				EDHOC_MEM_ALLOC_SIZE(aad));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute K_3: %d", ret);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(iv, EDHOC_MEM_ALLOC_SIZE(iv), "IV_3");
	EDHOC_LOG_HEXDUMP_DBG(aad, EDHOC_MEM_ALLOC_SIZE(aad), "AAD_3");

	/* 4. Decrypt ciphertext. */
	EDHOC_MEM_ALLOC(uint8_t, ptxt, ctxt_len - csuite.aead_tag_length);
	if (NULL == ptxt) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = decrypt_ciphertext_3(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv), aad,
				   EDHOC_MEM_ALLOC_SIZE(aad), ctxt, ctxt_len,
				   ptxt, EDHOC_MEM_ALLOC_SIZE(ptxt));
	EDHOC_MEM_FREE(aad);
	EDHOC_MEM_FREE(iv);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Decrypt CIPHERTEXT_3: %d", ret);
		EDHOC_MEM_FREE(ptxt);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ptxt, EDHOC_MEM_ALLOC_SIZE(ptxt), "PLAINTEXT_3");

	/* 5. Parse CBOR plaintext (PLAINTEXT_3). */
	struct plaintext parsed_ptxt = { 0 };
	ret = parse_plaintext_3(ctx, ptxt, EDHOC_MEM_ALLOC_SIZE(ptxt),
				&parsed_ptxt);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse PLAINTEXT_3: %d", ret);
		EDHOC_MEM_FREE(ptxt);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* 6. Process EAD_3 if present. */
	if (NULL != ctx->itf.ead.process &&
	    0 != ARRAY_SIZE(ctx->ead_token) - 1 && 0 != ctx->nr_of_ead_tokens) {
		ret = ctx->itf.ead.process(ctx->user_ctx, ctx->message,
					   ctx->ead_token,
					   ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Process EAD_3: %d", ret);
			EDHOC_MEM_FREE(ptxt);
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;
		}

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			EDHOC_LOG_HEXDUMP_DBG(
				(const uint8_t *)&ctx->ead_token[i].label,
				sizeof(ctx->ead_token[i].label),
				"EAD_3 process label");

			if (0 != ctx->ead_token[i].value_len) {
				EDHOC_LOG_HEXDUMP_DBG(
					ctx->ead_token[i].value,
					ctx->ead_token[i].value_len,
					"EAD_3 process value");
			}
		}
	}

	/* 7. Verify if credentials from peer are trusted. */
	const uint8_t *pub_key = NULL;
	size_t pub_key_len = 0;
	ret = ctx->itf.cred.verify(ctx->user_ctx, &parsed_ptxt.auth_cred,
				   &pub_key, &pub_key_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Verify peer credentials: %d", ret);
		ctx->error_code =
			EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;
		EDHOC_MEM_FREE(ptxt);
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	/* 8. Compute PRK_4e3m. */
	ret = comp_prk_4e3m(ctx, &parsed_ptxt.auth_cred, pub_key, pub_key_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_4e3m: %d", ret);
		EDHOC_MEM_FREE(ptxt);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* 9a. Compute required buffer length for context_3. */
	size_t mac_context_len = 0;
	ret = edhoc_comp_mac_context_length(ctx, &parsed_ptxt.auth_cred,
					    &mac_context_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute MAC context length: %d", ret);
		EDHOC_MEM_FREE(ptxt);
		return EDHOC_ERROR_INVALID_MAC_3;
	}

	/* 9b. Cborise items required by context_3. */
	EDHOC_MEM_ALLOC(uint8_t, mac_3_context_buf,
			sizeof(struct mac_context) + mac_context_len);
	if (NULL == mac_3_context_buf) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(ptxt);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	struct mac_context *mac_context = (void *)mac_3_context_buf;
	mac_context->buf_len = mac_context_len;

	ret = edhoc_comp_mac_context(ctx, &parsed_ptxt.auth_cred, mac_context);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute MAC context: %d", ret);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(ptxt);
		return ret;
	}

	EDHOC_LOG_HEXDUMP_DBG(mac_context->conn_id, mac_context->conn_id_len,
			      "C_I");
	EDHOC_LOG_HEXDUMP_DBG(mac_context->id_cred, mac_context->id_cred_len,
			      "ID_CRED_I");
	EDHOC_LOG_HEXDUMP_DBG(mac_context->th, mac_context->th_len, "TH_3");
	EDHOC_LOG_HEXDUMP_DBG(mac_context->cred, mac_context->cred_len,
			      "CRED_I");
	EDHOC_LOG_HEXDUMP_DBG(mac_context->buf, mac_context->buf_len,
			      "context_3");

	/* 9c. Compute Message Authentication Code (MAC_3). */
	size_t mac_length = 0;
	ret = edhoc_comp_mac_length(ctx, &mac_length);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute MAC_3 length: %d", ret);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(ptxt);
		return EDHOC_ERROR_INVALID_MAC_3;
	}

	EDHOC_MEM_ALLOC(uint8_t, mac_buf, mac_length);
	if (NULL == mac_buf) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(ptxt);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}
	ret = edhoc_comp_mac(ctx, mac_context, mac_buf, mac_length);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute MAC_3: %d", ret);
		EDHOC_MEM_FREE(mac_buf);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(ptxt);
		return EDHOC_ERROR_INVALID_MAC_3;
	}

	/* 10. Verify Signature_or_MAC_3. */
	ret = edhoc_verify_sign_or_mac(ctx, mac_context, pub_key, pub_key_len,
				       parsed_ptxt.sign_or_mac,
				       parsed_ptxt.sign_or_mac_len, mac_buf,
				       mac_length);
	EDHOC_MEM_FREE(mac_buf);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Verify Signature_or_MAC_3: %d", ret);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(ptxt);
		return EDHOC_ERROR_INVALID_SIGN_OR_MAC_3;
	}

	/* 11. Compute transcript hash 4. */
	ret = comp_th_4(ctx, mac_context, ptxt, EDHOC_MEM_ALLOC_SIZE(ptxt));
	EDHOC_MEM_FREE(mac_3_context_buf);
	EDHOC_MEM_FREE(ptxt);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_4: %d", ret);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_INF("Process msg3 end");

	/* 12. Release the message-3 scoped secrets (PRK_4e3m lives on). */
	ret = edhoc_key_slot_release_up_to(ctx, EDHOC_KEY_SLOT_PRK_4E3M);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Release message 3 secrets: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* 13. Clean-up EAD tokens. */
	ctx->nr_of_ead_tokens = 0;
	ctx->itf.platform.zeroize(ctx->ead_token, sizeof(ctx->ead_token));

	ctx->is_oscore_export_allowed = true;
	ctx->status = EDHOC_SM_COMPLETED;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}
