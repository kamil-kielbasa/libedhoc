/**
 * \file    edhoc_message_3.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message 3 compose & process.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* EDHOC public headers: */
#include <edhoc/edhoc.h>
#include <edhoc/types.h>
#include <edhoc/values.h>
#include <edhoc/credentials.h>
#include <edhoc/cipher_suite.h>

/* EDHOC internal headers: */
#include "edhoc_context_internal.h"
#include "edhoc_key_slot_internal.h"
#include "edhoc_kdf_internal.h"
#include "edhoc_key_schedule_internal.h"
#include "edhoc_cipher_internal.h"
#include "edhoc_transcript_hash_internal.h"
#include "edhoc_ead_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_cbor_internal.h"
#include "edhoc_mac_internal.h"
#include "edhoc_plaintext_internal.h"
#include "edhoc_credentials_internal.h"
#include "edhoc_backend_log.h"
#include "edhoc_backend_memory.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_types.h>
#include <backend_cbor_message_3_encode.h>
#include <backend_cbor_message_3_decode.h>
#include <backend_cbor_bstr_type_encode.h>
#include <backend_cbor_plaintext_3_decode.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

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

/* Static function definitions --------------------------------------------- */

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

	if (0 != mac_ctx->id_cred_comp_len) {
		len += mac_ctx->id_cred_comp_len;
	} else {
		len += mac_ctx->id_cred_len;
	}

	len += sign_len;
	len += edhoc_cbor_bstr_head_length(sign_len);
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
	if (0 != mac_ctx->id_cred_comp_len) {
		memcpy(&ptxt[offset], mac_ctx->id_cred_comp,
		       mac_ctx->id_cred_comp_len);
		offset += mac_ctx->id_cred_comp_len;
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
		&ptxt[offset], sign_len + edhoc_cbor_bstr_head_length(sign_len),
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

STATIC int comp_th_4(struct edhoc_context *ctx,
		     const struct mac_context *mac_ctx, const uint8_t *ptxt,
		     size_t ptxt_len)
{
	if (NULL == mac_ctx) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const struct edhoc_th_input input = {
		.target = EDHOC_TH_STATE_4,
		.plaintext = ptxt,
		.plaintext_length = ptxt_len,
		.credential = mac_ctx->cred,
		.credential_length = mac_ctx->cred_len,
	};

	return edhoc_th_compute(ctx, &input);
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
	case plaintext_3_ID_CRED_I_int_c:
		ret = edhoc_credential_parse_kid_int(
			cbor_ptxt_3.plaintext_3_ID_CRED_I_int,
			&parsed_ptxt->kid_byte,
			&parsed_ptxt->peer_credential_id);
		break;

	case plaintext_3_ID_CRED_I_bstr_c:
		ret = edhoc_credential_parse_kid_bstr(
			cbor_ptxt_3.plaintext_3_ID_CRED_I_bstr.value,
			cbor_ptxt_3.plaintext_3_ID_CRED_I_bstr.len,
			&parsed_ptxt->peer_credential_id);
		break;

	case plaintext_3_ID_CRED_I_id_cred_x_m_c:
		ret = edhoc_credential_parse_map(
			&cbor_ptxt_3.plaintext_3_ID_CRED_I_id_cred_x_m,
			&parsed_ptxt->peer_credential_id);
		break;

	default:
		EDHOC_LOG_ERR("Invalid ID_CRED_I choice: %d",
			      cbor_ptxt_3.plaintext_3_ID_CRED_I_choice);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse ID_CRED_I: %d", ret);
		return ret;
	}

	/* Sign_or_MAC_3 */
	parsed_ptxt->sign_or_mac.value =
		cbor_ptxt_3.plaintext_3_Signature_or_MAC_3.value;
	parsed_ptxt->sign_or_mac.length =
		cbor_ptxt_3.plaintext_3_Signature_or_MAC_3.len;

	/* EAD_3 if present */
	if (cbor_ptxt_3.plaintext_3_ead_m_present) {
		ret = edhoc_ead_tokens_decode(ctx,
					      &cbor_ptxt_3.plaintext_3_ead_m);

		if (EDHOC_SUCCESS != ret) {
			return ret;
		}
	}

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

	if (EDHOC_SM_VERIFIED_M2 != ctx->state.machine ||
	    EDHOC_TH_STATE_3 != ctx->state.th.stage ||
	    EDHOC_PRK_STATE_3E2M != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d, %d", ctx->state.machine,
			      ctx->state.th.stage, ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->state.machine = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->state.message = EDHOC_MESSAGE_3;
	ctx->state.role = EDHOC_ROLE_INITIATOR;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);

	/* 2. Compose EAD_3 if present. */
	ret = edhoc_ead_compose(ctx);

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	/* 3. Select authentication credential. */
	const struct edhoc_call_context cred_call_context =
		edhoc_call_context(ctx);
	struct edhoc_credential_selected selected = { 0 };
	ret = ctx->interfaces.cred.select_local(ctx->user_context,
						&cred_call_context, &selected);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Select local credential: %d", ret);
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	ret = edhoc_credential_validate_selected(&selected);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Validate selected credential: %d", ret);
		return ret;
	}

	/* 4. Compute IV_3 and AAD_3 (K_3 is produced into its context slot). */
	EDHOC_MEM_ALLOC(uint8_t, iv, csuite->aead_iv_length);
	if (NULL == iv) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	size_t aad_len = 0;
	ret = edhoc_cipher_aad_length(ctx, &aad_len);

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

	ret = edhoc_cipher_derive(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv), aad,
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
	ret = edhoc_key_schedule_prk_advance(ctx, selected.private_key_id, NULL,
					     0);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_4e3m: %d", ret);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	struct edhoc_credential_material material = { 0 };
	ret = edhoc_credential_material_from_selected(&selected, &material);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return ret;
	}

	size_t mac_context_length = 0;
	ret = edhoc_mac_context_length(ctx, &material, &mac_context_length);

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

	ret = edhoc_mac_context_compose(ctx, &material, mac_context);
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
	ret = edhoc_mac_length(ctx, &mac_length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute MAC_3 length: %d", ret);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return ret;
	}

	EDHOC_MEM_ALLOC(uint8_t, mac_buf, mac_length);

	if (NULL == mac_buf) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_mac_compute(ctx, mac_context, mac_buf, mac_length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute MAC_3: %d", ret);
		EDHOC_MEM_FREE(mac_buf);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return ret;
	}

	/* 7. Compute signature if needed (Signature_or_MAC_3). */
	size_t sign_or_mac_length = 0;
	ret = edhoc_sign_or_mac_length(ctx, &sign_or_mac_length);

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

	ret = edhoc_sign_or_mac_compute(
		ctx, selected.private_key_id, mac_context, mac_buf, mac_length,
		signature, EDHOC_MEM_ALLOC_SIZE(signature), &signature_length);

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
			plaintext_len + csuite->aead_tag_length);

	if (NULL == ciphertext) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(plaintext);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_cipher_encrypt(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv), aad,
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

	EDHOC_LOG_HEXDUMP_DBG(ctx->state.th.value, ctx->state.th.length,
			      "TH_4");

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
	edhoc_ead_reset(ctx);

	ctx->is_oscore_export_allowed = true;
	ctx->state.machine = EDHOC_SM_COMPLETED;
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

	if (EDHOC_SM_WAIT_M3 != ctx->state.machine ||
	    EDHOC_TH_STATE_3 != ctx->state.th.stage ||
	    EDHOC_PRK_STATE_3E2M != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d, %d", ctx->state.machine,
			      ctx->state.th.stage, ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->state.machine = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->state.message = EDHOC_MESSAGE_3;
	ctx->state.role = EDHOC_ROLE_RESPONDER;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);

	/* 2. CBOR decode message 3. */
	const uint8_t *ctxt = NULL;
	size_t ctxt_len = 0;

	ret = parse_msg_3(msg_3, msg_3_len, &ctxt, &ctxt_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse msg3: %d", ret);
		return ret;
	}

	if (ctxt_len <= csuite->aead_tag_length) {
		EDHOC_LOG_ERR("CIPHERTEXT_3 not longer than the AEAD tag: %zu",
			      ctxt_len);
		return EDHOC_ERROR_MSG_3_PROCESS_FAILURE;
	}

	/* 3. Compute IV_3 and AAD_3 (K_3 is produced into its context slot). */
	EDHOC_MEM_ALLOC(uint8_t, iv, csuite->aead_iv_length);
	if (NULL == iv) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	size_t aad_len = 0;
	ret = edhoc_cipher_aad_length(ctx, &aad_len);

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

	ret = edhoc_cipher_derive(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv), aad,
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
	EDHOC_MEM_ALLOC(uint8_t, ptxt, ctxt_len - csuite->aead_tag_length);
	if (NULL == ptxt) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_cipher_decrypt(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv), aad,
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
	ret = edhoc_ead_process(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(ptxt);
		return ret;
	}

	/* 7. Verify if credentials from peer are trusted. */
	const struct edhoc_call_context call_context = edhoc_call_context(ctx);
	struct edhoc_credential_trusted trusted = { 0 };

	ret = ctx->interfaces.cred.authenticate_peer(
		ctx->user_context, &call_context,
		&parsed_ptxt.peer_credential_id, &trusted);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Verify peer credentials: %d", ret);
		ctx->error_code =
			EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;
		EDHOC_MEM_FREE(ptxt);
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	ret = edhoc_credential_validate_trusted(&parsed_ptxt.peer_credential_id,
						&trusted);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Validate trusted credentials: %d", ret);
		EDHOC_MEM_FREE(ptxt);
		return ret;
	}

	/* 8. Compute PRK_4e3m. */
	ret = edhoc_key_schedule_prk_advance(
		ctx, NULL, trusted.public_key.value, trusted.public_key.length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_4e3m: %d", ret);
		EDHOC_MEM_FREE(ptxt);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* 9a. Compute required buffer length for context_3. */
	struct edhoc_credential_material material = { 0 };
	ret = edhoc_credential_material_from_trusted(
		&parsed_ptxt.peer_credential_id, &trusted, &material);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(ptxt);
		return ret;
	}

	size_t mac_context_len = 0;
	ret = edhoc_mac_context_length(ctx, &material, &mac_context_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute MAC context length: %d", ret);
		EDHOC_MEM_FREE(ptxt);
		return ret;
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

	ret = edhoc_mac_context_compose(ctx, &material, mac_context);
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
	ret = edhoc_mac_length(ctx, &mac_length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute MAC_3 length: %d", ret);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(ptxt);
		return ret;
	}

	EDHOC_MEM_ALLOC(uint8_t, mac_buf, mac_length);

	if (NULL == mac_buf) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(ptxt);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_mac_compute(ctx, mac_context, mac_buf, mac_length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute MAC_3: %d", ret);
		EDHOC_MEM_FREE(mac_buf);
		EDHOC_MEM_FREE(mac_3_context_buf);
		EDHOC_MEM_FREE(ptxt);
		return ret;
	}

	/* 10. Verify Signature_or_MAC_3. */
	ret = edhoc_sign_or_mac_verify(
		ctx, mac_context, trusted.public_key.value,
		trusted.public_key.length, parsed_ptxt.sign_or_mac.value,
		parsed_ptxt.sign_or_mac.length, mac_buf, mac_length);

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
	edhoc_ead_reset(ctx);

	ctx->is_oscore_export_allowed = true;
	ctx->state.machine = EDHOC_SM_COMPLETED;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}
