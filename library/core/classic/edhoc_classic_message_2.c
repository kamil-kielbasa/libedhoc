/**
 * \file    edhoc_message_2.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message 2 compose & process.
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
#include <edhoc/cipher_suite.h>
#include <edhoc/credentials.h>

/* EDHOC internal headers: */
#include "edhoc_classic_internal.h"
#include "edhoc_context_internal.h"
#include "edhoc_key_slot_internal.h"
#include "edhoc_kdf_internal.h"
#include "edhoc_key_schedule_internal.h"
#include "edhoc_cipher_internal.h"
#include "edhoc_transcript_hash_internal.h"
#include "edhoc_ead_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_mac_internal.h"
#include "edhoc_plaintext_internal.h"
#include "edhoc_credentials_internal.h"
#include "edhoc_connection_id_internal.h"
#include "edhoc_backend_log.h"
#include "edhoc_backend_memory.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_message_2_encode.h>
#include <backend_cbor_message_2_decode.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Compute transcript hash 2 (TH_2).
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_th_2(struct edhoc_context *ctx);

/**
 * \brief Prepare MESSAGE_2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] ciphertext	Buffer containing the CIPHERTEXT_2.
 * \param ciphertext_len	Size of the \p ciphertext buffer in bytes.
 * \param[out] msg_2        	Buffer where the generated message 2 is to be written.
 * \param msg_2_size        	Size of the \p msg_2 buffer in bytes.
 * \param[out] msg_2_len	On success, the number of bytes that make up the message 2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int prepare_message_2(const struct edhoc_context *ctx,
			     const uint8_t *ciphertext, size_t ciphertext_len,
			     uint8_t *msg_2, size_t msg_2_size,
			     size_t *msg_2_len);

/**
 * \brief Compute from cborised message 2 length of ciphertext 2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] msg_2     	Buffer containing the message 2.
 * \param msg_2_len     	Size of the \p msg_2 buffer in bytes.
 * \param[out] len		Length of ciphertext 2 in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_ciphertext_2_len(const struct edhoc_context *ctx,
				 const uint8_t *msg_2, size_t msg_2_len,
				 size_t *len);

/**
 * \brief Decode message 2 and save into context and buffer.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] msg_2     	Buffer containing the message 2.
 * \param msg_2_len     	Size of the \p msg_2 buffer in bytes.
 * \param[in] ctxt_2	        Buffer containing the CIPHERTEXT_2.
 * \param ctxt_2_len	        Size of the \p ctxt_2 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int parse_msg_2(struct edhoc_context *ctx, const uint8_t *msg_2,
		       size_t msg_2_len, uint8_t *ctxt_2, size_t ctxt_2_len);

/**
 * \brief Compute transcript hash 3.
 *
 * \param[in,out] ctx		EDHOC context.
 * \param[in] mac_ctx	        MAC context.
 * \param[in] ptxt		Buffer containing the PLAINTEXT_2.
 * \param ptxt_len              Size of the \p ptxt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_th_3(struct edhoc_context *ctx,
		     const struct mac_context *mac_ctx, const uint8_t *ptxt,
		     size_t ptxt_len);

/* Static function definitions --------------------------------------------- */

STATIC int comp_th_2(struct edhoc_context *ctx)
{
	const struct edhoc_th_input input = {
		.target = EDHOC_TH_STATE_2,
	};

	return edhoc_th_compute(ctx, &input);
}

STATIC int prepare_message_2(const struct edhoc_context *ctx,
			     const uint8_t *ctxt, size_t ctxt_len,
			     uint8_t *msg_2, size_t msg_2_size,
			     size_t *msg_2_len)
{
	if (NULL == ctx || NULL == ctxt || 0 == ctxt_len || NULL == msg_2 ||
	    0 == msg_2_size || NULL == msg_2_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t offset = 0;

	size_t len = 0;
	len += ctx->ephemeral.own.length;
	len += ctxt_len;

	EDHOC_MEM_ALLOC(uint8_t, buffer, len);
	if (NULL == buffer) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	memcpy(&buffer[offset], ctx->ephemeral.own.value,
	       ctx->ephemeral.own.length);
	offset += ctx->ephemeral.own.length;

	memcpy(&buffer[offset], ctxt, ctxt_len);
	offset += ctxt_len;

	if (EDHOC_MEM_ALLOC_SIZE(buffer) < offset) {
		EDHOC_LOG_ERR("Buffer overflow: %zu, %zu",
			      EDHOC_MEM_ALLOC_SIZE(buffer), offset);
		EDHOC_MEM_FREE(buffer);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	const struct zcbor_string cbor_msg_2 = {
		.value = buffer,
		.len = EDHOC_MEM_ALLOC_SIZE(buffer),
	};

	ret = cbor_encode_message_2_G_Y_CIPHERTEXT_2(msg_2, msg_2_size,
						     &cbor_msg_2, msg_2_len);
	EDHOC_MEM_FREE(buffer);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc msg_2: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int comp_ciphertext_2_len(const struct edhoc_context *ctx,
				 const uint8_t *msg_2, size_t msg_2_len,
				 size_t *ctxt_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct zcbor_string dec_msg_2 = { 0 };
	ret = cbor_decode_message_2_G_Y_CIPHERTEXT_2(msg_2, msg_2_len,
						     &dec_msg_2, &len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR dec msg_2: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	if (len > msg_2_len) {
		EDHOC_LOG_ERR("Decoded length exceeds buffer: %zu, %zu", len,
			      msg_2_len);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	const size_t g_y_len =
		edhoc_selected_cipher_suite(ctx)->kem_ciphertext_length;

	if (dec_msg_2.len <= g_y_len) {
		EDHOC_LOG_ERR("Decoded message_2 too short for G_Y: %zu, %zu",
			      dec_msg_2.len, g_y_len);
		return EDHOC_ERROR_MSG_2_PROCESS_FAILURE;
	}

	len = dec_msg_2.len - g_y_len;

	*ctxt_len = len;
	return EDHOC_SUCCESS;
}

STATIC int parse_msg_2(struct edhoc_context *ctx, const uint8_t *msg_2,
		       size_t msg_2_len, uint8_t *ctxt_2, size_t ctxt_2_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct zcbor_string dec_msg_2 = { 0 };
	ret = cbor_decode_message_2_G_Y_CIPHERTEXT_2(msg_2, msg_2_len,
						     &dec_msg_2, &len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR decode message_2: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	if (len > msg_2_len) {
		EDHOC_LOG_ERR("Message 2 length mismatch: %zu, %zu", len,
			      msg_2_len);
		return EDHOC_ERROR_MSG_2_PROCESS_FAILURE;
	}

	/* Get Diffie-Hellmann peer public key (G_Y). */
	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);
	ctx->ephemeral.peer.length = csuite->kem_ciphertext_length;
	memcpy(ctx->ephemeral.peer.value, dec_msg_2.value,
	       ctx->ephemeral.peer.length);

	/* Get CIPHERTEXT_2. */
	const size_t offset = ctx->ephemeral.peer.length;
	memcpy(ctxt_2, &dec_msg_2.value[offset], ctxt_2_len);

	return EDHOC_SUCCESS;
}

STATIC int comp_th_3(struct edhoc_context *ctx,
		     const struct mac_context *mac_ctx, const uint8_t *ptxt,
		     size_t ptxt_len)
{
	if (NULL == mac_ctx) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const struct edhoc_th_input input = {
		.target = EDHOC_TH_STATE_3,
		.plaintext = ptxt,
		.plaintext_length = ptxt_len,
		.credential = mac_ctx->cred,
		.credential_length = mac_ctx->cred_len,
	};

	return edhoc_th_compute(ctx, &input);
}

/* Module interface function definitions ----------------------------------- */

/**
 * Steps for composition of message 2:
 *	1.  KEM encapsulate to the peer's G_X (produce G_Y and G_XY).
 *	2.  Compute Transcript Hash 2 (TH_2).
 *	3.  Compute Pseudo Random Key 2 (PRK_2e).
 *	4.  Fetch authentication credentials.
 *	5.  Compose EAD_2 if present.
 *	6.  Compute pseudorandom key (PRK_3e2m).
 *	7a. Compute required buffer length for context_2.
 *	7b. Cborise items required by context_2.
 *	7c. Compute Message Authentication Code (MAC_2).
 *	8.  Compute signature if needed (Signature_or_MAC_2).
 *	9.  Prepare plaintext (PLAINTEXT_2).
 *	10. Compute key stream (KEYSTREAM_2).
 *	11. Compute Transcript Hash 3 (TH_3).
 *	12. Compute ciphertext (CIPHERTEXT_2).
 *	13. Cborise items for message 2.
 *	14. Release the message-2 scoped secrets (PRK_3e2m lives on).
 *	15. Clean-up EAD tokens.
 */
int edhoc_classic_message_2_compose(struct edhoc_context *ctx, uint8_t *msg_2,
				    size_t msg_2_size, size_t *msg_2_len)
{
	EDHOC_LOG_INF("Compose msg2 start");

	if (NULL == ctx || msg_2 == NULL || 0 == msg_2_size ||
	    NULL == msg_2_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_context_configured(ctx)) {
		EDHOC_LOG_ERR("Context not fully configured");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_SM_RECEIVED_M1 != ctx->state.machine ||
	    EDHOC_TH_STATE_1 != ctx->state.th.stage ||
	    EDHOC_PRK_STATE_INVALID != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d, %d", ctx->state.machine,
			      ctx->state.th.stage, ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->state.machine = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->state.message = EDHOC_MESSAGE_2;
	ctx->state.role = EDHOC_ROLE_RESPONDER;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. KEM encapsulate to the peer's G_X: produce the KEM ciphertext G_Y
	 * (sent in message 2) and the shared-secret handle. */
	ret = edhoc_key_schedule_encapsulate(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Encapsulate: %d", ret);
		return EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->ephemeral.own.value,
			      ctx->ephemeral.own.length, "G_Y");

	/* 2. Compute Transcript Hash 2 (TH_2). */
	ret = comp_th_2(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_2: %d", ret);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->state.th.value, ctx->state.th.length,
			      "TH_2");

	/* 3. Compute Pseudo Random Key 2 (PRK_2e). */
	ret = edhoc_key_schedule_prk_initial(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_2e: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 4. Select authentication credential. */
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

	/* 5. Compose EAD_2 if present. */
	ret = edhoc_ead_compose(ctx);

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	/* 6. Compute pseudorandom key (PRK_3e2m). */
	ret = edhoc_key_schedule_prk_advance(ctx, selected.private_key_id, NULL,
					     0);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_3e2m: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 7a. Compute required buffer length for context_2. */
	struct edhoc_credential_material material = { 0 };
	ret = edhoc_credential_material_from_selected(&selected, &material);

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	size_t mac_ctx_len = 0;
	ret = edhoc_mac_context_length(ctx, &material, &mac_ctx_len);

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	/* 7b. Cborise items required by context_2. */
	EDHOC_MEM_ALLOC(uint8_t, mac_ctx_buf,
			sizeof(struct mac_context) + mac_ctx_len);
	if (NULL == mac_ctx_buf) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	struct mac_context *mac_ctx = (void *)mac_ctx_buf;
	mac_ctx->buf_len = mac_ctx_len;

	ret = edhoc_mac_context_compose(ctx, &material, mac_ctx);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(mac_ctx_buf);
		return ret;
	}

	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->conn_id, mac_ctx->conn_id_len, "C_R");
	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->id_cred, mac_ctx->id_cred_len,
			      "ID_CRED_R");
	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->th, mac_ctx->th_len, "TH_2");
	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->cred, mac_ctx->cred_len, "CRED_R");
	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->buf, mac_ctx->buf_len, "context_2");

	/* 7c. Compute Message Authentication Code (MAC_2). */
	size_t mac_length = 0;
	ret = edhoc_mac_length(ctx, &mac_length);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(mac_ctx_buf);
		return ret;
	}

	EDHOC_MEM_ALLOC(uint8_t, mac_buf, mac_length);
	if (NULL == mac_buf) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(mac_ctx_buf);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}
	ret = edhoc_mac_compute(ctx, mac_ctx, mac_buf, mac_length);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(mac_buf);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return ret;
	}

	/* 8. Compute signature if needed (Signature_or_MAC_2). */
	size_t sign_or_mac_length = 0;
	ret = edhoc_sign_or_mac_length(ctx, &sign_or_mac_length);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(mac_buf);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return ret;
	}

	size_t signature_length = 0;
	EDHOC_MEM_ALLOC(uint8_t, signature, sign_or_mac_length);
	if (NULL == signature) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(mac_buf);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}
	ret = edhoc_sign_or_mac_compute(ctx, selected.private_key_id, mac_ctx,
					mac_buf, mac_length, signature,
					EDHOC_MEM_ALLOC_SIZE(signature),
					&signature_length);
	EDHOC_MEM_FREE(mac_buf);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(signature);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return ret;
	}

	EDHOC_LOG_HEXDUMP_DBG(signature, signature_length,
			      "Signature_or_MAC_2");

	/* 9. Prepare plaintext (PLAINTEXT_2). */
	const struct edhoc_plaintext_input plaintext_input = {
		.id = EDHOC_PLAINTEXT_CLASSIC_2,
		.mac_context = mac_ctx,
		.signature = signature,
		.signature_length = signature_length,
	};

	size_t plaintext_len = 0;
	ret = edhoc_plaintext_length(ctx, &plaintext_input, &plaintext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute plaintext_2 length: %d", ret);
		EDHOC_MEM_FREE(signature);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	EDHOC_MEM_ALLOC(uint8_t, plaintext, plaintext_len);
	if (NULL == plaintext) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(signature);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	plaintext_len = 0;
	ret = edhoc_plaintext_compose(ctx, &plaintext_input, plaintext,
				      EDHOC_MEM_ALLOC_SIZE(plaintext),
				      &plaintext_len);
	EDHOC_MEM_FREE(signature);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Prepare plaintext_2: %d", ret);
		EDHOC_MEM_FREE(plaintext);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(plaintext, plaintext_len, "PLAINTEXT_2");

	/* 10. Compute key stream (KEYSTREAM_2). */
	EDHOC_MEM_ALLOC(uint8_t, keystream, plaintext_len);
	if (NULL == keystream) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(plaintext);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_cipher_keystream(ctx, keystream,
				     EDHOC_MEM_ALLOC_SIZE(keystream));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute keystream_2: %d", ret);
		EDHOC_MEM_FREE(keystream);
		EDHOC_MEM_FREE(plaintext);
		EDHOC_MEM_FREE(mac_ctx_buf);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(keystream, EDHOC_MEM_ALLOC_SIZE(keystream),
			      "KEYSTREAM_2");

	/* 11. Compute Transcript Hash 3 (TH_3). */
	ret = comp_th_3(ctx, mac_ctx, plaintext, plaintext_len);
	EDHOC_MEM_FREE(mac_ctx_buf);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_3: %d", ret);
		EDHOC_MEM_FREE(keystream);
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->state.th.value, ctx->state.th.length,
			      "TH_3");

	/* 12. Compute ciphertext (CIPHERTEXT_2). */
	edhoc_cipher_xor(plaintext, keystream, plaintext_len);
	EDHOC_MEM_FREE(keystream);
	const uint8_t *ciphertext = plaintext;
	const size_t ciphertext_len = plaintext_len;

	EDHOC_LOG_HEXDUMP_DBG(ciphertext, ciphertext_len, "CIPHERTEXT_2");

	/* 13. Cborise items for message 2. */
	ret = prepare_message_2(ctx, ciphertext, ciphertext_len, msg_2,
				msg_2_size, msg_2_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Prepare message_2: %d", ret);
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_MEM_FREE(plaintext);

	EDHOC_LOG_HEXDUMP_DBG(msg_2, *msg_2_len, "message_2");
	EDHOC_LOG_INF("Compose msg2 end");

	/* 14. Release the message-2 scoped secrets (PRK_3e2m lives on). */
	ret = edhoc_key_slot_release_up_to(ctx, EDHOC_KEY_SLOT_PRK_3E2M);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Release message 2 secrets: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* 15. Clean-up EAD tokens. */
	edhoc_ead_reset(ctx);

	ctx->state.machine = EDHOC_SM_WAIT_M3;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}

/**
 * Steps for processing of message 2:
 * 	1.  Compute required length for ciphertext.
 *      2.  Decode cborised message 2.
 *      3.  Compute Diffie-Hellmann shared secret (G_XY).
 *      4.  Compute Transcript Hash 2 (TH_2).
 *      5.  Compute Pseudo Random Key 2 (PRK_2e).
 *      6.  Compute key stream (KEYSTREAM_2).
 *      7.  Compute plaintext (PLAINTEXT_2).
 *      8.  Parse plaintext (PLAINTEXT_2).
 *      9.  Process EAD if present.
 *      10. Verify if credentials from peer are trusted.
 *      11. Compute pseudorandom key (PRK_3e2m).
 *      12. Compute required buffer length for context_2.
 *      13. Cborise items required by context_2.
 *      14. Compute Message Authentication Code (MAC_2).
 *      15. Verify Signature_or_MAC_2.
 *      16. Compute Transcript Hash 3 (TH_3).
 *      17. Release the message-2 scoped secrets (PRK_3e2m lives on).
 *      18. Clean-up EAD tokens.
 */
int edhoc_classic_message_2_process(struct edhoc_context *ctx,
				    const uint8_t *msg_2, size_t msg_2_len)
{
	EDHOC_LOG_INF("Process msg2 start");

	if (NULL == ctx || NULL == msg_2 || 0 == msg_2_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_context_configured(ctx)) {
		EDHOC_LOG_ERR("Context not fully configured");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_SM_WAIT_M2 != ctx->state.machine ||
	    EDHOC_TH_STATE_1 != ctx->state.th.stage ||
	    EDHOC_PRK_STATE_INVALID != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d, %d", ctx->state.machine,
			      ctx->state.th.stage, ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->state.machine = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->state.message = EDHOC_MESSAGE_2;
	ctx->state.role = EDHOC_ROLE_INITIATOR;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	/* 1. Compute required length for ciphertext. */
	ret = comp_ciphertext_2_len(ctx, msg_2, msg_2_len, &len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute ciphertext length: %d", ret);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	EDHOC_MEM_ALLOC(uint8_t, ciphertext_2, len);
	if (NULL == ciphertext_2) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	/* 2. Decode cborised message 2. */
	ret = parse_msg_2(ctx, msg_2, msg_2_len, ciphertext_2,
			  EDHOC_MEM_ALLOC_SIZE(ciphertext_2));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse msg2: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ciphertext_2, EDHOC_MEM_ALLOC_SIZE(ciphertext_2),
			      "CIPHERTEXT_2");

	/* 3. KEM decapsulate the peer's G_Y into the shared-secret handle. */
	ret = edhoc_key_schedule_decapsulate(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Decapsulate: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE;
	}

	/* 4. Compute Transcript Hash 2 (TH_2). */
	ret = comp_th_2(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_2: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->state.th.value, ctx->state.th.length,
			      "TH_2");

	/* 5. Compute Pseudo Random Key 2 (PRK_2e). */
	ret = edhoc_key_schedule_prk_initial(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_2e: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 6. Compute key stream (KEYSTREAM_2). */
	EDHOC_MEM_ALLOC(uint8_t, keystream, EDHOC_MEM_ALLOC_SIZE(ciphertext_2));
	if (NULL == keystream) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_cipher_keystream(ctx, keystream,
				     EDHOC_MEM_ALLOC_SIZE(keystream));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute keystream: %d", ret);
		EDHOC_MEM_FREE(keystream);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(keystream, EDHOC_MEM_ALLOC_SIZE(keystream),
			      "KEYSTREAM_2");

	/* 7. Compute plaintext (PLAINTEXT_2). */
	edhoc_cipher_xor(ciphertext_2, keystream,
			 EDHOC_MEM_ALLOC_SIZE(ciphertext_2));
	EDHOC_MEM_FREE(keystream);
	const uint8_t *plaintext = ciphertext_2;
	const size_t plaintext_len = EDHOC_MEM_ALLOC_SIZE(ciphertext_2);

	EDHOC_LOG_HEXDUMP_DBG(plaintext, plaintext_len, "PLAINTEXT_2");

	/* 8. Parse plaintext (PLAINTEXT_2). */
	struct plaintext parsed_ptxt = { 0 };
	ret = edhoc_plaintext_parse(ctx, EDHOC_PLAINTEXT_CLASSIC_2, plaintext,
				    plaintext_len, &parsed_ptxt);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse plaintext: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->negotiation.peer_connection_id.value,
			      ctx->negotiation.peer_connection_id.length,
			      "C_R");

	/* 9. Process EAD if present. */
	ret = edhoc_ead_process(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(ciphertext_2);
		return ret;
	}

	/* 10. Verify if credentials from peer are trusted. */
	const struct edhoc_call_context call_context = edhoc_call_context(ctx);
	struct edhoc_credential_trusted trusted = { 0 };

	ret = ctx->interfaces.cred.authenticate_peer(
		ctx->user_context, &call_context,
		&parsed_ptxt.peer_credential_id, &trusted);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Credentials verification: %d", ret);
		ctx->error_code =
			EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	ret = edhoc_credential_validate_trusted(&parsed_ptxt.peer_credential_id,
						&trusted);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Validate trusted credentials: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return ret;
	}

	/* 11. Compute pseudorandom key (PRK_3e2m). */
	ret = edhoc_key_schedule_prk_advance(
		ctx, NULL, trusted.public_key.value, trusted.public_key.length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_3e2m: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 12. Compute required buffer length for context_2. */
	struct edhoc_credential_material material = { 0 };
	ret = edhoc_credential_material_from_trusted(
		&parsed_ptxt.peer_credential_id, &trusted, &material);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(ciphertext_2);
		return ret;
	}

	size_t mac_context_len = 0;
	ret = edhoc_mac_context_length(ctx, &material, &mac_context_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute MAC context length: %d", ret);
		EDHOC_MEM_FREE(ciphertext_2);
		return ret;
	}

	/* 13. Cborise items required by context_2. */
	EDHOC_MEM_ALLOC(uint8_t, mac_ctx_buf,
			sizeof(struct mac_context) + mac_context_len);
	if (NULL == mac_ctx_buf) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	struct mac_context *mac_ctx = (void *)mac_ctx_buf;
	mac_ctx->buf_len = mac_context_len;

	ret = edhoc_mac_context_compose(ctx, &material, mac_ctx);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(mac_ctx_buf);
		EDHOC_MEM_FREE(ciphertext_2);
		return ret;
	}

	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->conn_id, mac_ctx->conn_id_len, "C_R");
	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->id_cred, mac_ctx->id_cred_len,
			      "ID_CRED_R");
	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->th, mac_ctx->th_len, "TH_2");
	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->cred, mac_ctx->cred_len, "CRED_R");
	EDHOC_LOG_HEXDUMP_DBG(mac_ctx->buf, mac_ctx->buf_len, "context_2");

	/* 14. Compute Message Authentication Code (MAC_2). */
	size_t mac_length = 0;
	ret = edhoc_mac_length(ctx, &mac_length);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(mac_ctx_buf);
		EDHOC_MEM_FREE(ciphertext_2);
		return ret;
	}

	EDHOC_MEM_ALLOC(uint8_t, mac_buf, mac_length);
	if (NULL == mac_buf) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(mac_ctx_buf);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}
	ret = edhoc_mac_compute(ctx, mac_ctx, mac_buf, mac_length);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(mac_buf);
		EDHOC_MEM_FREE(mac_ctx_buf);
		EDHOC_MEM_FREE(ciphertext_2);
		return ret;
	}

	/* 15. Verify Signature_or_MAC_2. */
	ret = edhoc_sign_or_mac_verify(ctx, mac_ctx, trusted.public_key.value,
				       trusted.public_key.length,
				       parsed_ptxt.sign_or_mac.value,
				       parsed_ptxt.sign_or_mac.length, mac_buf,
				       mac_length);
	EDHOC_MEM_FREE(mac_buf);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Signature or MAC_2 verification: %d", ret);
		EDHOC_MEM_FREE(mac_ctx_buf);
		EDHOC_MEM_FREE(ciphertext_2);
		return EDHOC_ERROR_INVALID_SIGN_OR_MAC_2;
	}

	/* 16. Compute Transcript Hash 3 (TH_3). */
	ret = comp_th_3(ctx, mac_ctx, plaintext, plaintext_len);
	EDHOC_MEM_FREE(mac_ctx_buf);
	EDHOC_MEM_FREE(ciphertext_2);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_3: %d", ret);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->state.th.value, ctx->state.th.length,
			      "TH_3");
	EDHOC_LOG_INF("Process msg2 end");

	/* 17. Release the message-2 scoped secrets (PRK_3e2m lives on). */
	ret = edhoc_key_slot_release_up_to(ctx, EDHOC_KEY_SLOT_PRK_3E2M);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Release message 2 secrets: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* 18. Clean-up EAD tokens. */
	edhoc_ead_reset(ctx);

	ctx->state.machine = EDHOC_SM_VERIFIED_M2;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}
