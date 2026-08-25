/**
 * \file    edhoc_psk_message_2.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC-PSK message 2 compose & process
 *          (draft-ietf-lake-edhoc-psk: 5.2).
 *
 *          Message 2 is the classic one minus everything that identifies the
 *          Responder: PLAINTEXT_2A carries C_R and an optional EAD_2, so no
 *          credential is selected and no MAC is computed.
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

/* EDHOC internal headers: */
#include "edhoc_psk_internal.h"
#include "edhoc_context_internal.h"
#include "edhoc_key_slot_internal.h"
#include "edhoc_key_schedule_internal.h"
#include "edhoc_cipher_internal.h"
#include "edhoc_transcript_hash_internal.h"
#include "edhoc_ead_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_plaintext_internal.h"
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
 * \brief Compose the G_Y_CIPHERTEXT_2 byte string.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] ctxt	        Buffer containing the CIPHERTEXT_2A.
 * \param ctxt_len	        Size of the \p ctxt buffer in bytes.
 * \param[out] msg_2        	Buffer for the message.
 * \param msg_2_size        	Size of the \p msg_2 buffer in bytes.
 * \param[out] msg_2_len	On success, number of bytes written.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int compose_g_y_ciphertext_2a(const struct edhoc_context *ctx,
				     const uint8_t *ctxt, size_t ctxt_len,
				     uint8_t *msg_2, size_t msg_2_size,
				     size_t *msg_2_len);

/**
 * \brief Split the G_Y_CIPHERTEXT_2 byte string. G_Y is stored in the context,
 *        CIPHERTEXT_2A is returned as a view into \p msg_2.
 *
 * \param[in,out] ctx		EDHOC context.
 * \param[in] msg_2     	Buffer containing the message.
 * \param msg_2_len     	Size of the \p msg_2 buffer in bytes.
 * \param[out] ctxt	        On success, a view of the CIPHERTEXT_2A.
 * \param[out] ctxt_len	        On success, its length in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int parse_g_y_ciphertext_2a(struct edhoc_context *ctx,
				   const uint8_t *msg_2, size_t msg_2_len,
				   const uint8_t **ctxt, size_t *ctxt_len);

/* Static function definitions --------------------------------------------- */

STATIC int compose_g_y_ciphertext_2a(const struct edhoc_context *ctx,
				     const uint8_t *ctxt, size_t ctxt_len,
				     uint8_t *msg_2, size_t msg_2_size,
				     size_t *msg_2_len)
{
	const size_t g_y_len = ctx->ephemeral.own.length;

	EDHOC_MEM_ALLOC(uint8_t, buffer, g_y_len + ctxt_len);

	if (NULL == buffer) {
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	memcpy(buffer, ctx->ephemeral.own.value, g_y_len);
	memcpy(&buffer[g_y_len], ctxt, ctxt_len);

	const struct zcbor_string input = {
		.value = buffer,
		.len = EDHOC_MEM_ALLOC_SIZE(buffer),
	};

	const int ret = cbor_encode_message_2_G_Y_CIPHERTEXT_2(
		msg_2, msg_2_size, &input, msg_2_len);
	edhoc_zeroize(ctx, buffer, EDHOC_MEM_ALLOC_SIZE(buffer));
	EDHOC_MEM_FREE(buffer);

	if (ZCBOR_SUCCESS != ret) {
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int parse_g_y_ciphertext_2a(struct edhoc_context *ctx,
				   const uint8_t *msg_2, size_t msg_2_len,
				   const uint8_t **ctxt, size_t *ctxt_len)
{
	size_t len = 0;
	struct zcbor_string output = { 0 };

	const int ret = cbor_decode_message_2_G_Y_CIPHERTEXT_2(msg_2, msg_2_len,
							       &output, &len);

	if (ZCBOR_SUCCESS != ret) {
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	const size_t g_y_len =
		edhoc_selected_cipher_suite(ctx)->kem_ciphertext_length;

	if (output.len <= g_y_len) {
		return EDHOC_ERROR_MSG_2_PROCESS_FAILURE;
	}

	ctx->ephemeral.peer.length = g_y_len;
	memcpy(ctx->ephemeral.peer.value, output.value, g_y_len);

	*ctxt = output.value + g_y_len;
	*ctxt_len = output.len - g_y_len;

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

bool edhoc_psk_is_selected(const struct edhoc_context *ctx)
{
	return NULL != ctx &&
	       EDHOC_METHOD_4 == ctx->negotiation.selected_method;
}

/**
 * Steps for composition of message 2:
 *	1.  KEM encapsulate to the peer's G_X (produce G_Y and G_XY).
 *	2.  Compute Transcript Hash 2 (TH_2).
 *	3.  Compute Pseudo Random Key 2 (PRK_2e).
 *	4.  Compose EAD_2 if present.
 *	5.  Compute pseudorandom key (PRK_3e2m), which equals PRK_2e.
 *	6.  Prepare plaintext (PLAINTEXT_2A).
 *	7.  Compute key stream (KEYSTREAM_2A).
 *	8.  Compute Transcript Hash 3 (TH_3).
 *	9.  Compute ciphertext (CIPHERTEXT_2A).
 *      10. Cborise items for message 2.
 *      11. Release the message-2 scoped secrets (PRK_3e2m lives on).
 *      12. Clean-up EAD tokens.
 */
int edhoc_psk_message_2_compose(struct edhoc_context *ctx, uint8_t *msg_2,
				size_t msg_2_size, size_t *msg_2_len)
{
	EDHOC_LOG_INF("Compose PSK msg2 start");

	if (NULL == ctx || NULL == msg_2 || 0 == msg_2_size ||
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

	/* 1. KEM encapsulate to the peer's G_X. */
	ret = edhoc_key_schedule_encapsulate(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Encapsulate: %d", ret);
		return EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->ephemeral.own.value,
			      ctx->ephemeral.own.length, "G_Y");

	/* 2. Compute Transcript Hash 2 (TH_2). */
	const struct edhoc_th_input th_2 = {
		.target = EDHOC_TH_STATE_2,
	};

	ret = edhoc_th_compute(ctx, &th_2);

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

	/* 4. Compose EAD_2 if present. */
	ret = edhoc_ead_compose(ctx);

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	/* 5. Compute pseudorandom key (PRK_3e2m), which equals PRK_2e. */
	ret = edhoc_key_schedule_prk_advance(ctx, NULL, NULL, 0);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_3e2m: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 6. Prepare plaintext (PLAINTEXT_2A). */
	const struct edhoc_plaintext_input plaintext_input = {
		.id = EDHOC_PLAINTEXT_PSK_2A,
	};

	size_t plaintext_len = 0;
	ret = edhoc_plaintext_length(ctx, &plaintext_input, &plaintext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PLAINTEXT_2A length: %d", ret);
		return ret;
	}

	EDHOC_MEM_ALLOC(uint8_t, plaintext, plaintext_len);

	if (NULL == plaintext) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	plaintext_len = 0;
	ret = edhoc_plaintext_compose(ctx, &plaintext_input, plaintext,
				      EDHOC_MEM_ALLOC_SIZE(plaintext),
				      &plaintext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Prepare PLAINTEXT_2A: %d", ret);
		edhoc_zeroize(ctx, plaintext, EDHOC_MEM_ALLOC_SIZE(plaintext));
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(plaintext, plaintext_len, "PLAINTEXT_2A");

	/* 7. Compute key stream (KEYSTREAM_2A). */
	EDHOC_MEM_ALLOC(uint8_t, keystream, plaintext_len);

	if (NULL == keystream) {
		EDHOC_LOG_ERR("Memory allocation failed");
		edhoc_zeroize(ctx, plaintext, EDHOC_MEM_ALLOC_SIZE(plaintext));
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_cipher_keystream(ctx, keystream,
				     EDHOC_MEM_ALLOC_SIZE(keystream));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute KEYSTREAM_2A: %d", ret);
		edhoc_zeroize(ctx, keystream, EDHOC_MEM_ALLOC_SIZE(keystream));
		EDHOC_MEM_FREE(keystream);
		edhoc_zeroize(ctx, plaintext, EDHOC_MEM_ALLOC_SIZE(plaintext));
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(keystream, EDHOC_MEM_ALLOC_SIZE(keystream),
			      "KEYSTREAM_2A");

	/* 8. Compute Transcript Hash 3 (TH_3). */
	const struct edhoc_th_input th_3 = {
		.target = EDHOC_TH_STATE_3,
		.plaintext = plaintext,
		.plaintext_length = plaintext_len,
	};

	ret = edhoc_th_compute(ctx, &th_3);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_3: %d", ret);
		edhoc_zeroize(ctx, keystream, EDHOC_MEM_ALLOC_SIZE(keystream));
		EDHOC_MEM_FREE(keystream);
		edhoc_zeroize(ctx, plaintext, EDHOC_MEM_ALLOC_SIZE(plaintext));
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->state.th.value, ctx->state.th.length,
			      "TH_3");

	/* 9. Compute ciphertext (CIPHERTEXT_2A). */
	edhoc_cipher_xor(plaintext, keystream, plaintext_len);
	edhoc_zeroize(ctx, keystream, EDHOC_MEM_ALLOC_SIZE(keystream));
	EDHOC_MEM_FREE(keystream);

	EDHOC_LOG_HEXDUMP_DBG(plaintext, plaintext_len, "CIPHERTEXT_2A");

	/* 10. Cborise items for message 2. */
	ret = compose_g_y_ciphertext_2a(ctx, plaintext, plaintext_len, msg_2,
					msg_2_size, msg_2_len);
	edhoc_zeroize(ctx, plaintext, EDHOC_MEM_ALLOC_SIZE(plaintext));
	EDHOC_MEM_FREE(plaintext);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compose G_Y_CIPHERTEXT_2: %d", ret);
		return ret;
	}

	EDHOC_LOG_HEXDUMP_DBG(msg_2, *msg_2_len, "message_2");
	EDHOC_LOG_INF("Compose PSK msg2 end");

	/* 11. Release the message-2 scoped secrets (PRK_3e2m lives on). */
	ret = edhoc_key_slot_release_up_to(ctx, EDHOC_KEY_SLOT_PRK_3E2M);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Release message 2 secrets: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* 12. Clean-up EAD tokens. */
	edhoc_ead_reset(ctx);

	ctx->state.machine = EDHOC_SM_WAIT_M3;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}

/**
 * Steps for processing of message 2:
 *	1.  Decode cborised message 2.
 *	2.  Copy out CIPHERTEXT_2A.
 *	3.  KEM decapsulate the peer's G_Y (produce G_XY).
 *	4.  Compute Transcript Hash 2 (TH_2).
 *	5.  Compute Pseudo Random Key 2 (PRK_2e).
 *	6.  Compute key stream (KEYSTREAM_2A).
 *	7.  Compute plaintext (PLAINTEXT_2A).
 *	8.  Parse plaintext (PLAINTEXT_2A).
 *	9.  Process EAD if present.
 *      10. Compute pseudorandom key (PRK_3e2m), which equals PRK_2e.
 *      11. Compute Transcript Hash 3 (TH_3).
 *      12. Release the message-2 scoped secrets (PRK_3e2m lives on).
 *      13. Clean-up EAD tokens.
 */
int edhoc_psk_message_2_process(struct edhoc_context *ctx, const uint8_t *msg_2,
				size_t msg_2_len)
{
	EDHOC_LOG_INF("Process PSK msg2 start");

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

	/* 1. Decode cborised message 2. */
	const uint8_t *ctxt = NULL;
	size_t ctxt_len = 0;

	int ret = parse_g_y_ciphertext_2a(ctx, msg_2, msg_2_len, &ctxt,
					  &ctxt_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse G_Y_CIPHERTEXT_2: %d", ret);
		return ret;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->ephemeral.peer.value,
			      ctx->ephemeral.peer.length, "G_Y");
	EDHOC_LOG_HEXDUMP_DBG(ctxt, ctxt_len, "CIPHERTEXT_2A");

	/* 2. Copy out CIPHERTEXT_2A; the XOR is done in place. */
	EDHOC_MEM_ALLOC(uint8_t, plaintext, ctxt_len);

	if (NULL == plaintext) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	memcpy(plaintext, ctxt, ctxt_len);

	/* 3. KEM decapsulate the peer's G_Y. */
	ret = edhoc_key_schedule_decapsulate(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Decapsulate: %d", ret);
		edhoc_zeroize(ctx, plaintext, EDHOC_MEM_ALLOC_SIZE(plaintext));
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE;
	}

	/* 4. Compute Transcript Hash 2 (TH_2). */
	const struct edhoc_th_input th_2 = {
		.target = EDHOC_TH_STATE_2,
	};

	ret = edhoc_th_compute(ctx, &th_2);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_2: %d", ret);
		edhoc_zeroize(ctx, plaintext, EDHOC_MEM_ALLOC_SIZE(plaintext));
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->state.th.value, ctx->state.th.length,
			      "TH_2");

	/* 5. Compute Pseudo Random Key 2 (PRK_2e). */
	ret = edhoc_key_schedule_prk_initial(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_2e: %d", ret);
		edhoc_zeroize(ctx, plaintext, EDHOC_MEM_ALLOC_SIZE(plaintext));
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 6. Compute key stream (KEYSTREAM_2A). */
	EDHOC_MEM_ALLOC(uint8_t, keystream, ctxt_len);

	if (NULL == keystream) {
		EDHOC_LOG_ERR("Memory allocation failed");
		edhoc_zeroize(ctx, plaintext, EDHOC_MEM_ALLOC_SIZE(plaintext));
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_cipher_keystream(ctx, keystream,
				     EDHOC_MEM_ALLOC_SIZE(keystream));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute KEYSTREAM_2A: %d", ret);
		edhoc_zeroize(ctx, keystream, EDHOC_MEM_ALLOC_SIZE(keystream));
		EDHOC_MEM_FREE(keystream);
		edhoc_zeroize(ctx, plaintext, EDHOC_MEM_ALLOC_SIZE(plaintext));
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(keystream, EDHOC_MEM_ALLOC_SIZE(keystream),
			      "KEYSTREAM_2A");

	/* 7. Compute plaintext (PLAINTEXT_2A). */
	edhoc_cipher_xor(plaintext, keystream, ctxt_len);
	edhoc_zeroize(ctx, keystream, EDHOC_MEM_ALLOC_SIZE(keystream));
	EDHOC_MEM_FREE(keystream);

	EDHOC_LOG_HEXDUMP_DBG(plaintext, ctxt_len, "PLAINTEXT_2A");

	/* 8. Parse plaintext (PLAINTEXT_2A). */
	ret = edhoc_plaintext_parse(ctx, EDHOC_PLAINTEXT_PSK_2A, plaintext,
				    ctxt_len, NULL);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse PLAINTEXT_2A: %d", ret);
		edhoc_zeroize(ctx, plaintext, EDHOC_MEM_ALLOC_SIZE(plaintext));
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_MSG_2_PROCESS_FAILURE;
	}

	/* 9. Process EAD if present. */
	ret = edhoc_ead_process(ctx);

	if (EDHOC_SUCCESS != ret) {
		edhoc_zeroize(ctx, plaintext, EDHOC_MEM_ALLOC_SIZE(plaintext));
		EDHOC_MEM_FREE(plaintext);
		return ret;
	}

	/* 10. Compute pseudorandom key (PRK_3e2m), which equals PRK_2e. */
	ret = edhoc_key_schedule_prk_advance(ctx, NULL, NULL, 0);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_3e2m: %d", ret);
		edhoc_zeroize(ctx, plaintext, EDHOC_MEM_ALLOC_SIZE(plaintext));
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 11. Compute Transcript Hash 3 (TH_3). */
	const struct edhoc_th_input th_3 = {
		.target = EDHOC_TH_STATE_3,
		.plaintext = plaintext,
		.plaintext_length = ctxt_len,
	};

	ret = edhoc_th_compute(ctx, &th_3);
	edhoc_zeroize(ctx, plaintext, EDHOC_MEM_ALLOC_SIZE(plaintext));
	EDHOC_MEM_FREE(plaintext);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_3: %d", ret);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->state.th.value, ctx->state.th.length,
			      "TH_3");
	EDHOC_LOG_INF("Process PSK msg2 end");

	/* 12. Release the message-2 scoped secrets (PRK_3e2m lives on). */
	ret = edhoc_key_slot_release_up_to(ctx, EDHOC_KEY_SLOT_PRK_3E2M);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Release message 2 secrets: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* 13. Clean-up EAD tokens. */
	edhoc_ead_reset(ctx);

	ctx->state.machine = EDHOC_SM_VERIFIED_M2;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}
