/**
 * \file    edhoc_classic_message_4.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message 4 compose & process.
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
#include "edhoc_classic_internal.h"
#include "edhoc_context_internal.h"
#include "edhoc_key_slot_internal.h"
#include "edhoc_kdf_internal.h"
#include "edhoc_cipher_internal.h"
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
#include <backend_cbor_message_4_encode.h>
#include <backend_cbor_message_4_decode.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Encode CIPHERTEXT_4 as message 4 (RFC 9528: 5.5.1).
 *
 * \param[in] ciphertext	Buffer containing the CIPHERTEXT_4.
 * \param ciphertext_len	Size of the \p ciphertext buffer in bytes.
 * \param[out] msg_4		Buffer where the generated message 4 is to be written.
 * \param msg_4_size		Size of the \p msg_4 buffer in bytes.
 * \param[out] msg_4_len	On success, the number of bytes that make up the message 4.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int compose_ciphertext_4(const uint8_t *ciphertext,
				size_t ciphertext_len, uint8_t *msg_4,
				size_t msg_4_size, size_t *msg_4_len);

/**
 * \brief Decode message 4 into a view of CIPHERTEXT_4 (RFC 9528: 5.5.1).
 *
 * \param[in] msg_4		Buffer containing the message 4.
 * \param msg_4_len		Size of the \p msg_4 buffer in bytes.
 * \param[out] ctxt_4		On success, a view of the CIPHERTEXT_4.
 * \param[out] ctxt_4_len	On success, the CIPHERTEXT_4 length in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int parse_ciphertext_4(const uint8_t *msg_4, size_t msg_4_len,
			      const uint8_t **ctxt_4, size_t *ctxt_4_len);

/* Static function definitions --------------------------------------------- */

STATIC int compose_ciphertext_4(const uint8_t *ciphertext,
				size_t ciphertext_len, uint8_t *msg_4,
				size_t msg_4_size, size_t *msg_4_len)
{
	if (NULL == ciphertext || 0 == ciphertext_len || NULL == msg_4 ||
	    0 == msg_4_size || NULL == msg_4_len) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const struct zcbor_string input = {
		.value = ciphertext,
		.len = ciphertext_len,
	};

	const int ret = cbor_encode_message_4_CIPHERTEXT_4(msg_4, msg_4_size,
							   &input, msg_4_len);

	if (ZCBOR_SUCCESS != ret) {
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int parse_ciphertext_4(const uint8_t *msg_4, size_t msg_4_len,
			      const uint8_t **ctxt_4, size_t *ctxt_4_len)
{
	if (NULL == msg_4 || 0 == msg_4_len || NULL == ctxt_4 ||
	    NULL == ctxt_4_len) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	size_t len = 0;
	struct zcbor_string output = { 0 };

	const int ret = cbor_decode_message_4_CIPHERTEXT_4(msg_4, msg_4_len,
							   &output, &len);

	if (ZCBOR_SUCCESS != ret) {
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	*ctxt_4 = output.value;
	*ctxt_4_len = output.len;

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
 *      7.  Release the message-4 scoped secrets (PRK_4e3m lives on).
 *      8.  Clean-up EAD tokens.
 */
int edhoc_classic_message_4_compose(struct edhoc_context *ctx, uint8_t *msg_4,
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

	if (EDHOC_SM_COMPLETED != ctx->state.machine ||
	    EDHOC_TH_STATE_4 != ctx->state.th.stage ||
	    EDHOC_PRK_STATE_4E3M != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d, %d", ctx->state.machine,
			      ctx->state.th.stage, ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->state.machine = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->state.message = EDHOC_MESSAGE_4;
	ctx->state.role = EDHOC_ROLE_RESPONDER;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);

	/* 2. Compose EAD_4 if present. */
	ret = edhoc_ead_compose(ctx);

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	/* 3a. Compute plaintext length (PLAINTEXT_4). */
	const struct edhoc_plaintext_input plaintext_input = {
		.id = EDHOC_PLAINTEXT_CLASSIC_4,
	};

	size_t plaintext_len = 0;
	ret = edhoc_plaintext_length(ctx, &plaintext_input, &plaintext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PLAINTEXT_4 length: %d", ret);
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* PLAINTEXT_4 is empty when there is no EAD_4; allocate at least one
	 * byte so the stack backend never forms a zero-length VLA (UB). */
	EDHOC_MEM_ALLOC(uint8_t, plaintext,
			0 != plaintext_len ? plaintext_len : 1);
	if (NULL == plaintext) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	/* 3b. Prepare plaintext (PLAINTEXT_4). */
	ret = edhoc_plaintext_compose(ctx, &plaintext_input, plaintext,
				      EDHOC_MEM_ALLOC_SIZE(plaintext),
				      &plaintext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Prepare PLAINTEXT_4: %d", ret);
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(plaintext, plaintext_len, "PLAINTEXT_4");

	/* 4. Compute K_4, IV_4 and AAD_4. */
	EDHOC_MEM_ALLOC(uint8_t, iv, csuite->aead_iv_length);
	if (NULL == iv) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	size_t aad_len = 0;
	ret = edhoc_cipher_aad_length(ctx, &aad_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(iv);
		EDHOC_MEM_FREE(plaintext);
		return ret;
	}

	EDHOC_MEM_ALLOC(uint8_t, aad, aad_len);
	if (NULL == aad) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(iv);
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_cipher_derive(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv), aad,
				  EDHOC_MEM_ALLOC_SIZE(aad));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute K_4/IV_4/AAD_4: %d", ret);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(iv, EDHOC_MEM_ALLOC_SIZE(iv), "IV_4");
	EDHOC_LOG_HEXDUMP_DBG(aad, EDHOC_MEM_ALLOC_SIZE(aad), "AAD_4");

	/* 5. Compute ciphertext. */
	size_t ciphertext_len = 0;
	EDHOC_MEM_ALLOC(uint8_t, ciphertext,
			plaintext_len + csuite->aead_tag_length);
	if (NULL == ciphertext) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_cipher_encrypt(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv), aad,
				   EDHOC_MEM_ALLOC_SIZE(aad), plaintext,
				   plaintext_len, ciphertext,
				   EDHOC_MEM_ALLOC_SIZE(ciphertext),
				   &ciphertext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute CIPHERTEXT_4: %d", ret);
		EDHOC_MEM_FREE(ciphertext);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		EDHOC_MEM_FREE(plaintext);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_MEM_FREE(aad);
	EDHOC_MEM_FREE(iv);
	EDHOC_MEM_FREE(plaintext);

	EDHOC_LOG_HEXDUMP_DBG(ciphertext, ciphertext_len, "CIPHERTEXT_4");

	/* 6. Generate edhoc message 4. */
	ret = compose_ciphertext_4(ciphertext, ciphertext_len, msg_4,
				   msg_4_size, msg_4_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Generate message_4: %d", ret);
		EDHOC_MEM_FREE(ciphertext);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_MEM_FREE(ciphertext);

	EDHOC_LOG_HEXDUMP_DBG(msg_4, *msg_4_len, "message_4");
	EDHOC_LOG_INF("Compose msg4 end");

	/* 7. Release the message-4 scoped secrets (PRK_4e3m lives on). */
	ret = edhoc_key_slot_release_up_to(ctx, EDHOC_KEY_SLOT_PRK_4E3M);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Release message 4 secrets: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* 8. Clean-up EAD tokens. */
	edhoc_ead_reset(ctx);

	ctx->state.machine = EDHOC_SM_PERSISTED;
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
 *      7. Release the message-4 scoped secrets (PRK_4e3m lives on).
 */
int edhoc_classic_message_4_process(struct edhoc_context *ctx,
				    const uint8_t *msg_4, size_t msg_4_len)
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

	if (EDHOC_SM_COMPLETED != ctx->state.machine ||
	    EDHOC_TH_STATE_4 != ctx->state.th.stage ||
	    EDHOC_PRK_STATE_4E3M != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d, %d", ctx->state.machine,
			      ctx->state.th.stage, ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->state.machine = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->state.message = EDHOC_MESSAGE_4;
	ctx->state.role = EDHOC_ROLE_INITIATOR;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);

	/* 2. CBOR decode message 3. */
	const uint8_t *ctxt = NULL;
	size_t ctxt_len = 0;

	ret = parse_ciphertext_4(msg_4, msg_4_len, &ctxt, &ctxt_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse message_4: %d", ret);
		return ret;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctxt, ctxt_len, "CIPHERTEXT_4");

	if (ctxt_len < csuite->aead_tag_length) {
		EDHOC_LOG_ERR("CIPHERTEXT_4 shorter than the AEAD tag: %zu",
			      ctxt_len);
		return EDHOC_ERROR_MSG_4_PROCESS_FAILURE;
	}

	/* 3. Compute K_4, IV_4 and AAD_4. */
	EDHOC_MEM_ALLOC(uint8_t, iv, csuite->aead_iv_length);
	if (NULL == iv) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	size_t aad_len = 0;
	ret = edhoc_cipher_aad_length(ctx, &aad_len);

	if (EDHOC_SUCCESS != ret) {
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
		EDHOC_LOG_ERR("Compute K_4/IV_4/AAD_4: %d", ret);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(iv, EDHOC_MEM_ALLOC_SIZE(iv), "IV_4");
	EDHOC_LOG_HEXDUMP_DBG(aad, EDHOC_MEM_ALLOC_SIZE(aad), "AAD_4");

	/* 4. Decrypt ciphertext. PLAINTEXT_4 is empty when there is no EAD_4;
	 * allocate at least one byte so the stack backend never forms a
	 * zero-length VLA (UB). */
	const size_t plaintext_len = ctxt_len - csuite->aead_tag_length;
	EDHOC_MEM_ALLOC(uint8_t, ptxt, 0 != plaintext_len ? plaintext_len : 1);
	if (NULL == ptxt) {
		EDHOC_LOG_ERR("Memory allocation failed");
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_cipher_decrypt(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv), aad,
				   EDHOC_MEM_ALLOC_SIZE(aad), ctxt, ctxt_len,
				   ptxt, plaintext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Decrypt CIPHERTEXT_4: %d", ret);
		EDHOC_MEM_FREE(ptxt);
		EDHOC_MEM_FREE(aad);
		EDHOC_MEM_FREE(iv);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_MEM_FREE(aad);
	EDHOC_MEM_FREE(iv);

	EDHOC_LOG_HEXDUMP_DBG(ptxt, plaintext_len, "PLAINTEXT_4");

	/* 5. Parse CBOR plaintext (PLAINTEXT_4). */
	ret = edhoc_plaintext_parse(ctx, EDHOC_PLAINTEXT_CLASSIC_4, ptxt,
				    plaintext_len, NULL);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse PLAINTEXT_4: %d", ret);
		EDHOC_MEM_FREE(ptxt);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* 6. Process EAD_4 if present.
	 *
	 * NOTE: ctx->ead.token[].value are zero-copy pointers into the
	 * plaintext buffer, so it must remain allocated until the EAD process
	 * callback has consumed the tokens.
	 */
	ret = edhoc_ead_process(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_MEM_FREE(ptxt);
		return ret;
	}

	EDHOC_MEM_FREE(ptxt);

	EDHOC_LOG_INF("Process msg4 end");

	/* 7. Release the message-4 scoped secrets (PRK_4e3m lives on). */
	ret = edhoc_key_slot_release_up_to(ctx, EDHOC_KEY_SLOT_PRK_4E3M);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Release message 4 secrets: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	edhoc_ead_reset(ctx);

	ctx->state.machine = EDHOC_SM_PERSISTED;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}
