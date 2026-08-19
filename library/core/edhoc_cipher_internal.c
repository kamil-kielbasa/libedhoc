/**
 * \file    edhoc_cipher_internal.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message encryption implementation.
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
#include <edhoc/types.h>
#include <edhoc/values.h>
#include <edhoc/cipher_suite.h>
#include <edhoc/crypto.h>

/* EDHOC internal headers: */
#include "edhoc_cipher_internal.h"
#include "edhoc_context_internal.h"
#include "edhoc_key_slot_internal.h"
#include "edhoc_kdf_internal.h"
#include "edhoc_cbor_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_backend_log.h"

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_types.h>
#include <backend_cbor_enc_structure_encode.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Module defines ---------------------------------------------------------- */

/** COSE context string of the Enc_structure used by messages 3 and 4. */
#define EDHOC_CIPHER_AAD_CONTEXT "Encrypt0"

/* Module types and type definitiones -------------------------------------- */

/**
 * \brief Everything that separates the AEAD of message 3 from that of
 *        message 4.
 */
struct aead_params {
	/** Handle of the PRK the key and the nonce are derived from. */
	enum edhoc_key_slot_id prk_slot;
	/** Handle the derived content-encryption key is published in. */
	enum edhoc_key_slot_id key_slot;
	/** EDHOC_KDF label of the content-encryption key. */
	int32_t key_label;
	/** EDHOC_KDF label of the nonce. */
	int32_t iv_label;
	/** Transcript hash the message must be at. */
	enum edhoc_th_state th_stage;
	/** PRK the message must be at. */
	enum edhoc_prk_state prk_state;
};

/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Select the AEAD parameters of the message being handled.
 *
 * \param[in] ctx               EDHOC context.
 * \param[out] params           On success, the selected parameters.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int comp_aead_params(const struct edhoc_context *ctx,
			    struct aead_params *params);

/* Static function definitions --------------------------------------------- */

STATIC int comp_aead_params(const struct edhoc_context *ctx,
			    struct aead_params *params)
{
	switch (ctx->state.message) {
	case EDHOC_MESSAGE_3:
		*params = (struct aead_params){
			.prk_slot = EDHOC_KEY_SLOT_PRK_3E2M,
			.key_slot = EDHOC_KEY_SLOT_K_3,
			.key_label = EDHOC_KDF_LABEL_K_3,
			.iv_label = EDHOC_KDF_LABEL_IV_3,
			.th_stage = EDHOC_TH_STATE_3,
			.prk_state = EDHOC_PRK_STATE_3E2M,
		};
		return EDHOC_SUCCESS;

	case EDHOC_MESSAGE_4:
		*params = (struct aead_params){
			.prk_slot = EDHOC_KEY_SLOT_PRK_4E3M,
			.key_slot = EDHOC_KEY_SLOT_K_4,
			.key_label = EDHOC_KDF_LABEL_K_4,
			.iv_label = EDHOC_KDF_LABEL_IV_4,
			.th_stage = EDHOC_TH_STATE_4,
			.prk_state = EDHOC_PRK_STATE_4E3M,
		};
		return EDHOC_SUCCESS;

	case EDHOC_MESSAGE_1:
	case EDHOC_MESSAGE_2:
	default:
		return EDHOC_ERROR_BAD_STATE;
	}
}

/* Module interface function definitions ----------------------------------- */

int edhoc_cipher_aad_length(const struct edhoc_context *ctx, size_t *length)
{
	if (NULL == ctx || NULL == length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	size_t len = 0;

	len += sizeof(EDHOC_CIPHER_AAD_CONTEXT) +
	       edhoc_cbor_tstr_head_length(sizeof(EDHOC_CIPHER_AAD_CONTEXT));
	len += edhoc_cbor_bstr_head_length(0);
	len += ctx->state.th.length +
	       edhoc_cbor_bstr_head_length(ctx->state.th.length);

	*length = len;

	return EDHOC_SUCCESS;
}

int edhoc_cipher_derive(struct edhoc_context *ctx, uint8_t *iv,
			size_t iv_length, uint8_t *aad, size_t aad_length)
{
	if (NULL == ctx || NULL == iv || 0 == iv_length || NULL == aad ||
	    0 == aad_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	struct aead_params params = { 0 };
	int ret = comp_aead_params(ctx, &params);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Invalid message for AEAD: %d",
			      ctx->state.message);
		return ret;
	}

	if (params.th_stage != ctx->state.th.stage) {
		EDHOC_LOG_ERR("Invalid TH state: %d, %d", ctx->state.th.stage,
			      params.th_stage);
		return EDHOC_ERROR_BAD_STATE;
	}

	if (params.prk_state != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Invalid PRK state: %d, %d", ctx->state.prk_state,
			      params.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);
	const void *prk_key_id = edhoc_key_slot_id(ctx, params.prk_slot);

	ret = edhoc_kdf_expand(ctx, prk_key_id, params.key_label,
			       ctx->state.th.value, ctx->state.th.length,
			       EDHOC_KEY_USAGE_AEAD,
			       edhoc_key_slot_id_mut(ctx, params.key_slot),
			       csuite->aead_key_length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Derive K_%d: %d", ctx->state.message + 1, ret);
		return ret;
	}

	edhoc_key_slot_mark_present(ctx, params.key_slot);

	ret = edhoc_kdf_expand_raw(ctx, prk_key_id, params.iv_label,
				   ctx->state.th.value, ctx->state.th.length,
				   iv, iv_length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Derive IV_%d: %d", ctx->state.message + 1, ret);
		return ret;
	}

	const struct enc_structure cose_enc_0 = {
		.enc_structure_protected.value = NULL,
		.enc_structure_protected.len = 0,
		.enc_structure_external_aad.value = ctx->state.th.value,
		.enc_structure_external_aad.len = ctx->state.th.length,
	};

	size_t len = 0;
	ret = cbor_encode_enc_structure(aad, aad_length, &cose_enc_0, &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc AAD_%d: %d", ctx->state.message + 1,
			      ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

int edhoc_cipher_encrypt(const struct edhoc_context *ctx, const uint8_t *iv,
			 size_t iv_length, const uint8_t *aad,
			 size_t aad_length, const uint8_t *plaintext,
			 size_t plaintext_length, uint8_t *ciphertext,
			 size_t ciphertext_size, size_t *ciphertext_length)
{
	/* PLAINTEXT_4 is empty when message 4 carries no EAD_4, so a zero
	 * length is a valid AEAD input here. */
	if (NULL == ctx || NULL == iv || 0 == iv_length || NULL == aad ||
	    0 == aad_length || NULL == plaintext || NULL == ciphertext ||
	    0 == ciphertext_size || NULL == ciphertext_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	struct aead_params params = { 0 };
	int ret = comp_aead_params(ctx, &params);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Invalid message for AEAD: %d",
			      ctx->state.message);
		return ret;
	}

	ret = edhoc_crypto(ctx)->aead_encrypt(
		ctx->user_context, edhoc_key_slot_id(ctx, params.key_slot), iv,
		iv_length, aad, aad_length, plaintext, plaintext_length,
		ciphertext, ciphertext_size, ciphertext_length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Encrypt CIPHERTEXT_%d: %d",
			      ctx->state.message + 1, ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

int edhoc_cipher_decrypt(const struct edhoc_context *ctx, const uint8_t *iv,
			 size_t iv_length, const uint8_t *aad,
			 size_t aad_length, const uint8_t *ciphertext,
			 size_t ciphertext_length, uint8_t *plaintext,
			 size_t plaintext_length)
{
	/* PLAINTEXT_4 is empty when message 4 carries no EAD_4, so a zero
	 * length is a valid AEAD output here. */
	if (NULL == ctx || NULL == iv || 0 == iv_length || NULL == aad ||
	    0 == aad_length || NULL == ciphertext || 0 == ciphertext_length ||
	    NULL == plaintext) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	struct aead_params params = { 0 };
	int ret = comp_aead_params(ctx, &params);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Invalid message for AEAD: %d",
			      ctx->state.message);
		return ret;
	}

	size_t len = 0;
	ret = edhoc_crypto(ctx)->aead_decrypt(
		ctx->user_context, edhoc_key_slot_id(ctx, params.key_slot), iv,
		iv_length, aad, aad_length, ciphertext, ciphertext_length,
		plaintext, plaintext_length, &len);

	if (EDHOC_SUCCESS != ret || plaintext_length != len) {
		EDHOC_LOG_ERR("Decrypt CIPHERTEXT_%d: %d, %zu, %zu",
			      ctx->state.message + 1, ret, plaintext_length,
			      len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

int edhoc_cipher_keystream(const struct edhoc_context *ctx, uint8_t *keystream,
			   size_t keystream_length)
{
	if (NULL == ctx || NULL == keystream || 0 == keystream_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_2 != ctx->state.th.stage) {
		EDHOC_LOG_ERR("Invalid TH state for keystream_2: %d",
			      ctx->state.th.stage);
		return EDHOC_ERROR_BAD_STATE;
	}

	/* For methods 0/2 PRK_2e was moved into PRK_3e2m, so read whichever
	 * handle still holds it. */
	const void *prk_2e_key_id =
		edhoc_key_slot_present(ctx, EDHOC_KEY_SLOT_PRK_2E) ?
			edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_2E) :
			edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_3E2M);

	const int ret = edhoc_kdf_expand_raw(ctx, prk_2e_key_id,
					     EDHOC_KDF_LABEL_KEYSTREAM_2,
					     ctx->state.th.value,
					     ctx->state.th.length, keystream,
					     keystream_length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Derive KEYSTREAM_2: %d, %zu", ret,
			      keystream_length);
		return ret;
	}

	return EDHOC_SUCCESS;
}

void edhoc_cipher_xor(uint8_t *restrict data, const uint8_t *restrict keystream,
		      size_t length)
{
	for (size_t i = 0; i < length; ++i)
		data[i] ^= keystream[i];
}
