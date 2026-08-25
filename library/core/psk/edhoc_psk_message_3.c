/**
 * \file    edhoc_psk_message_3.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC-PSK message 3 compose & process
 *          (draft-ietf-lake-edhoc-psk: 5.3).
 *
 *          Message 3 nests two protections: CIPHERTEXT_3B is a COSE_Encrypt0
 *          over PLAINTEXT_3B whose external_aad names both credentials, and
 *          CIPHERTEXT_3A is that object plus ID_CRED_PSK run through a
 *          keystream. There is no MAC_3 and no signature.
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
#include "edhoc_psk_internal.h"
#include "edhoc_context_internal.h"
#include "edhoc_key_slot_internal.h"
#include "edhoc_key_schedule_internal.h"
#include "edhoc_cipher_internal.h"
#include "edhoc_transcript_hash_internal.h"
#include "edhoc_ead_internal.h"
#include "edhoc_macros_internal.h"
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
#include <backend_cbor_bstr_type_encode.h>
#include <backend_cbor_message_3_encode.h>
#include <backend_cbor_message_3_decode.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */

/**
 * \brief The four items that draft-ietf-lake-edhoc-psk: 4 and 5.3.2 feed to
 *        both external_aad and TH_4, already CBOR-encoded and laid out back to
 *        back so that \p buf is the external_aad content verbatim.
 */
struct psk_context {
	/** ID_CRED_PSK in the compact encoding. */
	uint8_t *id_cred;
	/** Size of the \p id_cred buffer in bytes. */
	size_t id_cred_len;

	/** TH_3. */
	uint8_t *th;
	/** Size of the \p th buffer in bytes. */
	size_t th_len;

	/** CRED_I. */
	uint8_t *cred_i;
	/** Size of the \p cred_i buffer in bytes. */
	size_t cred_i_len;

	/** CRED_R. */
	uint8_t *cred_r;
	/** Size of the \p cred_r buffer in bytes. */
	size_t cred_r_len;

	/** Size of the \p buf buffer in bytes. */
	size_t buf_len;
	/** Flexible array member buffer. */
	uint8_t buf[];
};

/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Compute required buffer length for the PSK context.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] material		ID_CRED_PSK, CRED_I and CRED_R encoder input.
 * \param[out] length		On success, the required number of bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int
psk_context_length(const struct edhoc_context *ctx,
		   const struct edhoc_credential_material_psk *material,
		   size_t *length);

/**
 * \brief CBOR-encode the items of the PSK context.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] material		ID_CRED_PSK, CRED_I and CRED_R encoder input.
 * \param[out] psk_ctx		On success, the generated PSK context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int
psk_context_compose(const struct edhoc_context *ctx,
		    const struct edhoc_credential_material_psk *material,
		    struct psk_context *psk_ctx);

/* Static function definitions --------------------------------------------- */

STATIC int
psk_context_length(const struct edhoc_context *ctx,
		   const struct edhoc_credential_material_psk *material,
		   size_t *length)
{
	size_t len = 0;
	size_t item_len = 0;

	int ret = edhoc_th_encoded_length(ctx->state.th.length, &item_len);

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	len += item_len;

	ret = edhoc_credential_psk_id_cred_length(material, &item_len);

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	len += item_len;

	ret = edhoc_credential_psk_creds_length(material, &item_len);

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	len += item_len;

	*length = len;

	return EDHOC_SUCCESS;
}

STATIC int
psk_context_compose(const struct edhoc_context *ctx,
		    const struct edhoc_credential_material_psk *material,
		    struct psk_context *psk_ctx)
{
	size_t offset = 0;
	size_t len = 0;

	psk_ctx->id_cred = &psk_ctx->buf[offset];

	int ret = edhoc_credential_psk_encode_id_cred(
		material, psk_ctx->id_cred, psk_ctx->buf_len - offset, &len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc ID_CRED_PSK: %d", ret);
		return ret;
	}

	psk_ctx->id_cred_len = len;
	offset += len;

	psk_ctx->th = &psk_ctx->buf[offset];

	const struct zcbor_string th = {
		.value = ctx->state.th.value,
		.len = ctx->state.th.length,
	};

	len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		psk_ctx->th, psk_ctx->buf_len - offset, &th, &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc TH_3: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	psk_ctx->th_len = len;
	offset += len;

	psk_ctx->cred_i = &psk_ctx->buf[offset];

	ret = edhoc_credential_psk_encode_creds(material, psk_ctx->cred_i,
						psk_ctx->buf_len - offset,
						&psk_ctx->cred_i_len,
						&psk_ctx->cred_r_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc CRED_I and CRED_R: %d", ret);
		return ret;
	}

	psk_ctx->cred_r = &psk_ctx->cred_i[psk_ctx->cred_i_len];
	offset += psk_ctx->cred_i_len + psk_ctx->cred_r_len;

	psk_ctx->buf_len = offset;

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

/**
 * Steps for composition of message 3:
 *	1.  Choose most preferred cipher suite.
 *	2.  Compose EAD_3 if present.
 *	3.  Select authentication credential.
 *	4.  Compute PRK_4e3m.
 *	5a. Compute required buffer length for the PSK context.
 *	5b. Cborise ID_CRED_PSK, TH_3, CRED_I and CRED_R.
 *	6.  Compute K_3, IV_3 and AAD_3.
 *	7.  Prepare plaintext (PLAINTEXT_3B).
 *	8.  Compute ciphertext (CIPHERTEXT_3B).
 *	9.  Prepare plaintext (PLAINTEXT_3A).
 *	10. Compute key stream (KEYSTREAM_3A).
 *	11. Compute ciphertext (CIPHERTEXT_3A).
 *	12. Compute transcript hash 4.
 *	13. Generate edhoc message 3.
 *	14. Release the message-3 scoped secrets (PRK_4e3m lives on).
 *	15. Clean-up EAD tokens.
 */
int edhoc_psk_message_3_compose(struct edhoc_context *ctx, uint8_t *msg_3,
				size_t msg_3_size, size_t *msg_3_len)
{
	EDHOC_LOG_INF("Compose PSK msg3 start");

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

	ret = edhoc_credential_validate_selected(
		ctx->negotiation.selected_method, &selected);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Validate selected credential: %d", ret);
		return ret;
	}

	struct edhoc_credential_material_psk material = { 0 };

	ret = edhoc_credential_psk_material_from_selected(&selected, &material);

	if (EDHOC_SUCCESS != ret) {
		return ret;
	}

	/* 4. Compute PRK_4e3m. */
	ret = edhoc_key_schedule_prk_advance(ctx, selected.psk.psk_key_id, NULL,
					     0);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_4e3m: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 5a. Compute required buffer length for the PSK context. */
	size_t psk_context_len = 0;
	ret = psk_context_length(ctx, &material, &psk_context_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PSK context length: %d", ret);
		return ret;
	}

	/* 5b. Cborise ID_CRED_PSK, TH_3, CRED_I and CRED_R. */
	EDHOC_MEM_ALLOC(uint8_t, psk_context_buf,
			sizeof(struct psk_context) + psk_context_len);

	if (NULL == psk_context_buf) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	struct psk_context *psk_ctx = (void *)psk_context_buf;
	psk_ctx->buf_len = psk_context_len;

	ret = psk_context_compose(ctx, &material, psk_ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compose PSK context: %d", ret);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return ret;
	}

	EDHOC_LOG_HEXDUMP_DBG(psk_ctx->id_cred, psk_ctx->id_cred_len,
			      "ID_CRED_PSK");
	EDHOC_LOG_HEXDUMP_DBG(psk_ctx->cred_i, psk_ctx->cred_i_len, "CRED_I");
	EDHOC_LOG_HEXDUMP_DBG(psk_ctx->cred_r, psk_ctx->cred_r_len, "CRED_R");
	EDHOC_LOG_HEXDUMP_DBG(psk_ctx->buf, psk_ctx->buf_len, "external_aad_3");

	/* 6. Compute K_3, IV_3 and AAD_3. */
	EDHOC_MEM_ALLOC(uint8_t, iv, csuite->aead_iv_length);

	if (NULL == iv) {
		EDHOC_LOG_ERR("Memory allocation failed");
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	size_t aad_len = 0;
	ret = edhoc_cipher_aad_length(ctx, psk_ctx->buf_len, &aad_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute AAD_3 length: %d", ret);
		edhoc_zeroize(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv));
		EDHOC_MEM_FREE(iv);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return ret;
	}

	EDHOC_MEM_ALLOC(uint8_t, aad, aad_len);

	if (NULL == aad) {
		EDHOC_LOG_ERR("Memory allocation failed");
		edhoc_zeroize(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv));
		EDHOC_MEM_FREE(iv);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_cipher_derive(ctx, psk_ctx->buf, psk_ctx->buf_len, iv,
				  EDHOC_MEM_ALLOC_SIZE(iv), aad,
				  EDHOC_MEM_ALLOC_SIZE(aad));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute K_3: %d", ret);
		edhoc_zeroize(ctx, aad, EDHOC_MEM_ALLOC_SIZE(aad));
		EDHOC_MEM_FREE(aad);
		edhoc_zeroize(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv));
		EDHOC_MEM_FREE(iv);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(iv, EDHOC_MEM_ALLOC_SIZE(iv), "IV_3");
	EDHOC_LOG_HEXDUMP_DBG(aad, EDHOC_MEM_ALLOC_SIZE(aad), "AAD_3");

	/* 7. Prepare plaintext (PLAINTEXT_3B). */
	const struct edhoc_plaintext_input plaintext_3b_input = {
		.id = EDHOC_PLAINTEXT_PSK_3B,
	};

	size_t plaintext_3b_len = 0;
	ret = edhoc_plaintext_length(ctx, &plaintext_3b_input,
				     &plaintext_3b_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PLAINTEXT_3B length: %d", ret);
		edhoc_zeroize(ctx, aad, EDHOC_MEM_ALLOC_SIZE(aad));
		EDHOC_MEM_FREE(aad);
		edhoc_zeroize(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv));
		EDHOC_MEM_FREE(iv);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return ret;
	}

	/* PLAINTEXT_3B is empty when there is no EAD_3; allocate at least one
	 * byte so the stack backend never forms a zero-length VLA (UB). */
	EDHOC_MEM_ALLOC(uint8_t, plaintext_3b,
			0 != plaintext_3b_len ? plaintext_3b_len : 1);

	if (NULL == plaintext_3b) {
		EDHOC_LOG_ERR("Memory allocation failed");
		edhoc_zeroize(ctx, aad, EDHOC_MEM_ALLOC_SIZE(aad));
		EDHOC_MEM_FREE(aad);
		edhoc_zeroize(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv));
		EDHOC_MEM_FREE(iv);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	plaintext_3b_len = 0;
	ret = edhoc_plaintext_compose(ctx, &plaintext_3b_input, plaintext_3b,
				      EDHOC_MEM_ALLOC_SIZE(plaintext_3b),
				      &plaintext_3b_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Prepare PLAINTEXT_3B: %d", ret);
		edhoc_zeroize(ctx, plaintext_3b,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3b));
		EDHOC_MEM_FREE(plaintext_3b);
		edhoc_zeroize(ctx, aad, EDHOC_MEM_ALLOC_SIZE(aad));
		EDHOC_MEM_FREE(aad);
		edhoc_zeroize(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv));
		EDHOC_MEM_FREE(iv);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(plaintext_3b, plaintext_3b_len, "PLAINTEXT_3B");

	/* 8. Compute ciphertext (CIPHERTEXT_3B). */
	size_t ciphertext_3b_len = 0;
	EDHOC_MEM_ALLOC(uint8_t, ciphertext_3b,
			plaintext_3b_len + csuite->aead_tag_length);

	if (NULL == ciphertext_3b) {
		EDHOC_LOG_ERR("Memory allocation failed");
		edhoc_zeroize(ctx, plaintext_3b,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3b));
		EDHOC_MEM_FREE(plaintext_3b);
		edhoc_zeroize(ctx, aad, EDHOC_MEM_ALLOC_SIZE(aad));
		EDHOC_MEM_FREE(aad);
		edhoc_zeroize(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv));
		EDHOC_MEM_FREE(iv);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_cipher_encrypt(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv), aad,
				   EDHOC_MEM_ALLOC_SIZE(aad), plaintext_3b,
				   plaintext_3b_len, ciphertext_3b,
				   EDHOC_MEM_ALLOC_SIZE(ciphertext_3b),
				   &ciphertext_3b_len);

	edhoc_zeroize(ctx, aad, EDHOC_MEM_ALLOC_SIZE(aad));
	EDHOC_MEM_FREE(aad);
	edhoc_zeroize(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv));
	EDHOC_MEM_FREE(iv);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute CIPHERTEXT_3B: %d", ret);
		edhoc_zeroize(ctx, ciphertext_3b,
			      EDHOC_MEM_ALLOC_SIZE(ciphertext_3b));
		EDHOC_MEM_FREE(ciphertext_3b);
		edhoc_zeroize(ctx, plaintext_3b,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3b));
		EDHOC_MEM_FREE(plaintext_3b);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ciphertext_3b, ciphertext_3b_len,
			      "CIPHERTEXT_3B");

	/* 9. Prepare plaintext (PLAINTEXT_3A). */
	const struct edhoc_plaintext_input plaintext_3a_input = {
		.id = EDHOC_PLAINTEXT_PSK_3A,
		.id_cred_psk = psk_ctx->id_cred,
		.id_cred_psk_length = psk_ctx->id_cred_len,
		.ciphertext_3b = ciphertext_3b,
		.ciphertext_3b_length = ciphertext_3b_len,
	};

	size_t plaintext_3a_len = 0;
	ret = edhoc_plaintext_length(ctx, &plaintext_3a_input,
				     &plaintext_3a_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PLAINTEXT_3A length: %d", ret);
		edhoc_zeroize(ctx, ciphertext_3b,
			      EDHOC_MEM_ALLOC_SIZE(ciphertext_3b));
		EDHOC_MEM_FREE(ciphertext_3b);
		edhoc_zeroize(ctx, plaintext_3b,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3b));
		EDHOC_MEM_FREE(plaintext_3b);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return ret;
	}

	EDHOC_MEM_ALLOC(uint8_t, plaintext_3a, plaintext_3a_len);

	if (NULL == plaintext_3a) {
		EDHOC_LOG_ERR("Memory allocation failed");
		edhoc_zeroize(ctx, ciphertext_3b,
			      EDHOC_MEM_ALLOC_SIZE(ciphertext_3b));
		EDHOC_MEM_FREE(ciphertext_3b);
		edhoc_zeroize(ctx, plaintext_3b,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3b));
		EDHOC_MEM_FREE(plaintext_3b);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	plaintext_3a_len = 0;
	ret = edhoc_plaintext_compose(ctx, &plaintext_3a_input, plaintext_3a,
				      EDHOC_MEM_ALLOC_SIZE(plaintext_3a),
				      &plaintext_3a_len);
	edhoc_zeroize(ctx, ciphertext_3b, EDHOC_MEM_ALLOC_SIZE(ciphertext_3b));
	EDHOC_MEM_FREE(ciphertext_3b);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Prepare PLAINTEXT_3A: %d", ret);
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		edhoc_zeroize(ctx, plaintext_3b,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3b));
		EDHOC_MEM_FREE(plaintext_3b);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(plaintext_3a, plaintext_3a_len, "PLAINTEXT_3A");

	/* 10. Compute key stream (KEYSTREAM_3A). */
	EDHOC_MEM_ALLOC(uint8_t, keystream, plaintext_3a_len);

	if (NULL == keystream) {
		EDHOC_LOG_ERR("Memory allocation failed");
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		edhoc_zeroize(ctx, plaintext_3b,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3b));
		EDHOC_MEM_FREE(plaintext_3b);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_cipher_keystream(ctx, keystream,
				     EDHOC_MEM_ALLOC_SIZE(keystream));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute KEYSTREAM_3A: %d", ret);
		edhoc_zeroize(ctx, keystream, EDHOC_MEM_ALLOC_SIZE(keystream));
		EDHOC_MEM_FREE(keystream);
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		edhoc_zeroize(ctx, plaintext_3b,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3b));
		EDHOC_MEM_FREE(plaintext_3b);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(keystream, EDHOC_MEM_ALLOC_SIZE(keystream),
			      "KEYSTREAM_3A");

	/* 11. Compute ciphertext (CIPHERTEXT_3A). */
	edhoc_cipher_xor(plaintext_3a, keystream, plaintext_3a_len);

	edhoc_zeroize(ctx, keystream, EDHOC_MEM_ALLOC_SIZE(keystream));
	EDHOC_MEM_FREE(keystream);

	EDHOC_LOG_HEXDUMP_DBG(plaintext_3a, plaintext_3a_len, "CIPHERTEXT_3A");

	/* 12. Compute transcript hash 4. */
	const struct edhoc_th_input th_4 = {
		.target = EDHOC_TH_STATE_4,
		.id_cred = psk_ctx->id_cred,
		.id_cred_length = psk_ctx->id_cred_len,
		.plaintext = plaintext_3b,
		.plaintext_length = plaintext_3b_len,
		.credential = psk_ctx->cred_i,
		.credential_length = psk_ctx->cred_i_len,
		.peer_credential = psk_ctx->cred_r,
		.peer_credential_length = psk_ctx->cred_r_len,
	};

	ret = edhoc_th_compute(ctx, &th_4);

	edhoc_zeroize(ctx, plaintext_3b, EDHOC_MEM_ALLOC_SIZE(plaintext_3b));
	EDHOC_MEM_FREE(plaintext_3b);
	edhoc_zeroize(ctx, psk_context_buf,
		      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
	EDHOC_MEM_FREE(psk_context_buf);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_4: %d", ret);
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->state.th.value, ctx->state.th.length,
			      "TH_4");

	/* 13. Generate edhoc message 3. */
	const struct zcbor_string ciphertext_3a = {
		.value = plaintext_3a,
		.len = plaintext_3a_len,
	};

	ret = cbor_encode_message_3_CIPHERTEXT_3(msg_3, msg_3_size,
						 &ciphertext_3a, msg_3_len);

	edhoc_zeroize(ctx, plaintext_3a, EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
	EDHOC_MEM_FREE(plaintext_3a);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("Generate message_3: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(msg_3, *msg_3_len, "message_3");
	EDHOC_LOG_INF("Compose PSK msg3 end");

	/* 14. Release the message-3 scoped secrets (PRK_4e3m lives on). */
	ret = edhoc_key_slot_release_up_to(ctx, EDHOC_KEY_SLOT_PRK_4E3M);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Release message 3 secrets: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* 15. Clean-up EAD tokens. */
	edhoc_ead_reset(ctx);

	ctx->is_oscore_export_allowed = true;
	ctx->state.machine = EDHOC_SM_COMPLETED;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}

/**
 * Steps for processing of message 3:
 *	1.  Choose most preferred cipher suite.
 *	2.  CBOR decode message 3.
 *	3.  Compute key stream (KEYSTREAM_3A).
 *	4.  Compute plaintext (PLAINTEXT_3A).
 *	5.  Parse plaintext (PLAINTEXT_3A).
 *	6.  Verify if credentials from peer are trusted.
 *	7.  Compute PRK_4e3m.
 *	8a. Compute required buffer length for the PSK context.
 *	8b. Cborise ID_CRED_PSK, TH_3, CRED_I and CRED_R.
 *	9.  Compute K_3, IV_3 and AAD_3.
 *	10. Decrypt ciphertext (CIPHERTEXT_3B).
 *	11. Parse plaintext (PLAINTEXT_3B).
 *	12. Process EAD_3 if present.
 *	13. Compute transcript hash 4.
 *	14. Release the message-3 scoped secrets (PRK_4e3m lives on).
 *	15. Clean-up EAD tokens.
 */
int edhoc_psk_message_3_process(struct edhoc_context *ctx, const uint8_t *msg_3,
				size_t msg_3_len)
{
	EDHOC_LOG_INF("Process PSK msg3 start");

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
	size_t len = 0;
	struct zcbor_string ciphertext_3a = { 0 };

	ret = cbor_decode_message_3_CIPHERTEXT_3(msg_3, msg_3_len,
						 &ciphertext_3a, &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR dec message_3: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ciphertext_3a.value, ciphertext_3a.len,
			      "CIPHERTEXT_3A");

	/* 3. Compute key stream (KEYSTREAM_3A). */
	EDHOC_MEM_ALLOC(uint8_t, keystream, ciphertext_3a.len);

	if (NULL == keystream) {
		EDHOC_LOG_ERR("Memory allocation failed");
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_cipher_keystream(ctx, keystream,
				     EDHOC_MEM_ALLOC_SIZE(keystream));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute KEYSTREAM_3A: %d", ret);
		edhoc_zeroize(ctx, keystream, EDHOC_MEM_ALLOC_SIZE(keystream));
		EDHOC_MEM_FREE(keystream);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(keystream, EDHOC_MEM_ALLOC_SIZE(keystream),
			      "KEYSTREAM_3A");

	/* 4. Compute plaintext (PLAINTEXT_3A). */
	EDHOC_MEM_ALLOC(uint8_t, plaintext_3a, ciphertext_3a.len);

	if (NULL == plaintext_3a) {
		EDHOC_LOG_ERR("Memory allocation failed");
		edhoc_zeroize(ctx, keystream, EDHOC_MEM_ALLOC_SIZE(keystream));
		EDHOC_MEM_FREE(keystream);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	memcpy(plaintext_3a, ciphertext_3a.value, ciphertext_3a.len);
	edhoc_cipher_xor(plaintext_3a, keystream, ciphertext_3a.len);
	edhoc_zeroize(ctx, keystream, EDHOC_MEM_ALLOC_SIZE(keystream));
	EDHOC_MEM_FREE(keystream);

	EDHOC_LOG_HEXDUMP_DBG(plaintext_3a, ciphertext_3a.len, "PLAINTEXT_3A");

	/* 5. Parse plaintext (PLAINTEXT_3A). */
	struct plaintext parsed = { 0 };

	ret = edhoc_plaintext_parse(ctx, EDHOC_PLAINTEXT_PSK_3A, plaintext_3a,
				    ciphertext_3a.len, &parsed);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse PLAINTEXT_3A: %d", ret);
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		return EDHOC_ERROR_MSG_3_PROCESS_FAILURE;
	}

	/* 6. Verify if credentials from peer are trusted. */
	const struct edhoc_call_context cred_call_context =
		edhoc_call_context(ctx);
	struct edhoc_credential_trusted trusted = { 0 };

	ret = ctx->interfaces.cred.authenticate_peer(ctx->user_context,
						     &cred_call_context,
						     &parsed.peer_credential_id,
						     &trusted);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Authenticate peer credential: %d", ret);
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		ctx->error_code =
			EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	ret = edhoc_credential_validate_trusted(
		ctx->negotiation.selected_method, &parsed.peer_credential_id,
		&trusted);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Validate trusted credential: %d", ret);
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		return ret;
	}

	struct edhoc_credential_material_psk material = { 0 };

	ret = edhoc_credential_psk_material_from_trusted(
		&parsed.peer_credential_id, &trusted, &material);

	if (EDHOC_SUCCESS != ret) {
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		return ret;
	}

	/* 7. Compute PRK_4e3m. */
	ret = edhoc_key_schedule_prk_advance(ctx, trusted.psk.psk_key_id, NULL,
					     0);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PRK_4e3m: %d", ret);
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	/* 8a. Compute required buffer length for the PSK context. */
	size_t psk_context_len = 0;
	ret = psk_context_length(ctx, &material, &psk_context_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute PSK context length: %d", ret);
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		return ret;
	}

	/* 8b. Cborise ID_CRED_PSK, TH_3, CRED_I and CRED_R. */
	EDHOC_MEM_ALLOC(uint8_t, psk_context_buf,
			sizeof(struct psk_context) + psk_context_len);

	if (NULL == psk_context_buf) {
		EDHOC_LOG_ERR("Memory allocation failed");
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	struct psk_context *psk_ctx = (void *)psk_context_buf;
	psk_ctx->buf_len = psk_context_len;

	ret = psk_context_compose(ctx, &material, psk_ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compose PSK context: %d", ret);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		return ret;
	}

	EDHOC_LOG_HEXDUMP_DBG(psk_ctx->buf, psk_ctx->buf_len, "external_aad_3");

	/* 9. Compute K_3, IV_3 and AAD_3. */
	EDHOC_MEM_ALLOC(uint8_t, iv, csuite->aead_iv_length);

	if (NULL == iv) {
		EDHOC_LOG_ERR("Memory allocation failed");
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	size_t aad_len = 0;
	ret = edhoc_cipher_aad_length(ctx, psk_ctx->buf_len, &aad_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute AAD_3 length: %d", ret);
		edhoc_zeroize(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv));
		EDHOC_MEM_FREE(iv);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		return ret;
	}

	EDHOC_MEM_ALLOC(uint8_t, aad, aad_len);

	if (NULL == aad) {
		EDHOC_LOG_ERR("Memory allocation failed");
		edhoc_zeroize(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv));
		EDHOC_MEM_FREE(iv);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_cipher_derive(ctx, psk_ctx->buf, psk_ctx->buf_len, iv,
				  EDHOC_MEM_ALLOC_SIZE(iv), aad,
				  EDHOC_MEM_ALLOC_SIZE(aad));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute K_3: %d", ret);
		edhoc_zeroize(ctx, aad, EDHOC_MEM_ALLOC_SIZE(aad));
		EDHOC_MEM_FREE(aad);
		edhoc_zeroize(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv));
		EDHOC_MEM_FREE(iv);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(iv, EDHOC_MEM_ALLOC_SIZE(iv), "IV_3");
	EDHOC_LOG_HEXDUMP_DBG(aad, EDHOC_MEM_ALLOC_SIZE(aad), "AAD_3");

	/* 10. Decrypt ciphertext (CIPHERTEXT_3B). */
	if (csuite->aead_tag_length > parsed.ciphertext_3b.length) {
		EDHOC_LOG_ERR("CIPHERTEXT_3B too short: %zu",
			      parsed.ciphertext_3b.length);
		edhoc_zeroize(ctx, aad, EDHOC_MEM_ALLOC_SIZE(aad));
		EDHOC_MEM_FREE(aad);
		edhoc_zeroize(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv));
		EDHOC_MEM_FREE(iv);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		return EDHOC_ERROR_MSG_3_PROCESS_FAILURE;
	}

	const size_t plaintext_3b_len =
		parsed.ciphertext_3b.length - csuite->aead_tag_length;

	/* PLAINTEXT_3B is empty when there is no EAD_3; allocate at least one
	 * byte so the stack backend never forms a zero-length VLA (UB). */
	EDHOC_MEM_ALLOC(uint8_t, plaintext_3b,
			0 != plaintext_3b_len ? plaintext_3b_len : 1);

	if (NULL == plaintext_3b) {
		EDHOC_LOG_ERR("Memory allocation failed");
		edhoc_zeroize(ctx, aad, EDHOC_MEM_ALLOC_SIZE(aad));
		EDHOC_MEM_FREE(aad);
		edhoc_zeroize(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv));
		EDHOC_MEM_FREE(iv);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		edhoc_zeroize(ctx, plaintext_3a,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
		EDHOC_MEM_FREE(plaintext_3a);
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	ret = edhoc_cipher_decrypt(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv), aad,
				   EDHOC_MEM_ALLOC_SIZE(aad),
				   parsed.ciphertext_3b.value,
				   parsed.ciphertext_3b.length, plaintext_3b,
				   plaintext_3b_len);
	edhoc_zeroize(ctx, aad, EDHOC_MEM_ALLOC_SIZE(aad));
	EDHOC_MEM_FREE(aad);
	edhoc_zeroize(ctx, iv, EDHOC_MEM_ALLOC_SIZE(iv));
	EDHOC_MEM_FREE(iv);
	edhoc_zeroize(ctx, plaintext_3a, EDHOC_MEM_ALLOC_SIZE(plaintext_3a));
	EDHOC_MEM_FREE(plaintext_3a);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Decrypt CIPHERTEXT_3B: %d", ret);
		edhoc_zeroize(ctx, plaintext_3b,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3b));
		EDHOC_MEM_FREE(plaintext_3b);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return EDHOC_ERROR_MSG_3_PROCESS_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(plaintext_3b, plaintext_3b_len, "PLAINTEXT_3B");

	/* 11. Parse plaintext (PLAINTEXT_3B). */
	ret = edhoc_plaintext_parse(ctx, EDHOC_PLAINTEXT_PSK_3B, plaintext_3b,
				    plaintext_3b_len, NULL);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Parse PLAINTEXT_3B: %d", ret);
		edhoc_zeroize(ctx, plaintext_3b,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3b));
		EDHOC_MEM_FREE(plaintext_3b);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return EDHOC_ERROR_MSG_3_PROCESS_FAILURE;
	}

	/* 12. Process EAD_3 if present. */
	ret = edhoc_ead_process(ctx);

	if (EDHOC_SUCCESS != ret) {
		edhoc_zeroize(ctx, plaintext_3b,
			      EDHOC_MEM_ALLOC_SIZE(plaintext_3b));
		EDHOC_MEM_FREE(plaintext_3b);
		edhoc_zeroize(ctx, psk_context_buf,
			      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
		EDHOC_MEM_FREE(psk_context_buf);
		return ret;
	}

	/* 13. Compute transcript hash 4. */
	const struct edhoc_th_input th_4 = {
		.target = EDHOC_TH_STATE_4,
		.id_cred = psk_ctx->id_cred,
		.id_cred_length = psk_ctx->id_cred_len,
		.plaintext = plaintext_3b,
		.plaintext_length = plaintext_3b_len,
		.credential = psk_ctx->cred_i,
		.credential_length = psk_ctx->cred_i_len,
		.peer_credential = psk_ctx->cred_r,
		.peer_credential_length = psk_ctx->cred_r_len,
	};

	ret = edhoc_th_compute(ctx, &th_4);

	edhoc_zeroize(ctx, plaintext_3b, EDHOC_MEM_ALLOC_SIZE(plaintext_3b));
	EDHOC_MEM_FREE(plaintext_3b);
	edhoc_zeroize(ctx, psk_context_buf,
		      EDHOC_MEM_ALLOC_SIZE(psk_context_buf));
	EDHOC_MEM_FREE(psk_context_buf);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute TH_4: %d", ret);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(ctx->state.th.value, ctx->state.th.length,
			      "TH_4");
	EDHOC_LOG_INF("Process PSK msg3 end");

	/* 14. Release the message-3 scoped secrets (PRK_4e3m lives on). */
	ret = edhoc_key_slot_release_up_to(ctx, EDHOC_KEY_SLOT_PRK_4E3M);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Release message 3 secrets: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* 15. Clean-up EAD tokens. */
	edhoc_ead_reset(ctx);

	ctx->is_oscore_export_allowed = true;
	ctx->state.machine = EDHOC_SM_COMPLETED;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}
