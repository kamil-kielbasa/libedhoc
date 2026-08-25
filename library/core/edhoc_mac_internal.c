/**
 * \file    edhoc_mac_internal.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC MAC context, MAC and Signature_or_MAC implementation.
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

/* EDHOC internal headers: */
#include "edhoc_context_internal.h"
#include "edhoc_key_slot_internal.h"
#include "edhoc_kdf_internal.h"
#include "edhoc_key_schedule_internal.h"
#include "edhoc_transcript_hash_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_cbor_internal.h"
#include "edhoc_ead_internal.h"
#include "edhoc_mac_internal.h"
#include "edhoc_credentials_internal.h"
#include "edhoc_connection_id_internal.h"
#include "edhoc_backend_log.h"
#include "edhoc_backend_memory.h"

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_bstr_type_encode.h>
#include <backend_cbor_types.h>
#include <backend_cbor_sig_structure_encode.h>
#include <backend_cbor_ead_encode.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */

/** How the party that authenticates in a message proves its identity. */
enum auth_kind {
	/** Signature over COSE_Sign1 (methods 0 and 2 in message 2, 0 and 1
	 *  in message 3). */
	AUTH_SIGNATURE,
	/** Static Diffie-Hellman: Signature_or_MAC is the MAC itself. */
	AUTH_STATIC_DH,
};
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Compute COSE_Sign1.
 *
 * \param[in] ctx               EDHOC context.
 * \param[in] private_key_id    Handle of the local private key.
 * \param[in] mac_ctx           MAC context.
 * \param[in] mac               Buffer containing MAC 2/3.
 * \param mac_len               Size of the \p mac buffer in bytes.
 * \param[out] sign             Buffer containing signature.
 * \param sign_size             Size of the \p sign buffer in bytes.
 * \param[out] sign_len         On success, the number of bytes that make up the signature.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int sign_cose_sign_1(const struct edhoc_context *ctx,
			    const void *private_key_id,
			    const struct mac_context *mac_ctx,
			    const uint8_t *mac, size_t mac_len, uint8_t *sign,
			    size_t sign_size, size_t *sign_len);

/**
 * \brief Verify COSE_Sign1.
 *
 * \param[in] ctx               EDHOC context.
 * \param[in] mac_ctx           MAC context.
 * \param[in] pub_key           Buffer containing public key.
 * \param pub_key_len           Size of the \p pub_key buffer in bytes.
 * \param[in] mac               Buffer containing MAC 2/3.
 * \param mac_len               Size of the \p mac buffer in bytes.
 * \param[out] sign             Buffer containing signature.
 * \param sign_len              Size of the \p sign buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int verify_cose_sign_1(const struct edhoc_context *ctx,
			      const struct mac_context *mac_ctx,
			      const uint8_t *pub_key, size_t pub_key_len,
			      const uint8_t *mac, size_t mac_len,
			      const uint8_t *sign, size_t sign_len);

/**
 * \brief Connection identifier that goes into context_2 (RFC 9528: 5.3.2).
 *
 * \param[in] ctx               EDHOC context.
 * \param[out] connection_id    On success, the identifier to encode.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
STATIC int
comp_context_2_connection_id(const struct edhoc_context *ctx,
			     const struct connection_id **connection_id);

/* Static function definitions --------------------------------------------- */

STATIC int sign_cose_sign_1(const struct edhoc_context *ctx,
			    const void *private_key_id,
			    const struct mac_context *mac_ctx,
			    const uint8_t *mac, size_t mac_len, uint8_t *sign,
			    size_t sign_size, size_t *sign_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct sig_structure cose_sign_1 = {
		.sig_structure_protected.value = mac_ctx->id_cred,
		.sig_structure_protected.len = mac_ctx->id_cred_len,
		.sig_structure_external_aad.value = mac_ctx->th,
		.sig_structure_external_aad.len =
			mac_ctx->th_len + mac_ctx->cred_len + mac_ctx->ead_len,
		.sig_structure_payload.value = mac,
		.sig_structure_payload.len = mac_len,
	};

	size_t len = 0;
	len += sizeof("Signature1");
	len += edhoc_cbor_tstr_head_length(sizeof("Signature1"));
	len += mac_ctx->id_cred_len;
	len += edhoc_cbor_bstr_head_length(mac_ctx->id_cred_len);
	len += mac_ctx->th_len + mac_ctx->cred_len + mac_ctx->ead_len;
	len += edhoc_cbor_bstr_head_length(mac_ctx->th_len + mac_ctx->cred_len +
					   mac_ctx->ead_len);
	len += mac_len;
	len += edhoc_cbor_int_head_length((int32_t)mac_len);

	EDHOC_MEM_ALLOC(uint8_t, cose_sign_1_buf, len);
	if (NULL == cose_sign_1_buf) {
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	size_t cose_sign_1_buf_len = 0;
	ret = cbor_encode_sig_structure(cose_sign_1_buf,
					EDHOC_MEM_ALLOC_SIZE(cose_sign_1_buf),
					&cose_sign_1, &cose_sign_1_buf_len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_MEM_FREE(cose_sign_1_buf);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	ret = edhoc_crypto(ctx)->sign(ctx->user_context, private_key_id,
				      cose_sign_1_buf, cose_sign_1_buf_len,
				      sign, sign_size, sign_len);
	EDHOC_MEM_FREE(cose_sign_1_buf);

	if (EDHOC_SUCCESS != ret) {
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int verify_cose_sign_1(const struct edhoc_context *ctx,
			      const struct mac_context *mac_ctx,
			      const uint8_t *pub_key, size_t pub_key_len,
			      const uint8_t *mac, size_t mac_len,
			      const uint8_t *sign, size_t sign_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct sig_structure cose_sign_1 = {
		.sig_structure_protected.value = mac_ctx->id_cred,
		.sig_structure_protected.len = mac_ctx->id_cred_len,
		.sig_structure_external_aad.value = mac_ctx->th,
		.sig_structure_external_aad.len =
			mac_ctx->th_len + mac_ctx->cred_len + mac_ctx->ead_len,
		.sig_structure_payload.value = mac,
		.sig_structure_payload.len = mac_len,
	};

	size_t len = 0;
	len += sizeof("Signature1");
	len += edhoc_cbor_tstr_head_length(sizeof("Signature1"));
	len += mac_ctx->id_cred_len;
	len += edhoc_cbor_bstr_head_length(mac_ctx->id_cred_len);
	len += mac_ctx->th_len + mac_ctx->cred_len + mac_ctx->ead_len;
	len += edhoc_cbor_bstr_head_length(mac_ctx->th_len + mac_ctx->cred_len +
					   mac_ctx->ead_len);
	len += mac_len;
	len += edhoc_cbor_int_head_length((int32_t)mac_len);

	EDHOC_MEM_ALLOC(uint8_t, cose_sign_1_buf, len);
	if (NULL == cose_sign_1_buf) {
		return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
	}

	size_t cose_sign_1_buf_len = 0;
	ret = cbor_encode_sig_structure(cose_sign_1_buf,
					EDHOC_MEM_ALLOC_SIZE(cose_sign_1_buf),
					&cose_sign_1, &cose_sign_1_buf_len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_MEM_FREE(cose_sign_1_buf);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* The crypto interface verifies against the peer's raw public key
	 * directly, so no key-store import is required. */
	ret = edhoc_crypto(ctx)->verify(ctx->user_context, pub_key, pub_key_len,
					cose_sign_1_buf, cose_sign_1_buf_len,
					sign, sign_len);
	EDHOC_MEM_FREE(cose_sign_1_buf);

	if (EDHOC_SUCCESS != ret) {
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

STATIC int
comp_context_2_connection_id(const struct edhoc_context *ctx,
			     const struct connection_id **connection_id)
{
	switch (ctx->state.role) {
	case EDHOC_ROLE_INITIATOR:
		*connection_id = &ctx->negotiation.peer_connection_id;
		return EDHOC_SUCCESS;
	case EDHOC_ROLE_RESPONDER:
		*connection_id = &ctx->negotiation.connection_id;
		return EDHOC_SUCCESS;
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}
}

/* Module interface function definitions ----------------------------------- */

int edhoc_mac_context_length(
	const struct edhoc_context *ctx,
	const struct edhoc_credential_material_asymmetric *material,
	size_t *mac_ctx_len)
{
	if (NULL == ctx || NULL == material || NULL == mac_ctx_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_is_initiator(ctx) && !edhoc_is_responder(ctx)) {
		EDHOC_LOG_ERR("Invalid role: %d", ctx->state.role);
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_MESSAGE_1 > ctx->state.message ||
	    EDHOC_MESSAGE_3 < ctx->state.message) {
		EDHOC_LOG_ERR("Invalid message: %d", ctx->state.message);
		return EDHOC_ERROR_BAD_STATE;
	}

	*mac_ctx_len = 0;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	/* C_R length. */
	if (EDHOC_MESSAGE_2 == ctx->state.message) {
		const struct connection_id *cid = NULL;

		ret = comp_context_2_connection_id(ctx, &cid);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Invalid role: %d", ctx->state.role);
			return ret;
		}

		*mac_ctx_len += edhoc_connection_id_encoded_length(cid);
	}

	/* ID_CRED length. */
	len = 0;
	ret = edhoc_credential_asymmetric_id_cred_length(material, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	*mac_ctx_len += len;

	/* TH length. */
	len = 0;
	ret = edhoc_th_encoded_length(ctx->state.th.length, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	*mac_ctx_len += len;

	/* CRED length. */
	len = 0;
	ret = edhoc_credential_asymmetric_cred_length(material, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	*mac_ctx_len += len;

	/* EAD length. */
	len = 0;
	ret = edhoc_ead_encoded_length(ctx, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	*mac_ctx_len += len;

	return EDHOC_SUCCESS;
}

int edhoc_mac_context_compose(
	const struct edhoc_context *ctx,
	const struct edhoc_credential_material_asymmetric *material,
	struct mac_context *mac_ctx)
{
	if (NULL == ctx || NULL == material || NULL == mac_ctx) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_is_initiator(ctx) && !edhoc_is_responder(ctx)) {
		EDHOC_LOG_ERR("Invalid role: %d", ctx->state.role);
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_MESSAGE_1 > ctx->state.message ||
	    EDHOC_MESSAGE_3 < ctx->state.message) {
		EDHOC_LOG_ERR("Invalid message: %d", ctx->state.message);
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_MESSAGE_2 == ctx->state.message &&
	    EDHOC_TH_STATE_2 != ctx->state.th.stage) {
		EDHOC_LOG_ERR("Invalid TH state for msg2: %d",
			      ctx->state.th.stage);
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_MESSAGE_3 == ctx->state.message &&
	    EDHOC_TH_STATE_3 != ctx->state.th.stage) {
		EDHOC_LOG_ERR("Invalid TH state for msg3: %d",
			      ctx->state.th.stage);
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	/* C_R length. */
	if (EDHOC_MESSAGE_2 == ctx->state.message) {
		const struct connection_id *cid = NULL;

		ret = comp_context_2_connection_id(ctx, &cid);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Invalid role: %d", ctx->state.role);
			return ret;
		}

		mac_ctx->conn_id = &mac_ctx->buf[0];
		mac_ctx->conn_id_len = edhoc_connection_id_encoded_length(cid);

		len = 0;
		ret = edhoc_connection_id_encode(cid, mac_ctx->conn_id,
						 mac_ctx->conn_id_len, &len);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("CBOR enc C_R: %d", ret);
			return ret;
		}

		mac_ctx->conn_id_len = len;
	}

	/* ID_CRED length. */
	mac_ctx->id_cred = &mac_ctx->buf[mac_ctx->conn_id_len];

	len = 0;
	ret = edhoc_credential_asymmetric_id_cred_length(material, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	mac_ctx->id_cred_len = len;

	/* ID_CRED cborising. */
	len = 0;
	ret = edhoc_credential_asymmetric_encode_id_cred(
		material, mac_ctx->id_cred, mac_ctx->id_cred_len, &len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc ID_CRED: %d", ret);
		return ret;
	}

	mac_ctx->id_cred_len = len;

	/* Compact encoding of ID_CRED, when the label allows it. */
	ret = edhoc_credential_asymmetric_encode_id_cred_compact(
		material, mac_ctx->id_cred_comp,
		ARRAY_SIZE(mac_ctx->id_cred_comp), &mac_ctx->id_cred_comp_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc ID_CRED compact: %d", ret);
		return ret;
	}

	/* TH length. */
	mac_ctx->th = &mac_ctx->id_cred[mac_ctx->id_cred_len];

	len = 0;
	ret = edhoc_th_encoded_length(ctx->state.th.length, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	mac_ctx->th_len = len;

	/* TH cborising. */
	const struct zcbor_string th = {
		.value = ctx->state.th.value,
		.len = ctx->state.th.length,
	};

	len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		mac_ctx->th, mac_ctx->th_len, &th, &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc TH: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	mac_ctx->th_len = len;

	/* CRED length. */
	mac_ctx->cred = &mac_ctx->th[mac_ctx->th_len];

	len = 0;
	ret = edhoc_credential_asymmetric_cred_length(material, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	mac_ctx->cred_len = len;

	/* CRED cborising. */
	len = 0;
	ret = edhoc_credential_asymmetric_encode_cred(material, mac_ctx->cred,
						      mac_ctx->cred_len, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	mac_ctx->cred_len = len;

	/* EAD length. */
	if (edhoc_ead_is_present(ctx)) {
		len = 0;
		ret = edhoc_ead_encoded_length(ctx, &len);

		if (EDHOC_SUCCESS != ret)
			return ret;

		mac_ctx->is_ead = true;
		mac_ctx->ead = &mac_ctx->cred[mac_ctx->cred_len];
		mac_ctx->ead_len = len;
	} else {
		mac_ctx->is_ead = false;
		mac_ctx->ead = NULL;
		mac_ctx->ead_len = 0;
	}

	/* EAD cborising. */
	if (true == mac_ctx->is_ead) {
		struct ead tmp_ead = { 0 };

		ret = edhoc_ead_tokens_encode(ctx, &tmp_ead);

		if (EDHOC_SUCCESS != ret) {
			return ret;
		}

		len = 0;
		ret = cbor_encode_ead(mac_ctx->ead, mac_ctx->ead_len, &tmp_ead,
				      &len);

		if (ZCBOR_SUCCESS != ret) {
			EDHOC_LOG_ERR("CBOR enc EAD: %d", ret);
			return EDHOC_ERROR_CBOR_FAILURE;
		}

		mac_ctx->ead_len = len;
	}

	const size_t encoded_bytes = mac_ctx->conn_id_len +
				     mac_ctx->id_cred_len + mac_ctx->th_len +
				     mac_ctx->cred_len + mac_ctx->ead_len;

	if (encoded_bytes > mac_ctx->buf_len) {
		EDHOC_LOG_ERR("Buffer too small: %zu > %zu", encoded_bytes,
			      mac_ctx->buf_len);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	mac_ctx->buf_len = encoded_bytes;
	return EDHOC_SUCCESS;
}

int edhoc_mac_length(const struct edhoc_context *ctx, size_t *mac_len)
{
	if (NULL == ctx || NULL == mac_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_is_initiator(ctx) && !edhoc_is_responder(ctx)) {
		EDHOC_LOG_ERR("Invalid role: %d", ctx->state.role);
		return EDHOC_ERROR_BAD_STATE;
	}

	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);

	enum edhoc_auth_kind kind = EDHOC_AUTH_SIGNATURE;
	const int ret = edhoc_key_schedule_auth_kind(ctx, &kind);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("MAC length: message %d, method %d",
			      ctx->state.message,
			      ctx->negotiation.selected_method);
		return ret;
	}

	switch (kind) {
	case EDHOC_AUTH_SIGNATURE:
		*mac_len = csuite->hash_length;
		return EDHOC_SUCCESS;
	case EDHOC_AUTH_STATIC_DH:
		*mac_len = csuite->mac_length;
		return EDHOC_SUCCESS;
	case EDHOC_AUTH_PSK:
		EDHOC_LOG_ERR("No MAC in EDHOC-PSK");
		return EDHOC_ERROR_NOT_PERMITTED;
	default:
		EDHOC_LOG_ERR("Invalid authentication kind: %d", kind);
		return EDHOC_ERROR_NOT_PERMITTED;
	}
}

int edhoc_mac_compute(const struct edhoc_context *ctx,
		      const struct mac_context *mac_ctx, uint8_t *mac,
		      size_t mac_len)
{
	if (NULL == ctx || NULL == mac_ctx || NULL == mac || 0 == mac_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_MESSAGE_1 > ctx->state.message ||
	    EDHOC_MESSAGE_3 < ctx->state.message) {
		EDHOC_LOG_ERR("Invalid message: %d", ctx->state.message);
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_MESSAGE_2 == ctx->state.message &&
	    EDHOC_PRK_STATE_3E2M != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Invalid PRK state for msg2: %d",
			      ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_MESSAGE_3 == ctx->state.message &&
	    EDHOC_PRK_STATE_4E3M != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Invalid PRK state for msg3: %d",
			      ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	int32_t label = 0;
	const void *prk_key_id = NULL;

	switch (ctx->state.message) {
	case EDHOC_MESSAGE_2:
		label = EDHOC_KDF_LABEL_MAC_2;
		prk_key_id = edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_3E2M);
		break;
	case EDHOC_MESSAGE_3:
		label = EDHOC_KDF_LABEL_MAC_3;
		prk_key_id = edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_PRK_4E3M);
		break;

	case EDHOC_MESSAGE_1:
	case EDHOC_MESSAGE_4:
	default:
		EDHOC_LOG_ERR("Invalid message for MAC: %d",
			      ctx->state.message);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	const int ret = edhoc_kdf_expand_raw(ctx, prk_key_id, label,
					     mac_ctx->buf, mac_ctx->buf_len,
					     mac, mac_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Derive MAC: %d", ret);
		return ret;
	}

	return EDHOC_SUCCESS;
}

int edhoc_sign_or_mac_length(const struct edhoc_context *ctx,
			     size_t *sign_or_mac_len)
{
	if (NULL == ctx || NULL == sign_or_mac_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_is_initiator(ctx) && !edhoc_is_responder(ctx)) {
		EDHOC_LOG_ERR("Invalid role: %d", ctx->state.role);
		return EDHOC_ERROR_BAD_STATE;
	}

	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);

	enum edhoc_auth_kind kind = EDHOC_AUTH_SIGNATURE;
	const int ret = edhoc_key_schedule_auth_kind(ctx, &kind);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Signature_or_MAC length: message %d, method %d",
			      ctx->state.message,
			      ctx->negotiation.selected_method);
		return ret;
	}

	switch (kind) {
	case EDHOC_AUTH_SIGNATURE:
		*sign_or_mac_len = csuite->sign_length;
		return EDHOC_SUCCESS;
	case EDHOC_AUTH_STATIC_DH:
		*sign_or_mac_len = csuite->mac_length;
		return EDHOC_SUCCESS;
	case EDHOC_AUTH_PSK:
		EDHOC_LOG_ERR("No Signature_or_MAC in EDHOC-PSK");
		return EDHOC_ERROR_NOT_PERMITTED;
	default:
		EDHOC_LOG_ERR("Invalid authentication kind: %d", kind);
		return EDHOC_ERROR_NOT_PERMITTED;
	}
}

int edhoc_sign_or_mac_compute(const struct edhoc_context *ctx,
			      const void *private_key_id,
			      const struct mac_context *mac_ctx,
			      const uint8_t *mac, size_t mac_len, uint8_t *sign,
			      size_t sign_size, size_t *sign_len)
{
	if (NULL == ctx || NULL == private_key_id || NULL == mac_ctx ||
	    NULL == mac || 0 == mac_len || NULL == sign || 0 == sign_size ||
	    NULL == sign_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	enum edhoc_auth_kind kind = EDHOC_AUTH_SIGNATURE;
	const int ret = edhoc_key_schedule_auth_kind(ctx, &kind);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Signature_or_MAC: message %d, method %d",
			      ctx->state.message,
			      ctx->negotiation.selected_method);
		return ret;
	}

	switch (kind) {
	case EDHOC_AUTH_SIGNATURE:
		return sign_cose_sign_1(ctx, private_key_id, mac_ctx, mac,
					mac_len, sign, sign_size, sign_len);

	case EDHOC_AUTH_STATIC_DH:
		if (mac_len > sign_size) {
			EDHOC_LOG_ERR("Buffer too small: %zu > %zu", mac_len,
				      sign_size);
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		*sign_len = mac_len;
		memcpy(sign, mac, mac_len);
		return EDHOC_SUCCESS;

	case EDHOC_AUTH_PSK:
		EDHOC_LOG_ERR("No Signature_or_MAC in EDHOC-PSK");
		return EDHOC_ERROR_NOT_PERMITTED;

	default:
		EDHOC_LOG_ERR("Invalid authentication kind: %d", kind);
		return EDHOC_ERROR_NOT_PERMITTED;
	}
}

int edhoc_sign_or_mac_verify(const struct edhoc_context *ctx,
			     const struct mac_context *mac_ctx,
			     const uint8_t *pub_key, size_t pub_key_len,
			     const uint8_t *sign_or_mac, size_t sign_or_mac_len,
			     const uint8_t *mac, size_t mac_len)
{
	if (NULL == ctx || NULL == mac_ctx || NULL == pub_key ||
	    0 == pub_key_len || NULL == sign_or_mac || 0 == sign_or_mac_len ||
	    NULL == mac || 0 == mac_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	enum edhoc_auth_kind kind = EDHOC_AUTH_SIGNATURE;
	const int ret = edhoc_key_schedule_auth_kind(ctx, &kind);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Signature_or_MAC: message %d, method %d",
			      ctx->state.message,
			      ctx->negotiation.selected_method);
		return ret;
	}

	switch (kind) {
	case EDHOC_AUTH_SIGNATURE:
		return verify_cose_sign_1(ctx, mac_ctx, pub_key, pub_key_len,
					  mac, mac_len, sign_or_mac,
					  sign_or_mac_len);

	case EDHOC_AUTH_STATIC_DH:
		if (mac_len != sign_or_mac_len ||
		    0 != memcmp(sign_or_mac, mac, mac_len)) {
			EDHOC_LOG_ERR(
				"Invalid Signature_or_MAC_%d: MAC mismatch",
				ctx->state.message + 1);
			return (EDHOC_MESSAGE_2 == ctx->state.message) ?
				       EDHOC_ERROR_INVALID_SIGN_OR_MAC_2 :
				       EDHOC_ERROR_INVALID_SIGN_OR_MAC_3;
		}

		return EDHOC_SUCCESS;

	case EDHOC_AUTH_PSK:
		EDHOC_LOG_ERR("No Signature_or_MAC in EDHOC-PSK");
		return EDHOC_ERROR_NOT_PERMITTED;

	default:
		EDHOC_LOG_ERR("Invalid authentication kind: %d", kind);
		return EDHOC_ERROR_NOT_PERMITTED;
	}
}
