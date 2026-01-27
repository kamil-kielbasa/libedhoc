/**
 * \file    edhoc_message_2.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message 2.
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
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
#include <backend_cbor_message_2_encode.h>
#include <backend_cbor_message_2_decode.h>
#include <backend_cbor_bstr_type_encode.h>
#include <backend_cbor_bstr_type_decode.h>
#include <backend_cbor_int_type_encode.h>
#include <backend_cbor_int_type_decode.h>
#include <backend_cbor_id_cred_x_encode.h>
#include <backend_cbor_id_cred_x_decode.h>
#include <backend_cbor_sig_structure_encode.h>
#include <backend_cbor_info_encode.h>
#include <backend_cbor_plaintext_2_decode.h>
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
 * \brief Generate ECDH key pair (G_X, X).
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure. 
 */
static int gen_dh_keys(struct edhoc_context *ctx);

/** 
 * \brief Compute ECDH shared secret (G_XY).
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure. 
 */
static int comp_dh_secret(struct edhoc_context *ctx);

/** 
 * \brief Compute transcript hash 2 (TH_2).
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure. 
 */
static int comp_th_2(struct edhoc_context *ctx);

/** 
 * \brief Compute psuedo random key (PRK_2e).
 *
 * \param[in,out] ctx		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure. 
 */
static int comp_prk_2e(struct edhoc_context *ctx);

/** 
 * \brief Compute psuedo random key (PRK_3e2m).
 *
 * \param[in,out] ctx		EDHOC context.
 * \param[in] auth_cred         Authentication credentials.
 * \param[in] pub_key           Peer public static DH key. 
 * \param pub_key_len           Size of the \p pub_key buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_prk_3e2m(struct edhoc_context *ctx,
			 const struct edhoc_auth_creds *auth_cred,
			 const uint8_t *pub_key, size_t pub_key_len);

/** 
 * \brief Compute required PLAINTEXT_2 length.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] mac_ctx		MAC_2 context.
 * \param sign_len		Size of the signature buffer in bytes.
 * \param[out] plaintext_2_len  On success, length of PLAINTEXT_2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_plaintext_2_len(const struct edhoc_context *ctx,
				const struct mac_context *mac_ctx,
				size_t sign_len, size_t *plaintext_2_len);

/** 
 * \brief Prepare PLAINTEXT_2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] mac_ctx		Buffer containing the context_2.
 * \param[in] sign		Buffer containing the signature.
 * \param sign_len		Size of the \p sign buffer in bytes.
 * \param[out] ptxt	        Buffer where the generated plaintext is to be written.
 * \param ptxt_size		Size of the \p ptxt buffer in bytes.
 * \param[out] ptxt_len		On success, the number of bytes that make up the PLAINTEXT_2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int prepare_plaintext_2(const struct edhoc_context *ctx,
			       const struct mac_context *mac_ctx,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt, size_t ptxt_size,
			       size_t *ptxt_len);

/** 
 * \brief Compute KEYSTREAM_2.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] prk_2e		Buffer containing the PRK_2e.
 * \param prk_2e_len		Size of the \p prk_2e buffer in bytes.
 * \param[out] keystream	Buffer where the generated keystream is to be written.
 * \param keystream_len		Size of the \p keystream buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_keystream(const struct edhoc_context *ctx,
			  const uint8_t *prk_2e, size_t prk_2e_len,
			  uint8_t *keystream, size_t keystream_len);

/** 
 * \brief Compute CIPHERTEXT_2.
 *
 * \param[out] dst		Memory location to XOR to.
 * \param[in] src		Memory location to XOR from.
 * \param count			Number of bytes to XOR.
 */
static void xor_arrays(uint8_t *restrict dst, const uint8_t *restrict src,
		       size_t count);

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
static int prepare_message_2(const struct edhoc_context *ctx,
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
static int comp_ciphertext_2_len(const struct edhoc_context *ctx,
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
static int parse_msg_2(struct edhoc_context *ctx, const uint8_t *msg_2,
		       size_t msg_2_len, uint8_t *ctxt_2, size_t ctxt_2_len);

/** 
 * \brief Parsed cborised PLAINTEXT_2 for separate buffers.
 *
 * \param[in] ctx		EDHOC context.
 * \param[in] ptxt		Buffer containing the PLAINTEXT_2.
 * \param ptxt_len              Size of the \p plaintext buffer in bytes.
 * \param[out] parsed_ptxt     	Structure where parsed PLAINTEXT_2 is to be written.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int parse_plaintext(struct edhoc_context *ctx, const uint8_t *ptxt,
			   size_t ptxt_len, struct plaintext *parsed_ptxt);

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
static int comp_th_3(struct edhoc_context *ctx,
		     const struct mac_context *mac_ctx, const uint8_t *ptxt,
		     size_t ptxt_len);

/**
 * \brief Compute SALT_3e2m.
 * 
 * \param[in] ctx               EDHOC context.
 * \param[out] salt             Buffer where the generated salt is to be written.
 * \param salt_len              Size of the \p salt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_salt_3e2m(const struct edhoc_context *ctx, uint8_t *salt,
			  size_t salt_len);

/**
 * \brief Compute G_RX for PRK_3e2m.
 * 
 * \param[in,out] ctx           EDHOC context.
 * \param[in] auth_cred         Authentication credentials.
 * \param[in] pub_key           Peer public key.
 * \param pub_key_len           Peer public key length.
 * \param[out] grx              Buffer where the generated G_RX is to be written.
 * \param grx_len               Size of the \p grx buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int comp_grx(struct edhoc_context *ctx,
		    const struct edhoc_auth_creds *auth_cred,
		    const uint8_t *pub_key, size_t pub_key_len, uint8_t *grx,
		    size_t grx_len);

/* Static function definitions --------------------------------------------- */

static int gen_dh_keys(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("NULL context");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* Generate ephemeral key pair. */
	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_MAKE_KEY_PAIR, NULL,
				   0, key_id);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to import key for DH key generation: %d",
			      ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* Choose most preferred cipher suite. */
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	ctx->dh_pub_key_len = csuite.ecc_key_length;
	ctx->dh_priv_key_len = csuite.ecc_key_length;

	size_t pub_key_len = 0;
	size_t priv_key_len = 0;
	ret = ctx->crypto.make_key_pair(ctx->user_ctx, key_id, ctx->dh_priv_key,
					ctx->dh_priv_key_len, &priv_key_len,
					ctx->dh_pub_key, ctx->dh_pub_key_len,
					&pub_key_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);

	if (EDHOC_SUCCESS != ret || csuite.ecc_key_length != priv_key_len ||
	    csuite.ecc_key_length != pub_key_len) {
		EDHOC_LOG_ERR(
			"DH key pair generation failed: ret=%d, expected=%zu, priv=%zu, pub=%zu",
			ret, csuite.ecc_key_length, priv_key_len, pub_key_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int comp_dh_secret(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("NULL context");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_KEY_AGREEMENT,
				   ctx->dh_priv_key, ctx->dh_priv_key_len,
				   key_id);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to import key for DH secret: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];
	ctx->dh_secret_len = csuite.ecc_key_length;

	size_t secret_len = 0;
	ret = ctx->crypto.key_agreement(ctx->user_ctx, key_id,
					ctx->dh_peer_pub_key,
					ctx->dh_peer_pub_key_len,
					ctx->dh_secret, ctx->dh_secret_len,
					&secret_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);

	if (EDHOC_SUCCESS != ret || secret_len != csuite.ecc_key_length) {
		EDHOC_LOG_ERR(
			"Key agreement failed: ret=%d, expected=%zu, got=%zu",
			ret, csuite.ecc_key_length, secret_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int comp_th_2(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("NULL context");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_1 != ctx->th_state) {
		EDHOC_LOG_ERR("Invalid TH state: expected=%d, got=%d",
			      EDHOC_TH_STATE_1, ctx->th_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* Calculate required sizes for CBOR TH_2 = H(G_Y, H(message_1)). */
	size_t g_y_len = 0;
	g_y_len += csuite.ecc_key_length;
	g_y_len += edhoc_cbor_bstr_oh(csuite.ecc_key_length);

	size_t hash_len = 0;
	hash_len += csuite.hash_length;
	hash_len += edhoc_cbor_bstr_oh(csuite.hash_length);

	VLA_ALLOC(uint8_t, th_2, g_y_len + hash_len);
	memset(th_2, 0, VLA_SIZEOF(th_2));

	size_t offset = 0;
	size_t len_out = 0;
	struct zcbor_string cbor_bstr = { 0 };

	/* Cborise G_Y. */
	switch (ctx->role) {
	case EDHOC_INITIATOR:
		cbor_bstr.value = ctx->dh_peer_pub_key;
		cbor_bstr.len = ctx->dh_peer_pub_key_len;
		break;
	case EDHOC_RESPONDER:
		cbor_bstr.value = ctx->dh_pub_key;
		cbor_bstr.len = ctx->dh_pub_key_len;
		break;
	default:
		EDHOC_LOG_ERR("Invalid role: %d", ctx->role);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	len_out = 0;
	ret = cbor_encode_byte_string_type_bstr_type(th_2, g_y_len, &cbor_bstr,
						     &len_out);

	if (ZCBOR_SUCCESS != ret || g_y_len != len_out) {
		EDHOC_LOG_ERR(
			"CBOR encoding G_Y failed: ret=%d, expected=%zu, got=%zu",
			ret, g_y_len, len_out);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	offset += len_out;

	/* Cborise H(message_1). */
	cbor_bstr.value = ctx->th;
	cbor_bstr.len = ctx->th_len;

	len_out = 0;
	ret = cbor_encode_byte_string_type_bstr_type(&th_2[offset], hash_len,
						     &cbor_bstr, &len_out);

	if (ZCBOR_SUCCESS != ret || hash_len != len_out) {
		EDHOC_LOG_ERR(
			"CBOR encoding H(msg_1) failed: ret=%d, expected=%zu, got=%zu",
			ret, hash_len, len_out);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	offset += len_out;

	if (VLA_SIZE(th_2) < offset) {
		EDHOC_LOG_ERR("Buffer too small for TH_2: size=%zu, offset=%zu",
			      VLA_SIZE(th_2), offset);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	/* Calculate TH_2. */
	ctx->th_len = csuite.hash_length;

	size_t hash_length = 0;
	ret = ctx->crypto.hash(ctx->user_ctx, th_2, VLA_SIZE(th_2), ctx->th,
			       ctx->th_len, &hash_length);

	if (EDHOC_SUCCESS != ret || csuite.hash_length != hash_length) {
		EDHOC_LOG_ERR("TH_2 hash failed: ret=%d, expected=%zu, got=%zu",
			      ret, csuite.hash_length, hash_length);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ctx->th_state = EDHOC_TH_STATE_2;
	return EDHOC_SUCCESS;
}

static int comp_prk_2e(struct edhoc_context *ctx)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("NULL context");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_2 != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state) {
		EDHOC_LOG_ERR(
			"Invalid state for PRK_2e: th_state=%d, prk_state=%d",
			ctx->th_state, ctx->prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	ctx->prk_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_EXTRACT,
				   ctx->dh_secret, ctx->dh_secret_len, key_id);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to import key for PRK_2e: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	size_t out_len = 0;
	ret = ctx->crypto.extract(ctx->user_ctx, key_id, ctx->th, ctx->th_len,
				  ctx->prk, ctx->prk_len, &out_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);

	if (EDHOC_SUCCESS != ret || ctx->prk_len != out_len) {
		EDHOC_LOG_ERR(
			"PRK_2e extract failed: ret=%d, expected=%zu, got=%zu",
			ret, ctx->prk_len, out_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ctx->prk_state = EDHOC_PRK_STATE_2E;
	return EDHOC_SUCCESS;
}

static int comp_prk_3e2m(struct edhoc_context *ctx,
			 const struct edhoc_auth_creds *auth_cred,
			 const uint8_t *pub_key, size_t pub_key_len)
{
	if (NULL == ctx) {
		EDHOC_LOG_ERR("NULL context");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_PRK_STATE_2E != ctx->prk_state) {
		EDHOC_LOG_ERR("Invalid PRK state for PRK_3e2m: %d",
			      ctx->prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	switch (ctx->chosen_method) {
	case EDHOC_METHOD_0:
	case EDHOC_METHOD_2:
		ctx->prk_state = EDHOC_PRK_STATE_3E2M;
		return EDHOC_SUCCESS;

	case EDHOC_METHOD_1:
	case EDHOC_METHOD_3: {
		const size_t hash_len =
			ctx->csuite[ctx->chosen_csuite_idx].hash_length;

		VLA_ALLOC(uint8_t, salt_3e2m, hash_len);
		memset(salt_3e2m, 0, VLA_SIZEOF(salt_3e2m));

		int ret = comp_salt_3e2m(ctx, salt_3e2m, VLA_SIZE(salt_3e2m));

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Failed to compute SALT_3e2m: %d", ret);
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		EDHOC_LOG_HEXDUMP_INF(salt_3e2m, VLA_SIZE(salt_3e2m),
				      "SALT_3e2m");

		const size_t ecc_key_len =
			ctx->csuite[ctx->chosen_csuite_idx].ecc_key_length;

		VLA_ALLOC(uint8_t, grx, ecc_key_len);
		memset(grx, 0, VLA_SIZEOF(grx));

		ret = comp_grx(ctx, auth_cred, pub_key, pub_key_len, grx,
			       VLA_SIZE(grx));

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Failed to compute G_RX: %d", ret);
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		EDHOC_LOG_HEXDUMP_INF(grx, VLA_SIZE(grx), "G_RX");

		ctx->prk_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

		uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
		ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_EXTRACT, grx,
					   VLA_SIZE(grx), key_id);
		memset(grx, 0, VLA_SIZEOF(grx));

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("Failed to import key for PRK_3e2m: %d",
				      ret);
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		size_t out_len = 0;
		ret = ctx->crypto.extract(ctx->user_ctx, key_id, salt_3e2m,
					  VLA_SIZE(salt_3e2m), ctx->prk,
					  ctx->prk_len, &out_len);
		ctx->keys.destroy_key(ctx->user_ctx, key_id);

		if (EDHOC_SUCCESS != ret || ctx->prk_len != out_len) {
			EDHOC_LOG_ERR(
				"PRK_3e2m extract failed: ret=%d, expected=%zu, got=%zu",
				ret, ctx->prk_len, out_len);
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		ctx->prk_state = EDHOC_PRK_STATE_3E2M;
		return EDHOC_SUCCESS;
	}

	case EDHOC_METHOD_MAX:
		EDHOC_LOG_ERR("Invalid method: EDHOC_METHOD_MAX");
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	EDHOC_LOG_ERR("Unsupported method: %d", ctx->chosen_method);
	return EDHOC_ERROR_NOT_PERMITTED;
}

static int comp_plaintext_2_len(const struct edhoc_context *ctx,
				const struct mac_context *mac_ctx,
				size_t sign_len, size_t *plaintext_2_len)
{
	if (NULL == ctx || NULL == mac_ctx || 0 == sign_len ||
	    NULL == plaintext_2_len) {
		EDHOC_LOG_ERR("Invalid arguments in comp_plaintext_2_len");
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

	*plaintext_2_len = len;
	return EDHOC_SUCCESS;
}

static int prepare_plaintext_2(const struct edhoc_context *ctx,
			       const struct mac_context *mac_ctx,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt, size_t ptxt_size,
			       size_t *ptxt_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t offset = 0;

	switch (ctx->cid.encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER: {
		size_t len = 0;
		const int32_t value = ctx->cid.int_value;
		ret = cbor_encode_integer_type_int_type(
			ptxt, ptxt_size - offset, &value, &len);

		if (ZCBOR_SUCCESS != ret) {
			EDHOC_LOG_ERR("Failed to CBOR encode C_I integer");
			return EDHOC_ERROR_CBOR_FAILURE;
		}

		offset += len;
		break;
	}
	case EDHOC_CID_TYPE_BYTE_STRING: {
		size_t len = 0;
		const struct zcbor_string input = {
			.value = ctx->cid.bstr_value,
			.len = ctx->cid.bstr_length,
		};
		ret = cbor_encode_byte_string_type_bstr_type(
			ptxt, ptxt_size - offset, &input, &len);

		if (ZCBOR_SUCCESS != ret) {
			EDHOC_LOG_ERR("Failed to CBOR encode C_I byte string");
			return EDHOC_ERROR_CBOR_FAILURE;
		}

		offset += len;
		break;
	}
	default:
		EDHOC_LOG_ERR("Invalid C_I encode type: %d",
			      ctx->cid.encode_type);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

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
			EDHOC_LOG_ERR("Invalid ID_CRED_R encode type: %d",
				      mac_ctx->id_cred_enc_type);
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	} else {
		memcpy(&ptxt[offset], mac_ctx->id_cred, mac_ctx->id_cred_len);
		offset += mac_ctx->id_cred_len;
	}

	const struct zcbor_string cbor_sign_or_mac_2 = {
		.value = sign,
		.len = sign_len,
	};

	size_t len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		&ptxt[offset], sign_len + edhoc_cbor_bstr_oh(sign_len) + 1,
		&cbor_sign_or_mac_2, &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to CBOR encode Signature_or_MAC_2");
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	offset += len;

	if (mac_ctx->is_ead) {
		memcpy(&ptxt[offset], mac_ctx->ead, mac_ctx->ead_len);
		offset += mac_ctx->ead_len;
	}

	if (offset > ptxt_size) {
		EDHOC_LOG_ERR(
			"Buffer too small for plaintext_2: offset=%zu, size=%zu",
			offset, ptxt_size);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	*ptxt_len = offset;

	return EDHOC_SUCCESS;
}

static int comp_keystream(const struct edhoc_context *ctx,
			  const uint8_t *prk_2e, size_t prk_2e_len,
			  uint8_t *keystream, size_t keystream_len)
{
	if (NULL == ctx || NULL == prk_2e || 0 == prk_2e_len ||
	    NULL == keystream || 0 == keystream_len) {
		EDHOC_LOG_ERR("Invalid arguments in comp_keystream");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_2 != ctx->th_state) {
		EDHOC_LOG_ERR("Invalid TH state for keystream_2: %d",
			      ctx->th_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct info input_info = {
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTERAM_2,
		.info_context.value = ctx->th,
		.info_context.len = ctx->th_len,
		.info_length = (uint32_t)keystream_len,
	};

	size_t len = 0;
	len += edhoc_cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTERAM_2);
	len += ctx->th_len + edhoc_cbor_bstr_oh(ctx->th_len);
	len += edhoc_cbor_int_mem_req((int32_t)keystream_len);

	VLA_ALLOC(uint8_t, info, len);
	memset(info, 0, VLA_SIZEOF(info));

	len = 0;
	ret = cbor_encode_info(info, VLA_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret || VLA_SIZE(info) != len) {
		EDHOC_LOG_ERR(
			"Failed to CBOR encode info for keystream_2: ret=%d, expected_len=%zu, actual_len=%zu",
			ret, VLA_SIZE(info), len);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_EXPAND, prk_2e,
				   prk_2e_len, key_id);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to import PRK_2e for keystream: error=%d",
			      ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ret = ctx->crypto.expand(ctx->user_ctx, key_id, info, VLA_SIZE(info),
				 keystream, keystream_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR(
			"Failed to expand keystream_2: error=%d, keystream_len=%zu",
			ret, keystream_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static void xor_arrays(uint8_t *dst, const uint8_t *src, size_t count)
{
	for (size_t i = 0; i < count; ++i)
		dst[i] ^= src[i];
}

static int prepare_message_2(const struct edhoc_context *ctx,
			     const uint8_t *ctxt, size_t ctxt_len,
			     uint8_t *msg_2, size_t msg_2_size,
			     size_t *msg_2_len)
{
	if (NULL == ctx || NULL == ctxt || 0 == ctxt_len || NULL == msg_2 ||
	    0 == msg_2_size || NULL == msg_2_len) {
		EDHOC_LOG_ERR("Invalid arguments in prepare_message_2");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t offset = 0;

	size_t len = 0;
	len += ctx->dh_pub_key_len;
	len += ctxt_len;

	VLA_ALLOC(uint8_t, buffer, len);
	memset(buffer, 0, VLA_SIZEOF(buffer));

	memcpy(&buffer[offset], ctx->dh_pub_key, ctx->dh_pub_key_len);
	offset += ctx->dh_pub_key_len;

	memcpy(&buffer[offset], ctxt, ctxt_len);
	offset += ctxt_len;

	if (VLA_SIZE(buffer) < offset) {
		EDHOC_LOG_ERR(
			"Buffer overflow in prepare_message_2: buffer_size=%zu, offset=%zu",
			VLA_SIZE(buffer), offset);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	const struct zcbor_string cbor_msg_2 = {
		.value = buffer,
		.len = VLA_SIZE(buffer),
	};

	ret = cbor_encode_message_2_G_Y_CIPHERTEXT_2(msg_2, msg_2_size,
						     &cbor_msg_2, msg_2_len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to CBOR encode message_2: error=%d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int comp_ciphertext_2_len(const struct edhoc_context *ctx,
				 const uint8_t *msg_2, size_t msg_2_len,
				 size_t *ctxt_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct zcbor_string dec_msg_2 = { 0 };
	ret = cbor_decode_message_2_G_Y_CIPHERTEXT_2(msg_2, msg_2_len,
						     &dec_msg_2, &len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to CBOR decode message_2: error=%d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	if (len > msg_2_len) {
		EDHOC_LOG_ERR(
			"Decoded length exceeds buffer: decoded=%zu, msg_2_len=%zu",
			len, msg_2_len);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	len = dec_msg_2.len;
	len -= ctx->csuite[ctx->chosen_csuite_idx].ecc_key_length;

	*ctxt_len = len;
	return EDHOC_SUCCESS;
}

static int parse_msg_2(struct edhoc_context *ctx, const uint8_t *msg_2,
		       size_t msg_2_len, uint8_t *ctxt_2, size_t ctxt_2_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct zcbor_string dec_msg_2 = { 0 };
	ret = cbor_decode_message_2_G_Y_CIPHERTEXT_2(msg_2, msg_2_len,
						     &dec_msg_2, &len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to CBOR decode message_2: error=%d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	if (len > msg_2_len) {
		EDHOC_LOG_ERR(
			"Message 2 length mismatch: decoded=%zu, actual=%zu",
			len, msg_2_len);
		return EDHOC_ERROR_MSG_2_PROCESS_FAILURE;
	}

	/* Get Diffie-Hellmann peer public key (G_Y). */
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];
	ctx->dh_peer_pub_key_len = csuite.ecc_key_length;
	memcpy(ctx->dh_peer_pub_key, dec_msg_2.value, ctx->dh_peer_pub_key_len);

	/* Get CIPHERTEXT_2. */
	const size_t offset = ctx->dh_peer_pub_key_len;
	memcpy(ctxt_2, &dec_msg_2.value[offset], ctxt_2_len);

	return EDHOC_SUCCESS;
}

static int parse_plaintext(struct edhoc_context *ctx, const uint8_t *ptxt,
			   size_t ptxt_len, struct plaintext *parsed_ptxt)
{
	if (NULL == ctx || NULL == ptxt || 0 == ptxt_len ||
	    NULL == parsed_ptxt) {
		EDHOC_LOG_ERR("Invalid arguments in parse_plaintext");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct plaintext_2 cbor_ptxt_2 = { 0 };
	ret = cbor_decode_plaintext_2(ptxt, ptxt_len, &cbor_ptxt_2, &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to CBOR decode plaintext_2: error=%d",
			      ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* C_R */
	switch (cbor_ptxt_2.plaintext_2_C_R_choice) {
	case plaintext_2_C_R_int_c:
		if (ONE_BYTE_CBOR_INT_MIN_VALUE >
			    (int8_t)cbor_ptxt_2.plaintext_2_C_R_int ||
		    ONE_BYTE_CBOR_INT_MAX_VALUE <
			    (int8_t)cbor_ptxt_2.plaintext_2_C_R_int) {
			EDHOC_LOG_ERR(
				"C_R integer out of range: %d (expected %d to %d)",
				(int8_t)cbor_ptxt_2.plaintext_2_C_R_int,
				ONE_BYTE_CBOR_INT_MIN_VALUE,
				ONE_BYTE_CBOR_INT_MAX_VALUE);
			return EDHOC_ERROR_NOT_PERMITTED;
		}

		ctx->peer_cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
		ctx->peer_cid.int_value =
			(int8_t)cbor_ptxt_2.plaintext_2_C_R_int;
		break;

	case plaintext_2_C_R_bstr_c:
		if (ARRAY_SIZE(ctx->peer_cid.bstr_value) <
		    cbor_ptxt_2.plaintext_2_C_R_bstr.len) {
			EDHOC_LOG_ERR(
				"C_R byte string too large: %zu (max %zu)",
				cbor_ptxt_2.plaintext_2_C_R_bstr.len,
				ARRAY_SIZE(ctx->peer_cid.bstr_value));
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		ctx->peer_cid.encode_type = EDHOC_CID_TYPE_BYTE_STRING;
		ctx->peer_cid.bstr_length =
			cbor_ptxt_2.plaintext_2_C_R_bstr.len;
		memcpy(ctx->peer_cid.bstr_value,
		       cbor_ptxt_2.plaintext_2_C_R_bstr.value,
		       cbor_ptxt_2.plaintext_2_C_R_bstr.len);
		break;

	default:
		EDHOC_LOG_ERR("Invalid C_R choice: %d",
			      cbor_ptxt_2.plaintext_2_C_R_choice);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	/* ID_CRED_R */
	switch (cbor_ptxt_2.plaintext_2_ID_CRED_R_choice) {
	case plaintext_2_ID_CRED_R_int_c:
		parsed_ptxt->auth_cred.label = EDHOC_COSE_HEADER_KID;
		parsed_ptxt->auth_cred.key_id.encode_type =
			EDHOC_ENCODE_TYPE_INTEGER;
		parsed_ptxt->auth_cred.key_id.key_id_int =
			cbor_ptxt_2.plaintext_2_ID_CRED_R_int;
		break;

	case plaintext_2_ID_CRED_R_bstr_c:
		parsed_ptxt->auth_cred.label = EDHOC_COSE_HEADER_KID;
		parsed_ptxt->auth_cred.key_id.encode_type =
			EDHOC_ENCODE_TYPE_BYTE_STRING;
		parsed_ptxt->auth_cred.key_id.key_id_bstr_length =
			cbor_ptxt_2.plaintext_2_ID_CRED_R_bstr.len;
		memcpy(parsed_ptxt->auth_cred.key_id.key_id_bstr,
		       cbor_ptxt_2.plaintext_2_ID_CRED_R_bstr.value,
		       cbor_ptxt_2.plaintext_2_ID_CRED_R_bstr.len);
		break;

	case plaintext_2_ID_CRED_R_map_m_c: {
		const struct map *cbor_map =
			&cbor_ptxt_2.plaintext_2_ID_CRED_R_map_m;

		if (cbor_map->map_x5chain_present) {
			parsed_ptxt->auth_cred.label =
				EDHOC_COSE_HEADER_X509_CHAIN;

			const struct COSE_X509_r *cose_x509 =
				&cbor_map->map_x5chain.map_x5chain;

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
				if (ARRAY_SIZE(parsed_ptxt->auth_cred.x509_chain
						       .cert) <
				    cose_x509->COSE_X509_certs_l_certs_count) {
					EDHOC_LOG_ERR(
						"X.509 certificate chain too large: %zu (max %zu)",
						cose_x509->COSE_X509_certs_l_certs_count,
						ARRAY_SIZE(
							parsed_ptxt->auth_cred
								.x509_chain
								.cert));
					return EDHOC_ERROR_BUFFER_TOO_SMALL;
				}

				parsed_ptxt->auth_cred.x509_chain.nr_of_certs =
					cose_x509->COSE_X509_certs_l_certs_count;

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

			default:
				EDHOC_LOG_ERR("Invalid COSE_X509 choice: %d",
					      cose_x509->COSE_X509_choice);
				return EDHOC_ERROR_NOT_PERMITTED;
			}
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
						"X.509 hash algorithm string too large: %zu (max %zu)",
						cose_x509
							->COSE_CertHash_hashAlg_tstr
							.len,
						ARRAY_SIZE(
							parsed_ptxt->auth_cred
								.x509_hash
								.alg_bstr));
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

	/* Sign_or_MAC_2 */
	parsed_ptxt->sign_or_mac =
		cbor_ptxt_2.plaintext_2_Signature_or_MAC_2.value;
	parsed_ptxt->sign_or_mac_len =
		cbor_ptxt_2.plaintext_2_Signature_or_MAC_2.len;

	/* EAD_2 if present */
	if (cbor_ptxt_2.plaintext_2_EAD_2_m_present) {
		ctx->nr_of_ead_tokens =
			cbor_ptxt_2.plaintext_2_EAD_2_m.EAD_2_count;

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			ctx->ead_token[i].label =
				cbor_ptxt_2.plaintext_2_EAD_2_m.EAD_2[i]
					.ead_y_ead_label;
			ctx->ead_token[i].value =
				cbor_ptxt_2.plaintext_2_EAD_2_m.EAD_2[i]
					.ead_y_ead_value.value;
			ctx->ead_token[i].value_len =
				cbor_ptxt_2.plaintext_2_EAD_2_m.EAD_2[i]
					.ead_y_ead_value.len;
		}
	}

	return EDHOC_SUCCESS;
}

static int comp_th_3(struct edhoc_context *ctx,
		     const struct mac_context *mac_ctx, const uint8_t *ptxt,
		     size_t ptxt_len)
{
	if (NULL == ctx || NULL == mac_ctx || NULL == ptxt || 0 == ptxt_len) {
		EDHOC_LOG_ERR("Invalid arguments in comp_th_3");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_2 != ctx->th_state) {
		EDHOC_LOG_ERR("Bad TH state in comp_th_3: %d (expected %d)",
			      ctx->th_state, EDHOC_TH_STATE_2);
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t len = 0;
	len += ctx->th_len + edhoc_cbor_bstr_oh(ctx->th_len);
	len += ptxt_len;
	len += mac_ctx->cred_len;

	VLA_ALLOC(uint8_t, th_3, len);
	memset(th_3, 0, VLA_SIZEOF(th_3));

	size_t offset = 0;
	struct zcbor_string bstr = (struct zcbor_string){
		.value = ctx->th,
		.len = ctx->th_len,
	};

	len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		&th_3[offset], VLA_SIZE(th_3), &bstr, &len);
	offset += len;

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to CBOR encode TH_2 for TH_3: error=%d",
			      ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	memcpy(&th_3[offset], ptxt, ptxt_len);
	offset += ptxt_len;

	memcpy(&th_3[offset], mac_ctx->cred, mac_ctx->cred_len);
	offset += mac_ctx->cred_len;

	if (VLA_SIZE(th_3) < offset) {
		EDHOC_LOG_ERR(
			"Buffer overflow in comp_th_3: buffer_size=%zu, offset=%zu",
			VLA_SIZE(th_3), offset);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	/* Calculate TH_3. */
	ctx->th_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

	size_t hash_len = 0;
	ret = ctx->crypto.hash(ctx->user_ctx, th_3, VLA_SIZE(th_3), ctx->th,
			       ctx->th_len, &hash_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to hash TH_3: error=%d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ctx->th_state = EDHOC_TH_STATE_3;
	return EDHOC_SUCCESS;
}

static int comp_salt_3e2m(const struct edhoc_context *ctx, uint8_t *salt,
			  size_t salt_len)
{
	if (NULL == ctx || NULL == salt || 0 == salt_len) {
		EDHOC_LOG_ERR("Invalid arguments in comp_salt_3e2m");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_TH_STATE_2 != ctx->th_state ||
	    EDHOC_PRK_STATE_2E != ctx->prk_state) {
		EDHOC_LOG_ERR(
			"Bad state in comp_salt_3e2m: TH=%d (expected %d), PRK=%d (expected %d)",
			ctx->th_state, EDHOC_TH_STATE_2, ctx->prk_state,
			EDHOC_PRK_STATE_2E);
		return EDHOC_ERROR_BAD_STATE;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	const size_t hash_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

	const struct info input_info = {
		.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_SALT_3E2M,
		.info_context.value = ctx->th,
		.info_context.len = ctx->th_len,
		.info_length = (uint32_t)hash_len,
	};

	size_t len = 0;
	len += edhoc_cbor_int_mem_req(EDHOC_EXTRACT_PRK_INFO_LABEL_SALT_3E2M);
	len += ctx->th_len + edhoc_cbor_bstr_oh(ctx->th_len);
	len += edhoc_cbor_int_mem_req((int32_t)hash_len);

	VLA_ALLOC(uint8_t, info, len);
	memset(info, 0, VLA_SIZEOF(info));

	len = 0;
	ret = cbor_encode_info(info, VLA_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret || VLA_SIZE(info) != len) {
		EDHOC_LOG_ERR(
			"Failed to CBOR encode info for salt_3e2m: ret=%d, expected_len=%zu, actual_len=%zu",
			ret, VLA_SIZE(info), len);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_EXPAND, ctx->prk,
				   ctx->prk_len, key_id);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to import PRK_2e for salt_3e2m: error=%d",
			      ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	ret = ctx->crypto.expand(ctx->user_ctx, key_id, info, VLA_SIZE(info),
				 salt, salt_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR(
			"Failed to expand salt_3e2m: error=%d, salt_len=%zu",
			ret, salt_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int comp_grx(struct edhoc_context *ctx,
		    const struct edhoc_auth_creds *auth_cred,
		    const uint8_t *pub_key, size_t pub_key_len, uint8_t *grx,
		    size_t grx_len)
{
	if (NULL == ctx || NULL == auth_cred || NULL == grx || 0 == grx_len) {
		EDHOC_LOG_ERR("Invalid arguments in comp_grx");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	switch (ctx->role) {
	case EDHOC_INITIATOR: {
		uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
		ret = ctx->keys.import_key(ctx->user_ctx,
					   EDHOC_KT_KEY_AGREEMENT,
					   ctx->dh_priv_key,
					   ctx->dh_priv_key_len, key_id);
		ctx->dh_priv_key_len = 0;
		memset(ctx->dh_priv_key, 0, ARRAY_SIZE(ctx->dh_priv_key));

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR(
				"Failed to import DH private key for GRX (initiator): error=%d",
				ret);
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		size_t secret_len = 0;
		ret = ctx->crypto.key_agreement(ctx->user_ctx, key_id, pub_key,
						pub_key_len, grx, grx_len,
						&secret_len);

		ctx->keys.destroy_key(ctx->user_ctx, key_id);
		memset(key_id, 0, sizeof(key_id));

		if (EDHOC_SUCCESS != ret || secret_len != grx_len) {
			EDHOC_LOG_ERR(
				"Failed key agreement for GRX (initiator): error=%d, expected_len=%zu, actual_len=%zu",
				ret, grx_len, secret_len);
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		return EDHOC_SUCCESS;
	}

	case EDHOC_RESPONDER: {
		size_t secret_len = 0;
		ret = ctx->crypto.key_agreement(ctx->user_ctx,
						auth_cred->priv_key_id,
						ctx->dh_peer_pub_key,
						ctx->dh_peer_pub_key_len, grx,
						grx_len, &secret_len);

		if (EDHOC_SUCCESS != ret || secret_len != grx_len) {
			EDHOC_LOG_ERR(
				"Failed key agreement for GRX (responder): error=%d, expected_len=%zu, actual_len=%zu",
				ret, grx_len, secret_len);
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		return EDHOC_SUCCESS;
	}

	default:
		EDHOC_LOG_ERR("Invalid role in comp_grx: %d", ctx->role);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	EDHOC_LOG_ERR("Unreachable code in comp_grx - should not reach here");
	return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
}

/* Module interface function definitions ----------------------------------- */

/**
 * Steps for composition of message 2:
 *	1.  Generate ephemeral Diffie-Hellmann key pair.
 *	2.  Compute Diffie-Hellmann shared secret.
 *	3.  Compute Transcript Hash 2 (TH_2).
 *	4a. Compute Pseudo Random Key 2 (PRK_2e).
 *      4b. Copy of Pseudo Random Key 2 for keystream (step 12).
 *	5.  Fetch authentication credentials.
 *      6.  Compose EAD_2 if present.
 *      7.  Compute psuedo random key (PRK_3e2m).
 *	8a. Compute required buffer length for context_2.
 *	8b. Cborise items required by context_2.
 *	8c. Compute Message Authentication Code (MAC_2).
 *	9.  Compute signature if needed (Signature_or_MAC_2).
 *	10. Prepare plaintext (PLAINTEXT_2).
 *	11. Compute key stream (KEYSTREAM_2).
 *      12. Compute Transcript Hash 3 (TH_3).
 *	13. Compute ciphertext (CIPHERTEXT_2).
 *	14. Cborise items for message 2.
 *      15. Clean-up EAD tokens.
 */
int edhoc_message_2_compose(struct edhoc_context *ctx, uint8_t *msg_2,
			    size_t msg_2_size, size_t *msg_2_len)
{
	EDHOC_LOG_DBG("Composing EDHOC message 2");

	if (NULL == ctx || msg_2 == NULL || 0 == msg_2_size ||
	    NULL == msg_2_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_SM_RECEIVED_M1 != ctx->status ||
	    EDHOC_TH_STATE_1 != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state) {
		EDHOC_LOG_ERR(
			"Bad state in compose: status=%d, th_state=%d, prk_state=%d",
			ctx->status, ctx->th_state, ctx->prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_2;
	ctx->role = EDHOC_RESPONDER;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Generate ephemeral Diffie-Hellmann key pair. */
	ret = gen_dh_keys(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to generate DH keys: %d", ret);
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_INF(ctx->dh_pub_key, ctx->dh_pub_key_len, "G_Y");
	EDHOC_LOG_HEXDUMP_INF(ctx->dh_priv_key, ctx->dh_priv_key_len, "Y");

	/* 2. Compute Diffie-Hellmann shared secret. */
	ret = comp_dh_secret(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to compute DH secret: %d", ret);
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_INF(ctx->dh_secret, ctx->dh_secret_len, "G_XY");

	/* 3. Compute Transcript Hash 2 (TH_2). */
	ret = comp_th_2(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to compute TH_2: %d", ret);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_INF(ctx->th, ctx->th_len, "TH_2");

	/* 4a. Compute Pseudo Random Key 2 (PRK_2e). */
	ret = comp_prk_2e(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to compute PRK_2e: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_INF(ctx->prk, ctx->prk_len, "PRK_2e");

	/* 4b. Copy of Pseudo Random Key 2 for keystream (step 11). */
	VLA_ALLOC(uint8_t, prk_2e, ctx->prk_len);
	memcpy(prk_2e, ctx->prk, VLA_SIZEOF(prk_2e));

	/* 5. Fetch authentication credentials. */
	struct edhoc_auth_creds auth_cred = { 0 };
	ret = ctx->cred.fetch(ctx->user_ctx, &auth_cred);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to fetch credentials: %d", ret);
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	/* 6. Compose EAD_2 if present. */
	if (NULL != ctx->ead.compose && 0 != ARRAY_SIZE(ctx->ead_token) - 1) {
		ret = ctx->ead.compose(ctx->user_ctx, ctx->message,
				       ctx->ead_token,
				       ARRAY_SIZE(ctx->ead_token) - 1,
				       &ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret ||
		    ARRAY_SIZE(ctx->ead_token) - 1 < ctx->nr_of_ead_tokens) {
			EDHOC_LOG_ERR(
				"EAD_2 compose failure: ret=%d, tokens=%zu, max=%zu",
				ret, ctx->nr_of_ead_tokens,
				ARRAY_SIZE(ctx->ead_token) - 1);
			return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
		}

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			EDHOC_LOG_HEXDUMP_INF(
				(const uint8_t *)&ctx->ead_token[i].label,
				sizeof(ctx->ead_token[i].label),
				"EAD_2 compose label");

			if (0 != ctx->ead_token[i].value_len) {
				EDHOC_LOG_HEXDUMP_INF(
					ctx->ead_token[i].value,
					ctx->ead_token[i].value_len,
					"EAD_2 compose value");
			}
		}
	}

	/* 7. Compute psuedo random key (PRK_3e2m). */
	ret = comp_prk_3e2m(ctx, &auth_cred, NULL, 0);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to compute PRK_3e2m: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_INF(ctx->prk, ctx->prk_len, "PRK_3e2m");

	/* 8a. Compute required buffer length for context_2. */
	size_t mac_ctx_len = 0;
	ret = edhoc_comp_mac_context_length(ctx, &auth_cred, &mac_ctx_len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	/* 8b. Cborise items required by context_2. */
	VLA_ALLOC(uint8_t, mac_ctx_buf,
		  sizeof(struct mac_context) + mac_ctx_len);
	memset(mac_ctx_buf, 0, VLA_SIZEOF(mac_ctx_buf));

	struct mac_context *mac_ctx = (void *)mac_ctx_buf;
	mac_ctx->buf_len = mac_ctx_len;

	ret = edhoc_comp_mac_context(ctx, &auth_cred, mac_ctx);
	if (EDHOC_SUCCESS != ret)
		return ret;

	EDHOC_LOG_HEXDUMP_INF(mac_ctx->conn_id, mac_ctx->conn_id_len, "C_R");
	EDHOC_LOG_HEXDUMP_INF(mac_ctx->id_cred, mac_ctx->id_cred_len,
			      "ID_CRED_R");
	EDHOC_LOG_HEXDUMP_INF(mac_ctx->th, mac_ctx->th_len, "TH_2");
	EDHOC_LOG_HEXDUMP_INF(mac_ctx->cred, mac_ctx->cred_len, "CRED_R");
	EDHOC_LOG_HEXDUMP_INF(mac_ctx->buf, mac_ctx->buf_len, "context_2");

	/* 8c. Compute Message Authentication Code (MAC_2). */
	size_t mac_length = 0;
	ret = edhoc_comp_mac_length(ctx, &mac_length);
	if (EDHOC_SUCCESS != ret)
		return ret;

	VLA_ALLOC(uint8_t, mac_buf, mac_length);
	memset(mac_buf, 0, VLA_SIZEOF(mac_buf));
	ret = edhoc_comp_mac(ctx, mac_ctx, mac_buf, mac_length);
	if (EDHOC_SUCCESS != ret)
		return ret;

	/* 9. Compute signature if needed (Signature_or_MAC_2). */
	size_t sign_or_mac_length = 0;
	ret = edhoc_comp_sign_or_mac_length(ctx, &sign_or_mac_length);
	if (EDHOC_SUCCESS != ret)
		return ret;

	size_t signature_length = 0;
	VLA_ALLOC(uint8_t, signature, sign_or_mac_length);
	memset(signature, 0, VLA_SIZEOF(signature));
	ret = edhoc_comp_sign_or_mac(ctx, &auth_cred, mac_ctx, mac_buf,
				     mac_length, signature, VLA_SIZE(signature),
				     &signature_length);
	if (EDHOC_SUCCESS != ret)
		return ret;

	EDHOC_LOG_HEXDUMP_INF(signature, signature_length,
			      "Signature_or_MAC_2");

	/* 10. Prepare plaintext (PLAINTEXT_2). */
	size_t plaintext_len = 0;
	ret = comp_plaintext_2_len(ctx, mac_ctx, signature_length,
				   &plaintext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to compute plaintext_2 length: %d", ret);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	VLA_ALLOC(uint8_t, plaintext, plaintext_len);
	memset(plaintext, 0, VLA_SIZEOF(plaintext));

	plaintext_len = 0;
	ret = prepare_plaintext_2(ctx, mac_ctx, signature, signature_length,
				  plaintext, VLA_SIZE(plaintext),
				  &plaintext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to prepare plaintext_2: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_INF(plaintext, plaintext_len, "PLAINTEXT_2");

	/* 11. Compute key stream (KEYSTREAM_2). */
	VLA_ALLOC(uint8_t, keystream, plaintext_len);
	memset(keystream, 0, VLA_SIZEOF(keystream));

	ret = comp_keystream(ctx, prk_2e, VLA_SIZE(prk_2e), keystream,
			     VLA_SIZE(keystream));
	memset(prk_2e, 0, VLA_SIZEOF(prk_2e));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to compute keystream_2: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_INF(keystream, VLA_SIZE(keystream), "KEYSTREAM_2");

	/* 12. Compute Transcript Hash 3 (TH_3). */
	ret = comp_th_3(ctx, mac_ctx, plaintext, plaintext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to compute TH_3 in compose: %d", ret);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_INF(ctx->th, ctx->th_len, "TH_3");

	/* 13. Compute ciphertext (CIPHERTEXT_2). */
	xor_arrays(plaintext, keystream, plaintext_len);
	const uint8_t *ciphertext = plaintext;
	const size_t ciphertext_len = plaintext_len;

	EDHOC_LOG_HEXDUMP_INF(ciphertext, ciphertext_len, "CIPHERTEXT_2");

	/* 14. Cborise items for message 2. */
	ret = prepare_message_2(ctx, ciphertext, ciphertext_len, msg_2,
				msg_2_size, msg_2_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to prepare message_2: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_INF(msg_2, *msg_2_len, "message_2");

	/* 15. Clean-up EAD tokens. */
	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->status = EDHOC_SM_WAIT_M3;
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
 *      11. Compute psuedo random key (PRK_3e2m).
 *      12. Compute required buffer length for context_2.
 *      13. Cborise items required by context_2.
 *      14. Compute Message Authentication Code (MAC_2).
 *      15. Verify Signature_or_MAC_2.
 *      16. Compute Transcript Hash 3 (TH_3).
 *      17. Clean-up EAD tokens.
 */
int edhoc_message_2_process(struct edhoc_context *ctx, const uint8_t *msg_2,
			    size_t msg_2_len)
{
	EDHOC_LOG_DBG("Processing EDHOC message 2");

	if (NULL == ctx || NULL == msg_2 || 0 == msg_2_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_SM_WAIT_M2 != ctx->status ||
	    EDHOC_TH_STATE_1 != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state) {
		EDHOC_LOG_ERR(
			"Bad state in process: status=%d, th_state=%d, prk_state=%d",
			ctx->status, ctx->th_state, ctx->prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_2;
	ctx->role = EDHOC_INITIATOR;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	/* 1. Compute required length for ciphertext. */
	ret = comp_ciphertext_2_len(ctx, msg_2, msg_2_len, &len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to compute ciphertext length: %d", ret);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	VLA_ALLOC(uint8_t, ciphertext_2, len);
	memset(ciphertext_2, 0, VLA_SIZEOF(ciphertext_2));

	/* 2. Decode cborised message 2. */
	ret = parse_msg_2(ctx, msg_2, msg_2_len, ciphertext_2,
			  VLA_SIZE(ciphertext_2));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to parse message 2: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_INF(ciphertext_2, VLA_SIZE(ciphertext_2),
			      "CIPHERTEXT_2");

	/* 3. Compute Diffie-Hellmann shared secret (G_XY). */
	ret = comp_dh_secret(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to compute DH secret in process: %d",
			      ret);
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_INF(ctx->dh_secret, ctx->dh_secret_len, "G_XY");

	/* 4. Compute Transcript Hash 2 (TH_2). */
	ret = comp_th_2(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to compute TH_2 in process: %d", ret);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_INF(ctx->th, ctx->th_len, "TH_2");

	/* 5. Compute Pseudo Random Key 2 (PRK_2e). */
	ret = comp_prk_2e(ctx);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to compute PRK_2e in process: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_INF(ctx->prk, ctx->prk_len, "PRK_2e");

	/* 6. Compute key stream (KEYSTREAM_2). */
	VLA_ALLOC(uint8_t, keystream, VLA_SIZE(ciphertext_2));
	memset(keystream, 0, VLA_SIZEOF(keystream));

	ret = comp_keystream(ctx, ctx->prk, ctx->prk_len, keystream,
			     VLA_SIZE(keystream));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to compute keystream: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_INF(keystream, VLA_SIZE(keystream), "KEYSTREAM_2");

	/* 7. Compute plaintext (PLAINTEXT_2). */
	xor_arrays(ciphertext_2, keystream, VLA_SIZE(ciphertext_2));
	const uint8_t *plaintext = ciphertext_2;
	const size_t plaintext_len = VLA_SIZE(ciphertext_2);

	EDHOC_LOG_HEXDUMP_INF(plaintext, plaintext_len, "PLAINTEXT_2");

	/* 8. Parse plaintext (PLAINTEXT_2). */
	struct plaintext parsed_ptxt = { 0 };
	ret = parse_plaintext(ctx, plaintext, plaintext_len, &parsed_ptxt);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to parse plaintext: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	switch (ctx->peer_cid.encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
		EDHOC_LOG_HEXDUMP_INF((const uint8_t *)&ctx->peer_cid.int_value,
				      sizeof(ctx->peer_cid.int_value), "C_R");
		break;
	case EDHOC_CID_TYPE_BYTE_STRING:
		EDHOC_LOG_HEXDUMP_INF(ctx->peer_cid.bstr_value,
				      ctx->peer_cid.bstr_length, "C_R");
		break;

	default:
		EDHOC_LOG_ERR("Invalid peer CID type in logger: %d",
			      ctx->peer_cid.encode_type);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	/* 9. Process EAD if present. */
	if (NULL != ctx->ead.process && 0 != ARRAY_SIZE(ctx->ead_token) - 1 &&
	    0 != ctx->nr_of_ead_tokens) {
		ret = ctx->ead.process(ctx->user_ctx, ctx->message,
				       ctx->ead_token, ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("EAD_2 process failure: %d", ret);
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;
		}

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			EDHOC_LOG_HEXDUMP_INF(
				(const uint8_t *)&ctx->ead_token[i].label,
				sizeof(ctx->ead_token[i].label),
				"EAD_2 process label");

			if (0 != ctx->ead_token[i].value_len) {
				EDHOC_LOG_HEXDUMP_INF(
					ctx->ead_token[i].value,
					ctx->ead_token[i].value_len,
					"EAD_2 process value");
			}
		}
	}

	/* 10. Verify if credentials from peer are trusted. */
	const uint8_t *pub_key = NULL;
	size_t pub_key_len = 0;

	ret = ctx->cred.verify(ctx->user_ctx, &parsed_ptxt.auth_cred, &pub_key,
			       &pub_key_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Credentials verification failed: %d", ret);
		ctx->error_code =
			EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	/* 11. Compute psuedo random key (PRK_3e2m). */
	ret = comp_prk_3e2m(ctx, &parsed_ptxt.auth_cred, pub_key, pub_key_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to compute PRK_3e2m in process: %d", ret);
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_INF(ctx->prk, ctx->prk_len, "PRK_3e2m");

	/* 12. Compute required buffer length for context_2. */
	size_t mac_context_len = 0;
	ret = edhoc_comp_mac_context_length(ctx, &parsed_ptxt.auth_cred,
					    &mac_context_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to compute MAC context length: %d", ret);
		return EDHOC_ERROR_INVALID_MAC_2;
	}

	/* 13. Cborise items required by context_2. */
	VLA_ALLOC(uint8_t, mac_ctx_buf,
		  sizeof(struct mac_context) + mac_context_len);
	memset(mac_ctx_buf, 0, VLA_SIZEOF(mac_ctx_buf));

	struct mac_context *mac_ctx = (void *)mac_ctx_buf;
	mac_ctx->buf_len = mac_context_len;

	ret = edhoc_comp_mac_context(ctx, &parsed_ptxt.auth_cred, mac_ctx);
	if (EDHOC_SUCCESS != ret)
		return ret;

	EDHOC_LOG_HEXDUMP_INF(mac_ctx->conn_id, mac_ctx->conn_id_len, "C_R");
	EDHOC_LOG_HEXDUMP_INF(mac_ctx->id_cred, mac_ctx->id_cred_len,
			      "ID_CRED_R");
	EDHOC_LOG_HEXDUMP_INF(mac_ctx->th, mac_ctx->th_len, "TH_2");
	EDHOC_LOG_HEXDUMP_INF(mac_ctx->cred, mac_ctx->cred_len, "CRED_R");
	EDHOC_LOG_HEXDUMP_INF(mac_ctx->buf, mac_ctx->buf_len, "context_2");

	/* 14. Compute Message Authentication Code (MAC_2). */
	size_t mac_length = 0;
	ret = edhoc_comp_mac_length(ctx, &mac_length);
	if (EDHOC_SUCCESS != ret)
		return ret;

	VLA_ALLOC(uint8_t, mac_buf, mac_length);
	memset(mac_buf, 0, VLA_SIZEOF(mac_buf));
	ret = edhoc_comp_mac(ctx, mac_ctx, mac_buf, mac_length);
	if (EDHOC_SUCCESS != ret)
		return ret;

	/* 15. Verify Signature_or_MAC_2. */
	ret = edhoc_verify_sign_or_mac(ctx, mac_ctx, pub_key, pub_key_len,
				       parsed_ptxt.sign_or_mac,
				       parsed_ptxt.sign_or_mac_len, mac_buf,
				       mac_length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Signature or MAC_2 verification failed: %d",
			      ret);
		return EDHOC_ERROR_INVALID_SIGN_OR_MAC_2;
	}

	/* 16. Compute Transcript Hash 3 (TH_3). */
	ret = comp_th_3(ctx, mac_ctx, plaintext, plaintext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Failed to compute TH_3: %d", ret);
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_INF(ctx->th, ctx->th_len, "TH_3");

	/* 17. Clean-up EAD tokens. */
	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->status = EDHOC_SM_VERIFIED_M2;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}
