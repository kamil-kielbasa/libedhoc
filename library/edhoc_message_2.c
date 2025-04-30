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
#include <backend_cbor_plaintext_2b_decode.h>
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
 * \param[in,out] edhoc_context		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure. 
 */
static int generate_dh_keys(struct edhoc_context *edhoc_context);

/** 
 * \brief Compute ECDH shared secret (G_XY).
 *
 * \param[in,out] edhoc_context		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure. 
 */
static int compute_dh_secret(struct edhoc_context *edhoc_context);

/** 
 * \brief Compute transcript hash 2 (TH_2).
 *
 * \param[in,out] edhoc_context		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure. 
 */
static int compute_th_2(struct edhoc_context *edhoc_context);

/** 
 * \brief Compute psuedo random key (PRK_2e).
 *
 * \param[in,out] edhoc_context		EDHOC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure. 
 */
static int compute_prk_2e(struct edhoc_context *edhoc_context);

/** 
 * \brief Compute psuedo random key (PRK_3e2m).
 *
 * \param[in,out] edhoc_context		EDHOC context.
 * \param[in] auth_credentials		Authentication credentials.
 * \param[in] public_key           	Peer public static DH key. 
 * \param public_key_length           	Size of the \p public_key buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_prk_3e2m(struct edhoc_context *edhoc_context,
			    const struct edhoc_auth_creds *auth_credentials,
			    const uint8_t *public_key,
			    size_t public_key_length);

/** 
 * \brief Compute required PLAINTEXT_2 length.
 *
 * \param[in] edhoc_context		EDHOC context.
 * \param[in] mac_context		MAC_2 context.
 * \param signature_length		Size of the signature buffer in bytes.
 * \param[out] plaintext_2_length  	On success, length of PLAINTEXT_2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_plaintext_2_length(const struct edhoc_context *edhoc_context,
				      const struct mac_context *mac_context,
				      size_t signature_length,
				      size_t *plaintext_2_length);

/** 
 * \brief Prepare PLAINTEXT_2.
 *
 * \param[in] edhoc_context		EDHOC context.
 * \param[in] mac_context		Buffer containing the context_2.
 * \param[in] signature			Buffer containing the signature.
 * \param signature_length		Size of the \p signature buffer in bytes.
 * \param[out] plaintext_2	        Buffer where the generated plaintext is to be written.
 * \param plaintext_2_size		Size of the \p plaintext_2 buffer in bytes.
 * \param[out] plaintext_2_length	On success, the number of bytes that make up the PLAINTEXT_2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int prepare_plaintext_2(const struct edhoc_context *edhoc_context,
			       const struct mac_context *mac_context,
			       const uint8_t *signature,
			       size_t signature_length, uint8_t *plaintext_2,
			       size_t plaintext_2_size,
			       size_t *plaintext_2_length);

/** 
 * \brief Prepare MESSAGE_2.
 *
 * \param[in] edhoc_context		EDHOC context.
 * \param[in] ciphertext_2		Buffer containing the CIPHERTEXT_2.
 * \param ciphertext_2_length		Size of the \p ciphertext_2 buffer in bytes.
 * \param[out] message_2        	Buffer where the generated message 2 is to be written.
 * \param message_2_size        	Size of the \p message_2 buffer in bytes.
 * \param[out] message_2_length		On success, the number of bytes that make up the message 2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int prepare_message_2(const struct edhoc_context *edhoc_context,
			     const uint8_t *ciphertext_2,
			     size_t ciphertext_2_length, uint8_t *message_2,
			     size_t message_2_size, size_t *message_2_length);

/** 
 * \brief Compute from cborised message 2 length of ciphertext 2.
 *
 * \param[in] edhoc_context		EDHOC context.
 * \param[in] message_2     		Buffer containing the message 2.
 * \param message_2_length     		Size of the \p message_2 buffer in bytes.
 * \param[out] ciphertext_2_length	Length of ciphertext 2 in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int
compute_ciphertext_2_length(const struct edhoc_context *edhoc_context,
			    const uint8_t *message_2, size_t message_2_length,
			    size_t *ciphertext_2_length);

/** 
 * \brief Decode message 2 and save into context and buffer.
 *
 * \param[in] edhoc_context		EDHOC context.
 * \param[in] message_2     		Buffer containing the message 2.
 * \param message_2_length     		Size of the \p message_2 buffer in bytes.
 * \param[in] ciphertext_2	        Buffer containing the CIPHERTEXT_2.
 * \param ciphertext_2_length	        Size of the \p ciphertext_2 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int parse_message_2(struct edhoc_context *edhoc_context,
			   const uint8_t *message_2, size_t message_2_length,
			   uint8_t *ciphertext_2, size_t ciphertext_2_length);

/** 
 * \brief Parsed cborised PLAINTEXT_2 for separate buffers.
 *
 * \param[in] edhoc_context		EDHOC context.
 * \param[in] plaintext_2		Buffer containing the PLAINTEXT_2.
 * \param plaintext_2_length            Size of the \p plaintext_2 buffer in bytes.
 * \param[out] parsed_plaintext_2	Structure where parsed PLAINTEXT_2 is to be written.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int parse_plaintext_2(struct edhoc_context *edhoc_context,
			     const uint8_t *plaintext_2,
			     size_t plaintext_2_length,
			     struct plaintext *parsed_plaintext_2);

/** 
 * \brief Compute transcript hash 3.
 *
 * \param[in,out] edhoc_context		EDHOC context.
 * \param[in] mac_context	        MAC context.
 * \param[in] plaintext_2		Buffer containing the PLAINTEXT_2.
 * \param plaintext_2_length            Size of the \p plaintext_2 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_th_3(struct edhoc_context *edhoc_context,
			const struct mac_context *mac_context,
			const uint8_t *plaintext_2, size_t plaintext_2_length);

/**
 * \brief Compute SALT_3e2m.
 * 
 * \param[in] edhoc_context             EDHOC context.
 * \param[out] salt             	Buffer where the generated salt is to be written.
 * \param salt_length              	Size of the \p salt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_salt_3e2m(const struct edhoc_context *edhoc_context,
			     uint8_t *salt, size_t salt_length);

/**
 * \brief Compute G_RX for PRK_3e2m.
 * 
 * \param[in,out] edhoc_context		EDHOC context.
 * \param[in] auth_credential		Authentication credentials.
 * \param[in] public_key           	Peer public key.
 * \param public_key_length           	Peer public key length.
 * \param[out] grx              	Buffer where the generated G_RX is to be written.
 * \param grx_len               	Size of the \p grx buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_grx(struct edhoc_context *edhoc_context,
		       const struct edhoc_auth_creds *auth_credential,
		       const uint8_t *public_key, size_t public_key_length,
		       uint8_t *grx, size_t grx_len);

/**
 * \brief Compute required buffer length for C_R (message_2).
 * 
 * \param[in] connection_id     	EDHOC connection identifier.
 * \param[out] connection_id_length	On success, number of bytes that make up 
 *                              	C_R length requirements.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_cid_length(const struct edhoc_connection_id *connection_id,
			      size_t *connection_id_length);

/**
 * \brief Compute required buffer length for EAD (2/3).
 * 
 * \param[in] edhoc_context    		EDHOC context.
 * \param[out] ead_2_length   		On success, number of bytes that make up 
 *                              	EAD buffer length requirements.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_ead_length(const struct edhoc_context *edhoc_context,
			      size_t *ead_2_length);

/** 
 * \brief Compute required PLAINTEXT_2B length.
 *
 * \param[in] edhoc_context		EDHOC context.
 * \param[out] plaintext_2b_length  	On success, length of PLAINTEXT_2B.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int
compute_plaintext_2b_length(const struct edhoc_context *edhoc_context,
			    size_t *plaintext_2b_length);

/** 
 * \brief Prepare PLAINTEXT_2B.
 *
 * \param[in] edhoc_context		EDHOC context.
 * \param[out] plaintext_2b	        Buffer where the generated plaintext is to be written.
 * \param plaintext_2b_size		Size of the \p plaintext_2b buffer in bytes.
 * \param[out] plaintext_2b_length	On success, the number of bytes that make up the PLAINTEXT_2B.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int prepare_plaintext_2b(const struct edhoc_context *edhoc_context,
				uint8_t *plaintext_2b, size_t plaintext_2b_size,
				size_t *plaintext_2b_length);

/** 
 * \brief Parsed cborised PLAINTEXT_2B for separate buffers.
 *
 * \param[in] edhoc_context		EDHOC context.
 * \param[in] plaintext_2b		Buffer containing the PLAINTEXT_2B.
 * \param plaintext_2b_length		Size of the \p plaintext_2b buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int parse_plaintext_2b(struct edhoc_context *edhoc_context,
			      const uint8_t *plaintext_2b,
			      size_t plaintext_2b_length);

/** 
 * \brief Compute transcript hash 3 for EDHOC-PSK.
 *
 * \param[in,out] edhoc_context		EDHOC context.
 * \param[in] plaintext_2		Buffer containing the PLAINTEXT_2.
 * \param plaintext_2_length            Size of the \p plaintext_2 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_th_3_psk(struct edhoc_context *edhoc_context,
			    const uint8_t *plaintext_2,
			    size_t plaintext_2_length);

/** 
 * \brief Compose classical EDHOC message 2.
 *
 * \param[in,out] edhoc_context     	EDHOC context.
 * \param[out] message_2            	Buffer where the generated message 2 is to be written.
 * \param message_2_size            	Size of the \p message_2 buffer in bytes.
 * \param[out] message_2_length        	On success, the number of bytes that make up the message 2.
 * 
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int edhoc_classic_message_2_compose(struct edhoc_context *edhoc_context,
					   uint8_t *message_2,
					   size_t message_2_size,
					   size_t *message_2_length);

/**
 * \brief Process classical EDHOC message 2.
 *
 * \param[in,out] edhoc_context     	EDHOC context.
 * \param[in] message_2             	Buffer containing the message 2.
 * \param message_2_length             	Size of the \p message_2 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int edhoc_classic_message_2_process(struct edhoc_context *edhoc_context,
					   const uint8_t *message_2,
					   size_t message_2_length);

/** 
 * \brief Compose pre-shared key EDHOC message 2.
 *
 * \param[in,out] edhoc_context 	EDHOC context.
 * \param[out] message_2        	Buffer where the generated message 2 is to be written.
 * \param message_2_size        	Size of the \p message_2 buffer in bytes.
 * \param[out] message_2_length 	On success, the number of bytes that make up the message 2.
 * 
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int edhoc_psk_message_2_compose(struct edhoc_context *edhoc_context,
				       uint8_t *message_2,
				       size_t message_2_size,
				       size_t *message_2_length);

/**
 * \brief Process pre-shared key EDHOC message 2.
 *
 * \param[in,out] edhoc_context 	EDHOC context.
 * \param[in] message_2         	Buffer containing the message 2.
 * \param message_2_length      	Size of the \p message_2 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int edhoc_psk_message_2_process(struct edhoc_context *edhoc_context,
				       const uint8_t *message_2,
				       size_t message_2_length);

/* Static function definitions --------------------------------------------- */

static int generate_dh_keys(struct edhoc_context *ctx)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* Generate ephemeral key pair. */
	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_MAKE_KEY_PAIR, NULL,
				   0, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

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
	    csuite.ecc_key_length != pub_key_len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int compute_dh_secret(struct edhoc_context *ctx)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_KEY_AGREEMENT,
				   ctx->dh_priv_key, ctx->dh_priv_key_len,
				   key_id);
	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

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

	if (EDHOC_SUCCESS != ret || secret_len != csuite.ecc_key_length)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int compute_th_2(struct edhoc_context *ctx)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_1 != ctx->th_state)
		return EDHOC_ERROR_BAD_STATE;

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
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	len_out = 0;
	ret = cbor_encode_byte_string_type_bstr_type(th_2, g_y_len, &cbor_bstr,
						     &len_out);

	if (ZCBOR_SUCCESS != ret || g_y_len != len_out)
		return EDHOC_ERROR_CBOR_FAILURE;

	offset += len_out;

	/* Cborise H(message_1). */
	cbor_bstr.value = ctx->th;
	cbor_bstr.len = ctx->th_len;

	len_out = 0;
	ret = cbor_encode_byte_string_type_bstr_type(&th_2[offset], hash_len,
						     &cbor_bstr, &len_out);

	if (ZCBOR_SUCCESS != ret || hash_len != len_out)
		return EDHOC_ERROR_CBOR_FAILURE;

	offset += len_out;

	if (VLA_SIZE(th_2) < offset)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	/* Calculate TH_2. */
	ctx->th_len = csuite.hash_length;

	size_t hash_length = 0;
	ret = ctx->crypto.hash(ctx->user_ctx, th_2, VLA_SIZE(th_2), ctx->th,
			       ctx->th_len, &hash_length);

	if (EDHOC_SUCCESS != ret || csuite.hash_length != hash_length)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->th_state = EDHOC_TH_STATE_2;
	return EDHOC_SUCCESS;
}

static int compute_prk_2e(struct edhoc_context *ctx)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_2 != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	ctx->prk_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_EXTRACT,
				   ctx->dh_secret, ctx->dh_secret_len, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	size_t out_len = 0;
	ret = ctx->crypto.extract(ctx->user_ctx, key_id, ctx->th, ctx->th_len,
				  ctx->prk, ctx->prk_len, &out_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);

	if (EDHOC_SUCCESS != ret || ctx->prk_len != out_len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->prk_state = EDHOC_PRK_STATE_2E;
	return EDHOC_SUCCESS;
}

static int compute_prk_3e2m(struct edhoc_context *ctx,
			    const struct edhoc_auth_creds *auth_creds,
			    const uint8_t *pub_key, size_t pub_key_len)
{
	if (NULL == ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_PRK_STATE_2E != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	switch (ctx->chosen_method) {
	case EDHOC_METHOD_0:
	case EDHOC_METHOD_2:
	case EDHOC_METHOD_PSK:
		ctx->prk_state = EDHOC_PRK_STATE_3E2M;
		return EDHOC_SUCCESS;

	case EDHOC_METHOD_1:
	case EDHOC_METHOD_3: {
		const size_t hash_len =
			ctx->csuite[ctx->chosen_csuite_idx].hash_length;

		VLA_ALLOC(uint8_t, salt_3e2m, hash_len);
		memset(salt_3e2m, 0, VLA_SIZEOF(salt_3e2m));

		int ret =
			compute_salt_3e2m(ctx, salt_3e2m, VLA_SIZE(salt_3e2m));

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		if (NULL != ctx->logger)
			ctx->logger(ctx->user_ctx, "SALT_3e2m", salt_3e2m,
				    VLA_SIZE(salt_3e2m));

		const size_t ecc_key_len =
			ctx->csuite[ctx->chosen_csuite_idx].ecc_key_length;

		VLA_ALLOC(uint8_t, grx, ecc_key_len);
		memset(grx, 0, VLA_SIZEOF(grx));

		ret = compute_grx(ctx, auth_creds, pub_key, pub_key_len, grx,
				  VLA_SIZE(grx));

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		if (NULL != ctx->logger)
			ctx->logger(ctx->user_ctx, "G_RX", grx, VLA_SIZE(grx));

		ctx->prk_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

		uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
		ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_EXTRACT, grx,
					   VLA_SIZE(grx), key_id);
		memset(grx, 0, VLA_SIZEOF(grx));

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		size_t out_len = 0;
		ret = ctx->crypto.extract(ctx->user_ctx, key_id, salt_3e2m,
					  VLA_SIZE(salt_3e2m), ctx->prk,
					  ctx->prk_len, &out_len);
		ctx->keys.destroy_key(ctx->user_ctx, key_id);

		if (EDHOC_SUCCESS != ret || ctx->prk_len != out_len)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		ctx->prk_state = EDHOC_PRK_STATE_3E2M;
		return EDHOC_SUCCESS;
	}

	case EDHOC_METHOD_MAX:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	return EDHOC_ERROR_NOT_PERMITTED;
}

static int compute_plaintext_2_length(const struct edhoc_context *ctx,
				      const struct mac_context *mac_ctx,
				      size_t sign_len, size_t *ptxt_2_len)
{
	if (NULL == ctx || NULL == mac_ctx || 0 == sign_len ||
	    NULL == ptxt_2_len)
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

	*ptxt_2_len = len;
	return EDHOC_SUCCESS;
}

static int prepare_plaintext_2(const struct edhoc_context *ctx,
			       const struct mac_context *mac_ctx,
			       const uint8_t *sign, size_t sign_len,
			       uint8_t *ptxt_2, size_t ptxt_2_size,
			       size_t *ptxt_2_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t offset = 0;

	switch (ctx->cid.encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER: {
		size_t len = 0;
		const int32_t value = ctx->cid.int_value;
		ret = cbor_encode_integer_type_int_type(
			ptxt_2, ptxt_2_size - offset, &value, &len);

		if (ZCBOR_SUCCESS != ret)
			return EDHOC_ERROR_CBOR_FAILURE;

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
			ptxt_2, ptxt_2_size - offset, &input, &len);

		if (ZCBOR_SUCCESS != ret)
			return EDHOC_ERROR_CBOR_FAILURE;

		offset += len;
		break;
	}
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (mac_ctx->id_cred_is_comp_enc) {
		switch (mac_ctx->id_cred_enc_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			memcpy(&ptxt_2[offset], &mac_ctx->id_cred_int, 1);
			offset += 1;
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			memcpy(&ptxt_2[offset], &mac_ctx->id_cred_bstr,
			       mac_ctx->id_cred_bstr_len);
			offset += mac_ctx->id_cred_bstr_len;
			break;
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	} else {
		memcpy(&ptxt_2[offset], mac_ctx->id_cred, mac_ctx->id_cred_len);
		offset += mac_ctx->id_cred_len;
	}

	const struct zcbor_string cbor_sign_or_mac_2 = {
		.value = sign,
		.len = sign_len,
	};

	size_t len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		&ptxt_2[offset], sign_len + edhoc_cbor_bstr_oh(sign_len) + 1,
		&cbor_sign_or_mac_2, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	offset += len;

	if (mac_ctx->is_ead) {
		memcpy(&ptxt_2[offset], mac_ctx->ead, mac_ctx->ead_len);
		offset += mac_ctx->ead_len;
	}

	if (offset > ptxt_2_size)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	*ptxt_2_len = offset;

	return EDHOC_SUCCESS;
}

static int prepare_message_2(const struct edhoc_context *ctx,
			     const uint8_t *ctxt_2, size_t ctxt_2_len,
			     uint8_t *msg_2, size_t msg_2_size,
			     size_t *msg_2_len)
{
	if (NULL == ctx || NULL == ctxt_2 || 0 == ctxt_2_len || NULL == msg_2 ||
	    0 == msg_2_size || NULL == msg_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t offset = 0;

	size_t len = 0;
	len += ctx->dh_pub_key_len;
	len += ctxt_2_len;

	VLA_ALLOC(uint8_t, buffer, len);
	memset(buffer, 0, VLA_SIZEOF(buffer));

	memcpy(&buffer[offset], ctx->dh_pub_key, ctx->dh_pub_key_len);
	offset += ctx->dh_pub_key_len;

	memcpy(&buffer[offset], ctxt_2, ctxt_2_len);
	offset += ctxt_2_len;

	if (VLA_SIZE(buffer) < offset)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	const struct zcbor_string cbor_msg_2 = {
		.value = buffer,
		.len = VLA_SIZE(buffer),
	};

	ret = cbor_encode_message_2_G_Y_CIPHERTEXT_2(msg_2, msg_2_size,
						     &cbor_msg_2, msg_2_len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	return EDHOC_SUCCESS;
}

static int compute_ciphertext_2_length(const struct edhoc_context *ctx,
				       const uint8_t *msg_2, size_t msg_2_len,
				       size_t *ctxt_2_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct zcbor_string dec_msg_2 = { 0 };
	ret = cbor_decode_message_2_G_Y_CIPHERTEXT_2(msg_2, msg_2_len,
						     &dec_msg_2, &len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (len > msg_2_len)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	len = dec_msg_2.len;
	len -= ctx->csuite[ctx->chosen_csuite_idx].ecc_key_length;

	*ctxt_2_len = len;
	return EDHOC_SUCCESS;
}

static int parse_message_2(struct edhoc_context *ctx, const uint8_t *msg_2,
			   size_t msg_2_len, uint8_t *ctxt_2, size_t ctxt_2_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct zcbor_string dec_msg_2 = { 0 };
	ret = cbor_decode_message_2_G_Y_CIPHERTEXT_2(msg_2, msg_2_len,
						     &dec_msg_2, &len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (len > msg_2_len)
		return EDHOC_ERROR_MSG_2_PROCESS_FAILURE;

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

static int parse_plaintext_2(struct edhoc_context *ctx, const uint8_t *ptxt_2,
			     size_t ptxt_2_len, struct plaintext *parsed_ptxt_2)
{
	if (NULL == ctx || NULL == ptxt_2 || 0 == ptxt_2_len ||
	    NULL == parsed_ptxt_2)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct plaintext_2 dec_ptxt_2 = { 0 };
	ret = cbor_decode_plaintext_2(ptxt_2, ptxt_2_len, &dec_ptxt_2, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	/* C_R */
	switch (dec_ptxt_2.plaintext_2_C_R_choice) {
	case plaintext_2_C_R_int_c:
		if (ONE_BYTE_CBOR_INT_MIN_VALUE >
			    (int8_t)dec_ptxt_2.plaintext_2_C_R_int ||
		    ONE_BYTE_CBOR_INT_MAX_VALUE <
			    (int8_t)dec_ptxt_2.plaintext_2_C_R_int)
			return EDHOC_ERROR_NOT_PERMITTED;

		ctx->peer_cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
		ctx->peer_cid.int_value =
			(int8_t)dec_ptxt_2.plaintext_2_C_R_int;
		break;

	case plaintext_2_C_R_bstr_c:
		if (ARRAY_SIZE(ctx->peer_cid.bstr_value) <
		    dec_ptxt_2.plaintext_2_C_R_bstr.len)
			return EDHOC_ERROR_BUFFER_TOO_SMALL;

		ctx->peer_cid.encode_type = EDHOC_CID_TYPE_BYTE_STRING;
		ctx->peer_cid.bstr_length = dec_ptxt_2.plaintext_2_C_R_bstr.len;
		memcpy(ctx->peer_cid.bstr_value,
		       dec_ptxt_2.plaintext_2_C_R_bstr.value,
		       dec_ptxt_2.plaintext_2_C_R_bstr.len);
		break;

	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	/* ID_CRED_R */
	switch (dec_ptxt_2.plaintext_2_ID_CRED_R_choice) {
	case plaintext_2_ID_CRED_R_int_c:
		parsed_ptxt_2->auth_creds.label = EDHOC_COSE_HEADER_KID;
		parsed_ptxt_2->auth_creds.key_id.encode_type =
			EDHOC_ENCODE_TYPE_INTEGER;
		parsed_ptxt_2->auth_creds.key_id.key_id_int =
			dec_ptxt_2.plaintext_2_ID_CRED_R_int;
		break;

	case plaintext_2_ID_CRED_R_bstr_c:
		parsed_ptxt_2->auth_creds.label = EDHOC_COSE_HEADER_KID;
		parsed_ptxt_2->auth_creds.key_id.encode_type =
			EDHOC_ENCODE_TYPE_BYTE_STRING;
		parsed_ptxt_2->auth_creds.key_id.key_id_bstr_length =
			dec_ptxt_2.plaintext_2_ID_CRED_R_bstr.len;
		memcpy(parsed_ptxt_2->auth_creds.key_id.key_id_bstr,
		       dec_ptxt_2.plaintext_2_ID_CRED_R_bstr.value,
		       dec_ptxt_2.plaintext_2_ID_CRED_R_bstr.len);
		break;

	case plaintext_2_ID_CRED_R_map_m_c: {
		const struct map *cbor_map =
			&dec_ptxt_2.plaintext_2_ID_CRED_R_map_m;

		if (cbor_map->map_x5chain_present) {
			parsed_ptxt_2->auth_creds.label =
				EDHOC_COSE_HEADER_X509_CHAIN;

			const struct COSE_X509_r *cose_x509 =
				&cbor_map->map_x5chain.map_x5chain;

			switch (cose_x509->COSE_X509_choice) {
			case COSE_X509_bstr_c:
				parsed_ptxt_2->auth_creds.x509_chain
					.nr_of_certs = 1;
				parsed_ptxt_2->auth_creds.x509_chain.cert[0] =
					cose_x509->COSE_X509_bstr.value;
				parsed_ptxt_2->auth_creds.x509_chain
					.cert_len[0] =
					cose_x509->COSE_X509_bstr.len;
				break;
			case COSE_X509_certs_l_c: {
				if (ARRAY_SIZE(parsed_ptxt_2->auth_creds
						       .x509_chain.cert) <
				    cose_x509->COSE_X509_certs_l_certs_count)
					return EDHOC_ERROR_BUFFER_TOO_SMALL;

				parsed_ptxt_2->auth_creds.x509_chain
					.nr_of_certs =
					cose_x509->COSE_X509_certs_l_certs_count;

				for (size_t i = 0;
				     i <
				     cose_x509->COSE_X509_certs_l_certs_count;
				     ++i) {
					parsed_ptxt_2->auth_creds.x509_chain
						.cert[i] =
						cose_x509
							->COSE_X509_certs_l_certs
								[i]
							.value;
					parsed_ptxt_2->auth_creds.x509_chain
						.cert_len[i] =
						cose_x509
							->COSE_X509_certs_l_certs
								[i]
							.len;
				}
				break;
			}

			default:
				return EDHOC_ERROR_NOT_PERMITTED;
			}
		}

		if (cbor_map->map_x5t_present) {
			parsed_ptxt_2->auth_creds.label =
				EDHOC_COSE_HEADER_X509_HASH;

			const struct COSE_CertHash *cose_x509 =
				&cbor_map->map_x5t.map_x5t;

			parsed_ptxt_2->auth_creds.x509_hash.cert_fp =
				cose_x509->COSE_CertHash_hashValue.value;
			parsed_ptxt_2->auth_creds.x509_hash.cert_fp_len =
				cose_x509->COSE_CertHash_hashValue.len;

			switch (cose_x509->COSE_CertHash_hashAlg_choice) {
			case COSE_CertHash_hashAlg_int_c:
				parsed_ptxt_2->auth_creds.x509_hash.encode_type =
					EDHOC_ENCODE_TYPE_INTEGER;
				parsed_ptxt_2->auth_creds.x509_hash.alg_int =
					cose_x509->COSE_CertHash_hashAlg_int;
				break;
			case COSE_CertHash_hashAlg_tstr_c:
				if (ARRAY_SIZE(parsed_ptxt_2->auth_creds
						       .x509_hash.alg_bstr) <
				    cose_x509->COSE_CertHash_hashAlg_tstr.len)
					return EDHOC_ERROR_BUFFER_TOO_SMALL;

				parsed_ptxt_2->auth_creds.x509_hash.encode_type =
					EDHOC_ENCODE_TYPE_BYTE_STRING;
				parsed_ptxt_2->auth_creds.x509_hash
					.alg_bstr_length =
					cose_x509->COSE_CertHash_hashAlg_tstr
						.len;
				memcpy(parsed_ptxt_2->auth_creds.x509_hash
					       .alg_bstr,
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

	/* Sign_or_MAC_2 */
	parsed_ptxt_2->sign_or_mac =
		dec_ptxt_2.plaintext_2_Signature_or_MAC_2.value;
	parsed_ptxt_2->sign_or_mac_len =
		dec_ptxt_2.plaintext_2_Signature_or_MAC_2.len;

	/* EAD_2 if present */
	if (dec_ptxt_2.plaintext_2_EAD_2_m_present) {
		ctx->nr_of_ead_tokens =
			dec_ptxt_2.plaintext_2_EAD_2_m.EAD_2_count;

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			ctx->ead_token[i].label =
				dec_ptxt_2.plaintext_2_EAD_2_m.EAD_2[i]
					.ead_y_ead_label;
			ctx->ead_token[i].value =
				dec_ptxt_2.plaintext_2_EAD_2_m.EAD_2[i]
					.ead_y_ead_value.value;
			ctx->ead_token[i].value_len =
				dec_ptxt_2.plaintext_2_EAD_2_m.EAD_2[i]
					.ead_y_ead_value.len;
		}
	}

	return EDHOC_SUCCESS;
}

static int compute_th_3(struct edhoc_context *ctx,
			const struct mac_context *mac_ctx,
			const uint8_t *ptxt_2, size_t ptxt_2_len)
{
	if (NULL == ctx || NULL == mac_ctx || NULL == ptxt_2 || 0 == ptxt_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_2 != ctx->th_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t len = 0;
	len += ctx->th_len + edhoc_cbor_bstr_oh(ctx->th_len);
	len += ptxt_2_len;
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

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	memcpy(&th_3[offset], ptxt_2, ptxt_2_len);
	offset += ptxt_2_len;

	memcpy(&th_3[offset], mac_ctx->cred, mac_ctx->cred_len);
	offset += mac_ctx->cred_len;

	if (VLA_SIZE(th_3) < offset)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	/* Calculate TH_3. */
	ctx->th_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

	size_t hash_len = 0;
	ret = ctx->crypto.hash(ctx->user_ctx, th_3, VLA_SIZE(th_3), ctx->th,
			       ctx->th_len, &hash_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->th_state = EDHOC_TH_STATE_3;
	return EDHOC_SUCCESS;
}

static int compute_salt_3e2m(const struct edhoc_context *ctx, uint8_t *salt,
			     size_t salt_len)
{
	if (NULL == ctx || NULL == salt || 0 == salt_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_2 != ctx->th_state ||
	    EDHOC_PRK_STATE_2E != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

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

static int compute_grx(struct edhoc_context *ctx,
		       const struct edhoc_auth_creds *auth_creds,
		       const uint8_t *pub_key, size_t pub_key_len, uint8_t *grx,
		       size_t grx_len)
{
	if (NULL == ctx || NULL == auth_creds || NULL == grx || 0 == grx_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

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

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		size_t secret_len = 0;
		ret = ctx->crypto.key_agreement(ctx->user_ctx, key_id, pub_key,
						pub_key_len, grx, grx_len,
						&secret_len);

		ctx->keys.destroy_key(ctx->user_ctx, key_id);
		memset(key_id, 0, sizeof(key_id));

		if (EDHOC_SUCCESS != ret || secret_len != grx_len)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		return EDHOC_SUCCESS;
	}

	case EDHOC_RESPONDER: {
		size_t secret_len = 0;
		ret = ctx->crypto.key_agreement(ctx->user_ctx,
						auth_creds->priv_key_id,
						ctx->dh_peer_pub_key,
						ctx->dh_peer_pub_key_len, grx,
						grx_len, &secret_len);

		if (EDHOC_SUCCESS != ret || secret_len != grx_len)
			return EDHOC_ERROR_CRYPTO_FAILURE;

		return EDHOC_SUCCESS;
	}

	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;
}

static int compute_cid_length(const struct edhoc_connection_id *cid,
			      size_t *cid_len)
{
	if (NULL == cid || NULL == cid_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	*cid_len = 0;

	switch (cid->encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
		*cid_len = 1;
		break;
	case EDHOC_CID_TYPE_BYTE_STRING:
		*cid_len += cid->bstr_length + 1;
		*cid_len += edhoc_cbor_bstr_oh(cid->bstr_length);
		break;
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	return EDHOC_SUCCESS;
}

static int compute_ead_length(const struct edhoc_context *ctx, size_t *ead_len)
{
	if (NULL == ctx || NULL == ead_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
		*ead_len += edhoc_cbor_int_mem_req(ctx->ead_token[i].label);
		*ead_len += ctx->ead_token[i].value_len;
		*ead_len += edhoc_cbor_bstr_oh(ctx->ead_token[i].value_len);
	}

	return EDHOC_SUCCESS;
}

static int compute_plaintext_2b_length(const struct edhoc_context *ctx,
				       size_t *ptxt_2b_len)
{
	if (NULL == ctx || NULL == ptxt_2b_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	const struct edhoc_connection_id *cid = NULL;

	switch (ctx->role) {
	case EDHOC_INITIATOR:
		cid = &ctx->peer_cid;
		break;
	case EDHOC_RESPONDER:
		cid = &ctx->cid;
		break;
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	len = 0;
	ret = compute_cid_length(cid, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	*ptxt_2b_len += len;

	len = 0;
	ret = compute_ead_length(ctx, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	*ptxt_2b_len += len;

	return EDHOC_SUCCESS;
}

static int prepare_plaintext_2b(const struct edhoc_context *ctx,
				uint8_t *ptxt_2b, size_t ptxt_2b_size,
				size_t *ptxt_2b_len)
{
	if (NULL == ctx || NULL == ptxt_2b || 0 == ptxt_2b_size ||
	    NULL == ptxt_2b_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t offset = 0;

	switch (ctx->cid.encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER: {
		size_t len = 0;
		const int32_t value = ctx->cid.int_value;
		ret = cbor_encode_integer_type_int_type(
			ptxt_2b, ptxt_2b_size - offset, &value, &len);

		if (ZCBOR_SUCCESS != ret)
			return EDHOC_ERROR_CBOR_FAILURE;

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
			ptxt_2b, ptxt_2b_size - offset, &input, &len);

		if (ZCBOR_SUCCESS != ret)
			return EDHOC_ERROR_CBOR_FAILURE;

		offset += len;
		break;
	}
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	if (0 != ctx->nr_of_ead_tokens) {
		struct ead tmp_ead = { .ead_count = ctx->nr_of_ead_tokens };

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			tmp_ead.ead[i].ead_x_ead_label =
				ctx->ead_token[i].label;
			tmp_ead.ead[i].ead_x_ead_value_present =
				(NULL != ctx->ead_token[i].value);
			tmp_ead.ead[i].ead_x_ead_value.value =
				ctx->ead_token[i].value;
			tmp_ead.ead[i].ead_x_ead_value.len =
				ctx->ead_token[i].value_len;
		}

		size_t len = 0;
		ret = cbor_encode_ead(&ptxt_2b[offset], ptxt_2b_size - offset,
				      &tmp_ead, &len);

		if (ZCBOR_SUCCESS != ret)
			return EDHOC_ERROR_CBOR_FAILURE;

		offset += len;
	}

	if (offset > ptxt_2b_size)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	*ptxt_2b_len = offset;
	return EDHOC_SUCCESS;
}

static int parse_plaintext_2b(struct edhoc_context *ctx, const uint8_t *ptxt_2b,
			      size_t ptxt_2b_len)
{
	if (NULL == ctx || NULL == ptxt_2b || 0 == ptxt_2b_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	struct plaintext_2b dec_ptxt_2b = { 0 };
	ret = cbor_decode_plaintext_2b(ptxt_2b, ptxt_2b_len, &dec_ptxt_2b,
				       &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	/* C_R */
	switch (dec_ptxt_2b.plaintext_2b_C_R_choice) {
	case plaintext_2b_C_R_int_c:
		if (ONE_BYTE_CBOR_INT_MIN_VALUE >
			    (int8_t)dec_ptxt_2b.plaintext_2b_C_R_int ||
		    ONE_BYTE_CBOR_INT_MAX_VALUE <
			    (int8_t)dec_ptxt_2b.plaintext_2b_C_R_int)
			return EDHOC_ERROR_NOT_PERMITTED;

		ctx->peer_cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
		ctx->peer_cid.int_value =
			(int8_t)dec_ptxt_2b.plaintext_2b_C_R_int;
		break;

	case plaintext_2_C_R_bstr_c:
		if (ARRAY_SIZE(ctx->peer_cid.bstr_value) <
		    dec_ptxt_2b.plaintext_2b_C_R_bstr.len)
			return EDHOC_ERROR_BUFFER_TOO_SMALL;

		ctx->peer_cid.encode_type = EDHOC_CID_TYPE_BYTE_STRING;
		ctx->peer_cid.bstr_length =
			dec_ptxt_2b.plaintext_2b_C_R_bstr.len;
		memcpy(ctx->peer_cid.bstr_value,
		       dec_ptxt_2b.plaintext_2b_C_R_bstr.value,
		       dec_ptxt_2b.plaintext_2b_C_R_bstr.len);
		break;

	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	/* EAD_2 if present */
	if (true == dec_ptxt_2b.plaintext_2b_EAD_2_m_present) {
		ctx->nr_of_ead_tokens =
			dec_ptxt_2b.plaintext_2b_EAD_2_m.EAD_2_count;

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			ctx->ead_token[i].label =
				dec_ptxt_2b.plaintext_2b_EAD_2_m.EAD_2[i]
					.ead_y_ead_label;
			ctx->ead_token[i].value =
				dec_ptxt_2b.plaintext_2b_EAD_2_m.EAD_2[i]
					.ead_y_ead_value.value;
			ctx->ead_token[i].value_len =
				dec_ptxt_2b.plaintext_2b_EAD_2_m.EAD_2[i]
					.ead_y_ead_value.len;
		}
	}

	return EDHOC_SUCCESS;
}

static int compute_th_3_psk(struct edhoc_context *ctx, const uint8_t *ptxt_2,
			    size_t ptxt_2_len)
{
	if (NULL == ctx || NULL == ptxt_2 || 0 == ptxt_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_TH_STATE_2 != ctx->th_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t len = 0;
	len += ctx->th_len + edhoc_cbor_bstr_oh(ctx->th_len);
	len += ptxt_2_len;

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

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	memcpy(&th_3[offset], ptxt_2, ptxt_2_len);
	offset += ptxt_2_len;

	if (VLA_SIZE(th_3) < offset)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	/* Calculate TH_3. */
	ctx->th_len = ctx->csuite[ctx->chosen_csuite_idx].hash_length;

	size_t hash_len = 0;
	ret = ctx->crypto.hash(ctx->user_ctx, th_3, VLA_SIZE(th_3), ctx->th,
			       ctx->th_len, &hash_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->th_state = EDHOC_TH_STATE_3;
	return EDHOC_SUCCESS;
}

static int edhoc_classic_message_2_compose(struct edhoc_context *ctx,
					   uint8_t *msg_2, size_t msg_2_size,
					   size_t *msg_2_len)
{
	/*
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

	if (NULL == ctx || msg_2 == NULL || 0 == msg_2_size ||
	    NULL == msg_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_SM_RECEIVED_M1 != ctx->status ||
	    EDHOC_TH_STATE_1 != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_2;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Generate ephemeral Diffie-Hellmann key pair. */
	ret = generate_dh_keys(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;

	if (NULL != ctx->logger) {
		ctx->logger(ctx->user_ctx, "G_Y", ctx->dh_pub_key,
			    ctx->dh_pub_key_len);
		ctx->logger(ctx->user_ctx, "Y", ctx->dh_priv_key,
			    ctx->dh_priv_key_len);
	}

	/* 2. Compute Diffie-Hellmann shared secret. */
	ret = compute_dh_secret(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "G_XY", ctx->dh_secret,
			    ctx->dh_secret_len);

	/* 3. Compute Transcript Hash 2 (TH_2). */
	ret = compute_th_2(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_2", ctx->th, ctx->th_len);

	/* 4a. Compute Pseudo Random Key 2 (PRK_2e). */
	ret = compute_prk_2e(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_2e", ctx->prk, ctx->prk_len);

	/* 4b. Copy of Pseudo Random Key 2 for keystream (step 11). */
	VLA_ALLOC(uint8_t, prk_2e, ctx->prk_len);
	memcpy(prk_2e, ctx->prk, VLA_SIZEOF(prk_2e));

	/* 5. Fetch authentication credentials. */
	struct edhoc_auth_creds auth_creds = { 0 };
	ret = ctx->cred.fetch(ctx->user_ctx, &auth_creds);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/* 6. Compose EAD_2 if present. */
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
					    "EAD_2 compose label",
					    (const uint8_t *)&ctx->ead_token[i]
						    .label,
					    sizeof(ctx->ead_token[i].label));

				if (0 != ctx->ead_token[i].value_len)
					ctx->logger(
						ctx->user_ctx,
						"EAD_2 compose value",
						ctx->ead_token[i].value,
						ctx->ead_token[i].value_len);
			}
		}
	}

	/* 7. Compute psuedo random key (PRK_3e2m). */
	ret = compute_prk_3e2m(ctx, &auth_creds, NULL, 0);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_3e2m", ctx->prk, ctx->prk_len);

	/* 8a. Compute required buffer length for context_2. */
	size_t mac_ctx_len = 0;
	ret = edhoc_comp_mac_context_length(ctx, &auth_creds, &mac_ctx_len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	/* 8b. Cborise items required by context_2. */
	VLA_ALLOC(uint8_t, mac_ctx_buf,
		  sizeof(struct mac_context) + mac_ctx_len);
	memset(mac_ctx_buf, 0, VLA_SIZEOF(mac_ctx_buf));

	struct mac_context *mac_ctx = (void *)mac_ctx_buf;
	mac_ctx->buf_len = mac_ctx_len;

	ret = edhoc_comp_mac_context(ctx, &auth_creds, mac_ctx);
	if (EDHOC_SUCCESS != ret)
		return ret;

	if (NULL != ctx->logger) {
		ctx->logger(ctx->user_ctx, "C_R", mac_ctx->conn_id,
			    mac_ctx->conn_id_len);
		ctx->logger(ctx->user_ctx, "ID_CRED_R", mac_ctx->id_cred,
			    mac_ctx->id_cred_len);
		ctx->logger(ctx->user_ctx, "TH_2", mac_ctx->th,
			    mac_ctx->th_len);
		ctx->logger(ctx->user_ctx, "CRED_R", mac_ctx->cred,
			    mac_ctx->cred_len);
		ctx->logger(ctx->user_ctx, "context_2", mac_ctx->buf,
			    mac_ctx->buf_len);
	}

	/* 8c. Compute Message Authentication Code (MAC_2). */
	size_t mac_len = 0;
	ret = edhoc_comp_mac_length(ctx, &mac_len);
	if (EDHOC_SUCCESS != ret)
		return ret;

	VLA_ALLOC(uint8_t, mac_buf, mac_len);
	memset(mac_buf, 0, VLA_SIZEOF(mac_buf));
	ret = edhoc_comp_mac(ctx, mac_ctx, mac_buf, mac_len);
	if (EDHOC_SUCCESS != ret)
		return ret;

	/* 9. Compute signature if needed (Signature_or_MAC_2). */
	size_t sign_or_mac_len = 0;
	ret = edhoc_comp_sign_or_mac_length(ctx, &sign_or_mac_len);
	if (EDHOC_SUCCESS != ret)
		return ret;

	size_t sign_len = 0;
	VLA_ALLOC(uint8_t, sign, sign_or_mac_len);
	memset(sign, 0, VLA_SIZEOF(sign));
	ret = edhoc_comp_sign_or_mac(ctx, &auth_creds, mac_ctx, mac_buf,
				     mac_len, sign, VLA_SIZE(sign), &sign_len);
	if (EDHOC_SUCCESS != ret)
		return ret;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "Signature_or_MAC_2", sign,
			    sign_len);

	/* 10. Prepare plaintext (PLAINTEXT_2). */
	size_t ptxt_2_len = 0;
	ret = compute_plaintext_2_length(ctx, mac_ctx, sign_len, &ptxt_2_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	VLA_ALLOC(uint8_t, ptxt_2, ptxt_2_len);
	memset(ptxt_2, 0, VLA_SIZEOF(ptxt_2));

	ptxt_2_len = 0;
	ret = prepare_plaintext_2(ctx, mac_ctx, sign, sign_len, ptxt_2,
				  VLA_SIZE(ptxt_2), &ptxt_2_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PLAINTEXT_2", ptxt_2, ptxt_2_len);

	/* 11. Compute key stream (KEYSTREAM_2). */
	VLA_ALLOC(uint8_t, kstr_2, ptxt_2_len);
	memset(kstr_2, 0, VLA_SIZEOF(kstr_2));

	enum edhoc_prk_state old_prk_state = ctx->prk_state;
	ctx->prk_state = EDHOC_PRK_STATE_2E;

	ret = edhoc_comp_keystream(ctx,
				   EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTERAM_2,
				   prk_2e, VLA_SIZE(prk_2e), kstr_2,
				   VLA_SIZE(kstr_2));

	memset(prk_2e, 0, VLA_SIZEOF(prk_2e));
	ctx->prk_state = old_prk_state;

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "KEYSTREAM_2", kstr_2,
			    VLA_SIZE(kstr_2));

	/* 12. Compute Transcript Hash 3 (TH_3). */
	ret = compute_th_3(ctx, mac_ctx, ptxt_2, ptxt_2_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_3", ctx->th, ctx->th_len);

	/* 13. Compute ciphertext (CIPHERTEXT_2). */
	edhoc_xor_arrays(ptxt_2, kstr_2, ptxt_2_len);
	const uint8_t *ctxt_2 = ptxt_2;
	const size_t ctxt_2_len = ptxt_2_len;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "CIPHERTEXT_2", ctxt_2, ctxt_2_len);

	/* 14. Cborise items for message 2. */
	ret = prepare_message_2(ctx, ctxt_2, ctxt_2_len, msg_2, msg_2_size,
				msg_2_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "message_2", msg_2, *msg_2_len);

	/* 15. Clean-up EAD tokens. */
	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->status = EDHOC_SM_WAIT_M3;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}

static int edhoc_classic_message_2_process(struct edhoc_context *ctx,
					   const uint8_t *msg_2,
					   size_t msg_2_len)
{
	/*
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
	if (NULL == ctx || NULL == msg_2 || 0 == msg_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_SM_WAIT_M2 != ctx->status ||
	    EDHOC_TH_STATE_1 != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_2;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	/* 1. Compute required length for ciphertext. */
	ret = compute_ciphertext_2_length(ctx, msg_2, msg_2_len, &len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	VLA_ALLOC(uint8_t, ctxt_2, len);
	memset(ctxt_2, 0, VLA_SIZEOF(ctxt_2));

	/* 2. Decode cborised message 2. */
	ret = parse_message_2(ctx, msg_2, msg_2_len, ctxt_2, VLA_SIZE(ctxt_2));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "CIPHERTEXT_2", ctxt_2,
			    VLA_SIZE(ctxt_2));

	/* 3. Compute Diffie-Hellmann shared secret (G_XY). */
	ret = compute_dh_secret(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "G_XY", ctx->dh_secret,
			    ctx->dh_secret_len);

	/* 4. Compute Transcript Hash 2 (TH_2). */
	ret = compute_th_2(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_2", ctx->th, ctx->th_len);

	/* 5. Compute Pseudo Random Key 2 (PRK_2e). */
	ret = compute_prk_2e(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_2e", ctx->prk, ctx->prk_len);

	/* 6. Compute key stream (KEYSTREAM_2). */
	VLA_ALLOC(uint8_t, kstr_2, VLA_SIZE(ctxt_2));
	memset(kstr_2, 0, VLA_SIZEOF(kstr_2));

	ret = edhoc_comp_keystream(ctx,
				   EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTERAM_2,
				   ctx->prk, ctx->prk_len, kstr_2,
				   VLA_SIZE(kstr_2));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "KEYSTREAM_2", kstr_2,
			    VLA_SIZE(kstr_2));

	/* 7. Compute plaintext (PLAINTEXT_2). */
	edhoc_xor_arrays(ctxt_2, kstr_2, VLA_SIZE(ctxt_2));
	const uint8_t *ptxt_2 = ctxt_2;
	const size_t ptxt_2_len = VLA_SIZE(ctxt_2);

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PLAINTEXT_2", ptxt_2, ptxt_2_len);

	/* 8. Parse plaintext (PLAINTEXT_2). */
	struct plaintext parsed_ptxt_2 = { 0 };
	ret = parse_plaintext_2(ctx, ptxt_2, ptxt_2_len, &parsed_ptxt_2);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger) {
		switch (ctx->peer_cid.encode_type) {
		case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
			ctx->logger(ctx->user_ctx, "C_R",
				    (const uint8_t *)&ctx->peer_cid.int_value,
				    sizeof(ctx->peer_cid.int_value));
			break;
		case EDHOC_CID_TYPE_BYTE_STRING:
			ctx->logger(ctx->user_ctx, "C_R",
				    ctx->peer_cid.bstr_value,
				    ctx->peer_cid.bstr_length);
			break;

		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	/* 9. Process EAD if present. */
	if (NULL != ctx->ead.process && 0 != ARRAY_SIZE(ctx->ead_token) - 1 &&
	    0 != ctx->nr_of_ead_tokens) {
		ret = ctx->ead.process(ctx->user_ctx, ctx->message,
				       ctx->ead_token, ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;

		if (NULL != ctx->logger) {
			for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
				ctx->logger(ctx->user_ctx,
					    "EAD_2 process label",
					    (const uint8_t *)&ctx->ead_token[i]
						    .label,
					    sizeof(ctx->ead_token[i].label));

				if (0 != ctx->ead_token[i].value_len)
					ctx->logger(
						ctx->user_ctx,
						"EAD_2 process value",
						ctx->ead_token[i].value,
						ctx->ead_token[i].value_len);
			}
		}
	}

	/* 10. Verify if credentials from peer are trusted. */
	const uint8_t *pub_key = NULL;
	size_t pub_key_len = 0;

	ret = ctx->cred.verify(ctx->user_ctx, &parsed_ptxt_2.auth_creds,
			       &pub_key, &pub_key_len);

	if (EDHOC_SUCCESS != ret) {
		ctx->error_code =
			EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	/* 11. Compute psuedo random key (PRK_3e2m). */
	ret = compute_prk_3e2m(ctx, &parsed_ptxt_2.auth_creds, pub_key,
			       pub_key_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_3e2m", ctx->prk, ctx->prk_len);

	/* 12. Compute required buffer length for context_2. */
	size_t mac_context_len = 0;
	ret = edhoc_comp_mac_context_length(ctx, &parsed_ptxt_2.auth_creds,
					    &mac_context_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_MAC_2;

	/* 13. Cborise items required by context_2. */
	VLA_ALLOC(uint8_t, mac_ctx_buf,
		  sizeof(struct mac_context) + mac_context_len);
	memset(mac_ctx_buf, 0, VLA_SIZEOF(mac_ctx_buf));

	struct mac_context *mac_ctx = (void *)mac_ctx_buf;
	mac_ctx->buf_len = mac_context_len;

	ret = edhoc_comp_mac_context(ctx, &parsed_ptxt_2.auth_creds, mac_ctx);
	if (EDHOC_SUCCESS != ret)
		return ret;

	if (NULL != ctx->logger) {
		ctx->logger(ctx->user_ctx, "C_R", mac_ctx->conn_id,
			    mac_ctx->conn_id_len);
		ctx->logger(ctx->user_ctx, "ID_CRED_R", mac_ctx->id_cred,
			    mac_ctx->id_cred_len);
		ctx->logger(ctx->user_ctx, "TH_2", mac_ctx->th,
			    mac_ctx->th_len);
		ctx->logger(ctx->user_ctx, "CRED_R", mac_ctx->cred,
			    mac_ctx->cred_len);
		ctx->logger(ctx->user_ctx, "context_2", mac_ctx->buf,
			    mac_ctx->buf_len);
	}

	/* 14. Compute Message Authentication Code (MAC_2). */
	size_t mac_len = 0;
	ret = edhoc_comp_mac_length(ctx, &mac_len);
	if (EDHOC_SUCCESS != ret)
		return ret;

	VLA_ALLOC(uint8_t, mac_buf, mac_len);
	memset(mac_buf, 0, VLA_SIZEOF(mac_buf));
	ret = edhoc_comp_mac(ctx, mac_ctx, mac_buf, mac_len);
	if (EDHOC_SUCCESS != ret)
		return ret;

	/* 15. Verify Signature_or_MAC_2. */
	ret = edhoc_verify_sign_or_mac(ctx, mac_ctx, pub_key, pub_key_len,
				       parsed_ptxt_2.sign_or_mac,
				       parsed_ptxt_2.sign_or_mac_len, mac_buf,
				       mac_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_INVALID_SIGN_OR_MAC_2;

	/* 16. Compute Transcript Hash 3 (TH_3). */
	ret = compute_th_3(ctx, mac_ctx, ptxt_2, ptxt_2_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_3", ctx->th, ctx->th_len);

	/* 17. Clean-up EAD tokens. */
	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->status = EDHOC_SM_VERIFIED_M2;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}

static int edhoc_psk_message_2_compose(struct edhoc_context *ctx,
				       uint8_t *msg_2, size_t msg_2_size,
				       size_t *msg_2_len)
{
	/*
	 * Steps for composition of message 2:
	 *
	 * 	1.  Generate ephemeral Diffie-Hellmann key pair.
 	 *	2.  Compute Diffie-Hellmann shared secret.
 	 *	3.  Compute Transcript Hash 2 (TH_2).
 	 *	4a. Compute Pseudo Random Key 2 (PRK_2e).
 	 *      4b. Copy of Pseudo Random Key 2 for keystream (step 7).
	 * 	5.  Compose EAD_2 if present.
	 *	6.  Prepare plaintext (PLAINTEXT_2B).
	 *	7.  Compute key stream (KEYSTREAM_2).
	 *	8.  Compute psuedo random key (PRK_3e2m).
	 *	9.  Compute Transcript Hash 3 (TH_3).
	 * 	10. Compute ciphertext (CIPHERTEXT_2).
	 *	11. Cborise items for message 2.
	 *	12. Clean-up EAD tokens.
	 */

	if (NULL == ctx || msg_2 == NULL || 0 == msg_2_size ||
	    NULL == msg_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_SM_RECEIVED_M1 != ctx->status ||
	    EDHOC_TH_STATE_1 != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_2;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Generate ephemeral Diffie-Hellmann key pair. */
	ret = generate_dh_keys(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;

	if (NULL != ctx->logger) {
		ctx->logger(ctx->user_ctx, "G_Y", ctx->dh_pub_key,
			    ctx->dh_pub_key_len);
		ctx->logger(ctx->user_ctx, "Y", ctx->dh_priv_key,
			    ctx->dh_priv_key_len);
	}

	/* 2. Compute Diffie-Hellmann shared secret. */
	ret = compute_dh_secret(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "G_XY", ctx->dh_secret,
			    ctx->dh_secret_len);

	/* 3. Compute Transcript Hash 2 (TH_2). */
	ret = compute_th_2(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_2", ctx->th, ctx->th_len);

	/* 4a. Compute Pseudo Random Key 2 (PRK_2e). */
	ret = compute_prk_2e(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_2e", ctx->prk, ctx->prk_len);

	/* 4b. Copy of Pseudo Random Key 2 for keystream (step 11). */
	VLA_ALLOC(uint8_t, prk_2e, ctx->prk_len);
	memcpy(prk_2e, ctx->prk, VLA_SIZEOF(prk_2e));

	/* 5. Compose EAD_2 if present. */
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
					    "EAD_2 compose label",
					    (const uint8_t *)&ctx->ead_token[i]
						    .label,
					    sizeof(ctx->ead_token[i].label));

				if (0 != ctx->ead_token[i].value_len)
					ctx->logger(
						ctx->user_ctx,
						"EAD_2 compose value",
						ctx->ead_token[i].value,
						ctx->ead_token[i].value_len);
			}
		}
	}

	/* 6. Prepare plaintext (PLAINTEXT_2B). */
	size_t ptxt_2b_len = 0;
	ret = compute_plaintext_2b_length(ctx, &ptxt_2b_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	VLA_ALLOC(uint8_t, ptxt_2b, ptxt_2b_len);
	memset(ptxt_2b, 0, VLA_SIZEOF(ptxt_2b));

	ptxt_2b_len = 0;
	ret = prepare_plaintext_2b(ctx, ptxt_2b, VLA_SIZE(ptxt_2b),
				   &ptxt_2b_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PLAINTEXT_2B", ptxt_2b,
			    ptxt_2b_len);

	/* 7. Compute key stream (KEYSTREAM_2). */
	VLA_ALLOC(uint8_t, kstr_2, ptxt_2b_len);
	memset(kstr_2, 0, VLA_SIZEOF(kstr_2));

	ret = edhoc_comp_keystream(ctx,
				   EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTERAM_2,
				   prk_2e, VLA_SIZE(prk_2e), kstr_2,
				   VLA_SIZE(kstr_2));
	memset(prk_2e, 0, VLA_SIZEOF(prk_2e));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "KEYSTREAM_2", kstr_2,
			    VLA_SIZE(kstr_2));

	/* 8. Compute psuedo random key (PRK_3e2m). */
	ret = compute_prk_3e2m(ctx, NULL, NULL, 0);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_3e2m", ctx->prk, ctx->prk_len);

	/* 9. Compute Transcript Hash 3 (TH_3). */
	ret = compute_th_3_psk(ctx, ptxt_2b, ptxt_2b_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_3", ctx->th, ctx->th_len);

	/* 10. Compute ciphertext (CIPHERTEXT_2). */
	edhoc_xor_arrays(ptxt_2b, kstr_2, ptxt_2b_len);
	const uint8_t *ctxt_2 = ptxt_2b;
	const size_t ctxt_2_len = ptxt_2b_len;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "CIPHERTEXT_2", ctxt_2, ctxt_2_len);

	/* 11. Cborise items for message 2. */
	ret = prepare_message_2(ctx, ctxt_2, ctxt_2_len, msg_2, msg_2_size,
				msg_2_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "message_2", msg_2, *msg_2_len);

	/* 12. Clean-up EAD tokens. */
	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->status = EDHOC_SM_WAIT_M3;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}

static int edhoc_psk_message_2_process(struct edhoc_context *ctx,
				       const uint8_t *msg_2, size_t msg_2_len)
{
	/*
	 * Steps for processing of message 2:
	 * 	1.  Compute required length for ciphertext.
	 *      2.  Decode cborised message 2.
	 *      3.  Compute Diffie-Hellmann shared secret (G_XY).
	 *      4.  Compute Transcript Hash 2 (TH_2).
	 *      5.  Compute Pseudo Random Key 2 (PRK_2e).
	 *      6.  Compute keystream (KEYSTREAM_2).
	 *      7.  Compute plaintext (PLAINTEXT_2B).
	 *      8.  Parse plaintext (PLAINTEXT_2B).
	 *      9.  Process EAD if present.
	 *      10. Compute psuedo random key (PRK_3e2m).
	 *      11. Compute Transcript Hash 3 (TH_3).
	 *      12. Clean-up EAD tokens.
	 */

	if (NULL == ctx || NULL == msg_2 || 0 == msg_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_SM_WAIT_M2 != ctx->status ||
	    EDHOC_TH_STATE_1 != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_2;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Compute required length for ciphertext. */
	size_t ctxt_2_len = 0;
	ret = compute_ciphertext_2_length(ctx, msg_2, msg_2_len, &ctxt_2_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	VLA_ALLOC(uint8_t, ctxt_2, ctxt_2_len);
	memset(ctxt_2, 0, VLA_SIZEOF(ctxt_2));

	/* 2. Decode cborised message 2. */
	ret = parse_message_2(ctx, msg_2, msg_2_len, ctxt_2, VLA_SIZE(ctxt_2));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "CIPHERTEXT_2", ctxt_2,
			    VLA_SIZE(ctxt_2));

	/* 3. Compute Diffie-Hellmann shared secret (G_XY). */
	ret = compute_dh_secret(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "G_XY", ctx->dh_secret,
			    ctx->dh_secret_len);

	/* 4. Compute Transcript Hash 2 (TH_2). */
	ret = compute_th_2(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_2", ctx->th, ctx->th_len);

	/* 5. Compute Pseudo Random Key 2 (PRK_2e). */
	ret = compute_prk_2e(ctx);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_2e", ctx->prk, ctx->prk_len);

	/* 6. Compute keystream (KEYSTREAM_2). */
	VLA_ALLOC(uint8_t, kstr_2, VLA_SIZE(ctxt_2));
	memset(kstr_2, 0, VLA_SIZEOF(kstr_2));

	ret = edhoc_comp_keystream(ctx,
				   EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTERAM_2,
				   ctx->prk, ctx->prk_len, kstr_2,
				   VLA_SIZE(kstr_2));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "KEYSTREAM_2", kstr_2,
			    VLA_SIZE(kstr_2));

	/* 7. Compute plaintext (PLAINTEXT_2B). */
	edhoc_xor_arrays(ctxt_2, kstr_2, VLA_SIZE(ctxt_2));
	const uint8_t *ptxt_2b = ctxt_2;
	const size_t ptxt_2b_len = VLA_SIZE(ctxt_2);

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PLAINTEXT_2", ptxt_2b, ptxt_2b_len);

	/* 8. Parse plaintext (PLAINTEXT_2B). */
	ret = parse_plaintext_2b(ctx, ptxt_2b, ptxt_2b_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger) {
		switch (ctx->peer_cid.encode_type) {
		case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
			ctx->logger(ctx->user_ctx, "C_R",
				    (const uint8_t *)&ctx->peer_cid.int_value,
				    sizeof(ctx->peer_cid.int_value));
			break;
		case EDHOC_CID_TYPE_BYTE_STRING:
			ctx->logger(ctx->user_ctx, "C_R",
				    ctx->peer_cid.bstr_value,
				    ctx->peer_cid.bstr_length);
			break;

		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	/* 9. Process EAD if present. */
	if (NULL != ctx->ead.process && 0 != ARRAY_SIZE(ctx->ead_token) - 1 &&
	    0 != ctx->nr_of_ead_tokens) {
		ret = ctx->ead.process(ctx->user_ctx, ctx->message,
				       ctx->ead_token, ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;

		if (NULL != ctx->logger) {
			for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
				ctx->logger(ctx->user_ctx,
					    "EAD_2 process label",
					    (const uint8_t *)&ctx->ead_token[i]
						    .label,
					    sizeof(ctx->ead_token[i].label));

				if (0 != ctx->ead_token[i].value_len)
					ctx->logger(
						ctx->user_ctx,
						"EAD_2 process value",
						ctx->ead_token[i].value,
						ctx->ead_token[i].value_len);
			}
		}
	}

	/* 10. Compute psuedo random key (PRK_3e2m). */
	ret = compute_prk_3e2m(ctx, NULL, NULL, 0);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "PRK_3e2m", ctx->prk, ctx->prk_len);

	/* 11. Compute Transcript Hash 3 (TH_3). */
	ret = compute_th_3_psk(ctx, ptxt_2b, ptxt_2b_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE;

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "TH_3", ctx->th, ctx->th_len);

	/* 12. Clean-up EAD tokens. */
	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->status = EDHOC_SM_VERIFIED_M2;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

int edhoc_message_2_compose(struct edhoc_context *ctx, uint8_t *msg_2,
			    size_t msg_2_size, size_t *msg_2_len)
{
	if (NULL == ctx || NULL == msg_2 || 0 == msg_2_size ||
	    NULL == msg_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	switch (ctx->mode) {
	case EDHOC_MODE_CLASSIC_RFC_9528:
		return edhoc_classic_message_2_compose(ctx, msg_2, msg_2_size,
						       msg_2_len);

	case EDHOC_MODE_PSK_DRAFT:
		return edhoc_psk_message_2_compose(ctx, msg_2, msg_2_size,
						   msg_2_len);

	default:
		return EDHOC_ERROR_BAD_STATE;
	}
}

int edhoc_message_2_process(struct edhoc_context *ctx, const uint8_t *msg_2,
			    size_t msg_2_len)
{
	if (NULL == ctx || NULL == msg_2 || 0 == msg_2_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	switch (ctx->mode) {
	case EDHOC_MODE_CLASSIC_RFC_9528:
		return edhoc_classic_message_2_process(ctx, msg_2, msg_2_len);

	case EDHOC_MODE_PSK_DRAFT:
		return edhoc_psk_message_2_process(ctx, msg_2, msg_2_len);

	default:
		return EDHOC_ERROR_BAD_STATE;
	}
}
