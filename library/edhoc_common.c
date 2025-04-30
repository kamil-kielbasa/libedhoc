/**
 * \file    edhoc_common.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC common implementations:
 *          - CBOR utilities.
 *          - MAC context.
 *          - MAC & Signature_or_MAC.
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

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
#pragma clang diagnostic ignored "-Wreserved-identifier"
#pragma clang diagnostic ignored "-Wpadded"
#pragma clang diagnostic ignored "-Wdocumentation"
#endif

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_int_type_encode.h>
#include <backend_cbor_int_type_decode.h>
#include <backend_cbor_bstr_type_encode.h>
#include <backend_cbor_id_cred_x_encode.h>
#include <backend_cbor_id_cred_x_decode.h>
#include <backend_cbor_ead_encode.h>
#include <backend_cbor_sig_structure_encode.h>
#include <backend_cbor_info_encode.h>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/** 
 * \brief Check if integer might be encoded as CBOR one byte. 
 *
 * \param value                 	Value for cbor encoding.
 *
 * \return True if might be encoded as one byte cbor integer,
 *         otherwise false.
 */
static inline bool edhoc_cbor_is_one_byte_int(int32_t value);

/**
 * \brief Compute required buffer length for C_R (message_2).
 * 
 * \param[in] connection_id             EDHOC connection identifier.
 * \param[out] connection_id_length	On success, number of bytes that make up 
 *                              	C_R length requirements.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int
compute_conn_id_length(const struct edhoc_connection_id *connection_id,
		       size_t *connection_id_length);

/**
 * \brief Compute required buffer length for ID_CRED (I/R).
 * 
 * \param[in] auth_credentials		Authentication credentials.
 * \param[out] id_credentials_length   	On success, number of bytes that make up 
 *                              	ID_CRED length requirements.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int
compute_id_cred_length(const struct edhoc_auth_creds *auth_credentials,
		       size_t *id_credentials_length);

/**
 * \brief Compute required buffer length for TH (2/3).
 * 
 * \param th_length                	Transcript hash length.
 * \param[out] cbor_th_length 		On success, number of bytes that make up 
 *                              	TH length requirements.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_th_length(size_t th_length, size_t *cbor_th_length);

/**
 * \brief Compute required buffer length for CRED (I/R).
 * 
 * \param[in] auth_credentials		Authentication credentials.
 * \param[out] credentials_length	On success, number of bytes that make up 
 *                              	CRED length requirements.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_cred_length(const struct edhoc_auth_creds *auth_credentials,
			       size_t *credentials_length);

/**
 * \brief Compute required buffer length for EAD (2/3).
 * 
 * \param[in] edhoc_context		EDHOC context.
 * \param[out] ead_length              	On success, number of bytes that make up 
 *                              	EAD buffer length requirements.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int compute_ead_length(const struct edhoc_context *edhoc_context,
			      size_t *ead_length);

/**
 * \brief Perform compact encoding described in:
 *        - RFC 9528: 3.5.3.2. Compact Encoding of ID_CRED Fields for 'kid'.
 * 
 * \param[in] auth_credentials 		Authentication credentials.
 * \param[in,out] mac_context       	Structure containing the MAC context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int kid_compact_encoding(const struct edhoc_auth_creds *auth_credentials,
				struct mac_context *mac_context);

/**
 * \brief Compute COSE_Sign1.
 * 
 * \param[in] edhoc_context 		EDHOC context.
 * \param[in] auth_credentials       	Authentication credentials.
 * \param[in] mac_context           	MAC context.
 * \param[in] mac               	Buffer containing MAC 2/3.
 * \param mac_length               	Size of the \p mac buffer in bytes.
 * \param[out] signature             	Buffer containing signature.
 * \param signature_size             	Size of the \p signature buffer in bytes.
 * \param[out] signature_length         On success, the number of bytes that make up the signature.
 * 
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int sign_cose_sign_1(const struct edhoc_context *edhoc_context,
			    const struct edhoc_auth_creds *auth_credentials,
			    const struct mac_context *mac_context,
			    const uint8_t *mac, size_t mac_length,
			    uint8_t *signature, size_t signature_size,
			    size_t *signature_length);

/**
 * \brief Verify COSE_Sign1.
 * 
 * \param[in] edhoc_context       	EDHOC context.
 * \param[in] mac_context           	MAC context.
 * \param[in] public_key           	Buffer containing public key.
 * \param public_key_length           	Size of the \p pub_key buffer in bytes.
 * \param[in] mac               	Buffer containing MAC 2/3.
 * \param mac_length               	Size of the \p mac buffer in bytes.
 * \param[out] signature             	Buffer containing signature.
 * \param signature_length              Size of the \p signature buffer in bytes.
 * 
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
static int verify_cose_sign_1(const struct edhoc_context *edhoc_context,
			      const struct mac_context *mac_context,
			      const uint8_t *public_key,
			      size_t public_key_length, const uint8_t *mac,
			      size_t mac_length, const uint8_t *signature,
			      size_t signature_length);

/* Static function definitions --------------------------------------------- */

static inline bool edhoc_cbor_is_one_byte_int(int32_t value)
{
	return 1 == edhoc_cbor_int_mem_req(value);
}

static int compute_conn_id_length(const struct edhoc_connection_id *cid,
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

static int compute_id_cred_length(const struct edhoc_auth_creds *auth_creds,
				  size_t *id_cred_len)
{
	if (NULL == auth_creds || NULL == id_cred_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	*id_cred_len = 0;
	const size_t nr_of_items = 1;

	switch (auth_creds->label) {
	case EDHOC_COSE_ANY:
		*id_cred_len += auth_creds->any.id_cred_len;
		break;

	case EDHOC_COSE_HEADER_KID:
		*id_cred_len += edhoc_cbor_map_oh(nr_of_items);

		switch (auth_creds->key_id.encode_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			*id_cred_len += edhoc_cbor_int_mem_req(
				auth_creds->key_id.key_id_int);
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			*id_cred_len += auth_creds->key_id.key_id_bstr_length;
			*id_cred_len += edhoc_cbor_bstr_oh(
				auth_creds->key_id.key_id_bstr_length);
			break;
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
		break;

	case EDHOC_COSE_HEADER_X509_CHAIN:
		*id_cred_len += edhoc_cbor_map_oh(nr_of_items);
		for (size_t i = 0; i < auth_creds->x509_chain.nr_of_certs;
		     ++i) {
			*id_cred_len += auth_creds->x509_chain.cert_len[i];
			*id_cred_len += edhoc_cbor_bstr_oh(
				auth_creds->x509_chain.cert_len[i]);
		}

		if (auth_creds->x509_chain.nr_of_certs > 1)
			*id_cred_len += edhoc_cbor_array_oh(
				auth_creds->x509_chain.nr_of_certs);

		break;

	case EDHOC_COSE_HEADER_X509_HASH:
		*id_cred_len += edhoc_cbor_map_oh(nr_of_items);
		*id_cred_len += edhoc_cbor_array_oh(nr_of_items);

		switch (auth_creds->x509_hash.encode_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			*id_cred_len += edhoc_cbor_int_mem_req(
				auth_creds->x509_hash.alg_int);
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			*id_cred_len += auth_creds->x509_hash.alg_bstr_length;
			*id_cred_len += edhoc_cbor_bstr_oh(
				auth_creds->x509_hash.alg_bstr_length);
			break;
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}

		*id_cred_len += auth_creds->x509_hash.cert_fp_len;
		*id_cred_len +=
			edhoc_cbor_bstr_oh(auth_creds->x509_hash.cert_fp_len);
		break;

	default:
		return EDHOC_ERROR_NOT_SUPPORTED;
	}

	return EDHOC_SUCCESS;
}

static int compute_th_length(size_t th_len, size_t *cbor_th_len)
{
	if (0 == th_len || NULL == cbor_th_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	*cbor_th_len = 0;
	*cbor_th_len += th_len;
	*cbor_th_len += edhoc_cbor_bstr_oh(th_len);

	return EDHOC_SUCCESS;
}

static int compute_cred_length(const struct edhoc_auth_creds *auth_creds,
			       size_t *cred_len)
{
	if (NULL == auth_creds || NULL == cred_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	switch (auth_creds->label) {
	case EDHOC_COSE_ANY:
		*cred_len += auth_creds->any.cred_len;
		break;

	case EDHOC_COSE_HEADER_KID:
		*cred_len += auth_creds->key_id.cred_len;
		*cred_len += edhoc_cbor_bstr_oh(auth_creds->key_id.cred_len);
		break;

	case EDHOC_COSE_HEADER_X509_CHAIN: {
		const size_t end_entity_idx = 0;
		*cred_len += auth_creds->x509_chain.cert_len[end_entity_idx];
		*cred_len += edhoc_cbor_bstr_oh(
			auth_creds->x509_chain.cert_len[end_entity_idx]);
		break;
	}

	case EDHOC_COSE_HEADER_X509_HASH:
		*cred_len += auth_creds->x509_hash.cert_len;
		*cred_len += edhoc_cbor_bstr_oh(auth_creds->x509_hash.cert_len);
		break;

	default:
		return EDHOC_ERROR_NOT_SUPPORTED;
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

static int kid_compact_encoding(const struct edhoc_auth_creds *auth_creds,
				struct mac_context *mac_ctx)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	mac_ctx->id_cred_is_comp_enc = true;

	switch (auth_creds->key_id.encode_type) {
	case EDHOC_ENCODE_TYPE_INTEGER: {
		mac_ctx->id_cred_enc_type = EDHOC_ENCODE_TYPE_INTEGER;
		if (true == auth_creds->key_id.cred_is_cbor) {
			mac_ctx->id_cred_int = auth_creds->key_id.key_id_int;
		} else {
			len = 0;
			ret = cbor_encode_integer_type_int_type(
				(uint8_t *)&mac_ctx->id_cred_int,
				sizeof(mac_ctx->id_cred_int),
				&auth_creds->key_id.key_id_int, &len);

			if (ZCBOR_SUCCESS != ret)
				return EDHOC_ERROR_CBOR_FAILURE;
		}
		break;
	}

	case EDHOC_ENCODE_TYPE_BYTE_STRING: {
		mac_ctx->id_cred_enc_type = EDHOC_ENCODE_TYPE_BYTE_STRING;

		if (true == auth_creds->key_id.cred_is_cbor) {
			if (1 == auth_creds->key_id.key_id_bstr_length) {
				int32_t val = auth_creds->key_id.key_id_bstr[0];
				int32_t result = 0;

				len = 0;
				ret = cbor_decode_integer_type_int_type(
					(uint8_t *)&val, sizeof(val), &result,
					&len);

				if (ZCBOR_SUCCESS != ret)
					return EDHOC_ERROR_CBOR_FAILURE;

				if (true ==
				    edhoc_cbor_is_one_byte_int(result)) {
					mac_ctx->id_cred_int = val;
					mac_ctx->id_cred_enc_type =
						EDHOC_ENCODE_TYPE_INTEGER;
					break;
				}
			}

			mac_ctx->id_cred_bstr_len =
				auth_creds->key_id.key_id_bstr_length;
			memcpy(mac_ctx->id_cred_bstr,
			       auth_creds->key_id.key_id_bstr,
			       auth_creds->key_id.key_id_bstr_length);
		} else {
			const struct zcbor_string input = {
				.value = auth_creds->key_id.key_id_bstr,
				.len = auth_creds->key_id.key_id_bstr_length,
			};

			ret = cbor_encode_byte_string_type_bstr_type(
				mac_ctx->id_cred_bstr,
				ARRAY_SIZE(mac_ctx->id_cred_bstr) - 1, &input,
				&mac_ctx->id_cred_bstr_len);

			if (ZCBOR_SUCCESS != ret)
				return EDHOC_ERROR_CBOR_FAILURE;
		}
		break;
	}
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	return EDHOC_SUCCESS;
}

static int sign_cose_sign_1(const struct edhoc_context *ctx,
			    const struct edhoc_auth_creds *auth_creds,
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
	len += edhoc_cbor_tstr_oh(sizeof("Signature1"));
	len += mac_ctx->id_cred_len;
	len += edhoc_cbor_bstr_oh(mac_ctx->id_cred_len);
	len += mac_ctx->th_len + mac_ctx->cred_len + mac_ctx->ead_len;
	len += edhoc_cbor_bstr_oh(mac_ctx->th_len + mac_ctx->cred_len +
				  mac_ctx->ead_len);
	len += mac_len;
	len += edhoc_cbor_int_mem_req((int32_t)mac_len);

	VLA_ALLOC(uint8_t, cose_sign_1_buf, len);
	memset(cose_sign_1_buf, 0, VLA_SIZEOF(cose_sign_1_buf));

	size_t cose_sign_1_buf_len = 0;
	ret = cbor_encode_sig_structure(cose_sign_1_buf,
					VLA_SIZE(cose_sign_1_buf), &cose_sign_1,
					&cose_sign_1_buf_len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	ret = ctx->crypto.signature(ctx->user_ctx, auth_creds->priv_key_id,
				    cose_sign_1_buf, cose_sign_1_buf_len, sign,
				    sign_size, sign_len);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

static int verify_cose_sign_1(const struct edhoc_context *ctx,
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
	len += edhoc_cbor_tstr_oh(sizeof("Signature1"));
	len += mac_ctx->id_cred_len;
	len += edhoc_cbor_bstr_oh(mac_ctx->id_cred_len);
	len += mac_ctx->th_len + mac_ctx->cred_len + mac_ctx->ead_len;
	len += edhoc_cbor_bstr_oh(mac_ctx->th_len + mac_ctx->cred_len +
				  mac_ctx->ead_len);
	len += mac_len;
	len += edhoc_cbor_int_mem_req((int32_t)mac_len);

	VLA_ALLOC(uint8_t, cose_sign_1_buf, len);
	memset(cose_sign_1_buf, 0, VLA_SIZEOF(cose_sign_1_buf));

	size_t cose_sign_1_buf_len = 0;
	ret = cbor_encode_sig_structure(cose_sign_1_buf,
					VLA_SIZE(cose_sign_1_buf), &cose_sign_1,
					&cose_sign_1_buf_len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	uint8_t kid[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_VERIFY, pub_key,
				   pub_key_len, kid);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.verify(ctx->user_ctx, kid, cose_sign_1_buf,
				 cose_sign_1_buf_len, sign, sign_len);
	ctx->keys.destroy_key(ctx->user_ctx, kid);
	memset(kid, 0, sizeof(kid));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

size_t edhoc_cbor_int_mem_req(int32_t value)
{
	if (value >= ONE_BYTE_CBOR_INT_MIN_VALUE &&
	    value <= ONE_BYTE_CBOR_INT_MAX_VALUE) {
		return 1;
	} else if (value >= -(UINT8_MAX + 1) && value <= UINT8_MAX) {
		return 2;
	} else if (value >= -(UINT16_MAX + 1) && value <= UINT16_MAX) {
		return 3;
	} else {
		return 4;
	}
}

size_t edhoc_cbor_tstr_oh(size_t length)
{
	if (length <= 23) {
		return 1;
	} else if (length <= UINT8_MAX) {
		return 2;
	} else if (length <= UINT16_MAX) {
		return 3;
	} else if (length <= UINT32_MAX) {
		return 4;
	} else {
		return 5;
	}
}

size_t edhoc_cbor_bstr_oh(size_t length)
{
	if (length <= 23) {
		return 1 + 1; // zcbor issue
	} else if (length <= UINT8_MAX) {
		return 2;
	} else if (length <= UINT16_MAX) {
		return 3;
	} else if (length <= UINT32_MAX) {
		return 4;
	} else {
		return 5;
	}
}

size_t edhoc_cbor_map_oh(size_t items)
{
	(void)items;

	return 3;
}

size_t edhoc_cbor_array_oh(size_t items)
{
	if (items < 24)
		return 1;
	if (items < 256)
		return 2;
	if (items < 65535)
		return 3;

	return 4;
}

int edhoc_comp_mac_context_length(const struct edhoc_context *ctx,
				  const struct edhoc_auth_creds *cred,
				  size_t *mac_ctx_len)
{
	if (NULL == ctx || NULL == cred || NULL == mac_ctx_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_INITIATOR != ctx->role && EDHOC_RESPONDER != ctx->role)
		return EDHOC_ERROR_BAD_STATE;

	if (EDHOC_MSG_1 > ctx->message || EDHOC_MSG_3 < ctx->message)
		return EDHOC_ERROR_BAD_STATE;

	*mac_ctx_len = 0;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	/* C_R length. */
	if (EDHOC_MSG_2 == ctx->message) {
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
		ret = compute_conn_id_length(cid, &len);

		if (EDHOC_SUCCESS != ret)
			return ret;

		*mac_ctx_len += len;
	}

	/* ID_CRED length. */
	len = 0;
	ret = compute_id_cred_length(cred, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	*mac_ctx_len += len;

	/* TH length. */
	len = 0;
	ret = compute_th_length(ctx->th_len, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	*mac_ctx_len += len;

	/* CRED length. */
	len = 0;
	ret = compute_cred_length(cred, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	*mac_ctx_len += len;

	/* EAD length. */
	len = 0;
	ret = compute_ead_length(ctx, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	*mac_ctx_len += len;

	return EDHOC_SUCCESS;
}

int edhoc_comp_mac_context(const struct edhoc_context *ctx,
			   const struct edhoc_auth_creds *cred,
			   struct mac_context *mac_ctx)
{
	if (NULL == ctx || NULL == cred || NULL == mac_ctx)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_INITIATOR != ctx->role && EDHOC_RESPONDER != ctx->role)
		return EDHOC_ERROR_BAD_STATE;

	if (EDHOC_MSG_1 > ctx->message || EDHOC_MSG_3 < ctx->message)
		return EDHOC_ERROR_BAD_STATE;

	if (EDHOC_MSG_2 == ctx->message && EDHOC_TH_STATE_2 != ctx->th_state)
		return EDHOC_ERROR_BAD_STATE;

	if (EDHOC_MSG_3 == ctx->message && EDHOC_TH_STATE_3 != ctx->th_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	size_t len = 0;

	/* C_R length. */
	if (EDHOC_MSG_2 == ctx->message) {
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

		mac_ctx->conn_id = &mac_ctx->buf[0];

		len = 0;
		ret = compute_conn_id_length(cid, &len);

		if (EDHOC_SUCCESS != ret)
			return ret;

		mac_ctx->conn_id_len = len;

		/* C_R cborising. */
		/* Cborise C_R. */
		switch (cid->encode_type) {
		case EDHOC_CID_TYPE_ONE_BYTE_INTEGER: {
			const int32_t value = cid->int_value;
			len = 0;
			ret = cbor_encode_integer_type_int_type(
				mac_ctx->conn_id, mac_ctx->conn_id_len, &value,
				&len);
			break;
		}
		case EDHOC_CID_TYPE_BYTE_STRING: {
			const struct zcbor_string cbor_bstr = {
				.value = cid->bstr_value,
				.len = cid->bstr_length,
			};
			len = 0;
			ret = cbor_encode_byte_string_type_bstr_type(
				mac_ctx->conn_id, mac_ctx->conn_id_len,
				&cbor_bstr, &len);
			break;
		}
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}

		if (ZCBOR_SUCCESS != ret)
			return EDHOC_ERROR_CBOR_FAILURE;

		mac_ctx->conn_id_len = len;
	}

	/* ID_CRED length. */
	mac_ctx->id_cred = &mac_ctx->buf[mac_ctx->conn_id_len];

	len = 0;
	ret = compute_id_cred_length(cred, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	mac_ctx->id_cred_len = len;

	/* ID_CRED cborising. */
	struct id_cred_x id_cred = { 0 };

	switch (cred->label) {
	case EDHOC_COSE_ANY:
		break;

	case EDHOC_COSE_HEADER_KID:
		id_cred.id_cred_x_kid_present = true;

		switch (cred->key_id.encode_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			id_cred.id_cred_x_kid.id_cred_x_kid_choice =
				id_cred_x_kid_int_c;
			id_cred.id_cred_x_kid.id_cred_x_kid_int =
				cred->key_id.key_id_int;
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			id_cred.id_cred_x_kid.id_cred_x_kid_choice =
				id_cred_x_kid_bstr_c;
			id_cred.id_cred_x_kid.id_cred_x_kid_bstr.value =
				cred->key_id.key_id_bstr;
			id_cred.id_cred_x_kid.id_cred_x_kid_bstr.len =
				cred->key_id.key_id_bstr_length;
			break;
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}

		break;

	case EDHOC_COSE_HEADER_X509_CHAIN: {
		if (0 == cred->x509_chain.nr_of_certs)
			return EDHOC_ERROR_BAD_STATE;

		id_cred.id_cred_x_x5chain_present = true;

		struct COSE_X509_r *cose_x509 =
			&id_cred.id_cred_x_x5chain.id_cred_x_x5chain;

		if (1 == cred->x509_chain.nr_of_certs) {
			cose_x509->COSE_X509_choice = COSE_X509_bstr_c;
			cose_x509->COSE_X509_bstr.value =
				cred->x509_chain.cert[0];
			cose_x509->COSE_X509_bstr.len =
				cred->x509_chain.cert_len[0];
		} else {
			if (ARRAY_SIZE(cose_x509->COSE_X509_certs_l_certs) <
			    cred->x509_chain.nr_of_certs)
				return EDHOC_ERROR_BUFFER_TOO_SMALL;

			cose_x509->COSE_X509_choice = COSE_X509_certs_l_c;
			cose_x509->COSE_X509_certs_l_certs_count =
				cred->x509_chain.nr_of_certs;

			for (size_t i = 0; i < cred->x509_chain.nr_of_certs;
			     ++i) {
				cose_x509->COSE_X509_certs_l_certs[i].value =
					cred->x509_chain.cert[i];
				cose_x509->COSE_X509_certs_l_certs[i].len =
					cred->x509_chain.cert_len[i];
			}
		}
		break;
	}

	case EDHOC_COSE_HEADER_X509_HASH: {
		id_cred.id_cred_x_x5t_present = true;

		struct COSE_CertHash *cose_x509 =
			&id_cred.id_cred_x_x5t.id_cred_x_x5t;

		cose_x509->COSE_CertHash_hashValue.value =
			cred->x509_hash.cert_fp;
		cose_x509->COSE_CertHash_hashValue.len =
			cred->x509_hash.cert_fp_len;

		switch (cred->x509_hash.encode_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			cose_x509->COSE_CertHash_hashAlg_choice =
				COSE_CertHash_hashAlg_int_c;
			cose_x509->COSE_CertHash_hashAlg_int =
				cred->x509_hash.alg_int;
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			cose_x509->COSE_CertHash_hashAlg_choice =
				COSE_CertHash_hashAlg_tstr_c;
			cose_x509->COSE_CertHash_hashAlg_tstr.value =
				cred->x509_hash.alg_bstr;
			cose_x509->COSE_CertHash_hashAlg_tstr.len =
				cred->x509_hash.alg_bstr_length;
			break;
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
		break;
	}
	default:
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (EDHOC_COSE_ANY == cred->label) {
		memcpy(mac_ctx->id_cred, cred->any.id_cred,
		       cred->any.id_cred_len);
	} else {
		len = 0;
		ret = cbor_encode_id_cred_x(
			mac_ctx->id_cred, mac_ctx->id_cred_len, &id_cred, &len);
		if (ZCBOR_SUCCESS != ret)
			return EDHOC_ERROR_CBOR_FAILURE;

		mac_ctx->id_cred_len = len;
	}

	/* Check compact encoding of ID_CRED_R. */
	if (EDHOC_COSE_HEADER_KID == cred->label) {
		ret = kid_compact_encoding(cred, mac_ctx);

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_CBOR_FAILURE;
	}

	if (EDHOC_COSE_ANY == cred->label &&
	    true == cred->any.is_id_cred_comp_enc) {
		mac_ctx->id_cred_is_comp_enc = true;
		mac_ctx->id_cred_enc_type = cred->any.encode_type;
		switch (mac_ctx->id_cred_enc_type) {
		case EDHOC_ENCODE_TYPE_INTEGER:
			memcpy(&mac_ctx->id_cred_int,
			       cred->any.id_cred_comp_enc,
			       cred->any.id_cred_comp_enc_length);
			break;
		case EDHOC_ENCODE_TYPE_BYTE_STRING:
			mac_ctx->id_cred_bstr_len =
				cred->any.id_cred_comp_enc_length;
			memcpy(&mac_ctx->id_cred_bstr,
			       cred->any.id_cred_comp_enc,
			       cred->any.id_cred_comp_enc_length);
			break;
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	/* TH length. */
	mac_ctx->th = &mac_ctx->id_cred[mac_ctx->id_cred_len];

	len = 0;
	ret = compute_th_length(ctx->th_len, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	mac_ctx->th_len = len;

	/* TH cborising. */
	const struct zcbor_string th = {
		.value = ctx->th,
		.len = ctx->th_len,
	};

	len = 0;
	ret = cbor_encode_byte_string_type_bstr_type(
		mac_ctx->th, mac_ctx->th_len, &th, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	mac_ctx->th_len = len;

	/* CRED length. */
	mac_ctx->cred = &mac_ctx->th[mac_ctx->th_len];

	len = 0;
	ret = compute_cred_length(cred, &len);

	if (EDHOC_SUCCESS != ret)
		return ret;

	mac_ctx->cred_len = len;

	/* CRED cborising. */
	struct zcbor_string _cred = { 0 };

	switch (cred->label) {
	case EDHOC_COSE_ANY:
		break;

	case EDHOC_COSE_HEADER_KID:
		_cred.value = cred->key_id.cred;
		_cred.len = cred->key_id.cred_len;
		break;

	case EDHOC_COSE_HEADER_X509_CHAIN: {
		const size_t end_entity_idx = 0;
		_cred.value = cred->x509_chain.cert[end_entity_idx];
		_cred.len = cred->x509_chain.cert_len[end_entity_idx];
		break;
	}

	case EDHOC_COSE_HEADER_X509_HASH:
		_cred.value = cred->x509_hash.cert;
		_cred.len = cred->x509_hash.cert_len;
		break;

	default:
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (EDHOC_COSE_HEADER_KID == cred->label &&
	    true == cred->key_id.cred_is_cbor) {
		memcpy(mac_ctx->cred, cred->key_id.cred, cred->key_id.cred_len);
		mac_ctx->cred_len = cred->key_id.cred_len;
	} else if (EDHOC_COSE_ANY == cred->label) {
		memcpy(mac_ctx->cred, cred->any.cred, cred->any.cred_len);
	} else {
		len = 0;
		ret = cbor_encode_byte_string_type_bstr_type(
			mac_ctx->cred, mac_ctx->cred_len, &_cred, &len);

		if (ZCBOR_SUCCESS != ret)
			return EDHOC_ERROR_CBOR_FAILURE;

		mac_ctx->cred_len = len;
	}

	/* EAD length. */
	if (0 != ctx->nr_of_ead_tokens) {
		len = 0;
		ret = compute_ead_length(ctx, &len);

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

		len = 0;
		ret = cbor_encode_ead(mac_ctx->ead, mac_ctx->ead_len, &tmp_ead,
				      &len);

		if (ZCBOR_SUCCESS != ret)
			return EDHOC_ERROR_CBOR_FAILURE;

		mac_ctx->ead_len = len;
	}

	const size_t encoded_bytes = mac_ctx->conn_id_len +
				     mac_ctx->id_cred_len + mac_ctx->th_len +
				     mac_ctx->cred_len + mac_ctx->ead_len;

	if (encoded_bytes > mac_ctx->buf_len)
		return EDHOC_ERROR_BUFFER_TOO_SMALL;

	mac_ctx->buf_len = encoded_bytes;
	return EDHOC_SUCCESS;
}

int edhoc_comp_mac_length(const struct edhoc_context *ctx, size_t *mac_len)
{
	if (NULL == ctx || NULL == mac_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_INITIATOR != ctx->role && EDHOC_RESPONDER != ctx->role)
		return EDHOC_ERROR_BAD_STATE;

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	if (EDHOC_MSG_2 == ctx->message) {
		switch (ctx->chosen_method) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_2:
			*mac_len = csuite.hash_length;
			return EDHOC_SUCCESS;

		case EDHOC_METHOD_1:
		case EDHOC_METHOD_3:
			*mac_len = csuite.mac_length;
			return EDHOC_SUCCESS;

		case EDHOC_METHOD_PSK:
		case EDHOC_METHOD_MAX:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	if (EDHOC_MSG_3 == ctx->message) {
		switch (ctx->chosen_method) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_1:
			*mac_len = csuite.hash_length;
			return EDHOC_SUCCESS;

		case EDHOC_METHOD_2:
		case EDHOC_METHOD_3:
			*mac_len = csuite.mac_length;
			return EDHOC_SUCCESS;

		case EDHOC_METHOD_PSK:
		case EDHOC_METHOD_MAX:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	return EDHOC_ERROR_NOT_PERMITTED;
}

int edhoc_comp_mac(const struct edhoc_context *ctx,
		   const struct mac_context *mac_ctx, uint8_t *mac,
		   size_t mac_len)
{
	if (NULL == ctx || NULL == mac_ctx || NULL == mac || 0 == mac_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_MSG_1 > ctx->message || EDHOC_MSG_3 < ctx->message)
		return EDHOC_ERROR_BAD_STATE;

	if (EDHOC_MSG_2 == ctx->message &&
	    EDHOC_PRK_STATE_3E2M != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	if (EDHOC_MSG_3 == ctx->message &&
	    EDHOC_PRK_STATE_4E3M != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	struct info info = {
		.info_context.value = mac_ctx->buf,
		.info_context.len = mac_ctx->buf_len,
		.info_length = (uint32_t)mac_len,
	};

	if (EDHOC_MSG_2 == ctx->message)
		info.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_MAC_2;

	if (EDHOC_MSG_3 == ctx->message)
		info.info_label = EDHOC_EXTRACT_PRK_INFO_LABEL_MAC_3;

	/* Calculate struct info cbor overhead. */
	size_t len = 0;
	len += edhoc_cbor_int_mem_req(info.info_label);
	len += mac_ctx->buf_len + edhoc_cbor_bstr_oh(mac_ctx->buf_len);
	len += edhoc_cbor_int_mem_req((int32_t)mac_len);

	VLA_ALLOC(uint8_t, info_buf, len);
	memset(info_buf, 0, VLA_SIZEOF(info_buf));

	len = 0;
	ret = cbor_encode_info(info_buf, VLA_SIZE(info_buf), &info, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	if (NULL != ctx->logger) {
		switch (ctx->message) {
		case EDHOC_MSG_2:
			ctx->logger(ctx->user_ctx, "MAC_2 info", info_buf, len);
			break;
		case EDHOC_MSG_3:
			ctx->logger(ctx->user_ctx, "MAC_3 info", info_buf, len);
			break;

		case EDHOC_MSG_1:
		case EDHOC_MSG_4:
		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	uint8_t kid[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_EXPAND, ctx->prk,
				   ctx->prk_len, kid);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.expand(ctx->user_ctx, kid, info_buf, len, mac,
				 mac_len);
	ctx->keys.destroy_key(ctx->user_ctx, kid);
	memset(kid, 0, sizeof(kid));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

int edhoc_comp_sign_or_mac_length(const struct edhoc_context *ctx,
				  size_t *sign_or_mac_len)
{
	if (NULL == ctx || NULL == sign_or_mac_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_INITIATOR != ctx->role && EDHOC_RESPONDER != ctx->role)
		return EDHOC_ERROR_BAD_STATE;

	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	if (EDHOC_MSG_2 == ctx->message) {
		switch (ctx->chosen_method) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_2:
			*sign_or_mac_len = csuite.ecc_sign_length;
			return EDHOC_SUCCESS;

		case EDHOC_METHOD_1:
		case EDHOC_METHOD_3:
			*sign_or_mac_len = csuite.mac_length;
			return EDHOC_SUCCESS;

		case EDHOC_METHOD_PSK:
		case EDHOC_METHOD_MAX:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	if (EDHOC_MSG_3 == ctx->message) {
		switch (ctx->chosen_method) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_1:
			*sign_or_mac_len = csuite.ecc_sign_length;
			return EDHOC_SUCCESS;

		case EDHOC_METHOD_2:
		case EDHOC_METHOD_3:
			*sign_or_mac_len = csuite.mac_length;
			return EDHOC_SUCCESS;

		case EDHOC_METHOD_PSK:
		case EDHOC_METHOD_MAX:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	return EDHOC_ERROR_NOT_PERMITTED;
}

int edhoc_comp_sign_or_mac(const struct edhoc_context *ctx,
			   const struct edhoc_auth_creds *cred,
			   const struct mac_context *mac_ctx,
			   const uint8_t *mac, size_t mac_len, uint8_t *sign,
			   size_t sign_size, size_t *sign_len)
{
	if (NULL == ctx || NULL == cred || NULL == mac_ctx || NULL == mac ||
	    0 == mac_len || NULL == sign || 0 == sign_size || NULL == sign_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_MSG_2 == ctx->message) {
		switch (ctx->chosen_method) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_2:
			return sign_cose_sign_1(ctx, cred, mac_ctx, mac,
						mac_len, sign, sign_size,
						sign_len);

		case EDHOC_METHOD_1:
		case EDHOC_METHOD_3:
			*sign_len = mac_len;
			memcpy(sign, mac, mac_len);
			return EDHOC_SUCCESS;

		case EDHOC_METHOD_PSK:
		case EDHOC_METHOD_MAX:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	if (EDHOC_MSG_3 == ctx->message) {
		switch (ctx->chosen_method) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_1:
			return sign_cose_sign_1(ctx, cred, mac_ctx, mac,
						mac_len, sign, sign_size,
						sign_len);

		case EDHOC_METHOD_2:
		case EDHOC_METHOD_3:
			*sign_len = mac_len;
			memcpy(sign, mac, mac_len);
			return EDHOC_SUCCESS;

		case EDHOC_METHOD_PSK:
		case EDHOC_METHOD_MAX:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	return EDHOC_ERROR_BAD_STATE;
}

int edhoc_verify_sign_or_mac(const struct edhoc_context *ctx,
			     const struct mac_context *mac_ctx,
			     const uint8_t *pub_key, size_t pub_key_len,
			     const uint8_t *sign_or_mac, size_t sign_or_mac_len,
			     const uint8_t *mac, size_t mac_len)
{
	if (NULL == ctx || NULL == mac_ctx || NULL == pub_key ||
	    0 == pub_key_len || NULL == sign_or_mac || 0 == sign_or_mac_len ||
	    NULL == mac || 0 == mac_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_MSG_2 == ctx->message) {
		switch (ctx->chosen_method) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_2:
			return verify_cose_sign_1(ctx, mac_ctx, pub_key,
						  pub_key_len, mac, mac_len,
						  sign_or_mac, sign_or_mac_len);

		case EDHOC_METHOD_1:
		case EDHOC_METHOD_3:
			if (mac_len != sign_or_mac_len ||
			    0 != memcmp(sign_or_mac, mac, mac_len))
				return EDHOC_ERROR_INVALID_SIGN_OR_MAC_2;

			return EDHOC_SUCCESS;

		case EDHOC_METHOD_PSK:
		case EDHOC_METHOD_MAX:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	if (EDHOC_MSG_3 == ctx->message) {
		switch (ctx->chosen_method) {
		case EDHOC_METHOD_0:
		case EDHOC_METHOD_1:
			return verify_cose_sign_1(ctx, mac_ctx, pub_key,
						  pub_key_len, mac, mac_len,
						  sign_or_mac, sign_or_mac_len);

		case EDHOC_METHOD_2:
		case EDHOC_METHOD_3:
			if (mac_len != sign_or_mac_len ||
			    0 != memcmp(sign_or_mac, mac, mac_len))
				return EDHOC_ERROR_INVALID_SIGN_OR_MAC_2;

			return EDHOC_SUCCESS;

		case EDHOC_METHOD_PSK:
		case EDHOC_METHOD_MAX:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	return EDHOC_ERROR_BAD_STATE;
}

int edhoc_comp_keystream(const struct edhoc_context *ctx, size_t prk_label,
			 const uint8_t *prk, size_t prk_len, uint8_t *kstr,
			 size_t kstr_len)
{
	if (NULL == ctx || NULL == prk || 0 == prk_len || NULL == kstr ||
	    0 == kstr_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	switch (prk_label) {
	case EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTERAM_2:
		if (EDHOC_TH_STATE_2 != ctx->th_state ||
		    EDHOC_PRK_STATE_2E != ctx->prk_state)
			return EDHOC_ERROR_BAD_STATE;
		break;
	case EDHOC_EXTRACT_PRK_INFO_LABEL_PSK_KEYSTREAM_3:
		if (EDHOC_TH_STATE_3 != ctx->th_state ||
		    EDHOC_PRK_STATE_3E2M != ctx->prk_state)
			return EDHOC_ERROR_BAD_STATE;
		break;
	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const struct info input_info = {
		.info_label = (int32_t)prk_label,
		.info_context.value = ctx->th,
		.info_context.len = ctx->th_len,
		.info_length = (uint32_t)kstr_len,
	};

	size_t len = 0;
	len += edhoc_cbor_int_mem_req((int32_t)prk_label);
	len += ctx->th_len + edhoc_cbor_bstr_oh(ctx->th_len);
	len += edhoc_cbor_int_mem_req((int32_t)kstr_len);

	VLA_ALLOC(uint8_t, info, len);
	memset(info, 0, VLA_SIZEOF(info));

	len = 0;
	ret = cbor_encode_info(info, VLA_SIZE(info), &input_info, &len);

	if (ZCBOR_SUCCESS != ret || VLA_SIZE(info) != len)
		return EDHOC_ERROR_CBOR_FAILURE;

	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_EXPAND, prk, prk_len,
				   key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ret = ctx->crypto.expand(ctx->user_ctx, key_id, info, VLA_SIZE(info),
				 kstr, kstr_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);
	memset(key_id, 0, sizeof(key_id));

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	return EDHOC_SUCCESS;
}

inline void edhoc_xor_arrays(uint8_t *restrict dst, const uint8_t *restrict src,
			     size_t count)
{
	for (size_t i = 0; i < count; ++i)
		dst[i] ^= src[i];
}
