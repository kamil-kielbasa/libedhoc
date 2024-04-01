/**
 * \file    edhoc_message_1.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message 1 compose & process.
 * \version 0.1
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */
#include "edhoc.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

/* CBOR header files: */
#include <zcbor_common.h>
#include <backend_cbor_message_1_encode.h>
#include <backend_cbor_message_1_decode.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/** 
 * \brief Check if integer might be encoded as CBOR one byte. 
 *
 * \param len		        Length of buffer.
 * \param val                   Value for cbor encoding.
 *
 * \retval True if might be encoded as one byte cbor integer,
 *         otherwise false.
 */
static inline bool is_cbor_one_byte(size_t len, int8_t val);

/* Static function definitions --------------------------------------------- */

static inline bool is_cbor_one_byte(size_t len, int8_t val)
{
	return (ONE_BYTE_CBOR_INT_LEN == len &&
		ONE_BYTE_CBOR_INT_MIN_VALUE <= val &&
		ONE_BYTE_CBOR_INT_MAX_VALUE >= val);
}

/* Module interface function definitions ----------------------------------- */

/*
 * Steps for composition of message 1:
 *      1.  Choose most preferred cipher suite.
 *      2.  Generate ephemeral Diffie-Hellmann key pair.
 *      3a. Fill CBOR structure for message 1 - method.
 *      3b. Fill CBOR structure for message 1 - cipher suite.
 *      3c. Fill CBOR structure for message 1 - ephemeral public key.
 *      3d. Fill CBOR structure for message 1 - connection identifier.
 *      3e. Fill CBOR structure for message 1 - external authorization data if present.
 *      4.  Encode cbor sequence of message 1.
 *      5.  Compute H(cbor(msg_1)) and cache it.
 */
int edhoc_message_1_compose(struct edhoc_context *ctx, uint8_t *msg_1,
			    size_t msg_1_size, size_t *msg_1_len)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	if (NULL == ctx || NULL == msg_1 || 0 == msg_1_size ||
	    NULL == msg_1_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (START != ctx->status || EDHOC_TH_STATE_INVALID != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	ctx->status = ABORTED;

	/* 1. Choose most preferred cipher suite. */
	if (0 == ctx->csuite_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	ctx->chosen_csuite_idx = ctx->csuite_len - 1;
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* 2. Generate ephemeral Diffie-Hellmann key pair. */
	uint8_t key_id[EDHOC_KID_LEN] = { 0 };
	ret = ctx->keys_cb.generate_key(EDHOC_KT_MAKE_KEY_PAIR, NULL, 0,
					key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_DIFFIE_HELLMAN_FAILURE;

	uint8_t dh_pub_key[csuite.ecc_key_len];
	memset(dh_pub_key, 0, sizeof(dh_pub_key));

	size_t dh_priv_key_len = 0;
	size_t dh_pub_key_len = 0;
	ret = ctx->crypto_cb.make_key_pair(key_id, ctx->dh_priv_key,
					   ARRAY_SIZE(ctx->dh_priv_key),
					   &dh_priv_key_len, dh_pub_key,
					   ARRAY_SIZE(dh_pub_key),
					   &dh_pub_key_len);
	ctx->keys_cb.destroy_key(key_id);

	if (EDHOC_SUCCESS != ret || csuite.ecc_key_len != dh_priv_key_len ||
	    csuite.ecc_key_len != dh_pub_key_len)
		return EDHOC_ERROR_DIFFIE_HELLMAN_FAILURE;

	ctx->dh_priv_key_len = dh_priv_key_len;

	struct message_1 cbor_enc_msg_1 = { 0 };

	/* 3a. Fill CBOR structure for message 1 - method. */
	cbor_enc_msg_1._message_1_METHOD = ctx->method;

	/* 3b. Fill CBOR structure for message 1 - cipher suite. */
	if (1UL == ctx->csuite_len) {
		cbor_enc_msg_1._message_1_SUITES_I._suites_choice = _suites_int;
		cbor_enc_msg_1._message_1_SUITES_I._suites_int = csuite.value;
	} else {
		cbor_enc_msg_1._message_1_SUITES_I._suites_choice =
			_suites__int;
		cbor_enc_msg_1._message_1_SUITES_I._suites__int_int_count =
			ctx->csuite_len;

		if (ARRAY_SIZE(cbor_enc_msg_1._message_1_SUITES_I
				       ._suites__int_int) < ctx->csuite_len) {
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		for (size_t i = 0; i < ctx->csuite_len; ++i) {
			cbor_enc_msg_1._message_1_SUITES_I._suites__int_int[i] =
				ctx->csuite[i].value;
		}
	}

	/* 3c. Fill CBOR structure for message 1 - ephemeral public key. */
	cbor_enc_msg_1._message_1_G_X.value = dh_pub_key;
	cbor_enc_msg_1._message_1_G_X.len = ARRAY_SIZE(dh_pub_key);

	/* 3d. Fill CBOR structure for message 1 - connection identifier. */
	if (is_cbor_one_byte(ctx->cid_len, (int8_t)ctx->cid[0])) {
		cbor_enc_msg_1._message_1_C_I_choice = _message_1_C_I_int;
		cbor_enc_msg_1._message_1_C_I_int = (int8_t)ctx->cid[0];
	} else {
		cbor_enc_msg_1._message_1_C_I_choice = _message_1_C_I_bstr;
		cbor_enc_msg_1._message_1_C_I_bstr.value = ctx->cid;
		cbor_enc_msg_1._message_1_C_I_bstr.len = ctx->cid_len;
	}

	/* 3e. Fill CBOR structure for message 1 - external authorization data if present. */
	if (NULL != ctx->ead_compose && 0 != ARRAY_SIZE(ctx->ead_token) - 1) {
		ret = ctx->ead_compose(ctx->user_ctx, EDHOC_MSG_1,
				       ctx->ead_token,
				       ARRAY_SIZE(ctx->ead_token) - 1,
				       &ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS != ret ||
		    ARRAY_SIZE(ctx->ead_token) - 1 < ctx->nr_of_ead_tokens)
			return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	if (0 != ctx->nr_of_ead_tokens) {
		cbor_enc_msg_1._message_1_EAD_1_present = true;
		cbor_enc_msg_1._message_1_EAD_1._ead_count =
			ctx->nr_of_ead_tokens;

		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			cbor_enc_msg_1._message_1_EAD_1._ead[i]
				._ead_value_present = true;
			cbor_enc_msg_1._message_1_EAD_1._ead[i]._ead_label =
				ctx->ead_token[i].label;
			cbor_enc_msg_1._message_1_EAD_1._ead[i]
				._ead_value.value = ctx->ead_token[i].value;
			cbor_enc_msg_1._message_1_EAD_1._ead[i]._ead_value.len =
				ctx->ead_token[i].value_len;
		}
	} else {
		cbor_enc_msg_1._message_1_EAD_1_present = false;
		cbor_enc_msg_1._message_1_EAD_1._ead_count = 0;
	}

	/* 4. Encode cbor sequence of message 1. */
	ret = cbor_encode_message_1(msg_1, msg_1_size, &cbor_enc_msg_1,
				    msg_1_len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	/* 5. Compute H(cbor(msg_1)) and cache it. */
	ctx->th_len = csuite.hash_len;
	size_t hash_len = 0;
	ret = ctx->crypto_cb.hash(msg_1, *msg_1_len, ctx->th, ctx->th_len,
				  &hash_len);

	if (EDHOC_SUCCESS != ret || csuite.hash_len != hash_len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->th_state = EDHOC_TH_STATE_1;
	ctx->status = WAIT_M2;
	return EDHOC_SUCCESS;
}

/*
 * Steps for processing of message 1:
 *      1.  Decode cborised message 1.
 *      2.  Choose most preferred cipher suite.
 *      3a. Verify method.
 *      3b. Verify cipher suite.
 *      3c. Verify ephemeral public key.
 *      3d. Verify connection identifier.
 *      4.  Process EAD if present.
 *      5.  Compute H(cbor(msg_1)) and cache it.
 */
int edhoc_message_1_process(struct edhoc_context *ctx, const uint8_t *msg_1,
			    size_t msg_1_len)
{
	if (NULL == ctx || msg_1 == NULL || 0 == msg_1_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (START != ctx->status || EDHOC_TH_STATE_INVALID != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	ctx->status = ABORTED;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Decode cborised message 1. */
	struct message_1 cbor_dec_msg_1 = { 0 };
	size_t len = 0;
	ret = cbor_decode_message_1(msg_1, msg_1_len, &cbor_dec_msg_1, &len);

	if (ZCBOR_SUCCESS != ret && msg_1_len <= len)
		return EDHOC_ERROR_CBOR_FAILURE;

	/* 2. Choose most preferred cipher suite. */
	if (0 == ctx->csuite_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	ctx->chosen_csuite_idx = ctx->csuite_len - 1;
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* 3a. Verify method. */
	if ((int32_t)ctx->method != cbor_dec_msg_1._message_1_METHOD)
		return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;

	/* 3b. Verify cipher suite. */
	switch (cbor_dec_msg_1._message_1_SUITES_I._suites_choice) {
	case _suites_int: {
		if (csuite.value !=
		    cbor_dec_msg_1._message_1_SUITES_I._suites_int)
			return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
		break;
	}

	case _suites__int: {
		if (csuite.value !=
		    cbor_dec_msg_1._message_1_SUITES_I
			    ._suites__int_int[cbor_dec_msg_1._message_1_SUITES_I
						      ._suites__int_int_count -
					      1]) {
			return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
		}

		break;
	}

	default:
		return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
	}

	/* 3c. Verify ephemeral public key. */
	if (cbor_dec_msg_1._message_1_G_X.len != csuite.ecc_key_len)
		return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;

	ctx->dh_peer_pub_key_len = cbor_dec_msg_1._message_1_G_X.len;
	memcpy(ctx->dh_peer_pub_key, cbor_dec_msg_1._message_1_G_X.value,
	       csuite.ecc_key_len);

	/* 3d. Verify connection identifier. */
	switch (cbor_dec_msg_1._message_1_C_I_choice) {
	case _message_1_C_I_bstr: {
		if (ARRAY_SIZE(ctx->peer_cid) <
		    cbor_dec_msg_1._message_1_C_I_bstr.len)
			return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;

		ctx->peer_cid_len = cbor_dec_msg_1._message_1_C_I_bstr.len;
		memcpy(ctx->cid, cbor_dec_msg_1._message_1_C_I_bstr.value,
		       cbor_dec_msg_1._message_1_C_I_bstr.len);
		break;
	}

	case _message_1_C_I_int: {
		if (ONE_BYTE_CBOR_INT_MIN_VALUE >
			    cbor_dec_msg_1._message_1_C_I_int ||
		    ONE_BYTE_CBOR_INT_MAX_VALUE <
			    cbor_dec_msg_1._message_1_C_I_int) {
			ctx->status = ABORTED;
			return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
		}

		ctx->peer_cid_len = ONE_BYTE_CBOR_INT_LEN;
		ctx->peer_cid[0] = (int8_t)cbor_dec_msg_1._message_1_C_I_int;
		break;
	}

	default:
		return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
	}

	/* 4. Process EAD if present. */
	if (true == cbor_dec_msg_1._message_1_EAD_1_present &&
	    NULL != ctx->ead_process) {
		if (ARRAY_SIZE(ctx->ead_token) - 1 <
		    cbor_dec_msg_1._message_1_EAD_1._ead_count)
			return EDHOC_ERROR_BUFFER_TOO_SMALL;

		ctx->nr_of_ead_tokens =
			cbor_dec_msg_1._message_1_EAD_1._ead_count;
		for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
			ctx->ead_token[i].label =
				cbor_dec_msg_1._message_1_EAD_1._ead[i]
					._ead_label;
			ctx->ead_token[i].value =
				cbor_dec_msg_1._message_1_EAD_1._ead[i]
					._ead_value.value;
			ctx->ead_token[i].value_len =
				cbor_dec_msg_1._message_1_EAD_1._ead[i]
					._ead_value.len;
		}

		ret = ctx->ead_process(ctx->user_ctx, EDHOC_MSG_1,
				       ctx->ead_token, ctx->nr_of_ead_tokens);

		ctx->nr_of_ead_tokens = 0;
		memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;
	}

	/* 5. Compute H(cbor(msg_1)) and cache it. */
	ctx->th_len = csuite.hash_len;
	size_t hash_len = 0;
	ret = ctx->crypto_cb.hash(msg_1, msg_1_len, ctx->th, ctx->th_len,
				  &hash_len);

	if (EDHOC_SUCCESS != ret || csuite.hash_len != hash_len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->th_state = EDHOC_TH_STATE_1;
	ctx->status = VERIFIED_M1;
	return EDHOC_SUCCESS;
}