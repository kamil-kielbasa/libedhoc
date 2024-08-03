/**
 * \file    edhoc_message_1.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message 1.
 * \version 0.4
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include "edhoc.h"

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
#include <backend_cbor_message_1_encode.h>
#include <backend_cbor_message_1_decode.h>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
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

	if (EDHOC_SM_START != ctx->status ||
	    EDHOC_TH_STATE_INVALID != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_1;
	ctx->role = EDHOC_INITIATOR;

	/* 1. Choose most preferred cipher suite. */
	if (0 == ctx->csuite_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	ctx->chosen_csuite_idx = ctx->csuite_len - 1;
	const struct edhoc_cipher_suite csuite =
		ctx->csuite[ctx->chosen_csuite_idx];

	/* 2. Generate ephemeral Diffie-Hellmann key pair. */
	uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	ret = ctx->keys.import_key(ctx->user_ctx, EDHOC_KT_MAKE_KEY_PAIR, NULL,
				   0, key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;

	uint8_t dh_pub_key[csuite.ecc_key_length];
	memset(dh_pub_key, 0, sizeof(dh_pub_key));

	size_t dh_priv_key_len = 0;
	size_t dh_pub_key_len = 0;
	ret = ctx->crypto.make_key_pair(ctx->user_ctx, key_id, ctx->dh_priv_key,
					ARRAY_SIZE(ctx->dh_priv_key),
					&dh_priv_key_len, dh_pub_key,
					ARRAY_SIZE(dh_pub_key),
					&dh_pub_key_len);
	ctx->keys.destroy_key(ctx->user_ctx, key_id);

	if (EDHOC_SUCCESS != ret || csuite.ecc_key_length != dh_priv_key_len ||
	    csuite.ecc_key_length != dh_pub_key_len)
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;

	ctx->dh_priv_key_len = dh_priv_key_len;

	if (NULL != ctx->logger) {
		ctx->logger(ctx->user_ctx, "G_X", dh_pub_key, dh_pub_key_len);
		ctx->logger(ctx->user_ctx, "X", ctx->dh_priv_key,
			    ctx->dh_priv_key_len);
	}

	struct message_1 cbor_enc_msg_1 = { 0 };

	/* 3a. Fill CBOR structure for message 1 - method. */
	cbor_enc_msg_1._message_1_METHOD = (int32_t)ctx->method;

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
	switch (ctx->cid.encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
		cbor_enc_msg_1._message_1_C_I_choice = _message_1_C_I_int;
		cbor_enc_msg_1._message_1_C_I_int = ctx->cid.int_value;
		break;

	case EDHOC_CID_TYPE_BYTE_STRING:
		cbor_enc_msg_1._message_1_C_I_choice = _message_1_C_I_bstr;
		cbor_enc_msg_1._message_1_C_I_bstr.value = ctx->cid.bstr_value;
		cbor_enc_msg_1._message_1_C_I_bstr.len = ctx->cid.bstr_length;
		break;

	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	/* 3e. Fill CBOR structure for message 1 - external authorization data if present. */
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
					    "EAD_1 compose label",
					    (const uint8_t *)&ctx->ead_token[i]
						    .label,
					    sizeof(ctx->ead_token[i].label));

				if (0 != ctx->ead_token[i].value_len)
					ctx->logger(
						ctx->user_ctx,
						"EAD_1 compose value",
						ctx->ead_token[i].value,
						ctx->ead_token[i].value_len);
			}
		}
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

	if (NULL != ctx->logger)
		ctx->logger(ctx->user_ctx, "message_1", msg_1, *msg_1_len);

	/* 5. Compute H(cbor(msg_1)) and cache it. */
	ctx->th_len = csuite.hash_length;
	size_t hash_len = 0;
	ret = ctx->crypto.hash(ctx->user_ctx, msg_1, *msg_1_len, ctx->th,
			       ctx->th_len, &hash_len);

	if (EDHOC_SUCCESS != ret || csuite.hash_length != hash_len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->nr_of_ead_tokens = 0;
	memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

	ctx->th_state = EDHOC_TH_STATE_1;
	ctx->status = EDHOC_SM_WAIT_M2;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
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

	if (EDHOC_SM_START != ctx->status ||
	    EDHOC_TH_STATE_INVALID != ctx->th_state ||
	    EDHOC_PRK_STATE_INVALID != ctx->prk_state)
		return EDHOC_ERROR_BAD_STATE;

	ctx->status = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->message = EDHOC_MSG_1;
	ctx->role = EDHOC_RESPONDER;

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
		    cbor_dec_msg_1._message_1_SUITES_I._suites_int) {
			ctx->error_code =
				EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
			return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
		}
		break;
	}

	case _suites__int: {
		if (csuite.value !=
		    cbor_dec_msg_1._message_1_SUITES_I
			    ._suites__int_int[cbor_dec_msg_1._message_1_SUITES_I
						      ._suites__int_int_count -
					      1]) {
			ctx->error_code =
				EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
			return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
		}

		break;
	}

	default:
		return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
	}

	/* 3c. Verify ephemeral public key. */
	if (cbor_dec_msg_1._message_1_G_X.len != csuite.ecc_key_length)
		return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;

	ctx->dh_peer_pub_key_len = cbor_dec_msg_1._message_1_G_X.len;
	memcpy(ctx->dh_peer_pub_key, cbor_dec_msg_1._message_1_G_X.value,
	       csuite.ecc_key_length);

	/* 3d. Verify connection identifier. */
	switch (cbor_dec_msg_1._message_1_C_I_choice) {
	case _message_1_C_I_int: {
		if (ONE_BYTE_CBOR_INT_MIN_VALUE >
			    cbor_dec_msg_1._message_1_C_I_int ||
		    ONE_BYTE_CBOR_INT_MAX_VALUE <
			    cbor_dec_msg_1._message_1_C_I_int)
			return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;

		ctx->peer_cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
		ctx->peer_cid.int_value =
			(int8_t)cbor_dec_msg_1._message_1_C_I_int;
		break;
	}

	case _message_1_C_I_bstr: {
		if (ARRAY_SIZE(ctx->peer_cid.bstr_value) <
		    cbor_dec_msg_1._message_1_C_I_bstr.len)
			return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;

		ctx->peer_cid.encode_type = EDHOC_CID_TYPE_BYTE_STRING;
		ctx->peer_cid.bstr_length =
			cbor_dec_msg_1._message_1_C_I_bstr.len;
		memcpy(ctx->peer_cid.bstr_value,
		       cbor_dec_msg_1._message_1_C_I_bstr.value,
		       cbor_dec_msg_1._message_1_C_I_bstr.len);
		break;
	}

	default:
		return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
	}

	if (NULL != ctx->logger) {
		switch (ctx->peer_cid.encode_type) {
		case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
			ctx->logger(ctx->user_ctx, "C_I",
				    (const uint8_t *)&ctx->peer_cid.int_value,
				    sizeof(ctx->peer_cid.int_value));
			break;
		case EDHOC_CID_TYPE_BYTE_STRING:
			ctx->logger(ctx->user_ctx, "C_I",
				    ctx->peer_cid.bstr_value,
				    ctx->peer_cid.bstr_length);
			break;

		default:
			return EDHOC_ERROR_NOT_PERMITTED;
		}
	}

	/* 4. Process EAD if present. */
	if (true == cbor_dec_msg_1._message_1_EAD_1_present &&
	    NULL != ctx->ead.process) {
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

		ret = ctx->ead.process(ctx->user_ctx, ctx->message,
				       ctx->ead_token, ctx->nr_of_ead_tokens);

		if (EDHOC_SUCCESS == ret && NULL != ctx->logger) {
			for (size_t i = 0; i < ctx->nr_of_ead_tokens; ++i) {
				ctx->logger(ctx->user_ctx,
					    "EAD_1 process label",
					    (const uint8_t *)&ctx->ead_token[i]
						    .label,
					    sizeof(ctx->ead_token[i].label));

				if (0 != ctx->ead_token[i].value_len)
					ctx->logger(
						ctx->user_ctx,
						"EAD_1 process value",
						ctx->ead_token[i].value,
						ctx->ead_token[i].value_len);
			}
		}

		ctx->nr_of_ead_tokens = 0;
		memset(ctx->ead_token, 0, sizeof(ctx->ead_token));

		if (EDHOC_SUCCESS != ret)
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;
	}

	/* 5. Compute H(cbor(msg_1)) and cache it. */
	ctx->th_len = csuite.hash_length;
	size_t hash_len = 0;
	ret = ctx->crypto.hash(ctx->user_ctx, msg_1, msg_1_len, ctx->th,
			       ctx->th_len, &hash_len);

	if (EDHOC_SUCCESS != ret || csuite.hash_length != hash_len)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	ctx->th_state = EDHOC_TH_STATE_1;
	ctx->status = EDHOC_SM_RECEIVED_M1;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}
