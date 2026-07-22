/**
 * \file    edhoc_message_1.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message 1 compose & process.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* EDHOC header: */
#include <edhoc/edhoc.h>
#include "edhoc_context_internal.h"
#include "edhoc_values_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_common_internal.h"
#include "edhoc_backend_log.h"
#include "edhoc_backend_memory.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_message_1_encode.h>
#include <backend_cbor_message_1_decode.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

/*
 * Steps for composition of message 1:
 *      1a. Choose most preferred cipher suite.
 *      1b. Choose most preferred method.
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
	EDHOC_LOG_INF("Compose msg1 start");

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	if (NULL == ctx || NULL == msg_1 || 0 == msg_1_size ||
	    NULL == msg_1_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_context_configured(ctx)) {
		EDHOC_LOG_ERR("Context not fully configured");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_SM_START != ctx->state.machine ||
	    EDHOC_TH_STATE_INVALID != ctx->state.th.stage ||
	    EDHOC_PRK_STATE_INVALID != ctx->state.prk_state)
		return EDHOC_ERROR_BAD_STATE;

	ctx->state.machine = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->state.message = EDHOC_MESSAGE_1;
	ctx->state.role = EDHOC_ROLE_INITIATOR;

	/* 1a. Choose most preferred cipher suite. */
	if (0 == ctx->negotiation.cipher_suite.count) {
		EDHOC_LOG_ERR("No cipher suites configured");
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->negotiation.selected_cipher_suite_index =
		ctx->negotiation.cipher_suite.count - 1;
	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);

	/* 1b. Choose most preferred method. */
	ctx->negotiation.selected_method = ctx->negotiation.method.entry[0];

	/* 2. Generate the ephemeral key pair (KEM). The decapsulation (private)
	 * key stays in the ephemeral key slot; the encapsulation (public) key
	 * G_X is written to ctx->ephemeral.own.value and serialised into message 1. */
	ctx->ephemeral.own.length = 0;
	ret = edhoc_crypto(ctx)->generate_key_pair(
		ctx->user_context,
		edhoc_key_slot_id(ctx, EDHOC_KEY_SLOT_EPHEMERAL),
		ctx->ephemeral.own.value, ARRAY_SIZE(ctx->ephemeral.own.value),
		&ctx->ephemeral.own.length);

	if (EDHOC_SUCCESS != ret ||
	    csuite->kem_encapsulation_key_length != ctx->ephemeral.own.length) {
		EDHOC_LOG_ERR("Generate key pair: %d, %zu, %zu", ret,
			      csuite->kem_encapsulation_key_length,
			      ctx->ephemeral.own.length);
		return EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE;
	}

	edhoc_key_slot_mark_present(ctx, EDHOC_KEY_SLOT_EPHEMERAL);

	EDHOC_LOG_HEXDUMP_DBG(ctx->ephemeral.own.value,
			      ctx->ephemeral.own.length, "G_X");

	struct message_1 cbor_enc_msg_1 = { 0 };

	/* 3a. Fill CBOR structure for message 1 - method. */
	cbor_enc_msg_1.message_1_METHOD =
		(int32_t)ctx->negotiation.selected_method;

	/* 3b. Fill CBOR structure for message 1 - cipher suite. */
	if (1UL == ctx->negotiation.cipher_suite.count) {
		cbor_enc_msg_1.message_1_SUITES_I.suites_choice = suites_int_c;
		cbor_enc_msg_1.message_1_SUITES_I.suites_int = csuite->value;
	} else {
		cbor_enc_msg_1.message_1_SUITES_I.suites_choice =
			suites_int_l_c;
		cbor_enc_msg_1.message_1_SUITES_I.suites_int_l_int_count =
			ctx->negotiation.cipher_suite.count;

		if (ARRAY_SIZE(
			    cbor_enc_msg_1.message_1_SUITES_I.suites_int_l_int) <
		    ctx->negotiation.cipher_suite.count) {
			EDHOC_LOG_ERR(
				"Buffer too small for cipher suites: %zu, %zu",
				ctx->negotiation.cipher_suite.count,
				ARRAY_SIZE(cbor_enc_msg_1.message_1_SUITES_I
						   .suites_int_l_int));
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		for (size_t i = 0; i < ctx->negotiation.cipher_suite.count;
		     ++i) {
			cbor_enc_msg_1.message_1_SUITES_I.suites_int_l_int[i] =
				ctx->negotiation.cipher_suite.entry[i].value;
		}
	}

	/* 3c. Fill CBOR structure for message 1 - ephemeral public key. */
	cbor_enc_msg_1.message_1_G_X.value = ctx->ephemeral.own.value;
	cbor_enc_msg_1.message_1_G_X.len = ctx->ephemeral.own.length;

	/* 3d. Fill CBOR structure for message 1 - connection identifier. */
	switch (ctx->negotiation.connection_id.encode_type) {
	case EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER:
		cbor_enc_msg_1.message_1_C_I_choice = message_1_C_I_int_c;
		/* NOLINTNEXTLINE(bugprone-signed-char-misuse,cert-str34-c) */
		cbor_enc_msg_1.message_1_C_I_int =
			ctx->negotiation.connection_id.int_value;
		break;

	case EDHOC_CONNECTION_ID_TYPE_BYTE_STRING:
		cbor_enc_msg_1.message_1_C_I_choice = message_1_C_I_bstr_c;
		cbor_enc_msg_1.message_1_C_I_bstr.value =
			ctx->negotiation.connection_id.bstr_value;
		cbor_enc_msg_1.message_1_C_I_bstr.len =
			ctx->negotiation.connection_id.bstr_length;
		break;

	default:
		EDHOC_LOG_ERR("Invalid cid enc type: %d",
			      ctx->negotiation.connection_id.encode_type);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	/* 3e. Fill CBOR structure for message 1 - external authorization data if present. */
	if (NULL != ctx->interfaces.ead.compose &&
	    0 != ARRAY_SIZE(ctx->ead.token) - 1) {
		ret = ctx->interfaces.ead.compose(
			ctx->user_context, ctx->state.message, ctx->ead.token,
			ARRAY_SIZE(ctx->ead.token) - 1, &ctx->ead.count);

		if (EDHOC_SUCCESS != ret ||
		    ARRAY_SIZE(ctx->ead.token) - 1 < ctx->ead.count) {
			EDHOC_LOG_ERR("EAD compose: %d, %zu, %zu", ret,
				      ctx->ead.count,
				      ARRAY_SIZE(ctx->ead.token) - 1);
			return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
		}

		for (size_t i = 0; i < ctx->ead.count; ++i) {
			EDHOC_LOG_HEXDUMP_DBG(
				(const uint8_t *)&ctx->ead.token[i].label,
				sizeof(ctx->ead.token[i].label),
				"EAD_1 compose token label");

			if (0 != ctx->ead.token[i].value_length) {
				EDHOC_LOG_HEXDUMP_DBG(
					ctx->ead.token[i].value,
					ctx->ead.token[i].value_length,
					"EAD_1 compose token value");
			}
		}
	}

	if (0 != ctx->ead.count) {
		cbor_enc_msg_1.message_1_EAD_1_m_present = true;
		cbor_enc_msg_1.message_1_EAD_1_m.EAD_1_count = ctx->ead.count;

		for (size_t i = 0; i < ctx->ead.count; ++i) {
			cbor_enc_msg_1.message_1_EAD_1_m.EAD_1[i]
				.ead_x_ead_value_present = true;
			cbor_enc_msg_1.message_1_EAD_1_m.EAD_1[i]
				.ead_x_ead_label = ctx->ead.token[i].label;
			cbor_enc_msg_1.message_1_EAD_1_m.EAD_1[i]
				.ead_x_ead_value.value =
				ctx->ead.token[i].value;
			cbor_enc_msg_1.message_1_EAD_1_m.EAD_1[i]
				.ead_x_ead_value.len =
				ctx->ead.token[i].value_length;
		}
	} else {
		cbor_enc_msg_1.message_1_EAD_1_m_present = false;
		cbor_enc_msg_1.message_1_EAD_1_m.EAD_1_count = 0;
	}

	/* 4. Encode cbor sequence of message 1. */
	ret = cbor_encode_message_1(msg_1, msg_1_size, &cbor_enc_msg_1,
				    msg_1_len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc msg1: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	EDHOC_LOG_HEXDUMP_DBG(msg_1, *msg_1_len, "message_1");

	/* 5. Compute H(cbor(msg_1)) and cache it. */
	ctx->state.th.length = csuite->hash_length;
	size_t hash_len = 0;
	const struct hash_segment segments[] = { { msg_1, *msg_1_len } };
	ret = edhoc_comp_hash(ctx, segments, ARRAY_SIZE(segments),
			      ctx->state.th.value, ctx->state.th.length,
			      &hash_len);

	if (EDHOC_SUCCESS != ret || csuite->hash_length != hash_len) {
		EDHOC_LOG_ERR("Hash: %d, %zu, %zu", ret, csuite->hash_length,
			      hash_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_INF("Compose msg1 end");

	edhoc_ead_reset(ctx);

	ctx->state.th.stage = EDHOC_TH_STATE_1;
	ctx->state.machine = EDHOC_SM_WAIT_M2;
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
	EDHOC_LOG_INF("Process msg1 start");

	if (NULL == ctx || msg_1 == NULL || 0 == msg_1_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!edhoc_context_configured(ctx)) {
		EDHOC_LOG_ERR("Context not fully configured");
		return EDHOC_ERROR_BAD_STATE;
	}

	if (EDHOC_SM_START != ctx->state.machine ||
	    EDHOC_TH_STATE_INVALID != ctx->state.th.stage ||
	    EDHOC_PRK_STATE_INVALID != ctx->state.prk_state) {
		EDHOC_LOG_ERR("Bad state: %d, %d, %d", ctx->state.machine,
			      ctx->state.th.stage, ctx->state.prk_state);
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->state.machine = EDHOC_SM_ABORTED;
	ctx->error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ctx->state.message = EDHOC_MESSAGE_1;
	ctx->state.role = EDHOC_ROLE_RESPONDER;

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* 1. Decode cborised message 1. */
	struct message_1 cbor_dec_msg_1 = { 0 };
	size_t len = 0;
	ret = cbor_decode_message_1(msg_1, msg_1_len, &cbor_dec_msg_1, &len);

	if (ZCBOR_SUCCESS != ret && msg_1_len <= len) {
		EDHOC_LOG_ERR("CBOR dec msg1: %d, %zu, %zu", ret, msg_1_len,
			      len);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* 2. Choose most preferred cipher suite. */
	if (0 == ctx->negotiation.cipher_suite.count) {
		EDHOC_LOG_ERR("No cipher suites configured");
		return EDHOC_ERROR_BAD_STATE;
	}

	ctx->negotiation.selected_cipher_suite_index =
		ctx->negotiation.cipher_suite.count - 1;
	const struct edhoc_cipher_suite *csuite =
		edhoc_selected_cipher_suite(ctx);

	/* 3a. Verify method. */
	bool method_match = false;
	for (size_t i = 0; i < ctx->negotiation.method.count; ++i) {
		if ((int32_t)ctx->negotiation.method.entry[i] ==
		    cbor_dec_msg_1.message_1_METHOD) {
			ctx->negotiation.selected_method =
				ctx->negotiation.method.entry[i];
			method_match = true;
			break;
		}
	}

	if (false == method_match) {
		EDHOC_LOG_ERR("Method mismatch: %d",
			      cbor_dec_msg_1.message_1_METHOD);
		return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
	}

	/* 3b. Verify cipher suite. */
	switch (cbor_dec_msg_1.message_1_SUITES_I.suites_choice) {
	case suites_int_c: {
		ctx->negotiation.peer_cipher_suite
			.entry[ctx->negotiation.peer_cipher_suite.count]
			.value = cbor_dec_msg_1.message_1_SUITES_I.suites_int;
		ctx->negotiation.peer_cipher_suite.count = 1;

		if (csuite->value !=
		    cbor_dec_msg_1.message_1_SUITES_I.suites_int) {
			EDHOC_LOG_ERR(
				"Wrong cipher suite: %d, %d", csuite->value,
				cbor_dec_msg_1.message_1_SUITES_I.suites_int);
			ctx->error_code =
				EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
			return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
		}

		break;
	}

	case suites_int_l_c: {
		if (0 ==
		    cbor_dec_msg_1.message_1_SUITES_I.suites_int_l_int_count) {
			EDHOC_LOG_ERR("Empty peer cipher suite list");
			ctx->error_code =
				EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
			return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
		}

		if (ARRAY_SIZE(ctx->negotiation.peer_cipher_suite.entry) <
		    cbor_dec_msg_1.message_1_SUITES_I.suites_int_l_int_count) {
			EDHOC_LOG_ERR(
				"Buffer too small for peer cipher suites: %zu, %zu",
				cbor_dec_msg_1.message_1_SUITES_I
					.suites_int_l_int_count,
				ARRAY_SIZE(ctx->negotiation.peer_cipher_suite
						   .entry));
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		ctx->negotiation.peer_cipher_suite.count =
			cbor_dec_msg_1.message_1_SUITES_I.suites_int_l_int_count;
		for (size_t i = 0; i < ctx->negotiation.peer_cipher_suite.count;
		     ++i)
			ctx->negotiation.peer_cipher_suite.entry[i].value =
				cbor_dec_msg_1.message_1_SUITES_I
					.suites_int_l_int[i];

		if (csuite->value !=
		    cbor_dec_msg_1.message_1_SUITES_I
			    .suites_int_l_int[cbor_dec_msg_1.message_1_SUITES_I
						      .suites_int_l_int_count -
					      1]) {
			EDHOC_LOG_ERR(
				"Wrong cipher suite: %d, %d", csuite->value,
				cbor_dec_msg_1.message_1_SUITES_I.suites_int_l_int
					[cbor_dec_msg_1.message_1_SUITES_I
						 .suites_int_l_int_count -
					 1]);
			ctx->error_code =
				EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
			return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
		}

		break;
	}

	default:
		EDHOC_LOG_ERR("Invalid cipher suite: %d",
			      cbor_dec_msg_1.message_1_SUITES_I.suites_choice);
		return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
	}

	/* 3c. Verify ephemeral public key (peer G_X = encapsulation key). */
	if (cbor_dec_msg_1.message_1_G_X.len !=
	    csuite->kem_encapsulation_key_length) {
		EDHOC_LOG_ERR("Invalid G_X length: %zu, %zu",
			      csuite->kem_encapsulation_key_length,
			      cbor_dec_msg_1.message_1_G_X.len);
		return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
	}

	ctx->ephemeral.peer.length = cbor_dec_msg_1.message_1_G_X.len;
	memcpy(ctx->ephemeral.peer.value, cbor_dec_msg_1.message_1_G_X.value,
	       csuite->kem_encapsulation_key_length);

	/* 3d. Verify connection identifier. */
	switch (cbor_dec_msg_1.message_1_C_I_choice) {
	case message_1_C_I_int_c: {
		if (ONE_BYTE_CBOR_INT_MIN_VALUE >
			    cbor_dec_msg_1.message_1_C_I_int ||
		    ONE_BYTE_CBOR_INT_MAX_VALUE <
			    cbor_dec_msg_1.message_1_C_I_int) {
			EDHOC_LOG_ERR("C_I integer out of range: %d",
				      cbor_dec_msg_1.message_1_C_I_int);
			return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
		}

		ctx->negotiation.peer_connection_id.encode_type =
			EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
		ctx->negotiation.peer_connection_id.int_value =
			(int8_t)cbor_dec_msg_1.message_1_C_I_int;
		break;
	}

	case message_1_C_I_bstr_c: {
		if (ARRAY_SIZE(ctx->negotiation.peer_connection_id.bstr_value) <
		    cbor_dec_msg_1.message_1_C_I_bstr.len) {
			EDHOC_LOG_ERR(
				"C_I byte string too large: %zu, %zu",
				cbor_dec_msg_1.message_1_C_I_bstr.len,
				ARRAY_SIZE(ctx->negotiation.peer_connection_id
						   .bstr_value));
			return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
		}

		ctx->negotiation.peer_connection_id.encode_type =
			EDHOC_CONNECTION_ID_TYPE_BYTE_STRING;
		ctx->negotiation.peer_connection_id.bstr_length =
			cbor_dec_msg_1.message_1_C_I_bstr.len;
		memcpy(ctx->negotiation.peer_connection_id.bstr_value,
		       cbor_dec_msg_1.message_1_C_I_bstr.value,
		       cbor_dec_msg_1.message_1_C_I_bstr.len);
		break;
	}

	default:
		EDHOC_LOG_ERR("Invalid C_I choice: %d",
			      cbor_dec_msg_1.message_1_C_I_choice);
		return EDHOC_ERROR_MSG_1_PROCESS_FAILURE;
	}

	switch (ctx->negotiation.peer_connection_id.encode_type) {
	case EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER:
		EDHOC_LOG_HEXDUMP_DBG(
			(const uint8_t *)&ctx->negotiation.peer_connection_id
				.int_value,
			sizeof(ctx->negotiation.peer_connection_id.int_value),
			"C_I");
		break;
	case EDHOC_CONNECTION_ID_TYPE_BYTE_STRING:
		EDHOC_LOG_HEXDUMP_DBG(
			ctx->negotiation.peer_connection_id.bstr_value,
			ctx->negotiation.peer_connection_id.bstr_length, "C_I");
		break;

	default:
		EDHOC_LOG_ERR("Invalid peer CID encoding type: %d",
			      ctx->negotiation.peer_connection_id.encode_type);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	/* 4. Process EAD if present. */
	if (true == cbor_dec_msg_1.message_1_EAD_1_m_present &&
	    NULL != ctx->interfaces.ead.process) {
		if (ARRAY_SIZE(ctx->ead.token) - 1 <
		    cbor_dec_msg_1.message_1_EAD_1_m.EAD_1_count) {
			EDHOC_LOG_ERR(
				"EAD buffer too small: %zu, %zu",
				cbor_dec_msg_1.message_1_EAD_1_m.EAD_1_count,
				ARRAY_SIZE(ctx->ead.token) - 1);
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		ctx->ead.count = cbor_dec_msg_1.message_1_EAD_1_m.EAD_1_count;
		for (size_t i = 0; i < ctx->ead.count; ++i) {
			ctx->ead.token[i].label =
				cbor_dec_msg_1.message_1_EAD_1_m.EAD_1[i]
					.ead_x_ead_label;
			ctx->ead.token[i].value =
				cbor_dec_msg_1.message_1_EAD_1_m.EAD_1[i]
					.ead_x_ead_value.value;
			ctx->ead.token[i].value_length =
				cbor_dec_msg_1.message_1_EAD_1_m.EAD_1[i]
					.ead_x_ead_value.len;
		}

		ret = ctx->interfaces.ead.process(ctx->user_context,
						  ctx->state.message,
						  ctx->ead.token,
						  ctx->ead.count);

		for (size_t i = 0; i < ctx->ead.count; ++i) {
			EDHOC_LOG_HEXDUMP_DBG(
				(const uint8_t *)&ctx->ead.token[i].label,
				sizeof(ctx->ead.token[i].label),
				"EAD_1 process token label");

			if (0 != ctx->ead.token[i].value_length) {
				EDHOC_LOG_HEXDUMP_DBG(
					ctx->ead.token[i].value,
					ctx->ead.token[i].value_length,
					"EAD_1 process token value");
			}
		}

		edhoc_ead_reset(ctx);

		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("EAD process: %d", ret);
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;
		}
	}

	/* 5. Compute H(cbor(msg_1)) and cache it. */
	ctx->state.th.length = csuite->hash_length;
	size_t hash_len = 0;
	const struct hash_segment segments[] = { { msg_1, msg_1_len } };
	ret = edhoc_comp_hash(ctx, segments, ARRAY_SIZE(segments),
			      ctx->state.th.value, ctx->state.th.length,
			      &hash_len);

	if (EDHOC_SUCCESS != ret || csuite->hash_length != hash_len) {
		EDHOC_LOG_ERR("Hash: %d, %zu, %zu", ret, csuite->hash_length,
			      hash_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	EDHOC_LOG_INF("Process msg1 end");

	ctx->state.th.stage = EDHOC_TH_STATE_1;
	ctx->state.machine = EDHOC_SM_RECEIVED_M1;
	ctx->error_code = EDHOC_ERROR_CODE_SUCCESS;
	return EDHOC_SUCCESS;
}
