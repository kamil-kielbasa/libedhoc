/**
 * \file    test_internals_message2.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for edhoc_classic_message_2.c internal functions.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Internal headers: */
#include "internals_common.h"
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(internals_message2);

TEST_SETUP(internals_message2)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(internals_message2)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_message2, comp_encapsulate_null)
{
	int ret = edhoc_key_schedule_encapsulate(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message2, comp_decapsulate_null)
{
	int ret = edhoc_key_schedule_decapsulate(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message2, comp_keystream_null)
{
	uint8_t ks[64] = { 0 };
	int ret = edhoc_cipher_keystream(NULL, ks, ARRAY_SIZE(ks));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message2, comp_keystream_bad_th_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.th.stage = EDHOC_TH_STATE_1;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;

	uint8_t ks[64] = { 0 };
	int ret = edhoc_cipher_keystream(&ctx, ks, ARRAY_SIZE(ks));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, comp_grx_null)
{
	int ret = edhoc_key_schedule_prk_advance(NULL, NULL, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message2, comp_grx_invalid_role)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.role = 99;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;
	ctx.state.th.stage = EDHOC_TH_STATE_2;

	const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	int ret = edhoc_key_schedule_prk_advance(&ctx, key_id, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, comp_plaintext_2_len_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	uint8_t buf[256] = { 0 };
	struct mac_context mc_storage = {
		.buf = buf,
		.buf_len = sizeof(buf),
	};
	struct mac_context *mc = &mc_storage;

	struct edhoc_plaintext_input input = {
		.id = EDHOC_PLAINTEXT_CLASSIC_2,
		.mac_context = mc,
		.signature_length = 8,
	};
	size_t len = 0;

	int ret = edhoc_plaintext_length(NULL, &input, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_length(&ctx, NULL, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_length(&ctx, &input, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	input.mac_context = NULL;
	ret = edhoc_plaintext_length(&ctx, &input, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	input.mac_context = mc;
	input.signature_length = 0;
	ret = edhoc_plaintext_length(&ctx, &input, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, compose_g_y_ciphertext_2_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	uint8_t ctxt[64] = { 0 };
	uint8_t msg[128] = { 0 };
	size_t msg_len = 0;

	int ret = compose_g_y_ciphertext_2(NULL, ctxt, ARRAY_SIZE(ctxt), msg,
					   ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = compose_g_y_ciphertext_2(&ctx, NULL, ARRAY_SIZE(ctxt), msg,
				       ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = compose_g_y_ciphertext_2(&ctx, ctxt, 0, msg, ARRAY_SIZE(msg),
				       &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = compose_g_y_ciphertext_2(&ctx, ctxt, ARRAY_SIZE(ctxt), NULL,
				       ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = compose_g_y_ciphertext_2(&ctx, ctxt, ARRAY_SIZE(ctxt), msg, 0,
				       &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = compose_g_y_ciphertext_2(&ctx, ctxt, ARRAY_SIZE(ctxt), msg,
				       ARRAY_SIZE(msg), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, parse_plaintext_2_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.message = EDHOC_MESSAGE_2;

	uint8_t ptxt[] = { 0x40 };
	struct plaintext parsed = { 0 };

	int ret = edhoc_plaintext_parse(NULL, EDHOC_PLAINTEXT_CLASSIC_2, ptxt,
					ARRAY_SIZE(ptxt), &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_CLASSIC_2, NULL,
				    ARRAY_SIZE(ptxt), &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_CLASSIC_2, ptxt, 0,
				    &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_CLASSIC_2, ptxt,
				    ARRAY_SIZE(ptxt), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, parse_plaintext_2_garbage)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.message = EDHOC_MESSAGE_2;

	const uint8_t garbage[] = { 0xFF, 0xFE, 0xFD };
	struct plaintext parsed = { 0 };

	int ret = edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_CLASSIC_2,
					garbage, ARRAY_SIZE(garbage), &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, parse_g_y_ciphertext_2_garbage)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	const uint8_t garbage[] = { 0x18 };
	const uint8_t *ctxt = NULL;
	size_t ctxt_len = 0;

	int ret = parse_g_y_ciphertext_2(&ctx, garbage, ARRAY_SIZE(garbage),
					 &ctxt, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, psk_g_y_ciphertext_2a_round_trip)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	internals_make_ecdh_peer_pub(ctx.ephemeral.own.value,
				     ARRAY_SIZE(ctx.ephemeral.own.value),
				     &ctx.ephemeral.own.length);

	const uint8_t ctxt[8] = {
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7
	};
	uint8_t msg[128] = { 0 };
	size_t msg_len = 0;

	int ret = compose_g_y_ciphertext_2a(&ctx, ctxt, ARRAY_SIZE(ctxt), msg,
					    ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t *parsed = NULL;
	size_t parsed_len = 0;

	ret = parse_g_y_ciphertext_2a(&ctx, msg, msg_len, &parsed, &parsed_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_size_t(ARRAY_SIZE(ctxt), parsed_len);
	TEST_ASSERT_EQUAL_HEX8_ARRAY(ctxt, parsed, parsed_len);
	TEST_ASSERT_EQUAL_HEX8_ARRAY(ctx.ephemeral.own.value,
				     ctx.ephemeral.peer.value,
				     ctx.ephemeral.own.length);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, psk_g_y_ciphertext_2a_compose_tiny_buffer)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.ephemeral.own.length = 32;

	const uint8_t ctxt[8] = { 0 };
	uint8_t msg[4] = { 0 };
	size_t msg_len = 0;

	int ret = compose_g_y_ciphertext_2a(&ctx, ctxt, ARRAY_SIZE(ctxt), msg,
					    ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, psk_g_y_ciphertext_2a_parse_rejects)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	const uint8_t garbage[] = { 0x18 };
	const uint8_t *ctxt = NULL;
	size_t ctxt_len = 0;

	int ret = parse_g_y_ciphertext_2a(&ctx, garbage, ARRAY_SIZE(garbage),
					  &ctxt, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	/* A well formed byte string that leaves no room for CIPHERTEXT_2A. */
	const uint8_t short_msg[34] = { 0x58, 0x20 };

	ret = parse_g_y_ciphertext_2a(&ctx, short_msg, ARRAY_SIZE(short_msg),
				      &ctxt, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_MSG_2_PROCESS_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message2, psk_plaintext_2a_int_connection_id)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	/* RFC 9528: 3.3.2 - a one byte identifier travels as a CBOR integer. */
	ctx.negotiation.connection_id.value[0] = 0x05;
	ctx.negotiation.connection_id.length = 1;

	const struct edhoc_plaintext_input input = {
		.id = EDHOC_PLAINTEXT_PSK_2A,
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_plaintext_length(&ctx, &input, &len));
	TEST_ASSERT_EQUAL_size_t(1, len);

	uint8_t ptxt[16] = { 0 };
	size_t ptxt_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_plaintext_compose(&ctx, &input, ptxt,
						  ARRAY_SIZE(ptxt), &ptxt_len));
	TEST_ASSERT_EQUAL_size_t(1, ptxt_len);
	TEST_ASSERT_EQUAL_HEX8(0x05, ptxt[0]);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_PSK_2A,
						ptxt, ptxt_len, NULL));
	TEST_ASSERT_EQUAL_size_t(1, ctx.negotiation.peer_connection_id.length);
	TEST_ASSERT_EQUAL_HEX8(0x05,
			       ctx.negotiation.peer_connection_id.value[0]);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message2, psk_plaintext_2a_bstr_connection_id)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	static const uint8_t cid[] = { 0x01, 0x02, 0x03 };

	memcpy(ctx.negotiation.connection_id.value, cid, ARRAY_SIZE(cid));
	ctx.negotiation.connection_id.length = ARRAY_SIZE(cid);

	const struct edhoc_plaintext_input input = {
		.id = EDHOC_PLAINTEXT_PSK_2A,
	};

	uint8_t ptxt[16] = { 0 };
	size_t ptxt_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_plaintext_compose(&ctx, &input, ptxt,
						  ARRAY_SIZE(ptxt), &ptxt_len));
	TEST_ASSERT_EQUAL_HEX8(0x43, ptxt[0]);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_PSK_2A,
						ptxt, ptxt_len, NULL));
	TEST_ASSERT_EQUAL_size_t(ARRAY_SIZE(cid),
				 ctx.negotiation.peer_connection_id.length);
	TEST_ASSERT_EQUAL_HEX8_ARRAY(
		cid, ctx.negotiation.peer_connection_id.value, ARRAY_SIZE(cid));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message2, psk_plaintext_2a_compose_tiny_buffer)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.negotiation.connection_id.value[0] = 0x05;
	ctx.negotiation.connection_id.length = 1;

	const struct edhoc_plaintext_input input = {
		.id = EDHOC_PLAINTEXT_PSK_2A,
	};

	uint8_t ptxt[1] = { 0 };
	size_t ptxt_len = 0;

	/* One byte holds the identifier but nothing that follows it. */
	ctx.negotiation.connection_id.value[0] = 0x40;
	ctx.negotiation.connection_id.length = 1;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE,
			  edhoc_plaintext_compose(&ctx, &input, ptxt, 0 + 1,
						  &ptxt_len));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message2, psk_plaintext_2a_parse_rejects)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	static const uint8_t garbage[] = { 0xff, 0xff };

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE,
			  edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_PSK_2A,
						garbage, ARRAY_SIZE(garbage),
						NULL));

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_PSK_2A,
						garbage, 0, NULL));

	/* A byte string longer than the connection identifier capacity. */
	static const uint8_t too_long[] = { 0x58, 0x21, 0x00, 0x00 };

	TEST_ASSERT_NOT_EQUAL(
		EDHOC_SUCCESS,
		edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_PSK_2A, too_long,
				      ARRAY_SIZE(too_long), NULL));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST_GROUP_RUNNER(internals_message2)
{
	RUN_TEST_CASE(internals_message2, comp_encapsulate_null);
	RUN_TEST_CASE(internals_message2, comp_decapsulate_null);
	RUN_TEST_CASE(internals_message2, comp_keystream_null);
	RUN_TEST_CASE(internals_message2, comp_keystream_bad_th_state);
	RUN_TEST_CASE(internals_message2, comp_grx_null);
	RUN_TEST_CASE(internals_message2, comp_grx_invalid_role);
	RUN_TEST_CASE(internals_message2, comp_plaintext_2_len_null);
	RUN_TEST_CASE(internals_message2, compose_g_y_ciphertext_2_null);
	RUN_TEST_CASE(internals_message2, parse_plaintext_2_null);
	RUN_TEST_CASE(internals_message2, parse_plaintext_2_garbage);
	RUN_TEST_CASE(internals_message2, parse_g_y_ciphertext_2_garbage);
	RUN_TEST_CASE(internals_message2, psk_g_y_ciphertext_2a_round_trip);
	RUN_TEST_CASE(internals_message2,
		      psk_g_y_ciphertext_2a_compose_tiny_buffer);
	RUN_TEST_CASE(internals_message2, psk_g_y_ciphertext_2a_parse_rejects);
	RUN_TEST_CASE(internals_message2, psk_plaintext_2a_int_connection_id);
	RUN_TEST_CASE(internals_message2, psk_plaintext_2a_bstr_connection_id);
	RUN_TEST_CASE(internals_message2, psk_plaintext_2a_compose_tiny_buffer);
	RUN_TEST_CASE(internals_message2, psk_plaintext_2a_parse_rejects);
}
