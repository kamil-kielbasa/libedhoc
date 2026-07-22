/**
 * \file    test_internals_message2.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for edhoc_message_2.c internal functions.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#include "internals_common.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(internals_message2);

TEST_SETUP(internals_message2)
{
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, psa_crypto_init());
	internals_crypto = edhoc_cipher_suite_0_get_crypto();
}

TEST_TEAR_DOWN(internals_message2)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_message2, comp_th_2_null)
{
	int ret = comp_th_2(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message2, comp_th_2_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.th.stage = EDHOC_TH_STATE_2;

	int ret = comp_th_2(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message2, comp_encapsulate_null)
{
	int ret = comp_encapsulate(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message2, comp_decapsulate_null)
{
	int ret = comp_decapsulate(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message2, comp_keystream_null)
{
	uint8_t ks[64];
	int ret = comp_keystream(NULL, ks, sizeof(ks));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message2, comp_keystream_bad_th_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_1;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;

	uint8_t ks[64];
	int ret = comp_keystream(&ctx, ks, sizeof(ks));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message2, comp_grx_null)
{
	struct edhoc_auth_credentials ac = { 0 };
	int ret = comp_grx(NULL, &ac, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message2, comp_grx_invalid_role)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = 99;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;
	ctx.state.th.stage = EDHOC_TH_STATE_2;

	struct edhoc_auth_credentials ac = { 0 };
	int ret = comp_grx(&ctx, &ac, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message2, comp_plaintext_2_len_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	uint8_t buf[256] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_plaintext_2_len(NULL, mc, 8, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_plaintext_2_len(&ctx, NULL, 8, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_plaintext_2_len(&ctx, mc, 0, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_plaintext_2_len(&ctx, mc, 8, NULL));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message2, prepare_message_2_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	uint8_t ctxt[64] = { 0 };
	uint8_t msg[128];
	size_t msg_len;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  prepare_message_2(NULL, ctxt, 64, msg, 128,
					    &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  prepare_message_2(&ctx, NULL, 64, msg, 128,
					    &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  prepare_message_2(&ctx, ctxt, 0, msg, 128, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  prepare_message_2(&ctx, ctxt, 64, NULL, 128,
					    &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  prepare_message_2(&ctx, ctxt, 64, msg, 0, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  prepare_message_2(&ctx, ctxt, 64, msg, 128, NULL));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message2, parse_plaintext_2_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	uint8_t ptxt[] = { 0x40 };
	struct plaintext parsed = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_plaintext_2(NULL, ptxt, 1, &parsed));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_plaintext_2(&ctx, NULL, 1, &parsed));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_plaintext_2(&ctx, ptxt, 0, &parsed));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_plaintext_2(&ctx, ptxt, 1, NULL));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message2, parse_plaintext_2_garbage)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	uint8_t garbage[] = { 0xFF, 0xFE, 0xFD };
	struct plaintext parsed = { 0 };

	int ret = parse_plaintext_2(&ctx, garbage, sizeof(garbage), &parsed);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message2, parse_msg_2_garbage)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	uint8_t garbage[] = { 0x18 };
	uint8_t ctxt[64];

	int ret =
		parse_msg_2(&ctx, garbage, sizeof(garbage), ctxt, sizeof(ctxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message2, prepare_plaintext_2_invalid_cid)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.negotiation.connection_id.encode_type = 99;

	uint8_t buf[256] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	mc->id_cred_is_comp_enc = true;
	mc->id_cred_enc_type = EDHOC_ENCODE_TYPE_INTEGER;
	mc->id_cred_int = 5;

	uint8_t sign[8] = { 0 };
	uint8_t ptxt[256];
	size_t ptxt_len;

	int ret = prepare_plaintext_2(&ctx, mc, sign, 8, ptxt, sizeof(ptxt),
				      &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message2, prepare_plaintext_2_invalid_id_cred)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	uint8_t buf[256] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	mc->id_cred_is_comp_enc = true;
	mc->id_cred_enc_type = 99;

	uint8_t sign[8] = { 0 };
	uint8_t ptxt[256];
	size_t ptxt_len;

	int ret = prepare_plaintext_2(&ctx, mc, sign, 8, ptxt, sizeof(ptxt),
				      &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST_GROUP_RUNNER(internals_message2)
{
	RUN_TEST_CASE(internals_message2, comp_th_2_null);
	RUN_TEST_CASE(internals_message2, comp_th_2_bad_state);
	RUN_TEST_CASE(internals_message2, comp_encapsulate_null);
	RUN_TEST_CASE(internals_message2, comp_decapsulate_null);
	RUN_TEST_CASE(internals_message2, comp_keystream_null);
	RUN_TEST_CASE(internals_message2, comp_keystream_bad_th_state);
	RUN_TEST_CASE(internals_message2, comp_grx_null);
	RUN_TEST_CASE(internals_message2, comp_grx_invalid_role);
	RUN_TEST_CASE(internals_message2, comp_plaintext_2_len_null);
	RUN_TEST_CASE(internals_message2, prepare_message_2_null);
	RUN_TEST_CASE(internals_message2, parse_plaintext_2_null);
	RUN_TEST_CASE(internals_message2, parse_plaintext_2_garbage);
	RUN_TEST_CASE(internals_message2, parse_msg_2_garbage);
	RUN_TEST_CASE(internals_message2, prepare_plaintext_2_invalid_cid);
	RUN_TEST_CASE(internals_message2, prepare_plaintext_2_invalid_id_cred);
}
