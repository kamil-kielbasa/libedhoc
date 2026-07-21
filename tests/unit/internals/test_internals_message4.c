/**
 * \file    test_internals_message4.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for edhoc_message_4.c internal functions.
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

TEST_GROUP(internals_message4);

TEST_SETUP(internals_message4)
{
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, psa_crypto_init());
	internals_crypto = edhoc_cipher_suite_0_get_crypto();
}

TEST_TEAR_DOWN(internals_message4)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_message4, comp_th_4_null)
{
	int ret = comp_th_4(NULL, NULL, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message4, comp_th_4_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_1;

	uint8_t buf[512] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	mc->th_len = 32;

	uint8_t ptxt[32] = { 0 };
	int ret = comp_th_4(&ctx, mc, ptxt, sizeof(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message4, comp_giy_null)
{
	struct edhoc_auth_creds ac = { 0 };
	int ret = comp_giy(NULL, &ac, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message4, comp_giy_invalid_role)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = 99;
	ctx.negotiation.selected_method = EDHOC_METHOD_2;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.state.th.stage = EDHOC_TH_STATE_3;

	struct edhoc_auth_creds ac = { 0 };
	int ret = comp_giy(&ctx, &ac, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message4, compute_plaintext_4_len_null)
{
	size_t len;
	int ret = compute_plaintext_4_len(NULL, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message4, compute_key_iv_aad_4_null)
{
	uint8_t key[16], iv[13], aad[256];
	int ret = compute_key_iv_aad_4(NULL, key, 16, iv, 13, aad, 256);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message4, compute_key_iv_aad_4_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_1;
	ctx.state.prk_state = EDHOC_PRK_STATE_INVALID;

	uint8_t key[16], iv[13], aad[256];
	int ret = compute_key_iv_aad_4(&ctx, key, 16, iv, 13, aad, 256);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message4, prepare_plaintext_4_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	uint8_t ptxt[64];
	size_t ptxt_len;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  prepare_plaintext_4(NULL, ptxt, 64, &ptxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  prepare_plaintext_4(&ctx, NULL, 64, &ptxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  prepare_plaintext_4(&ctx, ptxt, 64, NULL));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message4, gen_msg_4_null)
{
	uint8_t ctxt[] = { 0x40 };
	uint8_t msg[64];
	size_t msg_len;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  gen_msg_4(NULL, 1, msg, 64, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  gen_msg_4(ctxt, 0, msg, 64, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  gen_msg_4(ctxt, 1, NULL, 64, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  gen_msg_4(ctxt, 1, msg, 0, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  gen_msg_4(ctxt, 1, msg, 64, NULL));
}

TEST(internals_message4, parse_msg_4_null)
{
	uint8_t msg[] = { 0x40 };
	const uint8_t *ctxt;
	size_t ctxt_len;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_msg_4(NULL, 1, &ctxt, &ctxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_msg_4(msg, 0, &ctxt, &ctxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_msg_4(msg, 1, NULL, &ctxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_msg_4(msg, 1, &ctxt, NULL));
}

TEST(internals_message4, parse_plaintext_4_null)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	uint8_t ptxt[] = { 0x40 };

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_plaintext_4(NULL, ptxt, 1));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  parse_plaintext_4(&ctx, NULL, 1));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message4, parse_plaintext_4_empty)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	uint8_t empty[] = { 0x00 };

	int ret = parse_plaintext_4(&ctx, empty, 0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message4, compute_plaintext_4_len_large_ead_label)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	struct edhoc_ead_token tok = { .label = 70000,
				       .value = NULL,
				       .value_len = 0 };
	ctx.ead.count = 1;
	ctx.ead.token[0] = tok;

	size_t len = 0;
	int ret = compute_plaintext_4_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(len > 0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message4, compute_plaintext_4_len_large_ead_value)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	struct edhoc_ead_token tok = { .label = 1,
				       .value = NULL,
				       .value_len = 60000 };
	ctx.ead.count = 1;
	ctx.ead.token[0] = tok;

	size_t len = 0;
	int ret = compute_plaintext_4_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(len > 60000);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_message4, compute_plaintext_4_len_very_large_ead_value)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	struct edhoc_ead_token tok = { .label = 1,
				       .value = NULL,
				       .value_len = 70000 };
	ctx.ead.count = 1;
	ctx.ead.token[0] = tok;

	size_t len = 0;
	int ret = compute_plaintext_4_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(len > 70000);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST_GROUP_RUNNER(internals_message4)
{
	RUN_TEST_CASE(internals_message4, comp_th_4_null);
	RUN_TEST_CASE(internals_message4, comp_th_4_bad_state);
	RUN_TEST_CASE(internals_message4, comp_giy_null);
	RUN_TEST_CASE(internals_message4, comp_giy_invalid_role);
	RUN_TEST_CASE(internals_message4, compute_plaintext_4_len_null);
	RUN_TEST_CASE(internals_message4, compute_key_iv_aad_4_null);
	RUN_TEST_CASE(internals_message4, compute_key_iv_aad_4_bad_state);
	RUN_TEST_CASE(internals_message4, prepare_plaintext_4_null);
	RUN_TEST_CASE(internals_message4, gen_msg_4_null);
	RUN_TEST_CASE(internals_message4, parse_msg_4_null);
	RUN_TEST_CASE(internals_message4, parse_plaintext_4_null);
	RUN_TEST_CASE(internals_message4, parse_plaintext_4_empty);
	RUN_TEST_CASE(internals_message4,
		      compute_plaintext_4_len_large_ead_label);
	RUN_TEST_CASE(internals_message4,
		      compute_plaintext_4_len_large_ead_value);
	RUN_TEST_CASE(internals_message4,
		      compute_plaintext_4_len_very_large_ead_value);
}
