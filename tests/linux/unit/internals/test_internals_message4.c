/**
 * \file    test_internals_message4.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for edhoc_message_4.c internal functions.
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

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(internals_message4);

TEST_SETUP(internals_message4)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
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
	int ret = comp_th_4(&ctx, mc, ptxt, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message4, comp_giy_null)
{
	int ret = comp_giy(NULL, NULL, NULL, 0);
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

	const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	int ret = comp_giy(&ctx, key_id, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message4, compute_plaintext_4_len_null)
{
	size_t len = 0;

	int ret = compute_plaintext_4_len(NULL, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message4, compute_plaintext_4_len_large_ead_label)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);

	const struct edhoc_ead_token tok = {
		.label = 70000,
		.value = { .value = NULL, .length = 0 },
	};
	ctx.ead.count = 1;
	ctx.ead.token[0] = tok;

	size_t len = 0;
	int ret = compute_plaintext_4_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message4, compute_plaintext_4_len_large_ead_value)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);

	const struct edhoc_ead_token tok = {
		.label = 1,
		.value = { .value = NULL, .length = 60000 },
	};
	ctx.ead.count = 1;
	ctx.ead.token[0] = tok;

	size_t len = 0;
	int ret = compute_plaintext_4_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(60000, len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message4, compute_plaintext_4_len_very_large_ead_value)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);

	const struct edhoc_ead_token tok = {
		.label = 1,
		.value = { .value = NULL, .length = 70000 },
	};
	ctx.ead.count = 1;
	ctx.ead.token[0] = tok;

	size_t len = 0;
	int ret = compute_plaintext_4_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(70000, len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message4, compute_key_iv_aad_4_null)
{
	uint8_t iv[13] = { 0 };
	uint8_t aad[256] = { 0 };

	int ret = edhoc_cipher_derive(NULL, iv, ARRAY_SIZE(iv), aad,
				      ARRAY_SIZE(aad));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message4, compute_key_iv_aad_4_bad_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_1;
	ctx.state.prk_state = EDHOC_PRK_STATE_INVALID;

	uint8_t iv[13] = { 0 };
	uint8_t aad[256] = { 0 };

	int ret = edhoc_cipher_derive(&ctx, iv, ARRAY_SIZE(iv), aad,
				      ARRAY_SIZE(aad));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message4, prepare_plaintext_4_null)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);

	uint8_t ptxt[64] = { 0 };
	size_t ptxt_len = 0;

	int ret = prepare_plaintext_4(NULL, ptxt, ARRAY_SIZE(ptxt), &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = prepare_plaintext_4(&ctx, NULL, ARRAY_SIZE(ptxt), &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = prepare_plaintext_4(&ctx, ptxt, ARRAY_SIZE(ptxt), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message4, gen_msg_4_null)
{
	const uint8_t ctxt[] = { 0x40 };
	uint8_t msg[64] = { 0 };
	size_t msg_len = 0;

	int ret = gen_msg_4(NULL, ARRAY_SIZE(ctxt), msg, ARRAY_SIZE(msg),
			    &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = gen_msg_4(ctxt, 0, msg, ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = gen_msg_4(ctxt, ARRAY_SIZE(ctxt), NULL, ARRAY_SIZE(msg),
			&msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = gen_msg_4(ctxt, ARRAY_SIZE(ctxt), msg, 0, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = gen_msg_4(ctxt, ARRAY_SIZE(ctxt), msg, ARRAY_SIZE(msg), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message4, parse_msg_4_null)
{
	const uint8_t msg[] = { 0x40 };
	const uint8_t *ctxt = NULL;
	size_t ctxt_len = 0;

	int ret = parse_msg_4(NULL, ARRAY_SIZE(msg), &ctxt, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_msg_4(msg, 0, &ctxt, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_msg_4(msg, ARRAY_SIZE(msg), NULL, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_msg_4(msg, ARRAY_SIZE(msg), &ctxt, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message4, parse_plaintext_4_null)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);

	const uint8_t ptxt[] = { 0x40 };
	int ret = parse_plaintext_4(NULL, ptxt, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_plaintext_4(&ctx, NULL, ARRAY_SIZE(ptxt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message4, parse_plaintext_4_empty)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);

	const uint8_t empty[] = { 0x00 };
	int ret = parse_plaintext_4(&ctx, empty, 0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(internals_message4)
{
	/* comp_th_4 */
	RUN_TEST_CASE(internals_message4, comp_th_4_null);
	RUN_TEST_CASE(internals_message4, comp_th_4_bad_state);

	/* comp_giy */
	RUN_TEST_CASE(internals_message4, comp_giy_null);
	RUN_TEST_CASE(internals_message4, comp_giy_invalid_role);

	/* compute_plaintext_4_len */
	RUN_TEST_CASE(internals_message4, compute_plaintext_4_len_null);
	RUN_TEST_CASE(internals_message4,
		      compute_plaintext_4_len_large_ead_label);
	RUN_TEST_CASE(internals_message4,
		      compute_plaintext_4_len_large_ead_value);
	RUN_TEST_CASE(internals_message4,
		      compute_plaintext_4_len_very_large_ead_value);

	/* compute_key_iv_aad_4 */
	RUN_TEST_CASE(internals_message4, compute_key_iv_aad_4_null);
	RUN_TEST_CASE(internals_message4, compute_key_iv_aad_4_bad_state);

	/* prepare_plaintext_4 */
	RUN_TEST_CASE(internals_message4, prepare_plaintext_4_null);

	/* gen_msg_4 */
	RUN_TEST_CASE(internals_message4, gen_msg_4_null);

	/* parse_msg_4 */
	RUN_TEST_CASE(internals_message4, parse_msg_4_null);

	/* parse_plaintext_4 */
	RUN_TEST_CASE(internals_message4, parse_plaintext_4_null);
	RUN_TEST_CASE(internals_message4, parse_plaintext_4_empty);
}
