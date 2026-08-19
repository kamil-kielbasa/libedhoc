/**
 * \file    test_internals_message4.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for edhoc_classic_message_4.c internal functions.
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

TEST(internals_message4, comp_giy_null)
{
	int ret = edhoc_key_schedule_prk_advance(NULL, NULL, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message4, comp_giy_invalid_role)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = 99;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_2;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.state.th.stage = EDHOC_TH_STATE_3;

	const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	int ret = edhoc_key_schedule_prk_advance(&ctx, key_id, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

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

	const struct edhoc_plaintext_input input = {
		.id = EDHOC_PLAINTEXT_CLASSIC_4,
	};

	int ret = edhoc_plaintext_compose(NULL, &input, ptxt, ARRAY_SIZE(ptxt),
					  &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_compose(&ctx, &input, NULL, ARRAY_SIZE(ptxt),
				      &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_compose(&ctx, &input, ptxt, ARRAY_SIZE(ptxt),
				      NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message4, parse_plaintext_4_null)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);

	const uint8_t ptxt[] = { 0x40 };
	int ret = edhoc_plaintext_parse(NULL, EDHOC_PLAINTEXT_CLASSIC_4, ptxt,
					ARRAY_SIZE(ptxt), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_CLASSIC_4, NULL,
				    ARRAY_SIZE(ptxt), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message4, parse_plaintext_4_empty)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);

	const uint8_t empty[] = { 0x00 };
	int ret = edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_CLASSIC_4, empty,
					0, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message4, compose_ciphertext_4_null)
{
	uint8_t ctxt[16] = { 0 };
	uint8_t msg[32] = { 0 };
	size_t msg_len = 0;

	int ret = compose_ciphertext_4(NULL, ARRAY_SIZE(ctxt), msg,
				       ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = compose_ciphertext_4(ctxt, 0, msg, ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = compose_ciphertext_4(ctxt, ARRAY_SIZE(ctxt), NULL,
				   ARRAY_SIZE(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = compose_ciphertext_4(ctxt, ARRAY_SIZE(ctxt), msg, 0, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = compose_ciphertext_4(ctxt, ARRAY_SIZE(ctxt), msg, ARRAY_SIZE(msg),
				   NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_message4, parse_ciphertext_4_null)
{
	uint8_t msg[32] = { 0 };
	const uint8_t *ctxt = NULL;
	size_t ctxt_len = 0;

	int ret = parse_ciphertext_4(NULL, ARRAY_SIZE(msg), &ctxt, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_ciphertext_4(msg, 0, &ctxt, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_ciphertext_4(msg, ARRAY_SIZE(msg), NULL, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = parse_ciphertext_4(msg, ARRAY_SIZE(msg), &ctxt, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST_GROUP_RUNNER(internals_message4)
{
	RUN_TEST_CASE(internals_message4, compose_ciphertext_4_null);
	RUN_TEST_CASE(internals_message4, parse_ciphertext_4_null);
	/* comp_th_4 */

	/* comp_giy */
	RUN_TEST_CASE(internals_message4, comp_giy_null);
	RUN_TEST_CASE(internals_message4, comp_giy_invalid_role);

	/* compute_key_iv_aad_4 */
	RUN_TEST_CASE(internals_message4, compute_key_iv_aad_4_null);
	RUN_TEST_CASE(internals_message4, compute_key_iv_aad_4_bad_state);

	/* prepare_plaintext_4 */
	RUN_TEST_CASE(internals_message4, prepare_plaintext_4_null);

	/* parse_plaintext_4 */
	RUN_TEST_CASE(internals_message4, parse_plaintext_4_null);
	RUN_TEST_CASE(internals_message4, parse_plaintext_4_empty);
}
