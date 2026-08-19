/**
 * \file    test_internals_th.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for edhoc_transcript_hash_internal.c.
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

TEST_GROUP(internals_th);

TEST_SETUP(internals_th)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(internals_th)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_th, compute_null)
{
	const struct edhoc_th_input input = {
		.target = EDHOC_TH_STATE_2,
	};

	int ret = edhoc_th_compute(NULL, &input);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	struct edhoc_context ctx = { 0 };
	ret = edhoc_th_compute(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_th, compute_th_2_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.th.stage = EDHOC_TH_STATE_2;

	const struct edhoc_th_input input = {
		.target = EDHOC_TH_STATE_2,
	};

	int ret = edhoc_th_compute(&ctx, &input);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_th, compute_th_3_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.th.stage = EDHOC_TH_STATE_1;

	uint8_t cred[32] = { 0 };
	uint8_t ptxt[32] = { 0 };

	const struct edhoc_th_input input = {
		.target = EDHOC_TH_STATE_3,
		.plaintext = ptxt,
		.plaintext_length = ARRAY_SIZE(ptxt),
		.credential = cred,
		.credential_length = ARRAY_SIZE(cred),
	};

	int ret = edhoc_th_compute(&ctx, &input);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_th, compute_th_4_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.th.stage = EDHOC_TH_STATE_1;

	uint8_t cred[32] = { 0 };
	uint8_t ptxt[32] = { 0 };

	const struct edhoc_th_input input = {
		.target = EDHOC_TH_STATE_4,
		.plaintext = ptxt,
		.plaintext_length = ARRAY_SIZE(ptxt),
		.credential = cred,
		.credential_length = ARRAY_SIZE(cred),
	};

	int ret = edhoc_th_compute(&ctx, &input);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(internals_th)
{
	RUN_TEST_CASE(internals_th, compute_null);
	RUN_TEST_CASE(internals_th, compute_th_2_bad_state);
	RUN_TEST_CASE(internals_th, compute_th_3_bad_state);
	RUN_TEST_CASE(internals_th, compute_th_4_bad_state);
}
