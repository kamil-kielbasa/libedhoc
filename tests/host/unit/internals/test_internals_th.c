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

TEST(internals_th, compute_th_1_invalid_arguments)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	const struct edhoc_th_input input = {
		.target = EDHOC_TH_STATE_1,
	};

	int ret = edhoc_th_compute(&ctx, &input);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_th, compute_th_2_invalid_role)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.th.stage = EDHOC_TH_STATE_1;
	ctx.state.role = (enum edhoc_role)9;

	const struct edhoc_th_input input = {
		.target = EDHOC_TH_STATE_2,
	};

	int ret = edhoc_th_compute(&ctx, &input);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_th, compute_th_3_invalid_arguments)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.th.stage = EDHOC_TH_STATE_2;

	uint8_t ptxt[8] = { 0 };
	struct edhoc_th_input input = {
		.target = EDHOC_TH_STATE_3,
	};

	int ret = edhoc_th_compute(&ctx, &input);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	/* RFC 9528: 5.3.2 - classic EDHOC appends CRED_R to TH_3. */
	input.plaintext = ptxt;
	input.plaintext_length = ARRAY_SIZE(ptxt);

	ret = edhoc_th_compute(&ctx, &input);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_th, compute_th_4_invalid_arguments)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.th.stage = EDHOC_TH_STATE_3;

	uint8_t cred[8] = { 0 };
	struct edhoc_th_input input = {
		.target = EDHOC_TH_STATE_4,
	};

	int ret = edhoc_th_compute(&ctx, &input);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	/* RFC 9528: 5.4.2 - classic EDHOC hashes PLAINTEXT_3. */
	input.credential = cred;
	input.credential_length = ARRAY_SIZE(cred);

	ret = edhoc_th_compute(&ctx, &input);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	/* draft-ietf-lake-edhoc-psk: 5.4.2 - method 4 hashes ID_CRED_PSK,
	 * CRED_I and CRED_R instead. */
	ctx.negotiation.selected_method = EDHOC_METHOD_4;

	ret = edhoc_th_compute(&ctx, &input);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_th, compute_th_4_psk)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.negotiation.selected_method = EDHOC_METHOD_4;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 32;

	static const uint8_t id_cred_psk[] = { 0x42, 0x00, 0x10 };
	static const uint8_t cred_i[] = { 0xa1, 0x02, 0x41, 0x49 };
	static const uint8_t cred_r[] = { 0xa1, 0x02, 0x41, 0x52 };
	static const uint8_t plaintext_3b[] = { 0xff };

	const struct edhoc_th_input input = {
		.target = EDHOC_TH_STATE_4,
		.id_cred = id_cred_psk,
		.id_cred_length = ARRAY_SIZE(id_cred_psk),
		.plaintext = plaintext_3b,
		.plaintext_length = ARRAY_SIZE(plaintext_3b),
		.credential = cred_i,
		.credential_length = ARRAY_SIZE(cred_i),
		.peer_credential = cred_r,
		.peer_credential_length = ARRAY_SIZE(cred_r),
	};

	int ret = edhoc_th_compute(&ctx, &input);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, ctx.state.th.stage);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_th, compute_unknown_target)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.th.stage = (enum edhoc_th_state)8;

	const struct edhoc_th_input input = {
		.target = (enum edhoc_th_state)9,
	};

	int ret = edhoc_th_compute(&ctx, &input);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_th, encoded_length_null)
{
	size_t len = 0;

	int ret = edhoc_th_encoded_length(0, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_th_encoded_length(32, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST_GROUP_RUNNER(internals_th)
{
	RUN_TEST_CASE(internals_th, compute_null);
	RUN_TEST_CASE(internals_th, compute_th_2_bad_state);
	RUN_TEST_CASE(internals_th, compute_th_3_bad_state);
	RUN_TEST_CASE(internals_th, compute_th_4_bad_state);
	RUN_TEST_CASE(internals_th, compute_th_1_invalid_arguments);
	RUN_TEST_CASE(internals_th, compute_th_2_invalid_role);
	RUN_TEST_CASE(internals_th, compute_th_3_invalid_arguments);
	RUN_TEST_CASE(internals_th, compute_th_4_invalid_arguments);
	RUN_TEST_CASE(internals_th, compute_th_4_psk);
	RUN_TEST_CASE(internals_th, compute_unknown_target);
	RUN_TEST_CASE(internals_th, encoded_length_null);
}
