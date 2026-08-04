/**
 * \file    test_coverage_msg1.c
 * \author  Kamil Kielbasa
 * \brief   Coverage tests for EDHOC message 1 error paths.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Internal headers: */
#include "coverage_common.h"
#include "coverage_sweep.h"

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

TEST_GROUP(coverage_msg1);

TEST_SETUP(coverage_msg1)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(coverage_msg1)
{
	mbedtls_psa_crypto_free();
}

TEST(coverage_msg1, msg1_compose_generate_key_pair_fail)
{
	struct edhoc_context ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(1);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;

	ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg1, msg1_compose_hash_fail)
{
	struct edhoc_context ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(3);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;

	ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg1, msg1_compose_buffer_too_small)
{
	struct edhoc_context ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg[1] = { 0 };
	size_t msg_len = 0;

	ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg1, msg1_compose_no_cipher_suites)
{
	struct edhoc_context ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ctx.negotiation.cipher_suite.count = 0;

	coverage_mock_reset(0);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;

	ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg1, msg1_process_method_mismatch)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;

	ret = edhoc_message_1_compose(&init_ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	ret = edhoc_message_1_process(&resp_ctx, msg, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_MSG_1_PROCESS_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg1, msg1_process_hash_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;

	ret = edhoc_message_1_compose(&init_ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(1);

	ret = edhoc_message_1_process(&resp_ctx, msg, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg1, msg1_compose_bad_state)
{
	struct edhoc_context ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;

	ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg1, msg1_process_bad_cbor)
{
	struct edhoc_context ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	const uint8_t garbage[] = { 0xFF };

	ret = edhoc_message_1_process(&ctx, garbage, sizeof(garbage));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg1, msg1_compose_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 10;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context ctx = { 0 };

		int ret = coverage_setup_mock_context_initiator(&ctx,
								EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;

		ret = edhoc_message_1_compose(&ctx, msg1, sizeof(msg1),
					      &msg1_len);
		coverage_assert_sweep_result(
			ret, coverage_msg1_compose_must_fail(fail_pt));

		ret = edhoc_context_deinit(&ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg1, msg1_process_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 10;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };

		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(0);

		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;

		ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					      &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
		coverage_assert_sweep_result(
			ret, coverage_msg1_process_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg1, msg1_process_ead_failure)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_ead ead_compose = {
		.compose = coverage_mock_ead_compose_with_token,
		.process = coverage_mock_ead_process,
	};
	ret = edhoc_bind_ead(&init_ctx, &ead_compose);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_ead ead_fail = {
		.compose = coverage_mock_ead_compose,
		.process = coverage_mock_ead_process_fail,
	};
	ret = edhoc_bind_ead(&resp_ctx, &ead_fail);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;

	ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_EAD_PROCESS_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(coverage_msg1)
{
	/* Compose paths. */
	RUN_TEST_CASE(coverage_msg1, msg1_compose_generate_key_pair_fail);
	RUN_TEST_CASE(coverage_msg1, msg1_compose_hash_fail);
	RUN_TEST_CASE(coverage_msg1, msg1_compose_buffer_too_small);
	RUN_TEST_CASE(coverage_msg1, msg1_compose_no_cipher_suites);
	RUN_TEST_CASE(coverage_msg1, msg1_compose_bad_state);
	RUN_TEST_CASE(coverage_msg1, msg1_compose_failure_sweep);

	/* Process paths. */
	RUN_TEST_CASE(coverage_msg1, msg1_process_method_mismatch);
	RUN_TEST_CASE(coverage_msg1, msg1_process_hash_fail);
	RUN_TEST_CASE(coverage_msg1, msg1_process_bad_cbor);
	RUN_TEST_CASE(coverage_msg1, msg1_process_ead_failure);
	RUN_TEST_CASE(coverage_msg1, msg1_process_failure_sweep);
}
