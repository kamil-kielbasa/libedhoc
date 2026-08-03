/**
 * \file    test_coverage_msg2.c
 * \author  Kamil Kielbasa
 * \brief   Coverage tests for EDHOC message 2 error paths.
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

/*
 * Fail-point sweeps: coverage_mock_reset(N) arms the Nth mock crypto/CBOR
 * operation to fail. Each sweep drives message 2 compose/process across a range
 * of fail points [mock_fail_pt_first .. mock_fail_pt_last] and checks the
 * outcome against the expectation tables in coverage_sweep.h; a range simply
 * enumerates the mock operation indices reached by that particular variant.
 */

TEST_GROUP(coverage_msg2);

TEST_SETUP(coverage_msg2)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(coverage_msg2)
{
	mbedtls_psa_crypto_free();
}

TEST(coverage_msg2, msg2_compose_dh_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;

	ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(1);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_cred_fetch_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;

	ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(4);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_hash_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;

	ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(2);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_ead_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;

	ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(5);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_EAD_COMPOSE_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_signature_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;

	ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(7);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_encrypt_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;

	ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(8);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_bad_state)
{
	struct edhoc_context ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;

	ret = edhoc_message_2_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_failure_sweep)
{
	const int mock_fail_pt_first = 4;
	const int mock_fail_pt_last = 15;

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

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;

		ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					    sizeof(msg1), &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;

		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_compose_m0_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg2, msg2_compose_failure_sweep_high)
{
	const int mock_fail_pt_first = 16;
	const int mock_fail_pt_last = 20;

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

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;

		ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					    sizeof(msg1), &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;

		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_compose_m0_high_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg2, msg2_compose_method3_failure_sweep)
{
	const int mock_fail_pt_first = 4;
	const int mock_fail_pt_last = 12;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_3);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_3);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;

		ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					    sizeof(msg1), &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		coverage_assert_sweep_result(
			ret,
			coverage_msg2_compose_method_sweep_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg2, msg2_compose_method1_failure_sweep)
{
	const int mock_fail_pt_first = 4;
	const int mock_fail_pt_last = 12;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_1);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_1);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;

		ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					    sizeof(msg1), &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;

		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		coverage_assert_sweep_result(
			ret,
			coverage_msg2_compose_method_sweep_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg2, msg2_compose_method2_failure_sweep)
{
	const int mock_fail_pt_first = 4;
	const int mock_fail_pt_last = 12;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_2);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_2);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;

		ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					    sizeof(msg1), &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;

		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_compose_m0_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg2, msg2_compose_no_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;

	ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				    &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL_MESSAGE(EDHOC_SUCCESS, ret,
				  "msg2_compose with no failures");

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_process_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 15;

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

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;

		ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						 sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_process_m0_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg2, msg2_process_method3_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 20;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };

		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_3);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_3);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;

		ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						 sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_process_m3_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg2, msg2_process_method1_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 20;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_1);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_1);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;

		ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						 sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		coverage_assert_sweep_result(
			ret,
			coverage_msg2_process_method_sweep_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg2, msg2_process_method2_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 20;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_2);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_2);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						 sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_process_m0_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg2, msg2_compose_failure_sweep_very_high)
{
	const int mock_fail_pt_first = 21;
	const int mock_fail_pt_last = 30;

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

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;

		ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					    sizeof(msg1), &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;

		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_compose_gap_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg2, msg2_compose_method3_failure_sweep_high)
{
	const int mock_fail_pt_first = 13;
	const int mock_fail_pt_last = 30;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_3);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_3);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;

		ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					    sizeof(msg1), &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;

		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		coverage_assert_sweep_result(
			ret,
			coverage_msg2_compose_method3_high_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg2, msg2_process_truncated)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					 sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(msg2_len > 1);

	/* Every prefix of a valid message 2 must fail to process. */
	for (size_t trunc = 1; trunc < msg2_len && trunc < 10; trunc++) {
		struct edhoc_context init = { 0 };

		ret = coverage_setup_mock_context_initiator(&init,
							    EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;

		coverage_mock_reset(0);

		ret = edhoc_message_1_compose(&init, msg1, sizeof(msg1),
					      &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(0);

		ret = edhoc_message_2_process(&init, msg2, trunc);
		TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&init);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_extended_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 30;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context ctx = { 0 };
		int ret = coverage_setup_mock_context_initiator(&ctx,
								EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(0);

		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;

		ret = edhoc_message_1_compose(&ctx, msg1, sizeof(msg1),
					      &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		struct edhoc_context resp = { 0 };
		ret = coverage_setup_mock_context_initiator(&resp,
							    EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(0);

		ret = edhoc_message_1_process(&resp, msg1, msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;

		ret = edhoc_message_2_compose(&resp, msg2, sizeof(msg2),
					      &msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_compose_extended_must_fail(fail_pt));

		ret = edhoc_context_deinit(&ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg2, msg2_compose_bstr_cid)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret = coverage_setup_mock_context_bstr_cid_initiator(
		&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_bstr_cid_responder(&resp_ctx,
							     EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	coverage_mock_reset(0);

	ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					 sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_bstr_cid_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 30;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };

		int ret = coverage_setup_mock_context_bstr_cid_initiator(
			&init_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_bstr_cid_responder(
			&resp_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;

		coverage_mock_reset(0);

		ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					    sizeof(msg1), &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;

		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_compose_bstr_cid_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg2, msg2_process_bstr_cid_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 20;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret = coverage_setup_mock_context_bstr_cid_initiator(
			&init_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_bstr_cid_responder(
			&resp_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;

		ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						 sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_process_bstr_cid_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg2, msg2_compose_bstr_cid_tiny_buf)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret = coverage_setup_mock_context_bstr_cid_initiator(
		&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_bstr_cid_responder(&resp_ctx,
							     EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;

	coverage_mock_reset(0);

	ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				    &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg2[4] = { 0 };
	size_t msg2_len = 0;

	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_corrupted_method)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;

	coverage_mock_reset(0);

	ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				    &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.negotiation.selected_method = (enum edhoc_method)99;

	coverage_mock_reset(0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_tiny_buffer)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;

	coverage_mock_reset(0);

	ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				    &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg2[8] = { 0 };
	size_t msg2_len = 0;

	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_process_corrupted_method)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					 sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.negotiation.selected_method = (enum edhoc_method)99;

	coverage_mock_reset(0);

	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_x509_zero_certs_2)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_3);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_3);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;

	coverage_mock_reset(0);

	ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				    &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_credentials zero_creds = {
		.select_local = coverage_mock_cred_select_local_x509_zero_certs,
		.authenticate_peer = coverage_mock_cred_authenticate_peer,
	};
	ret = edhoc_bind_credentials(&resp_ctx, &zero_creds);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	/* An empty chain is rejected by the validation that follows fetch. */
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_cred_left_zeroed)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;

	coverage_mock_reset(0);

	ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				    &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_credentials silent_creds = {
		.select_local = coverage_mock_cred_select_local_untouched,
		.authenticate_peer = coverage_mock_cred_authenticate_peer,
	};
	ret = edhoc_bind_credentials(&resp_ctx, &silent_creds);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	/* The library zeroes the structure before the callback, so a callback
	 * that fills nothing leaves EDHOC_COSE_HEADER_NONE behind. */
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_invalid_cred_label)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;

	coverage_mock_reset(0);

	ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				    &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_credentials bad_creds = {
		.select_local = coverage_mock_cred_select_local_invalid_label,
		.authenticate_peer = coverage_mock_cred_authenticate_peer,
	};
	ret = edhoc_bind_credentials(&resp_ctx, &bad_creds);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_x509_zero_certs)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;

	coverage_mock_reset(0);

	ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				    &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_credentials zero_creds = {
		.select_local = coverage_mock_cred_select_local_x509_zero_certs,
		.authenticate_peer = coverage_mock_cred_authenticate_peer,
	};
	ret = edhoc_bind_credentials(&resp_ctx, &zero_creds);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	/* An empty chain is rejected by the validation that follows fetch. */
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_corrupted_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;

	ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				    &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.state.machine = EDHOC_SM_START;

	uint8_t msg2[256] = { 0 };
	size_t msg2_len = 0;

	coverage_mock_reset(0);

	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_process_corrupted_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;

	ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg2[256] = { 0 };
	size_t msg2_len = 0;

	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.state.machine = EDHOC_SM_COMPLETED;
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_compose_failure_sweep_gap)
{
	const int mock_fail_pt_first = 21;
	const int mock_fail_pt_last = 30;

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

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;

		ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					    sizeof(msg1), &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;

		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_compose_gap_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg2, msg2_process_failure_sweep_gap)
{
	const int mock_fail_pt_first = 21;
	const int mock_fail_pt_last = 30;

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

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;

		ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						 sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_process_gap_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg2, msg2_process_garbage)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;

	ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1, sizeof(msg1),
				    &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t garbage[] = { 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA };

	coverage_mock_reset(0);

	ret = edhoc_message_2_process(&init_ctx, garbage, sizeof(garbage));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg2, msg2_process_ead_value_failure)
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
	ret = edhoc_bind_ead(&resp_ctx, &ead_compose);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					 sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_ead ead_fail = {
		.compose = coverage_mock_ead_compose,
		.process = coverage_mock_ead_process_fail,
	};
	ret = edhoc_bind_ead(&init_ctx, &ead_fail);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_EAD_PROCESS_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(coverage_msg2)
{
	/* Compose — targeted failure points. */
	RUN_TEST_CASE(coverage_msg2, msg2_compose_dh_fail);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_cred_fetch_fail);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_hash_fail);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_ead_fail);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_signature_fail);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_encrypt_fail);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_bad_state);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_corrupted_method);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_corrupted_state);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_tiny_buffer);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_x509_zero_certs);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_x509_zero_certs_2);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_invalid_cred_label);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_cred_left_zeroed);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_no_fail);

	/* Compose — fail-point sweeps. */
	RUN_TEST_CASE(coverage_msg2, msg2_compose_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_failure_sweep_high);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_failure_sweep_very_high);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_failure_sweep_gap);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_method1_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_method2_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_method3_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_method3_failure_sweep_high);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_extended_sweep);

	/* Compose — byte-string connection ID. */
	RUN_TEST_CASE(coverage_msg2, msg2_compose_bstr_cid);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_bstr_cid_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_bstr_cid_tiny_buf);

	/* Process — targeted paths. */
	RUN_TEST_CASE(coverage_msg2, msg2_process_corrupted_method);
	RUN_TEST_CASE(coverage_msg2, msg2_process_corrupted_state);
	RUN_TEST_CASE(coverage_msg2, msg2_process_garbage);
	RUN_TEST_CASE(coverage_msg2, msg2_process_truncated);
	RUN_TEST_CASE(coverage_msg2, msg2_process_ead_value_failure);

	/* Process — fail-point sweeps. */
	RUN_TEST_CASE(coverage_msg2, msg2_process_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_process_failure_sweep_gap);
	RUN_TEST_CASE(coverage_msg2, msg2_process_method1_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_process_method2_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_process_method3_failure_sweep);

	/* Process — byte-string connection ID. */
	RUN_TEST_CASE(coverage_msg2, msg2_process_bstr_cid_failure_sweep);
}
