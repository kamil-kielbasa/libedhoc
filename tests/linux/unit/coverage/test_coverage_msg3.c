/**
 * \file    test_coverage_msg3.c
 * \author  Kamil Kielbasa
 * \brief   Coverage tests for EDHOC message 3 error paths.
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
 * operation to fail. Each sweep drives message 3 compose/process across a range
 * of fail points [mock_fail_pt_first .. mock_fail_pt_last] and checks the
 * outcome against the expectation tables in coverage_sweep.h; a range simply
 * enumerates the mock operation indices reached by that particular variant.
 */

TEST_GROUP(coverage_msg3);

TEST_SETUP(coverage_msg3)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(coverage_msg3)
{
	mbedtls_psa_crypto_free();
}

TEST(coverage_msg3, msg3_compose_bad_state)
{
	struct edhoc_context ctx = { 0 };
	int ret = coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	coverage_mock_reset(0);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	ret = edhoc_message_3_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg3, msg3_compose_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 20;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret =
			coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg2_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;

		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		coverage_assert_sweep_result(
			ret, coverage_msg3_compose_sweep_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg3, msg3_compose_method3_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 25;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret =
			coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_3);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_3);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg2_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;

		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		/* High points may succeed if compose finishes early */
		coverage_assert_sweep_result(
			ret, coverage_msg3_compose_method_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg3, msg3_compose_method1_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 25;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret =
			coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_1);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_1);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg2_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;

		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		coverage_assert_sweep_result(
			ret, coverage_msg3_compose_sweep_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg3, msg3_compose_method2_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 25;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret =
			coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_2);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_2);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg2_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;

		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		coverage_assert_sweep_result(
			ret, coverage_msg3_compose_method_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg3, msg3_process_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 20;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret =
			coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;

		ret = coverage_do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
						    sizeof(msg3), &msg3_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		coverage_assert_sweep_result(
			ret, coverage_msg3_process_sweep_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg3, msg3_process_method3_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 25;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret =
			coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_3);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_3);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;

		ret = coverage_do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
						    sizeof(msg3), &msg3_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		coverage_assert_sweep_result(
			ret, coverage_msg3_process_method_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg3, msg3_process_method1_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 25;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret =
			coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_1);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_1);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;

		ret = coverage_do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
						    sizeof(msg3), &msg3_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		coverage_assert_sweep_result(
			ret, coverage_msg3_process_sweep_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg3, msg3_process_method2_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 25;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret =
			coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_2);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_2);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;

		ret = coverage_do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
						    sizeof(msg3), &msg3_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		coverage_assert_sweep_result(
			ret, coverage_msg3_process_method_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg3, msg3_process_truncated)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;

	ret = coverage_do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
					    sizeof(msg3), &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(msg3_len > 1);

	/* Every prefix of a valid message 3 must fail to process. */
	for (size_t trunc = 1; trunc < msg3_len && trunc < 10; trunc++) {
		struct edhoc_context init = { 0 };
		struct edhoc_context resp = { 0 };

		ret = coverage_setup_mock_context(&init, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context(&resp, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t scratch[512] = { 0 };
		size_t scratch_len = 0;

		ret = coverage_do_mock_msg3_compose(
			&init, &resp, scratch, sizeof(scratch), &scratch_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(0);
		ret = edhoc_message_3_process(&resp, msg3, trunc);
		TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&init);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg3, msg3_compose_failure_sweep_extended)
{
	const int mock_fail_pt_first = 26;
	const int mock_fail_pt_last = 40;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret =
			coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						 sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(0);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;

		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		coverage_assert_sweep_result(
			ret, coverage_msg3_compose_extended_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg3, msg3_process_failure_sweep_extended)
{
	const int mock_fail_pt_first = 26;
	const int mock_fail_pt_last = 40;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret =
			coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;

		ret = coverage_do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
						    sizeof(msg3), &msg3_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		coverage_assert_sweep_result(
			ret, coverage_msg3_process_extended_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg3, msg3_compose_bstr_cid_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 30;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };

		int ret = coverage_setup_mock_context_bstr_cid(&init_ctx,
							       EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_bstr_cid(&resp_ctx,
							   EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;

		ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						 sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(0);

		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;

		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		coverage_assert_sweep_result(
			ret, coverage_msg3_compose_bstr_cid_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg3, msg3_compose_invalid_cred_label)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					 sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_credentials bad_creds = {
		.fetch = coverage_mock_cred_fetch_invalid_label,
		.verify = coverage_mock_cred_verify,
	};
	ret = edhoc_bind_credentials(&init_ctx, &bad_creds);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;

	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg3, msg3_compose_corrupted_method)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					 sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.negotiation.selected_method = (enum edhoc_method)99;

	coverage_mock_reset(0);

	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;

	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg3, msg3_compose_tiny_buffer)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;

	ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					 sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg3[8] = { 0 };
	size_t msg3_len = 0;

	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg3, msg3_process_corrupted_method)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;

	ret = coverage_do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
					    sizeof(msg3), &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.negotiation.selected_method = (enum edhoc_method)99;

	coverage_mock_reset(0);

	ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg3, msg3_process_ead_failure)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg2_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Bind EAD to initiator: compose with a token */
	const struct edhoc_ead ead_init = {
		.compose = coverage_mock_ead_compose_with_token,
		.process = coverage_mock_ead_process,
	};
	ret = edhoc_bind_ead(&init_ctx, &ead_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Bind EAD to responder: process always fails */
	const struct edhoc_ead ead_resp = {
		.compose = coverage_mock_ead_compose,
		.process = coverage_mock_ead_process_fail,
	};
	ret = edhoc_bind_ead(&resp_ctx, &ead_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;

	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_EAD_PROCESS_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg3, msg3_compose_corrupted_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg2_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.state.machine = EDHOC_SM_START;

	uint8_t msg3[256] = { 0 };
	size_t msg3_len = 0;

	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg3, msg3_compose_failure_sweep_gap)
{
	const int mock_fail_pt_first = 21;
	const int mock_fail_pt_last = 25;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret =
			coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg2_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;

		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		coverage_assert_sweep_result(
			ret, coverage_msg3_gap_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg3, msg3_process_failure_sweep_gap)
{
	const int mock_fail_pt_first = 21;
	const int mock_fail_pt_last = 25;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret =
			coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;

		ret = coverage_do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
						    sizeof(msg3), &msg3_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		coverage_assert_sweep_result(
			ret, coverage_msg3_gap_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg3, msg3_process_garbage)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg2_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t garbage[] = { 0xFF, 0xFE };
	coverage_mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, garbage, sizeof(garbage));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_MSG_3_PROCESS_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(coverage_msg3)
{
	/* Compose — targeted failure points. */
	RUN_TEST_CASE(coverage_msg3, msg3_compose_bad_state);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_corrupted_method);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_corrupted_state);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_invalid_cred_label);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_tiny_buffer);

	/* Compose — fail-point sweeps. */
	RUN_TEST_CASE(coverage_msg3, msg3_compose_failure_sweep);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_failure_sweep_extended);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_failure_sweep_gap);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_method1_failure_sweep);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_method2_failure_sweep);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_method3_failure_sweep);

	/* Compose — byte-string connection ID. */
	RUN_TEST_CASE(coverage_msg3, msg3_compose_bstr_cid_failure_sweep);

	/* Process — targeted paths. */
	RUN_TEST_CASE(coverage_msg3, msg3_process_corrupted_method);
	RUN_TEST_CASE(coverage_msg3, msg3_process_ead_failure);
	RUN_TEST_CASE(coverage_msg3, msg3_process_garbage);
	RUN_TEST_CASE(coverage_msg3, msg3_process_truncated);

	/* Process — fail-point sweeps. */
	RUN_TEST_CASE(coverage_msg3, msg3_process_failure_sweep);
	RUN_TEST_CASE(coverage_msg3, msg3_process_failure_sweep_extended);
	RUN_TEST_CASE(coverage_msg3, msg3_process_failure_sweep_gap);
	RUN_TEST_CASE(coverage_msg3, msg3_process_method1_failure_sweep);
	RUN_TEST_CASE(coverage_msg3, msg3_process_method2_failure_sweep);
	RUN_TEST_CASE(coverage_msg3, msg3_process_method3_failure_sweep);
}
