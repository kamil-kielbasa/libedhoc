/**
 * \file    test_coverage_msg2.c
 * \author  Kamil Kielbasa
 * \brief   Coverage tests for EDHOC message 2 error paths.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#include "coverage_common.h"
#include "coverage_sweep.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(coverage_msg2);

TEST_SETUP(coverage_msg2)
{
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, psa_crypto_init());
}

TEST_TEAR_DOWN(coverage_msg2)
{
	mbedtls_psa_crypto_free();
}

TEST(coverage_msg2, msg2_compose_dh_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));
	coverage_mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(1);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_compose_cred_fetch_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));
	coverage_mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(4);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_compose_hash_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));
	coverage_mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(2);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_compose_ead_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));
	coverage_mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(5);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_EAD_COMPOSE_FAILURE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_compose_signature_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));
	coverage_mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(7);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_compose_encrypt_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));
	coverage_mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(8);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_compose_bad_state)
{
	struct edhoc_context ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context(&ctx, EDHOC_METHOD_0));
	coverage_mock_reset(0);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_2_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(coverage_msg2, msg2_compose_failure_sweep)
{
	const int mock_fail_pt_first = 4;
	const int mock_fail_pt_last = 15;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init_ctx,
							      EDHOC_METHOD_0));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp_ctx,
							      EDHOC_METHOD_0));

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
						sizeof(msg1), &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_compose_m0_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
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
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init_ctx,
							      EDHOC_METHOD_0));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp_ctx,
							      EDHOC_METHOD_0));

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
						sizeof(msg1), &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_compose_m0_high_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
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
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init_ctx,
							      EDHOC_METHOD_3));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp_ctx,
							      EDHOC_METHOD_3));

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
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

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
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
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init_ctx,
							      EDHOC_METHOD_1));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp_ctx,
							      EDHOC_METHOD_1));

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
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

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
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
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init_ctx,
							      EDHOC_METHOD_2));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp_ctx,
							      EDHOC_METHOD_2));

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
						sizeof(msg1), &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		/* Method 2 (Responder = Signature) composes msg2 with the same
		 * crypto-op profile as method 0. */
		coverage_assert_sweep_result(
			ret, coverage_msg2_compose_m0_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
	}
}

TEST(coverage_msg2, msg2_compose_no_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL_MESSAGE(EDHOC_SUCCESS, ret,
				  "msg2_compose with no failures");

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_process_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 15;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init_ctx,
							      EDHOC_METHOD_0));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp_ctx,
							      EDHOC_METHOD_0));

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						     sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_process_m0_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
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
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init_ctx,
							      EDHOC_METHOD_3));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp_ctx,
							      EDHOC_METHOD_3));

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						     sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_process_m3_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
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
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init_ctx,
							      EDHOC_METHOD_1));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp_ctx,
							      EDHOC_METHOD_1));

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						     sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		coverage_assert_sweep_result(
			ret,
			coverage_msg2_process_method_sweep_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
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
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init_ctx,
							      EDHOC_METHOD_2));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp_ctx,
							      EDHOC_METHOD_2));

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						     sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_process_m0_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
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
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init_ctx,
							      EDHOC_METHOD_0));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp_ctx,
							      EDHOC_METHOD_0));

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
						sizeof(msg1), &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_compose_gap_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
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
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init_ctx,
							      EDHOC_METHOD_3));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp_ctx,
							      EDHOC_METHOD_3));

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
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

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
	}
}

TEST(coverage_msg2, msg2_process_truncated)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					     sizeof(msg2), &msg2_len);
	if (EDHOC_SUCCESS == ret) {
		struct edhoc_context init2 = { 0 };
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init2,
							      EDHOC_METHOD_0));
		coverage_mock_reset(0);
		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;
		int compose_ret = edhoc_message_1_compose(
			&init2, msg1, sizeof(msg1), &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, compose_ret);

		for (size_t trunc = 1; trunc < msg2_len && trunc < 10;
		     trunc++) {
			coverage_mock_reset(0);
			int r = edhoc_message_2_process(&init2, msg2, trunc);
			TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, r);
		}
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init2));
	}

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_compose_extended_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 30;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context ctx = { 0 };
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
							 &ctx, EDHOC_METHOD_0));

		coverage_mock_reset(0);
		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;
		edhoc_message_1_compose(&ctx, msg1, sizeof(msg1), &msg1_len);

		struct edhoc_context resp = { 0 };
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp,
							      EDHOC_METHOD_0));
		coverage_mock_reset(0);
		edhoc_message_1_process(&resp, msg1, msg1_len);

		coverage_mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = edhoc_message_2_compose(&resp, msg2, sizeof(msg2),
						  &msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_compose_extended_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp));
	}
}

TEST(coverage_msg2, msg2_compose_bstr_cid)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context_bstr_cid(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context_bstr_cid(
						 &resp_ctx, EDHOC_METHOD_0));

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	coverage_mock_reset(0);
	int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					     sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_compose_bstr_cid_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 30;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context_bstr_cid(
					  &init_ctx, EDHOC_METHOD_0));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context_bstr_cid(
					  &resp_ctx, EDHOC_METHOD_0));

		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;
		coverage_mock_reset(0);
		int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
						sizeof(msg1), &msg1_len);
		if (EDHOC_SUCCESS != ret) {
			TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
					  edhoc_context_deinit(&init_ctx));
			TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
					  edhoc_context_deinit(&resp_ctx));
			continue;
		}

		coverage_mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_compose_bstr_cid_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
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
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context_bstr_cid(
					  &init_ctx, EDHOC_METHOD_0));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context_bstr_cid(
					  &resp_ctx, EDHOC_METHOD_0));

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						     sizeof(msg2), &msg2_len);
		if (EDHOC_SUCCESS != ret) {
			TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
					  edhoc_context_deinit(&init_ctx));
			TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
					  edhoc_context_deinit(&resp_ctx));
			continue;
		}

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_process_bstr_cid_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
	}
}

TEST(coverage_msg2, msg2_compose_bstr_cid_tiny_buf)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context_bstr_cid(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context_bstr_cid(
						 &resp_ctx, EDHOC_METHOD_0));

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	coverage_mock_reset(0);
	int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					sizeof(msg1), &msg1_len);
	if (EDHOC_SUCCESS == ret) {
		coverage_mock_reset(0);
		uint8_t msg2[4] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);
	}

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_compose_corrupted_cid_type)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	coverage_mock_reset(0);
	int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.negotiation.connection_id.encode_type =
		(enum edhoc_connection_id_type)99;

	coverage_mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_compose_corrupted_method)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	coverage_mock_reset(0);
	int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.negotiation.selected_method = (enum edhoc_method)99;

	coverage_mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_compose_tiny_buffer)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	coverage_mock_reset(0);
	int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	uint8_t msg2[8] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_process_corrupted_method)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					     sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.negotiation.selected_method = (enum edhoc_method)99;

	coverage_mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_compose_x509_zero_certs_2)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_3));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_3));

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	coverage_mock_reset(0);
	int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_credentials zero_creds = {
		.fetch = coverage_mock_cred_fetch_x509_zero_certs,
		.verify = coverage_mock_cred_verify,
	};
	ret = edhoc_bind_credentials(&resp_ctx, &zero_creds);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	coverage_mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_compose_invalid_cred_label)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	coverage_mock_reset(0);
	int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_credentials bad_creds = {
		.fetch = coverage_mock_cred_fetch_invalid_label,
		.verify = coverage_mock_cred_verify,
	};
	ret = edhoc_bind_credentials(&resp_ctx, &bad_creds);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	coverage_mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_compose_x509_zero_certs)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	coverage_mock_reset(0);
	int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_credentials zero_creds = {
		.fetch = coverage_mock_cred_fetch_x509_zero_certs,
		.verify = coverage_mock_cred_verify,
	};
	ret = edhoc_bind_credentials(&resp_ctx, &zero_creds);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	coverage_mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_compose_corrupted_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.state.machine = EDHOC_SM_START;

	uint8_t msg2[256] = { 0 };
	size_t msg2_len = 0;
	coverage_mock_reset(0);
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_process_corrupted_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
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

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_compose_failure_sweep_gap)
{
	const int mock_fail_pt_first = 21;
	const int mock_fail_pt_last = 30;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init_ctx,
							      EDHOC_METHOD_0));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp_ctx,
							      EDHOC_METHOD_0));

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
						sizeof(msg1), &msg1_len);
		if (EDHOC_SUCCESS != ret) {
			TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
					  edhoc_context_deinit(&init_ctx));
			TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
					  edhoc_context_deinit(&resp_ctx));
			continue;
		}

		coverage_mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_compose_gap_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
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
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init_ctx,
							      EDHOC_METHOD_0));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp_ctx,
							      EDHOC_METHOD_0));

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						     sizeof(msg2), &msg2_len);
		if (EDHOC_SUCCESS != ret) {
			TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
					  edhoc_context_deinit(&init_ctx));
			TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
					  edhoc_context_deinit(&resp_ctx));
			continue;
		}

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		coverage_assert_sweep_result(
			ret, coverage_msg2_process_gap_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
	}
}

TEST(coverage_msg2, msg2_process_garbage)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t garbage[] = { 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA };
	coverage_mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, garbage, sizeof(garbage));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_msg2, msg2_process_ead_value_failure)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret;

	ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
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

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST_GROUP_RUNNER(coverage_msg2)
{
	RUN_TEST_CASE(coverage_msg2, msg2_compose_dh_fail);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_cred_fetch_fail);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_hash_fail);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_ead_fail);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_signature_fail);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_encrypt_fail);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_bad_state);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_failure_sweep_high);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_method3_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_method1_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_method2_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_no_fail);
	RUN_TEST_CASE(coverage_msg2, msg2_process_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_process_method3_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_process_method1_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_process_method2_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_failure_sweep_very_high);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_method3_failure_sweep_high);
	RUN_TEST_CASE(coverage_msg2, msg2_process_truncated);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_extended_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_bstr_cid);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_bstr_cid_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_process_bstr_cid_failure_sweep);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_bstr_cid_tiny_buf);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_corrupted_cid_type);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_corrupted_method);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_tiny_buffer);
	RUN_TEST_CASE(coverage_msg2, msg2_process_corrupted_method);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_x509_zero_certs_2);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_invalid_cred_label);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_x509_zero_certs);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_corrupted_state);
	RUN_TEST_CASE(coverage_msg2, msg2_process_corrupted_state);
	RUN_TEST_CASE(coverage_msg2, msg2_compose_failure_sweep_gap);
	RUN_TEST_CASE(coverage_msg2, msg2_process_failure_sweep_gap);
	RUN_TEST_CASE(coverage_msg2, msg2_process_garbage);
	RUN_TEST_CASE(coverage_msg2, msg2_process_ead_value_failure);
}
