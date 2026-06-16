/**
 * \file    test_coverage_msg3.c
 * \author  Kamil Kielbasa
 * \brief   Coverage tests for EDHOC message 3 error paths.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#include "coverage_common.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(coverage_msg3);

TEST_SETUP(coverage_msg3)
{
	psa_crypto_init();
}

TEST_TEAR_DOWN(coverage_msg3)
{
	mbedtls_psa_crypto_free();
}

TEST(coverage_msg3, msg3_compose_bad_state)
{
	struct edhoc_context ctx = { 0 };
	coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
	coverage_mock_reset(0);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_3_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(coverage_msg3, msg3_compose_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = coverage_do_mock_msg2_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg3, msg3_compose_method3_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_3);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

		int ret = coverage_do_mock_msg2_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		/* High points may succeed if compose finishes early */
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg3, msg3_compose_method1_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_1);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_1);

		int ret = coverage_do_mock_msg2_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg3, msg3_compose_method2_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_2);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_2);

		int ret = coverage_do_mock_msg2_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg3, msg3_process_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		int ret = coverage_do_mock_msg3_compose(
			&init_ctx, &resp_ctx, msg3, sizeof(msg3), &msg3_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg3, msg3_process_method3_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_3);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		int ret = coverage_do_mock_msg3_compose(
			&init_ctx, &resp_ctx, msg3, sizeof(msg3), &msg3_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg3, msg3_process_method1_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_1);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_1);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		int ret = coverage_do_mock_msg3_compose(
			&init_ctx, &resp_ctx, msg3, sizeof(msg3), &msg3_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg3, msg3_process_method2_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_2);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_2);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		int ret = coverage_do_mock_msg3_compose(
			&init_ctx, &resp_ctx, msg3, sizeof(msg3), &msg3_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg3, msg3_process_truncated)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	int ret = coverage_do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
						sizeof(msg3), &msg3_len);
	if (EDHOC_SUCCESS == ret) {
		for (size_t trunc = 1; trunc < msg3_len && trunc < 10;
		     trunc++) {
			struct edhoc_context resp2 = { 0 };
			coverage_setup_mock_context(&resp2, EDHOC_METHOD_0);
			coverage_mock_reset(0);

			uint8_t m1[512];
			size_t m1l;
			edhoc_message_1_compose(&init_ctx, m1, sizeof(m1),
						&m1l);

			int r = edhoc_message_3_process(&resp_ctx, msg3, trunc);
			(void)r;
			edhoc_context_deinit(&resp2);
		}
	}

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg3, msg3_compose_failure_sweep_extended)
{
	for (int fail_pt = 26; fail_pt <= 40; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						     sizeof(msg2), &msg2_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(0);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(fail_pt);
		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg3, msg3_process_failure_sweep_extended)
{
	for (int fail_pt = 26; fail_pt <= 40; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		int ret = coverage_do_mock_msg3_compose(
			&init_ctx, &resp_ctx, msg3, sizeof(msg3), &msg3_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg3, msg3_compose_bstr_cid_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 30; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						     sizeof(msg2), &msg2_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(0);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(fail_pt);
		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg3, msg3_compose_invalid_cred_label)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					     sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_credentials bad_creds = {
		.fetch = coverage_mock_cred_fetch_invalid_label,
		.verify = coverage_mock_cred_verify,
	};
	edhoc_bind_credentials(&init_ctx, &bad_creds);

	coverage_mock_reset(0);
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg3, msg3_compose_corrupted_method)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					     sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.chosen_method = (enum edhoc_method)99;

	coverage_mock_reset(0);
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg3, msg3_compose_tiny_buffer)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					     sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	uint8_t msg3[8] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg3, msg3_process_corrupted_method)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	int ret = coverage_do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
						sizeof(msg3), &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.chosen_method = (enum edhoc_method)99;

	coverage_mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg3, msg3_process_ead_failure)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = coverage_do_mock_msg2_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Bind EAD to initiator: compose with a token */
	const struct edhoc_ead ead_init = {
		.compose = coverage_mock_ead_compose_with_token,
		.process = coverage_mock_ead_process,
	};
	edhoc_bind_ead(&init_ctx, &ead_init);

	/* Bind EAD to responder: process always fails */
	const struct edhoc_ead ead_resp = {
		.compose = coverage_mock_ead_compose,
		.process = coverage_mock_ead_process_fail,
	};
	edhoc_bind_ead(&resp_ctx, &ead_resp);

	coverage_mock_reset(0);
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg3, msg3_compose_corrupted_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = coverage_do_mock_msg2_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.status = EDHOC_SM_START;

	uint8_t msg3[256] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg3, msg3_compose_failure_sweep_gap)
{
	for (int fail_pt = 21; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = coverage_do_mock_msg2_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(fail_pt);
		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
					      &msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg3, msg3_process_failure_sweep_gap)
{
	for (int fail_pt = 21; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg3[512] = { 0 };
		size_t msg3_len = 0;
		int ret = coverage_do_mock_msg3_compose(
			&init_ctx, &resp_ctx, msg3, sizeof(msg3), &msg3_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg3, msg3_process_garbage)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = coverage_do_mock_msg2_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t garbage[] = { 0xFF, 0xFE };
	coverage_mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, garbage, sizeof(garbage));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST_GROUP_RUNNER(coverage_msg3)
{
	RUN_TEST_CASE(coverage_msg3, msg3_compose_bad_state);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_failure_sweep);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_method3_failure_sweep);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_method1_failure_sweep);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_method2_failure_sweep);
	RUN_TEST_CASE(coverage_msg3, msg3_process_failure_sweep);
	RUN_TEST_CASE(coverage_msg3, msg3_process_method3_failure_sweep);
	RUN_TEST_CASE(coverage_msg3, msg3_process_method1_failure_sweep);
	RUN_TEST_CASE(coverage_msg3, msg3_process_method2_failure_sweep);
	RUN_TEST_CASE(coverage_msg3, msg3_process_truncated);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_failure_sweep_extended);
	RUN_TEST_CASE(coverage_msg3, msg3_process_failure_sweep_extended);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_bstr_cid_failure_sweep);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_invalid_cred_label);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_corrupted_method);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_tiny_buffer);
	RUN_TEST_CASE(coverage_msg3, msg3_process_corrupted_method);
	RUN_TEST_CASE(coverage_msg3, msg3_process_ead_failure);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_corrupted_state);
	RUN_TEST_CASE(coverage_msg3, msg3_compose_failure_sweep_gap);
	RUN_TEST_CASE(coverage_msg3, msg3_process_failure_sweep_gap);
	RUN_TEST_CASE(coverage_msg3, msg3_process_garbage);
}
