/**
 * \file    test_coverage_msg4.c
 * \author  Kamil Kielbasa
 * \brief   Coverage tests for EDHOC message 4 error paths.
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

TEST_GROUP(coverage_msg4);

TEST_SETUP(coverage_msg4)
{
	psa_crypto_init();
}

TEST_TEAR_DOWN(coverage_msg4)
{
	mbedtls_psa_crypto_free();
}

TEST(coverage_msg4, msg4_compose_bad_state)
{
	struct edhoc_context ctx = { 0 };
	coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
	coverage_mock_reset(0);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_4_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(coverage_msg4, msg4_compose_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg4, msg4_process_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(0);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg4, msg4_compose_method3_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_3);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

		int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg4, msg4_process_method3_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_3);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

		int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(0);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg4, msg4_compose_failure_sweep_extended)
{
	for (int fail_pt = 26; fail_pt <= 40; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(fail_pt);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg4, msg4_process_failure_sweep_extended)
{
	for (int fail_pt = 26; fail_pt <= 40; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(0);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg4, msg4_bstr_cid_full)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	uint8_t msg4[512] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	uint8_t secret[32], salt[32], sid[16], rid[16];
	size_t sid_len, rid_len;
	ret = edhoc_export_oscore_session(&init_ctx, secret, sizeof(secret),
					  salt, sizeof(salt), sid, sizeof(sid),
					  &sid_len, rid, sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg4, msg4_compose_method1_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_1);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_1);

		int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(fail_pt);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg4, msg4_process_method1_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_1);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_1);

		int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(0);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg4, msg4_compose_method2_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_2);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_2);

		int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(fail_pt);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg4, msg4_process_method2_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_2);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_2);

		int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(0);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg4, msg4_compose_tiny_buffer)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	uint8_t msg4[4] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg4, msg4_process_bad_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	uint8_t msg4[256] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.status = EDHOC_SM_START;
	ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg4, msg4_compose_corrupted_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.status = EDHOC_SM_START;

	uint8_t msg4[256] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg4, msg4_process_truncated)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	uint8_t msg4[256] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_4_process(&init_ctx, msg4, 2);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg4, msg4_process_ead_failure)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Bind EAD to responder: compose with a token */
	const struct edhoc_ead ead_resp = {
		.compose = coverage_mock_ead_compose_with_token,
		.process = coverage_mock_ead_process,
	};
	edhoc_bind_ead(&resp_ctx, &ead_resp);

	/* Bind EAD to initiator: process always fails */
	const struct edhoc_ead ead_init = {
		.compose = coverage_mock_ead_compose,
		.process = coverage_mock_ead_process_fail,
	};
	edhoc_bind_ead(&init_ctx, &ead_init);

	coverage_mock_reset(0);
	uint8_t msg4[512] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg4, msg4_compose_failure_sweep_gap)
{
	for (int fail_pt = 21; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(fail_pt);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg4, msg4_process_failure_sweep_gap)
{
	for (int fail_pt = 21; fail_pt <= 25; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(0);
		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;
		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg4, msg4_process_garbage)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t garbage[] = { 0xFF };
	coverage_mock_reset(0);
	ret = edhoc_message_4_process(&init_ctx, garbage, sizeof(garbage));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST_GROUP_RUNNER(coverage_msg4)
{
	RUN_TEST_CASE(coverage_msg4, msg4_compose_bad_state);
	RUN_TEST_CASE(coverage_msg4, msg4_compose_failure_sweep);
	RUN_TEST_CASE(coverage_msg4, msg4_process_failure_sweep);
	RUN_TEST_CASE(coverage_msg4, msg4_compose_method3_failure_sweep);
	RUN_TEST_CASE(coverage_msg4, msg4_process_method3_failure_sweep);
	RUN_TEST_CASE(coverage_msg4, msg4_compose_failure_sweep_extended);
	RUN_TEST_CASE(coverage_msg4, msg4_process_failure_sweep_extended);
	RUN_TEST_CASE(coverage_msg4, msg4_bstr_cid_full);
	RUN_TEST_CASE(coverage_msg4, msg4_compose_method1_failure_sweep);
	RUN_TEST_CASE(coverage_msg4, msg4_process_method1_failure_sweep);
	RUN_TEST_CASE(coverage_msg4, msg4_compose_method2_failure_sweep);
	RUN_TEST_CASE(coverage_msg4, msg4_process_method2_failure_sweep);
	RUN_TEST_CASE(coverage_msg4, msg4_compose_tiny_buffer);
	RUN_TEST_CASE(coverage_msg4, msg4_process_bad_state);
	RUN_TEST_CASE(coverage_msg4, msg4_compose_corrupted_state);
	RUN_TEST_CASE(coverage_msg4, msg4_process_truncated);
	RUN_TEST_CASE(coverage_msg4, msg4_process_ead_failure);
	RUN_TEST_CASE(coverage_msg4, msg4_compose_failure_sweep_gap);
	RUN_TEST_CASE(coverage_msg4, msg4_process_failure_sweep_gap);
	RUN_TEST_CASE(coverage_msg4, msg4_process_garbage);
}
