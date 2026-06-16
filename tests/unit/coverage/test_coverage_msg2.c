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

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(coverage_msg2);

TEST_SETUP(coverage_msg2)
{
	psa_crypto_init();
}

TEST_TEAR_DOWN(coverage_msg2)
{
	mbedtls_psa_crypto_free();
}

TEST(coverage_msg2, msg2_compose_dh_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	coverage_mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(3);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_compose_cred_fetch_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
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
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_compose_hash_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
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
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_compose_ead_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	coverage_mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(6);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_compose_signature_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	coverage_mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(10);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_compose_encrypt_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	coverage_mock_reset(0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(12);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_compose_bad_state)
{
	struct edhoc_context ctx = { 0 };
	coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
	coverage_mock_reset(0);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_2_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(coverage_msg2, msg2_compose_failure_sweep)
{
	for (int fail_pt = 4; fail_pt <= 15; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

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
		TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg2, msg2_compose_failure_sweep_high)
{
	for (int fail_pt = 16; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

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
		/* Some high failure points may succeed if compose finishes */
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg2, msg2_compose_method3_failure_sweep)
{
	for (int fail_pt = 4; fail_pt <= 12; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_3);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

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
		TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg2, msg2_compose_method1_failure_sweep)
{
	for (int fail_pt = 4; fail_pt <= 12; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_1);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_1);

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
		TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg2, msg2_compose_method2_failure_sweep)
{
	for (int fail_pt = 4; fail_pt <= 12; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_2);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_2);

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
		TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg2, msg2_compose_no_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

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

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_process_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 15; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						     sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg2, msg2_process_method3_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_3);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						     sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg2, msg2_process_method1_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_1);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_1);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						     sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg2, msg2_process_method2_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_2);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_2);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						     sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg2, msg2_compose_failure_sweep_very_high)
{
	for (int fail_pt = 21; fail_pt <= 30; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

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
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg2, msg2_compose_method3_failure_sweep_high)
{
	for (int fail_pt = 13; fail_pt <= 30; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_3);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

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
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg2, msg2_process_truncated)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					     sizeof(msg2), &msg2_len);
	if (EDHOC_SUCCESS == ret) {
		struct edhoc_context init2 = { 0 };
		coverage_setup_mock_context(&init2, EDHOC_METHOD_0);
		coverage_mock_reset(0);
		uint8_t m1[512];
		size_t m1l;
		edhoc_message_1_compose(&init2, m1, sizeof(m1), &m1l);

		for (size_t trunc = 1; trunc < msg2_len && trunc < 10;
		     trunc++) {
			coverage_mock_reset(0);
			int r = edhoc_message_2_process(&init2, msg2, trunc);
			(void)r;
		}
		edhoc_context_deinit(&init2);
	}

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_compose_extended_sweep)
{
	for (int fail_pt = 1; fail_pt <= 30; fail_pt++) {
		struct edhoc_context ctx = { 0 };
		coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);

		coverage_mock_reset(0);
		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;
		edhoc_message_1_compose(&ctx, msg1, sizeof(msg1), &msg1_len);

		struct edhoc_context resp = { 0 };
		coverage_setup_mock_context(&resp, EDHOC_METHOD_0);
		coverage_mock_reset(0);
		edhoc_message_1_process(&resp, msg1, msg1_len);

		coverage_mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		int ret = edhoc_message_2_compose(&resp, msg2, sizeof(msg2),
						  &msg2_len);
		(void)ret;

		edhoc_context_deinit(&ctx);
		edhoc_context_deinit(&resp);
	}
}

TEST(coverage_msg2, msg2_compose_bstr_cid)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	coverage_mock_reset(0);
	int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					     sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_compose_bstr_cid_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 30; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;
		coverage_mock_reset(0);
		int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
						sizeof(msg1), &msg1_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg2, msg2_process_bstr_cid_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
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

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg2, msg2_compose_bstr_cid_tiny_buf)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);

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
		TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	}

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_compose_corrupted_cid_type)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	coverage_mock_reset(0);
	int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.cid.encode_type = (enum edhoc_connection_id_type)99;

	coverage_mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_compose_corrupted_method)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	coverage_mock_reset(0);
	int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.chosen_method = (enum edhoc_method)99;

	coverage_mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_compose_tiny_buffer)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

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
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_process_corrupted_method)
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

	init_ctx.chosen_method = (enum edhoc_method)99;

	coverage_mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_compose_x509_zero_certs_2)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_3);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

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
	edhoc_bind_credentials(&resp_ctx, &zero_creds);

	coverage_mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_compose_invalid_cred_label)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

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
	edhoc_bind_credentials(&resp_ctx, &bad_creds);

	coverage_mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_compose_x509_zero_certs)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

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
	edhoc_bind_credentials(&resp_ctx, &zero_creds);

	coverage_mock_reset(0);
	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_compose_corrupted_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.status = EDHOC_SM_START;

	uint8_t msg2[256] = { 0 };
	size_t msg2_len = 0;
	coverage_mock_reset(0);
	ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2), &msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_process_corrupted_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

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

	init_ctx.status = EDHOC_SM_COMPLETED;
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_compose_failure_sweep_gap)
{
	for (int fail_pt = 21; fail_pt <= 30; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;
		int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
						sizeof(msg1), &msg1_len);
		if (EDHOC_SUCCESS != ret) {
			edhoc_context_deinit(&init_ctx);
			edhoc_context_deinit(&resp_ctx);
			continue;
		}

		coverage_mock_reset(fail_pt);
		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = edhoc_message_2_compose(&resp_ctx, msg2, sizeof(msg2),
					      &msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg2, msg2_process_failure_sweep_gap)
{
	for (int fail_pt = 21; fail_pt <= 30; fail_pt++) {
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

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		(void)ret;

		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg2, msg2_process_garbage)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
					sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t garbage[] = { 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA };
	coverage_mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, garbage, sizeof(garbage));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg2, msg2_process_ead_value_failure)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	const struct edhoc_ead ead_compose = {
		.compose = coverage_mock_ead_compose_with_token,
		.process = coverage_mock_ead_process,
	};
	edhoc_bind_ead(&resp_ctx, &ead_compose);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					     sizeof(msg2), &msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	const struct edhoc_ead ead_fail = {
		.compose = coverage_mock_ead_compose,
		.process = coverage_mock_ead_process_fail,
	};
	edhoc_bind_ead(&init_ctx, &ead_fail);

	coverage_mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

cleanup:
	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
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
