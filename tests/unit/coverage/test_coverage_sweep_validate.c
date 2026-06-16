/**
 * \file    test_coverage_sweep_validate.c
 * \author  Kamil Kielbasa
 * \brief   Self-checks for mock fail-point sweep expectation tables.
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

TEST_GROUP(coverage_sweep_validate);

TEST_SETUP(coverage_sweep_validate)
{
	psa_status_t status = psa_crypto_init();
	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(coverage_sweep_validate)
{
	mbedtls_psa_crypto_free();
}

/* Static function definitions --------------------------------------------- */

static void assert_table_matches(int fail_pt, int ret,
				 bool (*must_fail)(int fail_pt))
{
	const bool expect_fail = must_fail(fail_pt);
	const bool got_fail = (EDHOC_SUCCESS != ret);

	TEST_ASSERT_EQUAL(expect_fail, got_fail);
}

TEST(coverage_sweep_validate, msg1_compose_table)
{
	for (int fail_pt = 1; fail_pt <= 10; fail_pt++) {
		struct edhoc_context ctx = { 0 };
		int ret;

		ret = coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		coverage_mock_reset(fail_pt);

		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;
		ret = edhoc_message_1_compose(&ctx, msg1, sizeof(msg1),
					      &msg1_len);
		assert_table_matches(fail_pt, ret,
				     coverage_msg1_compose_must_fail);

		ret = edhoc_context_deinit(&ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_sweep_validate, msg1_process_table)
{
	for (int fail_pt = 1; fail_pt <= 10; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret;

		ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(0);
		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;
		ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					      &msg1_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
		assert_table_matches(fail_pt, ret,
				     coverage_msg1_process_must_fail);

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_sweep_validate, msg2_compose_m0_table)
{
	for (int fail_pt = 4; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret;

		ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
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
		assert_table_matches(fail_pt, ret,
				     coverage_msg2_compose_m0_must_fail);

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_sweep_validate, msg2_process_m0_table)
{
	for (int fail_pt = 1; fail_pt <= 15; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret;

		ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		uint8_t msg2[512] = { 0 };
		size_t msg2_len = 0;
		ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						 sizeof(msg2), &msg2_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
		assert_table_matches(fail_pt, ret,
				     coverage_msg2_process_m0_must_fail);

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_sweep_validate, msg3_compose_m0_table)
{
	for (int fail_pt = 1; fail_pt <= 20; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret;

		ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
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
		assert_table_matches(fail_pt, ret,
				     coverage_msg3_compose_sweep_must_fail);

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_sweep_validate, oscore_export_table)
{
	for (int fail_pt = 1; fail_pt <= 15; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret;

		ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		uint8_t master_secret[32] = { 0 };
		uint8_t master_salt[32] = { 0 };
		uint8_t sender_id[16] = { 0 };
		uint8_t recipient_id[16] = { 0 };
		size_t sender_id_len, recipient_id_len;
		ret = edhoc_export_oscore_session(
			&init_ctx, master_secret, sizeof(master_secret),
			master_salt, sizeof(master_salt), sender_id,
			sizeof(sender_id), &sender_id_len, recipient_id,
			sizeof(recipient_id), &recipient_id_len);
		assert_table_matches(fail_pt, ret,
				     coverage_oscore_export_must_fail);

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_sweep_validate, key_update_table)
{
	for (int fail_pt = 1; fail_pt <= 10; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret;

		ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		uint8_t entropy[32] = { 0x42 };
		ret = edhoc_export_key_update(&resp_ctx, entropy,
					      sizeof(entropy));
		assert_table_matches(fail_pt, ret,
				     coverage_key_update_must_fail);

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST_GROUP_RUNNER(coverage_sweep_validate)
{
	RUN_TEST_CASE(coverage_sweep_validate, msg1_compose_table);
	RUN_TEST_CASE(coverage_sweep_validate, msg1_process_table);
	RUN_TEST_CASE(coverage_sweep_validate, msg2_compose_m0_table);
	RUN_TEST_CASE(coverage_sweep_validate, msg2_process_m0_table);
	RUN_TEST_CASE(coverage_sweep_validate, msg3_compose_m0_table);
	RUN_TEST_CASE(coverage_sweep_validate, oscore_export_table);
	RUN_TEST_CASE(coverage_sweep_validate, key_update_table);
}
