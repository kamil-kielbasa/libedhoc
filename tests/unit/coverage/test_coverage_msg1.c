/**
 * \file    test_coverage_msg1.c
 * \author  Kamil Kielbasa
 * \brief   Coverage tests for EDHOC message 1 error paths.
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

TEST_GROUP(coverage_msg1);

TEST_SETUP(coverage_msg1)
{
	psa_crypto_init();
}

TEST_TEAR_DOWN(coverage_msg1)
{
	mbedtls_psa_crypto_free();
}

TEST(coverage_msg1, msg1_compose_key_import_fail)
{
	struct edhoc_context ctx = { 0 };
	coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
	coverage_mock_reset(1);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	edhoc_context_deinit(&ctx);
}

TEST(coverage_msg1, msg1_compose_make_key_pair_fail)
{
	struct edhoc_context ctx = { 0 };
	coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
	coverage_mock_reset(2);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	edhoc_context_deinit(&ctx);
}

TEST(coverage_msg1, msg1_compose_buffer_too_small)
{
	struct edhoc_context ctx = { 0 };
	coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
	coverage_mock_reset(0);

	uint8_t msg[1] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	edhoc_context_deinit(&ctx);
}

TEST(coverage_msg1, msg1_process_method_mismatch)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_1);
	coverage_mock_reset(0);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	int ret =
		edhoc_message_1_compose(&init_ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg, msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg1, msg1_process_hash_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	coverage_mock_reset(0);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	int ret =
		edhoc_message_1_compose(&init_ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(1);
	ret = edhoc_message_1_process(&resp_ctx, msg, msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg1, conn_id_byte_string)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3,
		.bstr_value = { 0x01, 0x02, 0x03 },
	};
	int ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(coverage_msg1, msg1_compose_bad_state)
{
	struct edhoc_context ctx = { 0 };
	coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
	coverage_mock_reset(0);

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;
	int ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_1_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(coverage_msg1, msg1_process_bad_cbor)
{
	struct edhoc_context ctx = { 0 };
	coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
	coverage_mock_reset(0);

	const uint8_t garbage[] = { 0xFF };
	int ret = edhoc_message_1_process(&ctx, garbage, sizeof(garbage));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(coverage_msg1, msg1_compose_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 10; fail_pt++) {
		struct edhoc_context ctx = { 0 };
		coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
		coverage_mock_reset(fail_pt);

		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;
		int ret = edhoc_message_1_compose(&ctx, msg1, sizeof(msg1),
						  &msg1_len);
		(void)ret;

		edhoc_context_deinit(&ctx);
	}
}

TEST(coverage_msg1, msg1_process_failure_sweep)
{
	for (int fail_pt = 1; fail_pt <= 10; fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

		coverage_mock_reset(0);
		uint8_t msg1[512] = { 0 };
		size_t msg1_len = 0;
		int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
						  &msg1_len);
		if (EDHOC_SUCCESS != ret)
			goto cleanup1;

		coverage_mock_reset(fail_pt);
		ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
		(void)ret;
cleanup1:
		edhoc_context_deinit(&init_ctx);
		edhoc_context_deinit(&resp_ctx);
	}
}

TEST(coverage_msg1, msg1_process_ead_failure)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	const struct edhoc_ead ead_compose = {
		.compose = coverage_mock_ead_compose_with_token,
		.process = coverage_mock_ead_process,
	};
	edhoc_bind_ead(&init_ctx, &ead_compose);

	const struct edhoc_ead ead_fail = {
		.compose = coverage_mock_ead_compose,
		.process = coverage_mock_ead_process_fail,
	};
	edhoc_bind_ead(&resp_ctx, &ead_fail);

	coverage_mock_reset(0);
	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&init_ctx, msg1, sizeof(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	ret = edhoc_message_1_process(&resp_ctx, msg1, msg1_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_msg1, msg1_compose_with_ead)
{
	struct edhoc_context ctx = { 0 };
	coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);

	const struct edhoc_ead ead_with_token = {
		.compose = coverage_mock_ead_compose_with_token,
		.process = coverage_mock_ead_process,
	};
	edhoc_bind_ead(&ctx, &ead_with_token);

	coverage_mock_reset(0);
	uint8_t msg1[512] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&ctx, msg1, sizeof(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST_GROUP_RUNNER(coverage_msg1)
{
	RUN_TEST_CASE(coverage_msg1, msg1_compose_key_import_fail);
	RUN_TEST_CASE(coverage_msg1, msg1_compose_make_key_pair_fail);
	RUN_TEST_CASE(coverage_msg1, msg1_compose_buffer_too_small);
	RUN_TEST_CASE(coverage_msg1, msg1_process_method_mismatch);
	RUN_TEST_CASE(coverage_msg1, msg1_process_hash_fail);
	RUN_TEST_CASE(coverage_msg1, conn_id_byte_string);
	RUN_TEST_CASE(coverage_msg1, msg1_compose_bad_state);
	RUN_TEST_CASE(coverage_msg1, msg1_process_bad_cbor);
	RUN_TEST_CASE(coverage_msg1, msg1_compose_failure_sweep);
	RUN_TEST_CASE(coverage_msg1, msg1_process_failure_sweep);
	RUN_TEST_CASE(coverage_msg1, msg1_process_ead_failure);
	RUN_TEST_CASE(coverage_msg1, msg1_compose_with_ead);
}
