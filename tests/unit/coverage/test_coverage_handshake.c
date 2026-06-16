/**
 * \file    test_coverage_handshake.c
 * \author  Kamil Kielbasa
 * \brief   Coverage tests for mock full-handshake flows.
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

TEST_GROUP(coverage_handshake);

TEST_SETUP(coverage_handshake)
{
	psa_crypto_init();
}

TEST_TEAR_DOWN(coverage_handshake)
{
	mbedtls_psa_crypto_free();
}

TEST(coverage_handshake, mock_full_handshake_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_handshake, mock_full_handshake_method1)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_1);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_1);

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_handshake, mock_full_handshake_method2)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_2);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_2);

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_handshake, mock_full_handshake_method3)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_3);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_handshake, mock_full_handshake_msg4_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);

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

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_handshake, mock_full_handshake_msg4_method3)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_3);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_3);

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

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_handshake, mock_handshake_kid_int_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context_kid(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context_kid(&resp_ctx, EDHOC_METHOD_0);

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_handshake, mock_handshake_kid_int_method3)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context_kid(&init_ctx, EDHOC_METHOD_3);
	coverage_setup_mock_context_kid(&resp_ctx, EDHOC_METHOD_3);

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_handshake, mock_handshake_kid_bstr_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	edhoc_bind_credentials(&init_ctx, &coverage_mock_creds_kid_bstr);
	edhoc_bind_credentials(&resp_ctx, &coverage_mock_creds_kid_bstr);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					     sizeof(msg2), &msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);

cleanup:
	(void)ret;
	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_handshake, mock_handshake_x5t_bstr_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	edhoc_bind_credentials(&init_ctx, &coverage_mock_creds_x5t_bstr);
	edhoc_bind_credentials(&resp_ctx, &coverage_mock_creds_x5t_bstr);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					     sizeof(msg2), &msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);

cleanup:
	(void)ret;
	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_handshake, mock_handshake_x5t_int_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	edhoc_bind_credentials(&init_ctx, &coverage_mock_creds_x5t_int);
	edhoc_bind_credentials(&resp_ctx, &coverage_mock_creds_x5t_int);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					     sizeof(msg2), &msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);

cleanup:
	(void)ret;
	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_handshake, mock_handshake_x5chain_multi_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	edhoc_bind_credentials(&init_ctx, &coverage_mock_creds_x5chain_multi);
	edhoc_bind_credentials(&resp_ctx, &coverage_mock_creds_x5chain_multi);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					     sizeof(msg2), &msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);

cleanup:
	(void)ret;
	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_handshake, mock_handshake_cose_any_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	edhoc_bind_credentials(&init_ctx, &coverage_mock_creds_cose_any);
	edhoc_bind_credentials(&resp_ctx, &coverage_mock_creds_cose_any);

	uint8_t msg2[512] = { 0 };
	size_t msg2_len = 0;
	int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
					     sizeof(msg2), &msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	ret = edhoc_message_2_process(&init_ctx, msg2, msg2_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3), &msg3_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	ret = edhoc_message_3_process(&resp_ctx, msg3, msg3_len);

cleanup:
	(void)ret;
	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_handshake, mock_handshake_bstr_cid_method0)
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

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_handshake, mock_full_handshake_msg4_method1)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_1);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_1);

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

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_handshake, mock_full_handshake_msg4_method2)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_2);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_2);

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

	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST(coverage_handshake, mock_handshake_ead_with_values)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	edhoc_bind_ead(&init_ctx, &coverage_mock_ead_with_value);
	edhoc_bind_ead(&resp_ctx, &coverage_mock_ead_with_value);

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	uint8_t msg4[512] = { 0 };
	size_t msg4_len = 0;
	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	if (EDHOC_SUCCESS != ret)
		goto cleanup;

	coverage_mock_reset(0);
	ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);

cleanup:
	edhoc_context_deinit(&init_ctx);
	edhoc_context_deinit(&resp_ctx);
}

TEST_GROUP_RUNNER(coverage_handshake)
{
	RUN_TEST_CASE(coverage_handshake, mock_full_handshake_method0);
	RUN_TEST_CASE(coverage_handshake, mock_full_handshake_method1);
	RUN_TEST_CASE(coverage_handshake, mock_full_handshake_method2);
	RUN_TEST_CASE(coverage_handshake, mock_full_handshake_method3);
	RUN_TEST_CASE(coverage_handshake, mock_full_handshake_msg4_method0);
	RUN_TEST_CASE(coverage_handshake, mock_full_handshake_msg4_method3);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_kid_int_method0);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_kid_int_method3);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_kid_bstr_method0);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_x5t_bstr_method0);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_x5t_int_method0);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_x5chain_multi_method0);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_cose_any_method0);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_bstr_cid_method0);
	RUN_TEST_CASE(coverage_handshake, mock_full_handshake_msg4_method1);
	RUN_TEST_CASE(coverage_handshake, mock_full_handshake_msg4_method2);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_ead_with_values);
}
