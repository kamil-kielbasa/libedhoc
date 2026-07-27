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
	psa_status_t status = psa_crypto_init();
	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(coverage_handshake)
{
	mbedtls_psa_crypto_free();
}

TEST(coverage_handshake, mock_full_handshake_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret;

	ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg4_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_handshake, mock_full_handshake_method1)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret;

	ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg4_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_handshake, mock_full_handshake_method2)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret;

	ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_2);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_2);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg4_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_handshake, mock_full_handshake_method3)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret;

	ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_3);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_3);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg4_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_handshake, mock_handshake_kid_int_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret;

	ret = coverage_setup_mock_context_kid(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = coverage_setup_mock_context_kid(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg4_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_handshake, mock_handshake_kid_int_method3)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret;

	ret = coverage_setup_mock_context_kid(&init_ctx, EDHOC_METHOD_3);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = coverage_setup_mock_context_kid(&resp_ctx, EDHOC_METHOD_3);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg4_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_handshake, mock_handshake_kid_bstr_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret;

	ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_bind_credentials(&init_ctx, &coverage_mock_creds_kid_bstr);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_bind_credentials(&resp_ctx, &coverage_mock_creds_kid_bstr);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg4_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_handshake, mock_handshake_x5t_bstr_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret;

	ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_bind_credentials(&init_ctx, &coverage_mock_creds_x5t_bstr);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_bind_credentials(&resp_ctx, &coverage_mock_creds_x5t_bstr);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg4_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_handshake, mock_handshake_x5t_int_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret;

	ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_bind_credentials(&init_ctx, &coverage_mock_creds_x5t_int);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_bind_credentials(&resp_ctx, &coverage_mock_creds_x5t_int);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg4_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_handshake, mock_handshake_x5chain_multi_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret;

	ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_bind_credentials(&init_ctx,
				     &coverage_mock_creds_x5chain_multi);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_bind_credentials(&resp_ctx,
				     &coverage_mock_creds_x5chain_multi);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg4_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_handshake, mock_handshake_cose_any_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret;

	ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_bind_credentials(&init_ctx, &coverage_mock_creds_cose_any);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_bind_credentials(&resp_ctx, &coverage_mock_creds_cose_any);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg4_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_handshake, mock_handshake_bstr_cid_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret;

	ret = coverage_setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = coverage_setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg4_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_handshake, mock_handshake_ead_with_values)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret;

	ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_bind_ead(&init_ctx, &coverage_mock_ead_with_value);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_bind_ead(&resp_ctx, &coverage_mock_ead_with_value);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg4_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(coverage_handshake)
{
	RUN_TEST_CASE(coverage_handshake, mock_full_handshake_method0);
	RUN_TEST_CASE(coverage_handshake, mock_full_handshake_method1);
	RUN_TEST_CASE(coverage_handshake, mock_full_handshake_method2);
	RUN_TEST_CASE(coverage_handshake, mock_full_handshake_method3);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_kid_int_method0);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_kid_int_method3);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_kid_bstr_method0);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_x5t_bstr_method0);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_x5t_int_method0);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_x5chain_multi_method0);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_cose_any_method0);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_bstr_cid_method0);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_ead_with_values);
}
