/**
 * \file    test_coverage_handshake.c
 * \author  Kamil Kielbasa
 * \brief   Coverage tests for mock full-handshake flows.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Internal headers: */
#include "coverage_common.h"

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

TEST_GROUP(coverage_handshake);

TEST_SETUP(coverage_handshake)
{
	const psa_status_t status = psa_crypto_init();

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

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
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

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_1);
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

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_2);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_2);
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

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_3);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_3);
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

	int ret = coverage_setup_mock_context_kid_initiator(&init_ctx,
							    EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_kid_responder(&resp_ctx,
							EDHOC_METHOD_0);
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

	int ret = coverage_setup_mock_context_kid_initiator(&init_ctx,
							    EDHOC_METHOD_3);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_kid_responder(&resp_ctx,
							EDHOC_METHOD_3);
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

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
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

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
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

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
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

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
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

TEST(coverage_handshake, mock_handshake_bstr_cid_method0)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_bstr_cid_initiator(
		&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_bstr_cid_responder(&resp_ctx,
							     EDHOC_METHOD_0);
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

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
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

TEST(coverage_handshake, error_msg_rejected_after_completed)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg_err[64] = { 0 };
	size_t msg_err_len = 0;

	ret = edhoc_message_error_compose(
		&resp_ctx, msg_err, sizeof(msg_err), &msg_err_len,
		EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	/* ERR_CODE = 1 with ERR_INFO = "abc". */
	const uint8_t forged[] = { 0x01, 0x63, 0x61, 0x62, 0x63 };
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;

	ret = edhoc_message_error_process(&init_ctx, forged, sizeof(forged),
					  &code, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	/* The rejected error message cost the session nothing. */
	uint8_t master_secret[16] = { 0 };

	ret = edhoc_export_raw(&init_ctx,
			       EDHOC_EXPORTER_LABEL_OSCORE_MASTER_SECRET, NULL,
			       0, master_secret, sizeof(master_secret));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_handshake, message_rejected_after_error_composed)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context_initiator(&init_ctx,
							EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_responder(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg_1[200] = { 0 };
	size_t msg_1_len = 0;

	ret = coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg_1, sizeof(msg_1),
				    &msg_1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg_err[64] = { 0 };
	size_t msg_err_len = 0;

	ret = edhoc_message_error_compose(
		&resp_ctx, msg_err, sizeof(msg_err), &msg_err_len,
		EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;

	ret = edhoc_error_get_code(&resp_ctx, &code);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED, code);

	uint8_t msg_2[500] = { 0 };
	size_t msg_2_len = 0;

	ret = edhoc_message_2_compose(&resp_ctx, msg_2, sizeof(msg_2),
				      &msg_2_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_message_error_process(&init_ctx, msg_err, msg_err_len,
					  &code, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED, code);

	/* Any non-empty payload: the state is checked before the content. */
	ret = edhoc_message_2_process(&init_ctx, msg_2, sizeof(msg_2));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

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
	RUN_TEST_CASE(coverage_handshake, mock_handshake_bstr_cid_method0);
	RUN_TEST_CASE(coverage_handshake, mock_handshake_ead_with_values);
	RUN_TEST_CASE(coverage_handshake, error_msg_rejected_after_completed);
	RUN_TEST_CASE(coverage_handshake,
		      message_rejected_after_error_composed);
}
