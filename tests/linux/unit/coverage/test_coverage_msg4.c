/**
 * \file    test_coverage_msg4.c
 * \author  Kamil Kielbasa
 * \brief   Coverage tests for EDHOC message 4 error paths.
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
 * operation to fail. Each sweep drives message 4 compose/process across a range
 * of fail points [mock_fail_pt_first .. mock_fail_pt_last] and checks the
 * outcome against the expectation tables in coverage_sweep.h; a range simply
 * enumerates the mock operation indices reached by that particular variant.
 */

TEST_GROUP(coverage_msg4);

TEST_SETUP(coverage_msg4)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(coverage_msg4)
{
	mbedtls_psa_crypto_free();
}

TEST(coverage_msg4, msg4_compose_bad_state)
{
	struct edhoc_context ctx = { 0 };
	int ret = coverage_setup_mock_context_initiator(&ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	coverage_mock_reset(0);

	uint8_t msg[512] = { 0 };
	size_t msg_len = 0;
	ret = edhoc_message_4_compose(&ctx, msg, sizeof(msg), &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg4, msg4_compose_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 20;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;

		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		coverage_assert_sweep_result(
			ret, coverage_msg4_compose_sweep_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg4, msg4_process_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 20;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(0);

		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;

		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		coverage_assert_sweep_result(
			ret, coverage_msg4_process_sweep_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg4, msg4_compose_method3_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 25;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };

		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_3);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_3);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;

		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		coverage_assert_sweep_result(
			ret, coverage_msg4_compose_method_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg4, msg4_process_method3_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 25;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };

		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_3);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_3);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(0);

		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;

		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		coverage_assert_sweep_result(
			ret, coverage_msg4_process_method_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg4, msg4_compose_failure_sweep_extended)
{
	const int mock_fail_pt_first = 26;
	const int mock_fail_pt_last = 40;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };

		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;

		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		coverage_assert_sweep_result(
			ret, coverage_msg4_compose_extended_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg4, msg4_process_failure_sweep_extended)
{
	const int mock_fail_pt_first = 26;
	const int mock_fail_pt_last = 40;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(0);

		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;

		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		coverage_assert_sweep_result(
			ret, coverage_msg4_process_extended_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg4, msg4_bstr_cid_full)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	int ret = coverage_setup_mock_context_bstr_cid_initiator(
		&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_bstr_cid_responder(&resp_ctx,
							     EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
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

	uint8_t master_secret[32] = { 0 };
	uint8_t master_salt[32] = { 0 };
	uint8_t sender_id[16] = { 0 };
	uint8_t recipient_id[16] = { 0 };
	size_t sender_id_len = 0;
	size_t recipient_id_len = 0;
	ret = edhoc_export_oscore_context_raw(
		&init_ctx, master_secret, sizeof(master_secret), master_salt,
		sizeof(master_salt), sender_id, sizeof(sender_id),
		&sender_id_len, recipient_id, sizeof(recipient_id),
		&recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg4, msg4_compose_method1_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 25;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_1);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_1);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;

		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		coverage_assert_sweep_result(
			ret, coverage_msg4_compose_method_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg4, msg4_process_method1_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 25;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_1);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_1);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(0);

		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;

		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		coverage_assert_sweep_result(
			ret, coverage_msg4_process_method_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg4, msg4_compose_method2_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 25;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_2);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_2);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;

		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		coverage_assert_sweep_result(
			ret, coverage_msg4_compose_method_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg4, msg4_process_method2_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 25;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_2);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_2);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(0);

		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;

		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		coverage_assert_sweep_result(
			ret, coverage_msg4_process_method_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg4, msg4_compose_tiny_buffer)
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

	coverage_mock_reset(0);

	uint8_t msg4[4] = { 0 };
	size_t msg4_len = 0;

	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg4, msg4_process_bad_state)
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

	coverage_mock_reset(0);

	uint8_t msg4[256] = { 0 };
	size_t msg4_len = 0;

	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.state.machine = EDHOC_SM_START;
	ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg4, msg4_compose_corrupted_state)
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

	resp_ctx.state.machine = EDHOC_SM_START;

	uint8_t msg4[256] = { 0 };
	size_t msg4_len = 0;

	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg4, msg4_process_truncated)
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

	coverage_mock_reset(0);

	uint8_t msg4[256] = { 0 };
	size_t msg4_len = 0;

	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	ret = edhoc_message_4_process(&init_ctx, msg4, 2);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_MSG_4_PROCESS_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg4, msg4_process_ead_failure)
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

	/* Bind EAD to responder: compose with a token */
	const struct edhoc_ead ead_resp = {
		.compose = coverage_mock_ead_compose_with_token,
		.process = coverage_mock_ead_process,
	};
	ret = edhoc_bind_ead(&resp_ctx, &ead_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Bind EAD to initiator: process always fails */
	const struct edhoc_ead ead_init = {
		.compose = coverage_mock_ead_compose,
		.process = coverage_mock_ead_process_fail,
	};
	ret = edhoc_bind_ead(&init_ctx, &ead_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t msg4[512] = { 0 };
	size_t msg4_len = 0;

	ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4), &msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_EAD_PROCESS_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_msg4, msg4_compose_failure_sweep_gap)
{
	const int mock_fail_pt_first = 21;
	const int mock_fail_pt_last = 25;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;

		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		coverage_assert_sweep_result(
			ret, coverage_msg4_gap_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg4, msg4_process_failure_sweep_gap)
{
	const int mock_fail_pt_first = 21;
	const int mock_fail_pt_last = 25;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		int ret = coverage_setup_mock_context_initiator(&init_ctx,
								EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_responder(&resp_ctx,
							    EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(0);

		uint8_t msg4[512] = { 0 };
		size_t msg4_len = 0;

		ret = edhoc_message_4_compose(&resp_ctx, msg4, sizeof(msg4),
					      &msg4_len);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		ret = edhoc_message_4_process(&init_ctx, msg4, msg4_len);
		coverage_assert_sweep_result(
			ret, coverage_msg4_process_gap_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_msg4, msg4_process_garbage)
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

	uint8_t garbage[] = { 0xFF };

	coverage_mock_reset(0);

	ret = edhoc_message_4_process(&init_ctx, garbage, sizeof(garbage));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_MSG_4_PROCESS_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(coverage_msg4)
{
	/* Compose — targeted failure points. */
	RUN_TEST_CASE(coverage_msg4, msg4_compose_bad_state);
	RUN_TEST_CASE(coverage_msg4, msg4_compose_corrupted_state);
	RUN_TEST_CASE(coverage_msg4, msg4_compose_tiny_buffer);

	/* Compose — fail-point sweeps. */
	RUN_TEST_CASE(coverage_msg4, msg4_compose_failure_sweep);
	RUN_TEST_CASE(coverage_msg4, msg4_compose_failure_sweep_extended);
	RUN_TEST_CASE(coverage_msg4, msg4_compose_failure_sweep_gap);
	RUN_TEST_CASE(coverage_msg4, msg4_compose_method1_failure_sweep);
	RUN_TEST_CASE(coverage_msg4, msg4_compose_method2_failure_sweep);
	RUN_TEST_CASE(coverage_msg4, msg4_compose_method3_failure_sweep);

	/* Process — targeted paths. */
	RUN_TEST_CASE(coverage_msg4, msg4_process_bad_state);
	RUN_TEST_CASE(coverage_msg4, msg4_process_ead_failure);
	RUN_TEST_CASE(coverage_msg4, msg4_process_garbage);
	RUN_TEST_CASE(coverage_msg4, msg4_process_truncated);

	/* Process — fail-point sweeps. */
	RUN_TEST_CASE(coverage_msg4, msg4_process_failure_sweep);
	RUN_TEST_CASE(coverage_msg4, msg4_process_failure_sweep_extended);
	RUN_TEST_CASE(coverage_msg4, msg4_process_failure_sweep_gap);
	RUN_TEST_CASE(coverage_msg4, msg4_process_method1_failure_sweep);
	RUN_TEST_CASE(coverage_msg4, msg4_process_method2_failure_sweep);
	RUN_TEST_CASE(coverage_msg4, msg4_process_method3_failure_sweep);

	/* Full handshake with byte-string connection ID + OSCORE export. */
	RUN_TEST_CASE(coverage_msg4, msg4_bstr_cid_full);
}
