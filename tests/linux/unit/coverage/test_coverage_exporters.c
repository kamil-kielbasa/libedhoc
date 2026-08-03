/**
 * \file    test_coverage_exporters.c
 * \author  Kamil Kielbasa
 * \brief   Coverage tests for EDHOC exporter error paths.
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

TEST_GROUP(coverage_exporters);

TEST_SETUP(coverage_exporters)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(coverage_exporters)
{
	mbedtls_psa_crypto_free();
}

TEST(coverage_exporters, export_raw_expand_fail)
{
	struct edhoc_context ctx = { 0 };

	int ret = coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.state.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.state.th.length = 32;

	uint8_t secret[32] = { 0 };
	coverage_mock_reset(2);
	ret = edhoc_export_raw(&ctx, 32769, NULL, 0, secret, sizeof(secret));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_exporters, oscore_export_raw_wrong_status)
{
	struct edhoc_context ctx = { 0 };

	int ret = coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.state.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.is_oscore_export_allowed = true;
	ctx.state.th.length = 32;
	ctx.negotiation.peer_connection_id.value[0] = 0x27;
	ctx.negotiation.peer_connection_id.length = 1;

	uint8_t ms[16] = { 0 };
	uint8_t salt[8] = { 0 };
	uint8_t sid[8] = { 0 };
	uint8_t rid[8] = { 0 };
	size_t sid_len = 0;
	size_t rid_len = 0;

	coverage_mock_reset(0);

	ret = edhoc_export_oscore_context_raw(&ctx, ms, sizeof(ms), salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, rid, sizeof(rid),
					      &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_exporters, key_update_success)
{
	struct edhoc_context ctx = { 0 };

	int ret = coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.state.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.state.th.length = 32;

	uint8_t context[16] = { 1, 2, 3 };

	coverage_mock_reset(0);

	ret = edhoc_export_key_update(&ctx, context, sizeof(context));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(ctx.is_oscore_export_allowed);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_exporters, key_update_extract_fail)
{
	struct edhoc_context ctx = { 0 };

	int ret = coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.state.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.state.th.length = 32;

	uint8_t context[16] = { 1, 2, 3 };

	coverage_mock_reset(1);

	ret = edhoc_export_key_update(&ctx, context, sizeof(context));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_exporters, oscore_export_raw_bstr_cid)
{
	struct edhoc_context ctx = { 0 };

	int ret = coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ctx.state.machine = EDHOC_SM_COMPLETED;
	ctx.state.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.is_oscore_export_allowed = true;
	ctx.state.th.length = 32;
	ctx.negotiation.peer_connection_id.value[0] = 0xAA;
	ctx.negotiation.peer_connection_id.value[1] = 0xBB;
	ctx.negotiation.peer_connection_id.length = 2;

	uint8_t ms[16] = { 0 };
	uint8_t salt[8] = { 0 };
	uint8_t sid[8] = { 0 };
	uint8_t rid[8] = { 0 };
	size_t sid_len = 0;
	size_t rid_len = 0;

	coverage_mock_reset(0);

	ret = edhoc_export_oscore_context_raw(&ctx, ms, sizeof(ms), salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, rid, sizeof(rid),
					      &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_exporters, export_raw_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 2;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context ctx = { 0 };

		int ret = coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ctx.state.machine = EDHOC_SM_COMPLETED;
		ctx.state.prk_state = EDHOC_PRK_STATE_OUT;
		ctx.state.th.length = 32;

		coverage_mock_reset(fail_pt);

		uint8_t secret[32] = { 0 };
		ret = edhoc_export_raw(&ctx, 32769, NULL, 0, secret,
				       sizeof(secret));
		if (fail_pt == 1) {
			TEST_ASSERT_EQUAL(EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE,
					  ret);
		} else {
			TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
		}

		ret = edhoc_context_deinit(&ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_exporters, oscore_export_raw_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 4;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context ctx = { 0 };

		int ret = coverage_setup_mock_context(&ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ctx.state.machine = EDHOC_SM_COMPLETED;
		ctx.state.prk_state = EDHOC_PRK_STATE_OUT;
		ctx.is_oscore_export_allowed = true;
		ctx.state.th.length = 32;
		ctx.negotiation.peer_connection_id.value[0] = 0x27;
		ctx.negotiation.peer_connection_id.length = 1;

		uint8_t ms[16] = { 0 };
		uint8_t salt[8] = { 0 };
		uint8_t sid[8] = { 0 };
		uint8_t rid[8] = { 0 };
		size_t sid_len = 0;
		size_t rid_len = 0;

		coverage_mock_reset(fail_pt);

		ret = edhoc_export_oscore_context_raw(
			&ctx, ms, sizeof(ms), salt, sizeof(salt), sid,
			sizeof(sid), &sid_len, rid, sizeof(rid), &rid_len);
		TEST_ASSERT_EQUAL(EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE, ret);

		ret = edhoc_context_deinit(&ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_exporters, exporter_failure_sweep_extended)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 15;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };

		int ret =
			coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
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
		size_t sender_id_len = 0;
		size_t recipient_id_len = 0;

		ret = edhoc_export_oscore_context_raw(
			&init_ctx, master_secret, sizeof(master_secret),
			master_salt, sizeof(master_salt), sender_id,
			sizeof(sender_id), &sender_id_len, recipient_id,
			sizeof(recipient_id), &recipient_id_len);
		coverage_assert_sweep_result(
			ret, coverage_oscore_export_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_exporters, oscore_export_raw_after_bstr_cid_handshake)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret =
		coverage_setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	uint8_t master_secret[32] = { 0 };
	uint8_t master_salt[32] = { 0 };
	uint8_t sender_id[16] = { 0 };
	uint8_t recipient_id[16] = { 0 };
	size_t sender_id_len = 0;
	size_t recipient_id_len = 0;

	ret = edhoc_export_oscore_context_raw(
		&resp_ctx, master_secret, sizeof(master_secret), master_salt,
		sizeof(master_salt), sender_id, sizeof(sender_id),
		&sender_id_len, recipient_id, sizeof(recipient_id),
		&recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_exporters, oscore_export_raw_bstr_cid_sid_too_small)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret =
		coverage_setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t master_secret[32] = { 0 };
	uint8_t master_salt[32] = { 0 };
	uint8_t sender_id[1] = { 0 };
	uint8_t recipient_id[16] = { 0 };
	size_t sender_id_len = 0;
	size_t recipient_id_len = 0;

	ret = edhoc_export_oscore_context_raw(
		&resp_ctx, master_secret, sizeof(master_secret), master_salt,
		sizeof(master_salt), sender_id, sizeof(sender_id),
		&sender_id_len, recipient_id, sizeof(recipient_id),
		&recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_exporters, oscore_export_raw_bstr_cid_rid_too_small)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret =
		coverage_setup_mock_context_bstr_cid(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context_bstr_cid(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);

	uint8_t master_secret[32] = { 0 };
	uint8_t master_salt[32] = { 0 };
	uint8_t sender_id[16] = { 0 };
	uint8_t recipient_id[1] = { 0 };
	size_t sender_id_len = 0;
	size_t recipient_id_len = 0;

	ret = edhoc_export_oscore_context_raw(
		&resp_ctx, master_secret, sizeof(master_secret), master_salt,
		sizeof(master_salt), sender_id, sizeof(sender_id),
		&sender_id_len, recipient_id, sizeof(recipient_id),
		&recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_exporters, key_update_prk_state_4e3m)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;

	ret = coverage_do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
					    sizeof(msg3), &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.state.machine = EDHOC_SM_COMPLETED;
	init_ctx.state.th.stage = EDHOC_TH_STATE_4;
	init_ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;

	coverage_mock_reset(0);

	uint8_t context[32] = { 0x42 };

	ret = edhoc_export_key_update(&init_ctx, context, sizeof(context));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_exporters, key_update_prk_state_4e3m_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;

	ret = coverage_do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
					    sizeof(msg3), &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.state.machine = EDHOC_SM_COMPLETED;
	init_ctx.state.th.stage = EDHOC_TH_STATE_4;
	init_ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;

	coverage_mock_reset(1);

	uint8_t context[32] = { 0x42 };

	ret = edhoc_export_key_update(&init_ctx, context, sizeof(context));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_exporters, oscore_export_raw_prk_state_4e3m)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	int ret = coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	resp_ctx.state.th.stage = EDHOC_TH_STATE_4;

	coverage_mock_reset(0);

	uint8_t master_secret[32] = { 0 };
	uint8_t master_salt[32] = { 0 };
	uint8_t sender_id[16] = { 0 };
	uint8_t recipient_id[16] = { 0 };
	size_t sender_id_len = 0;
	size_t recipient_id_len = 0;

	ret = edhoc_export_oscore_context_raw(
		&resp_ctx, master_secret, sizeof(master_secret), master_salt,
		sizeof(master_salt), sender_id, sizeof(sender_id),
		&sender_id_len, recipient_id, sizeof(recipient_id),
		&recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_exporters, oscore_export_raw_failure_sweep_4e3m)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 15;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };

		int ret =
			coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		resp_ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
		resp_ctx.state.th.stage = EDHOC_TH_STATE_4;

		coverage_mock_reset(fail_pt);

		uint8_t master_secret[32] = { 0 };
		uint8_t master_salt[32] = { 0 };
		uint8_t sender_id[16] = { 0 };
		uint8_t recipient_id[16] = { 0 };
		size_t sender_id_len = 0;
		size_t recipient_id_len = 0;

		ret = edhoc_export_oscore_context_raw(
			&resp_ctx, master_secret, sizeof(master_secret),
			master_salt, sizeof(master_salt), sender_id,
			sizeof(sender_id), &sender_id_len, recipient_id,
			sizeof(recipient_id), &recipient_id_len);

		coverage_assert_sweep_result(
			ret,
			coverage_oscore_export_extended_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_exporters, oscore_export_raw_bstr_cid_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 15;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };

		int ret = coverage_setup_mock_context_bstr_cid(&init_ctx,
							       EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context_bstr_cid(&resp_ctx,
							   EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);
		uint8_t master_secret[32] = { 0 };
		uint8_t master_salt[32] = { 0 };
		uint8_t sender_id[16] = { 0 };
		uint8_t recipient_id[16] = { 0 };
		size_t sender_id_len = 0;
		size_t recipient_id_len = 0;
		ret = edhoc_export_oscore_context_raw(
			&resp_ctx, master_secret, sizeof(master_secret),
			master_salt, sizeof(master_salt), sender_id,
			sizeof(sender_id), &sender_id_len, recipient_id,
			sizeof(recipient_id), &recipient_id_len);
		coverage_assert_sweep_result(
			ret,
			coverage_oscore_export_extended_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST(coverage_exporters, key_update_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 10;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };

		int ret =
			coverage_setup_mock_context(&init_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_setup_mock_context(&resp_ctx, EDHOC_METHOD_0);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

		coverage_mock_reset(fail_pt);

		uint8_t context[32] = { 0x42 };

		ret = edhoc_export_key_update(&resp_ctx, context,
					      sizeof(context));
		coverage_assert_sweep_result(
			ret, coverage_key_update_must_fail(fail_pt));

		ret = edhoc_context_deinit(&init_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
		ret = edhoc_context_deinit(&resp_ctx);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}

TEST_GROUP_RUNNER(coverage_exporters)
{
	RUN_TEST_CASE(coverage_exporters, export_raw_expand_fail);
	RUN_TEST_CASE(coverage_exporters, oscore_export_raw_wrong_status);
	RUN_TEST_CASE(coverage_exporters, key_update_success);
	RUN_TEST_CASE(coverage_exporters, key_update_extract_fail);
	RUN_TEST_CASE(coverage_exporters, oscore_export_raw_bstr_cid);
	RUN_TEST_CASE(coverage_exporters, export_raw_failure_sweep);
	RUN_TEST_CASE(coverage_exporters, oscore_export_raw_failure_sweep);
	RUN_TEST_CASE(coverage_exporters, exporter_failure_sweep_extended);
	RUN_TEST_CASE(coverage_exporters,
		      oscore_export_raw_after_bstr_cid_handshake);
	RUN_TEST_CASE(coverage_exporters,
		      oscore_export_raw_bstr_cid_sid_too_small);
	RUN_TEST_CASE(coverage_exporters,
		      oscore_export_raw_bstr_cid_rid_too_small);
	RUN_TEST_CASE(coverage_exporters, key_update_prk_state_4e3m);
	RUN_TEST_CASE(coverage_exporters, key_update_prk_state_4e3m_fail);
	RUN_TEST_CASE(coverage_exporters, oscore_export_raw_prk_state_4e3m);
	RUN_TEST_CASE(coverage_exporters, oscore_export_raw_failure_sweep_4e3m);
	RUN_TEST_CASE(coverage_exporters,
		      oscore_export_raw_bstr_cid_failure_sweep);
	RUN_TEST_CASE(coverage_exporters, key_update_failure_sweep);
}
