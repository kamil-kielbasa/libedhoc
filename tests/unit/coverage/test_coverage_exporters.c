/**
 * \file    test_coverage_exporters.c
 * \author  Kamil Kielbasa
 * \brief   Coverage tests for EDHOC exporter error paths.
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

TEST_GROUP(coverage_exporters);

TEST_SETUP(coverage_exporters)
{
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, psa_crypto_init());
}

TEST_TEAR_DOWN(coverage_exporters)
{
	mbedtls_psa_crypto_free();
}

TEST(coverage_exporters, prk_exporter_bad_label)
{
	struct edhoc_context ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context(&ctx, EDHOC_METHOD_0));
	ctx.status = EDHOC_SM_COMPLETED;
	ctx.prk_state = EDHOC_PRK_STATE_OUT;

	uint8_t secret[32] = { 0 };
	coverage_mock_reset(0);
	int ret = edhoc_export_prk_exporter(&ctx, 100, NULL, 0, secret,
					    sizeof(secret));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(coverage_exporters, prk_exporter_expand_fail)
{
	struct edhoc_context ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context(&ctx, EDHOC_METHOD_0));
	ctx.status = EDHOC_SM_COMPLETED;
	ctx.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.th_len = 32;

	uint8_t secret[32] = { 0 };
	coverage_mock_reset(2);
	int ret = edhoc_export_prk_exporter(&ctx, 32769, NULL, 0, secret,
					    sizeof(secret));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(coverage_exporters, oscore_export_wrong_status)
{
	struct edhoc_context ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context(&ctx, EDHOC_METHOD_0));
	ctx.status = EDHOC_SM_COMPLETED;
	ctx.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.is_oscore_export_allowed = true;
	ctx.th_len = 32;
	ctx.peer_cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.peer_cid.int_value = -8;

	uint8_t ms[16], salt[8], sid[8], rid[8];
	size_t sid_len, rid_len;

	coverage_mock_reset(0);
	int ret = edhoc_export_oscore_session(&ctx, ms, sizeof(ms), salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, rid, sizeof(rid),
					      &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(coverage_exporters, key_update_success)
{
	struct edhoc_context ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context(&ctx, EDHOC_METHOD_0));
	ctx.status = EDHOC_SM_COMPLETED;
	ctx.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.th_len = 32;

	uint8_t entropy[16] = { 1, 2, 3 };
	coverage_mock_reset(0);
	int ret = edhoc_export_key_update(&ctx, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(ctx.is_oscore_export_allowed);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(coverage_exporters, key_update_extract_fail)
{
	struct edhoc_context ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context(&ctx, EDHOC_METHOD_0));
	ctx.status = EDHOC_SM_COMPLETED;
	ctx.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.th_len = 32;

	uint8_t entropy[16] = { 1, 2, 3 };
	coverage_mock_reset(1);
	int ret = edhoc_export_key_update(&ctx, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(coverage_exporters, oscore_export_bstr_cid)
{
	struct edhoc_context ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context(&ctx, EDHOC_METHOD_0));
	ctx.status = EDHOC_SM_COMPLETED;
	ctx.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.is_oscore_export_allowed = true;
	ctx.th_len = 32;
	ctx.peer_cid.encode_type = EDHOC_CID_TYPE_BYTE_STRING;
	ctx.peer_cid.bstr_length = 2;
	ctx.peer_cid.bstr_value[0] = 0xAA;
	ctx.peer_cid.bstr_value[1] = 0xBB;

	uint8_t ms[16], salt[8], sid[8], rid[8];
	size_t sid_len, rid_len;

	coverage_mock_reset(0);
	int ret = edhoc_export_oscore_session(&ctx, ms, sizeof(ms), salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, rid, sizeof(rid),
					      &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(coverage_exporters, prk_exporter_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 2;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context ctx = { 0 };
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
							 &ctx, EDHOC_METHOD_0));
		ctx.status = EDHOC_SM_COMPLETED;
		ctx.prk_state = EDHOC_PRK_STATE_OUT;
		ctx.th_len = 32;

		uint8_t secret[32] = { 0 };
		coverage_mock_reset(fail_pt);
		int ret = edhoc_export_prk_exporter(&ctx, 32769, NULL, 0,
						    secret, sizeof(secret));
		if (fail_pt == 1) {
			TEST_ASSERT_EQUAL(EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE,
					  ret);
		} else {
			TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
		}

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
	}
}

TEST(coverage_exporters, oscore_export_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 4;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context ctx = { 0 };
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
							 &ctx, EDHOC_METHOD_0));
		ctx.status = EDHOC_SM_COMPLETED;
		ctx.prk_state = EDHOC_PRK_STATE_OUT;
		ctx.is_oscore_export_allowed = true;
		ctx.th_len = 32;
		ctx.peer_cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
		ctx.peer_cid.int_value = -8;

		uint8_t ms[16], salt[8], sid[8], rid[8];
		size_t sid_len, rid_len;

		coverage_mock_reset(fail_pt);
		int ret = edhoc_export_oscore_session(
			&ctx, ms, sizeof(ms), salt, sizeof(salt), sid,
			sizeof(sid), &sid_len, rid, sizeof(rid), &rid_len);
		TEST_ASSERT_EQUAL(EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE, ret);

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
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
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init_ctx,
							      EDHOC_METHOD_0));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp_ctx,
							      EDHOC_METHOD_0));

		int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
					  edhoc_context_deinit(&init_ctx));
			TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
					  edhoc_context_deinit(&resp_ctx));
			continue;
		}

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
		coverage_assert_sweep_result(
			ret, coverage_oscore_export_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
	}
}

TEST(coverage_exporters, oscore_export_after_bstr_cid_handshake)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context_bstr_cid(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context_bstr_cid(
						 &resp_ctx, EDHOC_METHOD_0));

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	uint8_t master_secret[32] = { 0 };
	uint8_t master_salt[32] = { 0 };
	uint8_t sender_id[16] = { 0 };
	uint8_t recipient_id[16] = { 0 };
	size_t sender_id_len, recipient_id_len;
	ret = edhoc_export_oscore_session(&resp_ctx, master_secret,
					  sizeof(master_secret), master_salt,
					  sizeof(master_salt), sender_id,
					  sizeof(sender_id), &sender_id_len,
					  recipient_id, sizeof(recipient_id),
					  &recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_exporters, oscore_export_invalid_cid_type)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.peer_cid.encode_type = (enum edhoc_connection_id_type)99;

	coverage_mock_reset(0);
	uint8_t master_secret[32] = { 0 };
	uint8_t master_salt[32] = { 0 };
	uint8_t sender_id[16] = { 0 };
	uint8_t recipient_id[16] = { 0 };
	size_t sender_id_len, recipient_id_len;
	ret = edhoc_export_oscore_session(&resp_ctx, master_secret,
					  sizeof(master_secret), master_salt,
					  sizeof(master_salt), sender_id,
					  sizeof(sender_id), &sender_id_len,
					  recipient_id, sizeof(recipient_id),
					  &recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_exporters, oscore_export_invalid_own_cid_type)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.cid.encode_type = (enum edhoc_connection_id_type)99;

	coverage_mock_reset(0);
	uint8_t master_secret[32] = { 0 };
	uint8_t master_salt[32] = { 0 };
	uint8_t sender_id[16] = { 0 };
	uint8_t recipient_id[16] = { 0 };
	size_t sender_id_len, recipient_id_len;
	ret = edhoc_export_oscore_session(&resp_ctx, master_secret,
					  sizeof(master_secret), master_salt,
					  sizeof(master_salt), sender_id,
					  sizeof(sender_id), &sender_id_len,
					  recipient_id, sizeof(recipient_id),
					  &recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_exporters, oscore_export_bstr_cid_sid_too_small)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context_bstr_cid(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context_bstr_cid(
						 &resp_ctx, EDHOC_METHOD_0));

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	uint8_t master_secret[32] = { 0 };
	uint8_t master_salt[32] = { 0 };
	uint8_t sender_id[1] = { 0 };
	uint8_t recipient_id[16] = { 0 };
	size_t sender_id_len, recipient_id_len;
	ret = edhoc_export_oscore_session(&resp_ctx, master_secret,
					  sizeof(master_secret), master_salt,
					  sizeof(master_salt), sender_id,
					  sizeof(sender_id), &sender_id_len,
					  recipient_id, sizeof(recipient_id),
					  &recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_exporters, oscore_export_bstr_cid_rid_too_small)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context_bstr_cid(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context_bstr_cid(
						 &resp_ctx, EDHOC_METHOD_0));

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	coverage_mock_reset(0);
	uint8_t master_secret[32] = { 0 };
	uint8_t master_salt[32] = { 0 };
	uint8_t sender_id[16] = { 0 };
	uint8_t recipient_id[1] = { 0 };
	size_t sender_id_len, recipient_id_len;
	ret = edhoc_export_oscore_session(&resp_ctx, master_secret,
					  sizeof(master_secret), master_salt,
					  sizeof(master_salt), sender_id,
					  sizeof(sender_id), &sender_id_len,
					  recipient_id, sizeof(recipient_id),
					  &recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_exporters, key_update_prk_state_4e3m)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));

	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	int ret = coverage_do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
						sizeof(msg3), &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.status = EDHOC_SM_COMPLETED;
	init_ctx.th_state = EDHOC_TH_STATE_4;
	init_ctx.prk_state = EDHOC_PRK_STATE_4E3M;

	coverage_mock_reset(0);
	uint8_t entropy[32] = { 0x42 };
	ret = edhoc_export_key_update(&init_ctx, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_exporters, key_update_prk_state_4e3m_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));

	uint8_t msg3[512] = { 0 };
	size_t msg3_len = 0;
	int ret = coverage_do_mock_msg3_compose(&init_ctx, &resp_ctx, msg3,
						sizeof(msg3), &msg3_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	init_ctx.status = EDHOC_SM_COMPLETED;
	init_ctx.th_state = EDHOC_TH_STATE_4;
	init_ctx.prk_state = EDHOC_PRK_STATE_4E3M;

	coverage_mock_reset(1);
	uint8_t entropy[32] = { 0x42 };
	ret = edhoc_export_key_update(&init_ctx, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_exporters, oscore_export_prk_state_4e3m)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &init_ctx, EDHOC_METHOD_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_setup_mock_context(
						 &resp_ctx, EDHOC_METHOD_0));

	int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	resp_ctx.th_state = EDHOC_TH_STATE_4;

	coverage_mock_reset(0);
	uint8_t master_secret[32] = { 0 };
	uint8_t master_salt[32] = { 0 };
	uint8_t sender_id[16] = { 0 };
	uint8_t recipient_id[16] = { 0 };
	size_t sender_id_len, recipient_id_len;
	ret = edhoc_export_oscore_session(&resp_ctx, master_secret,
					  sizeof(master_secret), master_salt,
					  sizeof(master_salt), sender_id,
					  sizeof(sender_id), &sender_id_len,
					  recipient_id, sizeof(recipient_id),
					  &recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_exporters, oscore_export_failure_sweep_4e3m)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 15;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init_ctx,
							      EDHOC_METHOD_0));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp_ctx,
							      EDHOC_METHOD_0));

		int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
					  edhoc_context_deinit(&init_ctx));
			TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
					  edhoc_context_deinit(&resp_ctx));
			continue;
		}

		resp_ctx.prk_state = EDHOC_PRK_STATE_4E3M;
		resp_ctx.th_state = EDHOC_TH_STATE_4;

		coverage_mock_reset(fail_pt);
		uint8_t master_secret[32] = { 0 };
		uint8_t master_salt[32] = { 0 };
		uint8_t sender_id[16] = { 0 };
		uint8_t recipient_id[16] = { 0 };
		size_t sender_id_len, recipient_id_len;
		ret = edhoc_export_oscore_session(
			&resp_ctx, master_secret, sizeof(master_secret),
			master_salt, sizeof(master_salt), sender_id,
			sizeof(sender_id), &sender_id_len, recipient_id,
			sizeof(recipient_id), &recipient_id_len);
		coverage_assert_sweep_result(
			ret,
			coverage_oscore_export_extended_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
	}
}

TEST(coverage_exporters, oscore_export_bstr_cid_failure_sweep)
{
	const int mock_fail_pt_first = 1;
	const int mock_fail_pt_last = 15;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     fail_pt++) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context_bstr_cid(
					  &init_ctx, EDHOC_METHOD_0));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context_bstr_cid(
					  &resp_ctx, EDHOC_METHOD_0));

		int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
					  edhoc_context_deinit(&init_ctx));
			TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
					  edhoc_context_deinit(&resp_ctx));
			continue;
		}

		coverage_mock_reset(fail_pt);
		uint8_t master_secret[32] = { 0 };
		uint8_t master_salt[32] = { 0 };
		uint8_t sender_id[16] = { 0 };
		uint8_t recipient_id[16] = { 0 };
		size_t sender_id_len, recipient_id_len;
		ret = edhoc_export_oscore_session(
			&resp_ctx, master_secret, sizeof(master_secret),
			master_salt, sizeof(master_salt), sender_id,
			sizeof(sender_id), &sender_id_len, recipient_id,
			sizeof(recipient_id), &recipient_id_len);
		coverage_assert_sweep_result(
			ret,
			coverage_oscore_export_extended_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
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
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&init_ctx,
							      EDHOC_METHOD_0));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_setup_mock_context(&resp_ctx,
							      EDHOC_METHOD_0));

		int ret = coverage_do_mock_msg3_process(&init_ctx, &resp_ctx);
		if (EDHOC_SUCCESS != ret) {
			TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
					  edhoc_context_deinit(&init_ctx));
			TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
					  edhoc_context_deinit(&resp_ctx));
			continue;
		}

		coverage_mock_reset(fail_pt);
		uint8_t entropy[32] = { 0x42 };
		ret = edhoc_export_key_update(&resp_ctx, entropy,
					      sizeof(entropy));
		coverage_assert_sweep_result(
			ret, coverage_key_update_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
	}
}

TEST_GROUP_RUNNER(coverage_exporters)
{
	RUN_TEST_CASE(coverage_exporters, prk_exporter_bad_label);
	RUN_TEST_CASE(coverage_exporters, prk_exporter_expand_fail);
	RUN_TEST_CASE(coverage_exporters, oscore_export_wrong_status);
	RUN_TEST_CASE(coverage_exporters, key_update_success);
	RUN_TEST_CASE(coverage_exporters, key_update_extract_fail);
	RUN_TEST_CASE(coverage_exporters, oscore_export_bstr_cid);
	RUN_TEST_CASE(coverage_exporters, prk_exporter_failure_sweep);
	RUN_TEST_CASE(coverage_exporters, oscore_export_failure_sweep);
	RUN_TEST_CASE(coverage_exporters, exporter_failure_sweep_extended);
	RUN_TEST_CASE(coverage_exporters,
		      oscore_export_after_bstr_cid_handshake);
	RUN_TEST_CASE(coverage_exporters, oscore_export_invalid_cid_type);
	RUN_TEST_CASE(coverage_exporters, oscore_export_invalid_own_cid_type);
	RUN_TEST_CASE(coverage_exporters, oscore_export_bstr_cid_sid_too_small);
	RUN_TEST_CASE(coverage_exporters, oscore_export_bstr_cid_rid_too_small);
	RUN_TEST_CASE(coverage_exporters, key_update_prk_state_4e3m);
	RUN_TEST_CASE(coverage_exporters, key_update_prk_state_4e3m_fail);
	RUN_TEST_CASE(coverage_exporters, oscore_export_prk_state_4e3m);
	RUN_TEST_CASE(coverage_exporters, oscore_export_failure_sweep_4e3m);
	RUN_TEST_CASE(coverage_exporters, oscore_export_bstr_cid_failure_sweep);
	RUN_TEST_CASE(coverage_exporters, key_update_failure_sweep);
}
