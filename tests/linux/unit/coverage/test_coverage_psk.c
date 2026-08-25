/**
 * \file    test_coverage_psk.c
 * \author  Kamil Kielbasa
 * \brief   Coverage tests for the EDHOC-PSK message error paths
 *          (draft-ietf-lake-edhoc-psk: 5).
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

TEST_GROUP(coverage_psk);

TEST_SETUP(coverage_psk)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(coverage_psk)
{
	mbedtls_psa_crypto_free();
}

TEST(coverage_psk, psk_full_flow_no_fail)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_responder(&resp_ctx));

	coverage_mock_reset(0);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_do_mock_msg4_process(&init_ctx, &resp_ctx));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_psk, psk_msg2_compose_failure_sweep)
{
	const int mock_fail_pt_first = 0;
	const int mock_fail_pt_last = 6;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     ++fail_pt) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };

		TEST_ASSERT_EQUAL(
			EDHOC_SUCCESS,
			coverage_setup_mock_context_psk_initiator(&init_ctx));
		TEST_ASSERT_EQUAL(
			EDHOC_SUCCESS,
			coverage_setup_mock_context_psk_responder(&resp_ctx));

		uint8_t msg1[256] = { 0 };
		size_t msg1_len = 0;

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_do_msg1_flow(&init_ctx, &resp_ctx,
							msg1, sizeof(msg1),
							&msg1_len));

		uint8_t msg2[256] = { 0 };
		size_t msg2_len = 0;

		coverage_mock_reset(fail_pt);

		const int ret = edhoc_message_2_compose(
			&resp_ctx, msg2, sizeof(msg2), &msg2_len);

		coverage_assert_sweep_result(
			ret, coverage_psk_msg2_compose_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
	}
}

TEST(coverage_psk, psk_msg2_process_failure_sweep)
{
	const int mock_fail_pt_first = 0;
	const int mock_fail_pt_last = 5;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     ++fail_pt) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };

		TEST_ASSERT_EQUAL(
			EDHOC_SUCCESS,
			coverage_setup_mock_context_psk_initiator(&init_ctx));
		TEST_ASSERT_EQUAL(
			EDHOC_SUCCESS,
			coverage_setup_mock_context_psk_responder(&resp_ctx));

		uint8_t msg2[256] = { 0 };
		size_t msg2_len = 0;

		TEST_ASSERT_EQUAL(
			EDHOC_SUCCESS,
			coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						   sizeof(msg2), &msg2_len));

		coverage_mock_reset(fail_pt);

		const int ret =
			edhoc_message_2_process(&init_ctx, msg2, msg2_len);

		coverage_assert_sweep_result(
			ret, coverage_psk_msg2_process_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
	}
}

TEST(coverage_psk, psk_msg3_compose_failure_sweep)
{
	const int mock_fail_pt_first = 0;
	const int mock_fail_pt_last = 9;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     ++fail_pt) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };

		TEST_ASSERT_EQUAL(
			EDHOC_SUCCESS,
			coverage_setup_mock_context_psk_initiator(&init_ctx));
		TEST_ASSERT_EQUAL(
			EDHOC_SUCCESS,
			coverage_setup_mock_context_psk_responder(&resp_ctx));

		coverage_mock_reset(0);

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_do_mock_msg2_process(
							 &init_ctx, &resp_ctx));

		uint8_t msg3[256] = { 0 };
		size_t msg3_len = 0;

		coverage_mock_reset(fail_pt);

		const int ret = edhoc_message_3_compose(
			&init_ctx, msg3, sizeof(msg3), &msg3_len);

		coverage_assert_sweep_result(
			ret, coverage_psk_msg3_compose_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
	}
}

TEST(coverage_psk, psk_msg3_process_failure_sweep)
{
	const int mock_fail_pt_first = 0;
	const int mock_fail_pt_last = 8;

	for (int fail_pt = mock_fail_pt_first; fail_pt <= mock_fail_pt_last;
	     ++fail_pt) {
		struct edhoc_context init_ctx = { 0 };
		struct edhoc_context resp_ctx = { 0 };

		TEST_ASSERT_EQUAL(
			EDHOC_SUCCESS,
			coverage_setup_mock_context_psk_initiator(&init_ctx));
		TEST_ASSERT_EQUAL(
			EDHOC_SUCCESS,
			coverage_setup_mock_context_psk_responder(&resp_ctx));

		coverage_mock_reset(0);

		uint8_t msg3[256] = { 0 };
		size_t msg3_len = 0;

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  coverage_do_mock_msg3_compose(
					  &init_ctx, &resp_ctx, msg3,
					  sizeof(msg3), &msg3_len));

		coverage_mock_reset(fail_pt);

		const int ret =
			edhoc_message_3_process(&resp_ctx, msg3, msg3_len);

		coverage_assert_sweep_result(
			ret, coverage_psk_msg3_process_must_fail(fail_pt));

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_ctx));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_ctx));
	}
}

TEST(coverage_psk, psk_msg2_compose_tiny_buffer)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_responder(&resp_ctx));

	coverage_mock_reset(0);

	uint8_t msg2[2] = { 0 };
	size_t msg2_len = 0;

	const int ret = coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						   sizeof(msg2), &msg2_len);

	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_psk, psk_msg3_compose_tiny_buffer)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_responder(&resp_ctx));

	coverage_mock_reset(0);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_do_mock_msg2_process(&init_ctx, &resp_ctx));

	uint8_t msg3[2] = { 0 };
	size_t msg3_len = 0;

	const int ret = edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
						&msg3_len);

	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

/*
 * The dispatch to the PSK flow reads the negotiated method, which message 1
 * settles, so every state and argument check below runs message 1 first.
 */

TEST(coverage_psk, psk_msg2_compose_bad_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_responder(&resp_ctx));

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
						sizeof(msg1), &msg1_len));

	uint8_t msg2[256] = { 0 };
	size_t msg2_len = 0;

	/* The Initiator is waiting for message 2, not composing it. */
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_message_2_compose(&init_ctx, msg2, sizeof(msg2),
						  &msg2_len));

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_message_2_compose(&init_ctx, NULL, sizeof(msg2),
						  &msg2_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_message_2_compose(&init_ctx, msg2, 0,
						  &msg2_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_message_2_compose(&init_ctx, msg2, sizeof(msg2),
						  NULL));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_psk, psk_msg2_process_bad_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_responder(&resp_ctx));

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
						sizeof(msg1), &msg1_len));

	static const uint8_t msg2[] = { 0x58, 0x20 };

	/* The Responder has just taken message 1, so it composes message 2. */
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_message_2_process(&resp_ctx, msg2,
						  sizeof(msg2)));

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_message_2_process(&resp_ctx, NULL,
						  sizeof(msg2)));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_message_2_process(&resp_ctx, msg2, 0));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_psk, psk_msg3_compose_bad_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_responder(&resp_ctx));

	uint8_t msg2[256] = { 0 };
	size_t msg2_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						     sizeof(msg2), &msg2_len));

	uint8_t msg3[256] = { 0 };
	size_t msg3_len = 0;

	/* The Responder is waiting for message 3, not composing it. */
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_message_3_compose(&resp_ctx, msg3, sizeof(msg3),
						  &msg3_len));

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_message_3_compose(&resp_ctx, NULL, sizeof(msg3),
						  &msg3_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_message_3_compose(&resp_ctx, msg3, 0,
						  &msg3_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_message_3_compose(&resp_ctx, msg3, sizeof(msg3),
						  NULL));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_psk, psk_msg3_process_bad_state)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_responder(&resp_ctx));

	coverage_mock_reset(0);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_do_mock_msg2_process(&init_ctx, &resp_ctx));

	static const uint8_t msg3[] = { 0x41, 0x00 };

	/* The Initiator has verified message 2, so it composes message 3. */
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_message_3_process(&init_ctx, msg3,
						  sizeof(msg3)));

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_message_3_process(&init_ctx, NULL,
						  sizeof(msg3)));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_message_3_process(&init_ctx, msg3, 0));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_psk, psk_msg3_compose_invalid_credential)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_responder(&resp_ctx));

	coverage_mock_reset(0);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_do_mock_msg2_process(&init_ctx, &resp_ctx));

	const struct edhoc_credentials bad_creds = {
		.select_local =
			coverage_mock_cred_select_local_psk_invalid_label,
		.authenticate_peer = coverage_mock_cred_authenticate_peer,
	};

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_bind_credentials(&init_ctx, &bad_creds));

	uint8_t msg3[256] = { 0 };
	size_t msg3_len = 0;

	/* draft-ietf-lake-edhoc-psk: 3.1 - ID_CRED_PSK is a 'kid' and nothing
	 * else. */
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED,
			  edhoc_message_3_compose(&init_ctx, msg3, sizeof(msg3),
						  &msg3_len));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_psk, psk_msg3_process_corrupted)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_responder(&resp_ctx));

	coverage_mock_reset(0);

	uint8_t msg3[256] = { 0 };
	size_t msg3_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_do_mock_msg3_compose(
						 &init_ctx, &resp_ctx, msg3,
						 sizeof(msg3), &msg3_len));

	/* Flipping CIPHERTEXT_3A makes PLAINTEXT_3A decode into something the
	 * parser rejects. */
	for (size_t i = 1; i < msg3_len; ++i) {
		msg3[i] ^= 0xff;
	}

	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS,
			      edhoc_message_3_process(&resp_ctx, msg3,
						      msg3_len));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_psk, psk_msg3_process_truncated)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_responder(&resp_ctx));

	coverage_mock_reset(0);

	uint8_t msg3[256] = { 0 };
	size_t msg3_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_do_mock_msg3_compose(
						 &init_ctx, &resp_ctx, msg3,
						 sizeof(msg3), &msg3_len));

	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS,
			      edhoc_message_3_process(&resp_ctx, msg3,
						      msg3_len - 1));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_psk, psk_full_flow_with_ead)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_responder(&resp_ctx));

	/* draft-ietf-lake-edhoc-psk: 5.2.2 and 5.3.2 - EAD_2 rides in
	 * PLAINTEXT_2A and EAD_3 in PLAINTEXT_3B, which is empty without it. */
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_bind_ead(&init_ctx,
					 &coverage_mock_ead_with_value));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_bind_ead(&resp_ctx,
					 &coverage_mock_ead_with_value));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_do_mock_msg4_process(&init_ctx, &resp_ctx));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_psk, psk_full_flow_bstr_connection_id)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	/* RFC 9528: 3.3.2 - identifiers that are not a single byte travel as a
	 * CBOR byte string, which PLAINTEXT_2A carries verbatim. */
	TEST_ASSERT_EQUAL(
		EDHOC_SUCCESS,
		coverage_setup_mock_context_psk_bstr_cid_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(
		EDHOC_SUCCESS,
		coverage_setup_mock_context_psk_bstr_cid_responder(&resp_ctx));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_do_mock_msg4_process(&init_ctx, &resp_ctx));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_psk, psk_resumption_exporters_agree)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_responder(&resp_ctx));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_do_mock_msg3_process(&init_ctx, &resp_ctx));

	uint8_t init_psk[32] = { 0 };
	uint8_t resp_psk[32] = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_export_resumption_psk_raw(
				  &init_ctx, init_psk, ARRAY_SIZE(init_psk)));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_export_resumption_psk_raw(
				  &resp_ctx, resp_psk, ARRAY_SIZE(resp_psk)));
	TEST_ASSERT_EQUAL_HEX8_ARRAY(init_psk, resp_psk, ARRAY_SIZE(init_psk));

	uint8_t init_kid[EDHOC_EXPORTER_RESUMPTION_KID_DEFAULT_LEN] = { 0 };
	uint8_t resp_kid[EDHOC_EXPORTER_RESUMPTION_KID_DEFAULT_LEN] = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_export_resumption_kid_raw(
				  &init_ctx, init_kid, ARRAY_SIZE(init_kid)));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_export_resumption_kid_raw(
				  &resp_ctx, resp_kid, ARRAY_SIZE(resp_kid)));
	TEST_ASSERT_EQUAL_HEX8_ARRAY(init_kid, resp_kid, ARRAY_SIZE(init_kid));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_psk, psk_resumption_exporters_rejected)
{
	struct edhoc_context ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&ctx));

	uint8_t psk[32] = { 0 };
	uint8_t kid[EDHOC_EXPORTER_RESUMPTION_KID_DEFAULT_LEN] = { 0 };
	void *key_id = NULL;

	/* RFC 9528: 4.2.1 - exporting needs PRK_exporter, which only a
	 * completed handshake has. */
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_export_resumption_psk_raw(&ctx, psk,
							  ARRAY_SIZE(psk)));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_export_resumption_kid_raw(&ctx, kid,
							  ARRAY_SIZE(kid)));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_export_resumption_psk(
				  &ctx, EDHOC_KEY_USAGE_AEAD, &key_id));

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_export_resumption_psk_raw(&ctx, NULL,
							  ARRAY_SIZE(psk)));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_export_resumption_kid_raw(&ctx, kid, 0));
	TEST_ASSERT_EQUAL(
		EDHOC_ERROR_INVALID_ARGUMENT,
		edhoc_export_resumption_psk(&ctx, EDHOC_KEY_USAGE_AEAD, NULL));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(coverage_psk, psk_not_configured)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_responder(&resp_ctx));

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_do_msg1_flow(&init_ctx, &resp_ctx, msg1,
						sizeof(msg1), &msg1_len));

	/* Message 1 selected method 4, so the dispatch reaches the PSK entry
	 * points; dropping a binding leaves the context incomplete. */
	init_ctx.interfaces.platform_present = false;
	resp_ctx.interfaces.platform_present = false;

	uint8_t msg[256] = { 0 };
	size_t msg_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_message_2_compose(&resp_ctx, msg, sizeof(msg),
						  &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_message_2_process(&init_ctx, msg1, msg1_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_message_3_compose(&init_ctx, msg, sizeof(msg),
						  &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_message_3_process(&resp_ctx, msg1, msg1_len));

	init_ctx.interfaces.platform_present = true;
	resp_ctx.interfaces.platform_present = true;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_psk, psk_msg2_process_malformed)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_responder(&resp_ctx));

	uint8_t msg2[256] = { 0 };
	size_t msg2_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						     sizeof(msg2), &msg2_len));

	coverage_mock_reset(0);

	/* G_Y_CIPHERTEXT_2 is a single byte string, so a shorter buffer no
	 * longer decodes. */
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS,
			      edhoc_message_2_process(&init_ctx, msg2,
						      msg2_len - 1));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_psk, psk_msg2_process_corrupted_plaintext)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_responder(&resp_ctx));

	uint8_t msg2[256] = { 0 };
	size_t msg2_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_do_full_msg2_flow(&init_ctx, &resp_ctx, msg2,
						     sizeof(msg2), &msg2_len));

	coverage_mock_reset(0);

	/* draft-ietf-lake-edhoc-psk: 5.2.2 - CIPHERTEXT_2A is only XOR
	 * masked, so the last byte decrypts straight into PLAINTEXT_2A. */
	msg2[msg2_len - 1] ^= 0xff;

	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS,
			      edhoc_message_2_process(&init_ctx, msg2,
						      msg2_len));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST(coverage_psk, psk_msg3_process_untrusted_credential)
{
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_initiator(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  coverage_setup_mock_context_psk_responder(&resp_ctx));

	uint8_t msg3[256] = { 0 };
	size_t msg3_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, coverage_do_mock_msg3_compose(
						 &init_ctx, &resp_ctx, msg3,
						 sizeof(msg3), &msg3_len));

	resp_ctx.interfaces.cred.authenticate_peer =
		coverage_mock_cred_authenticate_peer_psk_untrusted;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE,
			  edhoc_message_3_process(&resp_ctx, msg3, msg3_len));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&init_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&resp_ctx));
}

TEST_GROUP_RUNNER(coverage_psk)
{
	RUN_TEST_CASE(coverage_psk, psk_full_flow_no_fail);
	RUN_TEST_CASE(coverage_psk, psk_msg2_compose_failure_sweep);
	RUN_TEST_CASE(coverage_psk, psk_msg2_process_failure_sweep);
	RUN_TEST_CASE(coverage_psk, psk_msg3_compose_failure_sweep);
	RUN_TEST_CASE(coverage_psk, psk_msg3_process_failure_sweep);
	RUN_TEST_CASE(coverage_psk, psk_msg2_compose_tiny_buffer);
	RUN_TEST_CASE(coverage_psk, psk_msg3_compose_tiny_buffer);
	RUN_TEST_CASE(coverage_psk, psk_msg2_compose_bad_state);
	RUN_TEST_CASE(coverage_psk, psk_msg2_process_bad_state);
	RUN_TEST_CASE(coverage_psk, psk_msg3_compose_bad_state);
	RUN_TEST_CASE(coverage_psk, psk_msg3_process_bad_state);
	RUN_TEST_CASE(coverage_psk, psk_msg3_compose_invalid_credential);
	RUN_TEST_CASE(coverage_psk, psk_msg3_process_corrupted);
	RUN_TEST_CASE(coverage_psk, psk_msg3_process_truncated);
	RUN_TEST_CASE(coverage_psk, psk_full_flow_with_ead);
	RUN_TEST_CASE(coverage_psk, psk_full_flow_bstr_connection_id);
	RUN_TEST_CASE(coverage_psk, psk_resumption_exporters_agree);
	RUN_TEST_CASE(coverage_psk, psk_resumption_exporters_rejected);
	RUN_TEST_CASE(coverage_psk, psk_not_configured);
	RUN_TEST_CASE(coverage_psk, psk_msg2_process_malformed);
	RUN_TEST_CASE(coverage_psk, psk_msg2_process_corrupted_plaintext);
	RUN_TEST_CASE(coverage_psk, psk_msg3_process_untrusted_credential);
}
