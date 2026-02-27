/**
 * \file    test_exporters.c
 * \author  Kamil Kielbasa
 * \brief   Tests for EDHOC exporter and error getter API functions.
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include <edhoc.h>

/* Cipher suite 0 header: */
#include "edhoc_cipher_suite_0.h"
#include "test_cipher_suites.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* PSA crypto header: */
#include <psa/crypto.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */
/* Static variables and constants ------------------------------------------ */

static const struct edhoc_keys *keys;
static const struct edhoc_crypto *crypto;

/* Static function definitions --------------------------------------------- */

static void setup_basic_context(struct edhoc_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	edhoc_context_init(ctx);

	const enum edhoc_method method[] = { EDHOC_METHOD_0 };
	edhoc_set_methods(ctx, method, 1);

	edhoc_set_cipher_suites(ctx, &test_cipher_suite_0, 1);

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 1,
	};
	edhoc_set_connection_id(ctx, &cid);

	edhoc_bind_keys(ctx, keys);
	edhoc_bind_crypto(ctx, crypto);
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(exporters);

TEST_SETUP(exporters)
{
	psa_crypto_init();
	keys = edhoc_cipher_suite_0_get_keys();
	crypto = edhoc_cipher_suite_0_get_crypto();
}

TEST_TEAR_DOWN(exporters)
{
	mbedtls_psa_crypto_free();
}

/* -- edhoc_error_get_code tests -- */

TEST(exporters, error_get_code_success_default)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);

	enum edhoc_error_code code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	int ret = edhoc_error_get_code(&ctx, &code);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, code);

	edhoc_context_deinit(&ctx);
}

TEST(exporters, error_get_code_after_set)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);

	ctx.error_code = EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;
	int ret = edhoc_error_get_code(&ctx, &code);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED, code);

	edhoc_context_deinit(&ctx);
}

/* -- edhoc_error_get_cipher_suites tests -- */

TEST(exporters, error_get_cipher_suites_success)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);

	ctx.error_code = EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
	ctx.csuite_len = 2;
	ctx.csuite[0].value = 0;
	ctx.csuite[1].value = 2;
	ctx.peer_csuite_len = 1;
	ctx.peer_csuite[0].value = 3;

	int32_t cs[3] = { -1, -1, -1 };
	int32_t peer_cs[3] = { -1, -1, -1 };
	size_t cs_len = 0;
	size_t peer_cs_len = 0;

	int ret = edhoc_error_get_cipher_suites(&ctx, cs, 3, &cs_len, peer_cs,
						3, &peer_cs_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(2, cs_len);
	TEST_ASSERT_EQUAL(0, cs[0]);
	TEST_ASSERT_EQUAL(2, cs[1]);
	TEST_ASSERT_EQUAL(1, peer_cs_len);
	TEST_ASSERT_EQUAL(3, peer_cs[0]);

	edhoc_context_deinit(&ctx);
}

TEST(exporters, error_get_cipher_suites_peer_buffer_too_small)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);

	ctx.error_code = EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
	ctx.csuite_len = 1;
	ctx.csuite[0].value = 0;
	ctx.peer_csuite_len = 3;

	int32_t cs[3];
	int32_t peer_cs[1];
	size_t cs_len = 0;
	size_t peer_cs_len = 0;

	int ret = edhoc_error_get_cipher_suites(&ctx, cs, 3, &cs_len, peer_cs,
						1, &peer_cs_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	edhoc_context_deinit(&ctx);
}

/* -- edhoc_export_key_update error paths -- */

TEST(exporters, key_update_null_entropy)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_export_key_update(&ctx, NULL, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(exporters, key_update_zero_entropy_length)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const uint8_t entropy[32] = { 0 };
	int ret = edhoc_export_key_update(&ctx, entropy, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_export_key_update when EDHOC not completed.
 * @env       Basic context with status EDHOC_SM_START, prk_state 4E3M.
 * @action    Call edhoc_export_key_update(&ctx, entropy, 32).
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(exporters, key_update_bad_state_not_completed)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.status = EDHOC_SM_START;
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;

	const uint8_t entropy[32] = { 0xAA };
	int ret = edhoc_export_key_update(&ctx, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/* -- edhoc_export_oscore_session error paths -- */

/**
 * @scenario  edhoc_export_oscore_session when OSCORE export not allowed.
 * @env       Context completed but is_oscore_export_allowed = false.
 * @action    Call edhoc_export_oscore_session(&ctx, ...).
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(exporters, oscore_session_not_allowed)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.status = EDHOC_SM_COMPLETED;
	ctx.prk_state = EDHOC_PRK_STATE_OUT;
	ctx.is_oscore_export_allowed = false;

	uint8_t ms[16], salt[8], sid[8], rid[8];
	size_t sid_len, rid_len;

	int ret = edhoc_export_oscore_session(&ctx, ms, sizeof(ms), salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, rid, sizeof(rid),
					      &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_export_oscore_session when EDHOC not completed.
 * @env       Context with status EDHOC_SM_WAIT_M2, is_oscore_export_allowed = true.
 * @action    Call edhoc_export_oscore_session(&ctx, ...).
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(exporters, oscore_session_bad_state_not_completed)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.status = EDHOC_SM_WAIT_M2;
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.is_oscore_export_allowed = true;

	uint8_t ms[16], salt[8], sid[8], rid[8];
	size_t sid_len, rid_len;

	int ret = edhoc_export_oscore_session(&ctx, ms, sizeof(ms), salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, rid, sizeof(rid),
					      &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/* -- edhoc_export_prk_exporter error paths -- */

/**
 * @scenario  edhoc_export_prk_exporter with NULL secret buffer.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_export_prk_exporter(&ctx, label, NULL, 32).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(exporters, prk_exporter_null_secret)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_export_prk_exporter(
		&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_export_prk_exporter with zero secret length.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_export_prk_exporter(&ctx, label, secret, 0).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(exporters, prk_exporter_zero_length)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	uint8_t secret[32];
	int ret = edhoc_export_prk_exporter(
		&ctx, OSCORE_EXTRACT_LABEL_MASTER_SECRET, secret, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_export_prk_exporter with invalid label.
 * @env       Completed context with valid prk_state.
 * @action    Call edhoc_export_prk_exporter(&ctx, 100, secret, sizeof(secret)).
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(exporters, prk_exporter_invalid_label)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.status = EDHOC_SM_COMPLETED;
	ctx.prk_state = EDHOC_PRK_STATE_OUT;

	uint8_t secret[32];
	int ret = edhoc_export_prk_exporter(&ctx, 100, secret, sizeof(secret));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_export_prk_exporter when PRK not in valid state.
 * @env       Context with status EDHOC_SM_START, prk_state INVALID.
 * @action    Call edhoc_export_prk_exporter(&ctx, label, secret, sizeof(secret)).
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(exporters, prk_exporter_bad_state)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.status = EDHOC_SM_START;
	ctx.prk_state = EDHOC_PRK_STATE_INVALID;

	uint8_t secret[32];
	int ret = edhoc_export_prk_exporter(&ctx,
					    OSCORE_EXTRACT_LABEL_MASTER_SECRET,
					    secret, sizeof(secret));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  OSCORE export fails with CBOR encode error for sender ID.
 * @env       Valid completed context with ONE_BYTE_INTEGER peer CID set to 24
 *            (needs 2 CBOR bytes: 0x18 0x18) but sid buffer is only 1 byte.
 * @action    Call edhoc_export_oscore_session with sid_size = 1.
 * @expected  EDHOC_ERROR_CBOR_FAILURE from sender ID CBOR encode.
 */
TEST(exporters, oscore_session_sender_id_encode_fail)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.status = EDHOC_SM_COMPLETED;
	ctx.is_oscore_export_allowed = true;
	ctx.th_state = EDHOC_TH_STATE_4;
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	memset(ctx.th, 0xAB, 32);
	ctx.th_len = 32;
	memset(ctx.prk, 0xCD, 32);
	ctx.prk_len = 32;

	ctx.peer_cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.peer_cid.int_value = 24;

	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 1;

	uint8_t secret[16] = { 0 };
	uint8_t salt[8] = { 0 };
	uint8_t sid[1] = { 0 };
	size_t sid_len = 0;
	uint8_t rid[8] = { 0 };
	size_t rid_len = 0;

	int ret = edhoc_export_oscore_session(&ctx, secret, sizeof(secret),
					      salt, sizeof(salt), sid,
					      sizeof(sid), &sid_len, rid,
					      sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  OSCORE export fails with CBOR encode error for recipient ID.
 * @env       Valid completed context with small int peer CID (sender succeeds)
 *            but own CID set to 24 (needs 2 CBOR bytes) and rid buffer is 1 byte.
 * @action    Call edhoc_export_oscore_session with rid_size = 1.
 * @expected  EDHOC_ERROR_CBOR_FAILURE from recipient ID CBOR encode.
 */
TEST(exporters, oscore_session_recipient_id_encode_fail)
{
	struct edhoc_context ctx = { 0 };
	setup_basic_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.status = EDHOC_SM_COMPLETED;
	ctx.is_oscore_export_allowed = true;
	ctx.th_state = EDHOC_TH_STATE_4;
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	memset(ctx.th, 0xAB, 32);
	ctx.th_len = 32;
	memset(ctx.prk, 0xCD, 32);
	ctx.prk_len = 32;

	ctx.peer_cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.peer_cid.int_value = 1;

	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 24;

	uint8_t secret[16] = { 0 };
	uint8_t salt[8] = { 0 };
	uint8_t sid[8] = { 0 };
	size_t sid_len = 0;
	uint8_t rid[1] = { 0 };
	size_t rid_len = 0;

	int ret = edhoc_export_oscore_session(&ctx, secret, sizeof(secret),
					      salt, sizeof(salt), sid,
					      sizeof(sid), &sid_len, rid,
					      sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	edhoc_context_deinit(&ctx);
}

TEST_GROUP_RUNNER(exporters)
{
	RUN_TEST_CASE(exporters, error_get_code_success_default);
	RUN_TEST_CASE(exporters, error_get_code_after_set);

	RUN_TEST_CASE(exporters, error_get_cipher_suites_success);
	RUN_TEST_CASE(exporters, error_get_cipher_suites_peer_buffer_too_small);

	RUN_TEST_CASE(exporters, key_update_null_entropy);
	RUN_TEST_CASE(exporters, key_update_zero_entropy_length);
	RUN_TEST_CASE(exporters, key_update_bad_state_not_completed);

	RUN_TEST_CASE(exporters, oscore_session_not_allowed);
	RUN_TEST_CASE(exporters, oscore_session_bad_state_not_completed);

	RUN_TEST_CASE(exporters, prk_exporter_null_secret);
	RUN_TEST_CASE(exporters, prk_exporter_zero_length);
	RUN_TEST_CASE(exporters, prk_exporter_invalid_label);
	RUN_TEST_CASE(exporters, prk_exporter_bad_state);
	/* OSCORE CID CBOR encode failures */
	RUN_TEST_CASE(exporters, oscore_session_sender_id_encode_fail);
	RUN_TEST_CASE(exporters, oscore_session_recipient_id_encode_fail);
}
