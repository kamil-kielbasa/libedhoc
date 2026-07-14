/**
 * \file    test_api_negative.c
 * \author  Kamil Kielbasa
 * \brief   Negative tests for EDHOC public API error paths.
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#include "edhoc_context_internal.h"
#include <edhoc/edhoc.h>

/* Cipher suite 0 header: */
#include "edhoc_cipher_suite_0.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* PSA crypto header: */
#include <psa/crypto.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Test helpers: */
#include "test_ead.h"
#include "test_credentials.h"
#include "test_platform.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(api_negative);

TEST_SETUP(api_negative)
{
}

TEST_TEAR_DOWN(api_negative)
{
}

/* -- context_init / context_deinit NULL arguments -- */

TEST(api_negative, context_init_null)
{
	int ret = edhoc_context_init(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, context_deinit_null)
{
	int ret = edhoc_context_deinit(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, context_deinit_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	int ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- set_methods error paths -- */

TEST(api_negative, set_methods_null_ctx)
{
	const enum edhoc_method method[] = { EDHOC_METHOD_0 };
	int ret = edhoc_set_methods(NULL, method, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, set_methods_null_method)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_set_methods(&ctx, NULL, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, set_methods_zero_length)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const enum edhoc_method method[] = { EDHOC_METHOD_0 };
	int ret = edhoc_set_methods(&ctx, method, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, set_methods_too_many)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const enum edhoc_method method[] = { EDHOC_METHOD_0 };
	int ret = edhoc_set_methods(&ctx, method, EDHOC_METHOD_MAX + 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, set_methods_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	const enum edhoc_method method[] = { EDHOC_METHOD_0 };
	int ret = edhoc_set_methods(&ctx, method, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- set_cipher_suites error paths -- */

TEST(api_negative, set_cipher_suites_null_ctx)
{
	const struct edhoc_cipher_suite cs = { .value = 0 };
	int ret = edhoc_set_cipher_suites(NULL, &cs, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, set_cipher_suites_null_csuite)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_set_cipher_suites(&ctx, NULL, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, set_cipher_suites_zero_length)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const struct edhoc_cipher_suite cs = { .value = 0 };
	int ret = edhoc_set_cipher_suites(&ctx, &cs, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, set_cipher_suites_too_many)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const struct edhoc_cipher_suite cs = { .value = 0 };
	int ret = edhoc_set_cipher_suites(
		&ctx, &cs, CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES + 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, set_cipher_suites_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	const struct edhoc_cipher_suite cs = { .value = 0 };
	int ret = edhoc_set_cipher_suites(&ctx, &cs, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- set_connection_id error paths -- */

TEST(api_negative, set_connection_id_null_ctx)
{
	const struct edhoc_connection_id cid = { 0 };
	int ret = edhoc_set_connection_id(NULL, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, set_connection_id_null_cid)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_set_connection_id(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, set_connection_id_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 0,
	};
	int ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- set_user_context error paths -- */

TEST(api_negative, set_user_context_null_ctx)
{
	uint8_t dummy = 0;
	int ret = edhoc_set_user_context(NULL, &dummy);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, set_user_context_null_user_ctx)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_set_user_context(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, set_user_context_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	uint8_t dummy = 0;
	int ret = edhoc_set_user_context(&ctx, &dummy);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- bind_ead error paths -- */

TEST(api_negative, bind_ead_null_ctx)
{
	int ret = edhoc_bind_ead(NULL, &test_ead_stubs);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, bind_ead_null_ead)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_bind_ead(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, bind_ead_both_callbacks_null)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const struct edhoc_ead ead = { .compose = NULL, .process = NULL };
	int ret = edhoc_bind_ead(&ctx, &ead);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, bind_ead_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	int ret = edhoc_bind_ead(&ctx, &test_ead_stubs);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- bind_crypto error paths -- */

TEST(api_negative, bind_crypto_null_ctx)
{
	int ret = edhoc_bind_crypto(NULL, edhoc_cipher_suite_0_get_crypto());
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, bind_crypto_null_crypto)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_bind_crypto(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, bind_crypto_null_callbacks)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const struct edhoc_crypto crypto = { 0 };
	int ret = edhoc_bind_crypto(&ctx, &crypto);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, bind_crypto_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	int ret = edhoc_bind_crypto(&ctx, edhoc_cipher_suite_0_get_crypto());
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- bind_credentials error paths -- */

TEST(api_negative, bind_credentials_null_ctx)
{
	int ret = edhoc_bind_credentials(NULL, &test_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, bind_credentials_null_cred)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_bind_credentials(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, bind_credentials_null_callbacks)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const struct edhoc_credentials cred = { .fetch = NULL, .verify = NULL };
	int ret = edhoc_bind_credentials(&ctx, &cred);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, bind_credentials_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	int ret = edhoc_bind_credentials(&ctx, &test_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- bind_platform error paths -- */

TEST(api_negative, bind_platform_null_ctx)
{
	int ret = edhoc_bind_platform(NULL, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, bind_platform_null_platform)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_bind_platform(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, bind_platform_null_zeroize)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const struct edhoc_platform platform = { 0 }; /* zeroize == NULL */
	int ret = edhoc_bind_platform(&ctx, &platform);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, bind_platform_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	int ret = edhoc_bind_platform(&ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- message API rejects a not-fully-configured context -- */

TEST(api_negative, message_api_unconfigured_context)
{
	struct edhoc_context ctx = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_init(&ctx));

	uint8_t buf[64] = { 0 };
	size_t len = 0;

	/* A freshly initialized context has no mandatory inputs bound, so
	 * every message compose/process must reject it with
	 * EDHOC_ERROR_BAD_STATE (the presence gate fires before the state
	 * machine check). */
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_message_1_compose(&ctx, buf, sizeof(buf),
						  &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_message_1_process(&ctx, buf, sizeof(buf)));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_message_2_compose(&ctx, buf, sizeof(buf),
						  &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_message_2_process(&ctx, buf, sizeof(buf)));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_message_3_compose(&ctx, buf, sizeof(buf),
						  &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_message_3_process(&ctx, buf, sizeof(buf)));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_message_4_compose(&ctx, buf, sizeof(buf),
						  &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE,
			  edhoc_message_4_process(&ctx, buf, sizeof(buf)));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

/* -- error_get_code error paths -- */

TEST(api_negative, error_get_code_null_ctx)
{
	enum edhoc_error_code code;
	int ret = edhoc_error_get_code(NULL, &code);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, error_get_code_null_code)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_error_get_code(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, error_get_code_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	enum edhoc_error_code code;
	int ret = edhoc_error_get_code(&ctx, &code);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- error_get_cipher_suites error paths -- */

TEST(api_negative, error_get_cipher_suites_null_ctx)
{
	int32_t cs[3], peer_cs[3];
	size_t cs_len, peer_cs_len;
	int ret = edhoc_error_get_cipher_suites(NULL, cs, 3, &cs_len, peer_cs,
						3, &peer_cs_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, error_get_cipher_suites_null_params)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	size_t cs_len, peer_cs_len;

	int ret = edhoc_error_get_cipher_suites(&ctx, NULL, 3, &cs_len, NULL, 3,
						&peer_cs_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, error_get_cipher_suites_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	int32_t cs[3], peer_cs[3];
	size_t cs_len, peer_cs_len;
	int ret = edhoc_error_get_cipher_suites(&ctx, cs, 3, &cs_len, peer_cs,
						3, &peer_cs_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST(api_negative, error_get_cipher_suites_wrong_error_code)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	ctx.error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	int32_t cs[3], peer_cs[3];
	size_t cs_len, peer_cs_len;
	int ret = edhoc_error_get_cipher_suites(&ctx, cs, 3, &cs_len, peer_cs,
						3, &peer_cs_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
	edhoc_context_deinit(&ctx);
}

TEST(api_negative, error_get_cipher_suites_buffer_too_small)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	ctx.error_code = EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
	ctx.csuite_len = 3;
	int32_t cs[1], peer_cs[3];
	size_t cs_len, peer_cs_len;
	int ret = edhoc_error_get_cipher_suites(&ctx, cs, 1, &cs_len, peer_cs,
						3, &peer_cs_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
	edhoc_context_deinit(&ctx);
}

/* -- message compose/process with NULL context -- */

TEST(api_negative, message_1_compose_null_ctx)
{
	uint8_t buf[256];
	size_t len;
	int ret = edhoc_message_1_compose(NULL, buf, sizeof(buf), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_1_process_null_ctx)
{
	const uint8_t buf[] = { 0x01 };
	int ret = edhoc_message_1_process(NULL, buf, sizeof(buf));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_2_compose_null_ctx)
{
	uint8_t buf[256];
	size_t len;
	int ret = edhoc_message_2_compose(NULL, buf, sizeof(buf), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_2_process_null_ctx)
{
	const uint8_t buf[] = { 0x01 };
	int ret = edhoc_message_2_process(NULL, buf, sizeof(buf));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_3_compose_null_ctx)
{
	uint8_t buf[256];
	size_t len;
	int ret = edhoc_message_3_compose(NULL, buf, sizeof(buf), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_3_process_null_ctx)
{
	const uint8_t buf[] = { 0x01 };
	int ret = edhoc_message_3_process(NULL, buf, sizeof(buf));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_4_compose_null_ctx)
{
	uint8_t buf[256];
	size_t len;
	int ret = edhoc_message_4_compose(NULL, buf, sizeof(buf), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_4_process_null_ctx)
{
	const uint8_t buf[] = { 0x01 };
	int ret = edhoc_message_4_process(NULL, buf, sizeof(buf));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_error_compose_null_buf)
{
	size_t len;
	struct edhoc_error_info info = { 0 };
	int ret = edhoc_message_error_compose(NULL, 0, &len,
					      EDHOC_ERROR_CODE_SUCCESS, &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_error_process_null_buf)
{
	enum edhoc_error_code code;
	struct edhoc_error_info info = { 0 };
	int ret = edhoc_message_error_process(NULL, 0, &code, &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/* -- exporter with NULL context -- */

TEST(api_negative, export_prk_exporter_null_ctx)
{
	uint8_t secret[32];
	int ret = edhoc_export_prk_exporter(NULL, 0, NULL, 0, secret,
					    sizeof(secret));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, export_oscore_session_null_ctx)
{
	uint8_t ms[16], salt[8], sid[8], rid[8];
	size_t sid_len, rid_len;
	int ret = edhoc_export_oscore_session(NULL, ms, sizeof(ms), salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, rid, sizeof(rid),
					      &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, export_oscore_session_null_ms)
{
	struct edhoc_context ctx = { 0 };
	uint8_t salt[8], sid[8], rid[8];
	size_t sid_len, rid_len;
	int ret = edhoc_export_oscore_session(&ctx, NULL, 16, salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, rid, sizeof(rid),
					      &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, export_oscore_session_null_salt)
{
	struct edhoc_context ctx = { 0 };
	uint8_t ms[16], sid[8], rid[8];
	size_t sid_len, rid_len;
	int ret = edhoc_export_oscore_session(&ctx, ms, sizeof(ms), NULL, 8,
					      sid, sizeof(sid), &sid_len, rid,
					      sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, export_oscore_session_null_sid)
{
	struct edhoc_context ctx = { 0 };
	uint8_t ms[16], salt[8], rid[8];
	size_t sid_len, rid_len;
	int ret = edhoc_export_oscore_session(&ctx, ms, sizeof(ms), salt,
					      sizeof(salt), NULL, 8, &sid_len,
					      rid, sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, export_oscore_session_null_sid_len)
{
	struct edhoc_context ctx = { 0 };
	uint8_t ms[16], salt[8], sid[8], rid[8];
	size_t rid_len;
	int ret = edhoc_export_oscore_session(&ctx, ms, sizeof(ms), salt,
					      sizeof(salt), sid, sizeof(sid),
					      NULL, rid, sizeof(rid), &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, export_oscore_session_null_rid)
{
	struct edhoc_context ctx = { 0 };
	uint8_t ms[16], salt[8], sid[8];
	size_t sid_len, rid_len;
	int ret = edhoc_export_oscore_session(&ctx, ms, sizeof(ms), salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, NULL, 8, &rid_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, export_oscore_session_null_rid_len)
{
	struct edhoc_context ctx = { 0 };
	uint8_t ms[16], salt[8], sid[8], rid[8];
	size_t sid_len;
	int ret = edhoc_export_oscore_session(&ctx, ms, sizeof(ms), salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, rid, sizeof(rid), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_1_compose_null_len)
{
	struct edhoc_context ctx = { 0 };
	uint8_t buf[128];
	int ret = edhoc_message_1_compose(&ctx, buf, sizeof(buf), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_1_compose_null_buf)
{
	struct edhoc_context ctx = { 0 };
	size_t len;
	int ret = edhoc_message_1_compose(&ctx, NULL, 0, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_1_process_null_buf)
{
	struct edhoc_context ctx = { 0 };
	int ret = edhoc_message_1_process(&ctx, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, export_key_update_null_ctx)
{
	const uint8_t entropy[32] = { 0 };
	int ret = edhoc_export_key_update(NULL, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST_GROUP_RUNNER(api_negative)
{
	RUN_TEST_CASE(api_negative, context_init_null);
	RUN_TEST_CASE(api_negative, context_deinit_null);
	RUN_TEST_CASE(api_negative, context_deinit_not_initialized);

	RUN_TEST_CASE(api_negative, set_methods_null_ctx);
	RUN_TEST_CASE(api_negative, set_methods_null_method);
	RUN_TEST_CASE(api_negative, set_methods_zero_length);
	RUN_TEST_CASE(api_negative, set_methods_too_many);
	RUN_TEST_CASE(api_negative, set_methods_not_initialized);

	RUN_TEST_CASE(api_negative, set_cipher_suites_null_ctx);
	RUN_TEST_CASE(api_negative, set_cipher_suites_null_csuite);
	RUN_TEST_CASE(api_negative, set_cipher_suites_zero_length);
	RUN_TEST_CASE(api_negative, set_cipher_suites_too_many);
	RUN_TEST_CASE(api_negative, set_cipher_suites_not_initialized);

	RUN_TEST_CASE(api_negative, set_connection_id_null_ctx);
	RUN_TEST_CASE(api_negative, set_connection_id_null_cid);
	RUN_TEST_CASE(api_negative, set_connection_id_not_initialized);

	RUN_TEST_CASE(api_negative, set_user_context_null_ctx);
	RUN_TEST_CASE(api_negative, set_user_context_null_user_ctx);
	RUN_TEST_CASE(api_negative, set_user_context_not_initialized);

	RUN_TEST_CASE(api_negative, bind_ead_null_ctx);
	RUN_TEST_CASE(api_negative, bind_ead_null_ead);
	RUN_TEST_CASE(api_negative, bind_ead_both_callbacks_null);
	RUN_TEST_CASE(api_negative, bind_ead_not_initialized);

	RUN_TEST_CASE(api_negative, bind_crypto_null_ctx);
	RUN_TEST_CASE(api_negative, bind_crypto_null_crypto);
	RUN_TEST_CASE(api_negative, bind_crypto_null_callbacks);
	RUN_TEST_CASE(api_negative, bind_crypto_not_initialized);

	RUN_TEST_CASE(api_negative, bind_credentials_null_ctx);
	RUN_TEST_CASE(api_negative, bind_credentials_null_cred);
	RUN_TEST_CASE(api_negative, bind_credentials_null_callbacks);
	RUN_TEST_CASE(api_negative, bind_credentials_not_initialized);

	RUN_TEST_CASE(api_negative, bind_platform_null_ctx);
	RUN_TEST_CASE(api_negative, bind_platform_null_platform);
	RUN_TEST_CASE(api_negative, bind_platform_null_zeroize);
	RUN_TEST_CASE(api_negative, bind_platform_not_initialized);

	RUN_TEST_CASE(api_negative, message_api_unconfigured_context);

	RUN_TEST_CASE(api_negative, error_get_code_null_ctx);
	RUN_TEST_CASE(api_negative, error_get_code_null_code);
	RUN_TEST_CASE(api_negative, error_get_code_not_initialized);

	RUN_TEST_CASE(api_negative, error_get_cipher_suites_null_ctx);
	RUN_TEST_CASE(api_negative, error_get_cipher_suites_null_params);
	RUN_TEST_CASE(api_negative, error_get_cipher_suites_not_initialized);
	RUN_TEST_CASE(api_negative, error_get_cipher_suites_wrong_error_code);
	RUN_TEST_CASE(api_negative, error_get_cipher_suites_buffer_too_small);

	RUN_TEST_CASE(api_negative, message_1_compose_null_ctx);
	RUN_TEST_CASE(api_negative, message_1_process_null_ctx);
	RUN_TEST_CASE(api_negative, message_2_compose_null_ctx);
	RUN_TEST_CASE(api_negative, message_2_process_null_ctx);
	RUN_TEST_CASE(api_negative, message_3_compose_null_ctx);
	RUN_TEST_CASE(api_negative, message_3_process_null_ctx);
	RUN_TEST_CASE(api_negative, message_4_compose_null_ctx);
	RUN_TEST_CASE(api_negative, message_4_process_null_ctx);
	RUN_TEST_CASE(api_negative, message_error_compose_null_buf);
	RUN_TEST_CASE(api_negative, message_error_process_null_buf);

	RUN_TEST_CASE(api_negative, export_prk_exporter_null_ctx);
	RUN_TEST_CASE(api_negative, export_oscore_session_null_ctx);
	RUN_TEST_CASE(api_negative, export_oscore_session_null_ms);
	RUN_TEST_CASE(api_negative, export_oscore_session_null_salt);
	RUN_TEST_CASE(api_negative, export_oscore_session_null_sid);
	RUN_TEST_CASE(api_negative, export_oscore_session_null_sid_len);
	RUN_TEST_CASE(api_negative, export_oscore_session_null_rid);
	RUN_TEST_CASE(api_negative, export_oscore_session_null_rid_len);
	RUN_TEST_CASE(api_negative, message_1_compose_null_len);
	RUN_TEST_CASE(api_negative, message_1_compose_null_buf);
	RUN_TEST_CASE(api_negative, message_1_process_null_buf);
	RUN_TEST_CASE(api_negative, export_key_update_null_ctx);
}
