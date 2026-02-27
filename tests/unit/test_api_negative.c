/**
 * \file    test_api_negative.c
 * \author  Kamil Kielbasa
 * \brief   Negative tests for EDHOC public API error paths.
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

/**
 * @scenario  edhoc_context_init with NULL context.
 * @env       None.
 * @action    Call edhoc_context_init(NULL).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, context_init_null)
{
	int ret = edhoc_context_init(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_context_deinit with NULL context.
 * @env       None.
 * @action    Call edhoc_context_deinit(NULL).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, context_deinit_null)
{
	int ret = edhoc_context_deinit(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_context_deinit on uninitialized context.
 * @env       Zeroed context (never initialized).
 * @action    Call edhoc_context_deinit() on context.
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(api_negative, context_deinit_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	int ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- set_methods error paths -- */

/**
 * @scenario  edhoc_set_methods with NULL context.
 * @env       None.
 * @action    Call edhoc_set_methods(NULL, method, 1).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, set_methods_null_ctx)
{
	const enum edhoc_method method[] = { EDHOC_METHOD_0 };
	int ret = edhoc_set_methods(NULL, method, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_set_methods with NULL method array.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_set_methods(&ctx, NULL, 1).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, set_methods_null_method)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_set_methods(&ctx, NULL, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_set_methods with zero length.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_set_methods(&ctx, method, 0).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, set_methods_zero_length)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const enum edhoc_method method[] = { EDHOC_METHOD_0 };
	int ret = edhoc_set_methods(&ctx, method, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_set_methods with too many methods.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_set_methods with EDHOC_METHOD_MAX + 1 methods.
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, set_methods_too_many)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const enum edhoc_method method[] = { EDHOC_METHOD_0 };
	int ret = edhoc_set_methods(&ctx, method, EDHOC_METHOD_MAX + 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_set_methods on uninitialized context.
 * @env       Zeroed context (never initialized).
 * @action    Call edhoc_set_methods(&ctx, method, 1).
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(api_negative, set_methods_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	const enum edhoc_method method[] = { EDHOC_METHOD_0 };
	int ret = edhoc_set_methods(&ctx, method, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- set_cipher_suites error paths -- */

/**
 * @scenario  edhoc_set_cipher_suites with NULL context.
 * @env       None.
 * @action    Call edhoc_set_cipher_suites(NULL, &cs, 1).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, set_cipher_suites_null_ctx)
{
	const struct edhoc_cipher_suite cs = { .value = 0 };
	int ret = edhoc_set_cipher_suites(NULL, &cs, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_set_cipher_suites with NULL cipher suite array.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_set_cipher_suites(&ctx, NULL, 1).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, set_cipher_suites_null_csuite)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_set_cipher_suites(&ctx, NULL, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_set_cipher_suites with zero length.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_set_cipher_suites(&ctx, &cs, 0).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, set_cipher_suites_zero_length)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const struct edhoc_cipher_suite cs = { .value = 0 };
	int ret = edhoc_set_cipher_suites(&ctx, &cs, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_set_cipher_suites with too many suites.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_set_cipher_suites with CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES + 1.
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
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

/**
 * @scenario  edhoc_set_cipher_suites on uninitialized context.
 * @env       Zeroed context (never initialized).
 * @action    Call edhoc_set_cipher_suites(&ctx, &cs, 1).
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(api_negative, set_cipher_suites_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	const struct edhoc_cipher_suite cs = { .value = 0 };
	int ret = edhoc_set_cipher_suites(&ctx, &cs, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- set_connection_id error paths -- */

/**
 * @scenario  edhoc_set_connection_id with NULL context.
 * @env       None.
 * @action    Call edhoc_set_connection_id(NULL, &cid).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, set_connection_id_null_ctx)
{
	const struct edhoc_connection_id cid = { 0 };
	int ret = edhoc_set_connection_id(NULL, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_set_connection_id with NULL connection ID.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_set_connection_id(&ctx, NULL).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, set_connection_id_null_cid)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_set_connection_id(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_set_connection_id on uninitialized context.
 * @env       Zeroed context (never initialized).
 * @action    Call edhoc_set_connection_id(&ctx, &cid).
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
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

/**
 * @scenario  edhoc_set_user_context with NULL context.
 * @env       None.
 * @action    Call edhoc_set_user_context(NULL, &dummy).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, set_user_context_null_ctx)
{
	uint8_t dummy = 0;
	int ret = edhoc_set_user_context(NULL, &dummy);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_set_user_context with NULL user context.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_set_user_context(&ctx, NULL).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, set_user_context_null_user_ctx)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_set_user_context(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_set_user_context on uninitialized context.
 * @env       Zeroed context (never initialized).
 * @action    Call edhoc_set_user_context(&ctx, &dummy).
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(api_negative, set_user_context_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	uint8_t dummy = 0;
	int ret = edhoc_set_user_context(&ctx, &dummy);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- bind_ead error paths -- */

/**
 * @scenario  edhoc_bind_ead with NULL context.
 * @env       None.
 * @action    Call edhoc_bind_ead(NULL, &ead).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, bind_ead_null_ctx)
{
	int ret = edhoc_bind_ead(NULL, &test_ead_stubs);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_bind_ead with NULL EAD.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_bind_ead(&ctx, NULL).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, bind_ead_null_ead)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_bind_ead(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_bind_ead with both callbacks NULL.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_bind_ead with EAD having compose and process NULL.
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(api_negative, bind_ead_both_callbacks_null)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const struct edhoc_ead ead = { .compose = NULL, .process = NULL };
	int ret = edhoc_bind_ead(&ctx, &ead);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_bind_ead on uninitialized context.
 * @env       Zeroed context (never initialized).
 * @action    Call edhoc_bind_ead(&ctx, &ead).
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(api_negative, bind_ead_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	int ret = edhoc_bind_ead(&ctx, &test_ead_stubs);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- bind_keys error paths -- */

/**
 * @scenario  edhoc_bind_keys with NULL context.
 * @env       None.
 * @action    Call edhoc_bind_keys(NULL, keys).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, bind_keys_null_ctx)
{
	int ret = edhoc_bind_keys(NULL, edhoc_cipher_suite_0_get_keys());
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_bind_keys with NULL keys.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_bind_keys(&ctx, NULL).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, bind_keys_null_keys)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_bind_keys(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_bind_keys with NULL key callbacks.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_bind_keys with keys having import_key and destroy_key NULL.
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(api_negative, bind_keys_null_callbacks)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const struct edhoc_keys keys = { .import_key = NULL,
					 .destroy_key = NULL };
	int ret = edhoc_bind_keys(&ctx, &keys);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_bind_keys on uninitialized context.
 * @env       Zeroed context (never initialized).
 * @action    Call edhoc_bind_keys(&ctx, keys).
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(api_negative, bind_keys_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	int ret = edhoc_bind_keys(&ctx, edhoc_cipher_suite_0_get_keys());
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- bind_crypto error paths -- */

/**
 * @scenario  edhoc_bind_crypto with NULL context.
 * @env       None.
 * @action    Call edhoc_bind_crypto(NULL, crypto).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, bind_crypto_null_ctx)
{
	int ret = edhoc_bind_crypto(NULL, edhoc_cipher_suite_0_get_crypto());
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_bind_crypto with NULL crypto.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_bind_crypto(&ctx, NULL).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, bind_crypto_null_crypto)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_bind_crypto(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_bind_crypto with NULL crypto callbacks.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_bind_crypto with zeroed crypto struct.
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(api_negative, bind_crypto_null_callbacks)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const struct edhoc_crypto crypto = { 0 };
	int ret = edhoc_bind_crypto(&ctx, &crypto);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_bind_crypto on uninitialized context.
 * @env       Zeroed context (never initialized).
 * @action    Call edhoc_bind_crypto(&ctx, crypto).
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(api_negative, bind_crypto_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	int ret = edhoc_bind_crypto(&ctx, edhoc_cipher_suite_0_get_crypto());
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- bind_credentials error paths -- */

/**
 * @scenario  edhoc_bind_credentials with NULL context.
 * @env       None.
 * @action    Call edhoc_bind_credentials(NULL, &cred).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, bind_credentials_null_ctx)
{
	int ret = edhoc_bind_credentials(NULL, &test_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_bind_credentials with NULL credentials.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_bind_credentials(&ctx, NULL).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, bind_credentials_null_cred)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_bind_credentials(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_bind_credentials with NULL credential callbacks.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_bind_credentials with cred having fetch and verify NULL.
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(api_negative, bind_credentials_null_callbacks)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	const struct edhoc_credentials cred = { .fetch = NULL, .verify = NULL };
	int ret = edhoc_bind_credentials(&ctx, &cred);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_bind_credentials on uninitialized context.
 * @env       Zeroed context (never initialized).
 * @action    Call edhoc_bind_credentials(&ctx, &cred).
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(api_negative, bind_credentials_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	int ret = edhoc_bind_credentials(&ctx, &test_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- error_get_code error paths -- */

/**
 * @scenario  edhoc_error_get_code with NULL context.
 * @env       None.
 * @action    Call edhoc_error_get_code(NULL, &code).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, error_get_code_null_ctx)
{
	enum edhoc_error_code code;
	int ret = edhoc_error_get_code(NULL, &code);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_error_get_code with NULL code output.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_error_get_code(&ctx, NULL).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, error_get_code_null_code)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	int ret = edhoc_error_get_code(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_error_get_code on uninitialized context.
 * @env       Zeroed context (never initialized).
 * @action    Call edhoc_error_get_code(&ctx, &code).
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
TEST(api_negative, error_get_code_not_initialized)
{
	struct edhoc_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	enum edhoc_error_code code;
	int ret = edhoc_error_get_code(&ctx, &code);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/* -- error_get_cipher_suites error paths -- */

/**
 * @scenario  edhoc_error_get_cipher_suites with NULL context.
 * @env       None.
 * @action    Call edhoc_error_get_cipher_suites(NULL, ...).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, error_get_cipher_suites_null_ctx)
{
	int32_t cs[3], peer_cs[3];
	size_t cs_len, peer_cs_len;
	int ret = edhoc_error_get_cipher_suites(NULL, cs, 3, &cs_len, peer_cs,
						3, &peer_cs_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_error_get_cipher_suites with NULL output buffers.
 * @env       Initialized EDHOC context.
 * @action    Call edhoc_error_get_cipher_suites with NULL cs and peer_cs.
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
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

/**
 * @scenario  edhoc_error_get_cipher_suites on uninitialized context.
 * @env       Zeroed context (never initialized).
 * @action    Call edhoc_error_get_cipher_suites(&ctx, ...).
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
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

/**
 * @scenario  edhoc_error_get_cipher_suites when error_code is not WRONG_SELECTED_CIPHER_SUITE.
 * @env       Initialized context with EDHOC_ERROR_CODE_UNSPECIFIED_ERROR.
 * @action    Call edhoc_error_get_cipher_suites(&ctx, ...).
 * @expected  Returns EDHOC_ERROR_BAD_STATE.
 */
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

/**
 * @scenario  edhoc_error_get_cipher_suites with buffer too small for cipher suites.
 * @env       Initialized context with WRONG_SELECTED_CIPHER_SUITE and 3 suites.
 * @action    Call edhoc_error_get_cipher_suites with cs buffer size 1.
 * @expected  Returns EDHOC_ERROR_BUFFER_TOO_SMALL.
 */
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

/**
 * @scenario  edhoc_message_1_compose with NULL context.
 * @env       None.
 * @action    Call edhoc_message_1_compose(NULL, buf, sizeof(buf), &len).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, message_1_compose_null_ctx)
{
	uint8_t buf[256];
	size_t len;
	int ret = edhoc_message_1_compose(NULL, buf, sizeof(buf), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_message_1_process with NULL context.
 * @env       None.
 * @action    Call edhoc_message_1_process(NULL, buf, sizeof(buf)).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, message_1_process_null_ctx)
{
	const uint8_t buf[] = { 0x01 };
	int ret = edhoc_message_1_process(NULL, buf, sizeof(buf));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_message_2_compose with NULL context.
 * @env       None.
 * @action    Call edhoc_message_2_compose(NULL, buf, sizeof(buf), &len).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, message_2_compose_null_ctx)
{
	uint8_t buf[256];
	size_t len;
	int ret = edhoc_message_2_compose(NULL, buf, sizeof(buf), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_message_2_process with NULL context.
 * @env       None.
 * @action    Call edhoc_message_2_process(NULL, buf, sizeof(buf)).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, message_2_process_null_ctx)
{
	const uint8_t buf[] = { 0x01 };
	int ret = edhoc_message_2_process(NULL, buf, sizeof(buf));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_message_3_compose with NULL context.
 * @env       None.
 * @action    Call edhoc_message_3_compose(NULL, buf, sizeof(buf), &len).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, message_3_compose_null_ctx)
{
	uint8_t buf[256];
	size_t len;
	int ret = edhoc_message_3_compose(NULL, buf, sizeof(buf), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_message_3_process with NULL context.
 * @env       None.
 * @action    Call edhoc_message_3_process(NULL, buf, sizeof(buf)).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, message_3_process_null_ctx)
{
	const uint8_t buf[] = { 0x01 };
	int ret = edhoc_message_3_process(NULL, buf, sizeof(buf));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_message_4_compose with NULL context.
 * @env       None.
 * @action    Call edhoc_message_4_compose(NULL, buf, sizeof(buf), &len).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, message_4_compose_null_ctx)
{
	uint8_t buf[256];
	size_t len;
	int ret = edhoc_message_4_compose(NULL, buf, sizeof(buf), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_message_4_process with NULL context.
 * @env       None.
 * @action    Call edhoc_message_4_process(NULL, buf, sizeof(buf)).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, message_4_process_null_ctx)
{
	const uint8_t buf[] = { 0x01 };
	int ret = edhoc_message_4_process(NULL, buf, sizeof(buf));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_message_error_compose with NULL buffer.
 * @env       None.
 * @action    Call edhoc_message_error_compose(NULL, 0, &len, ...).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, message_error_compose_null_buf)
{
	size_t len;
	struct edhoc_error_info info = { 0 };
	int ret = edhoc_message_error_compose(NULL, 0, &len,
					      EDHOC_ERROR_CODE_SUCCESS, &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_message_error_process with NULL buffer.
 * @env       None.
 * @action    Call edhoc_message_error_process(NULL, 0, &code, &info).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, message_error_process_null_buf)
{
	enum edhoc_error_code code;
	struct edhoc_error_info info = { 0 };
	int ret = edhoc_message_error_process(NULL, 0, &code, &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/* -- exporter with NULL context -- */

/**
 * @scenario  edhoc_export_prk_exporter with NULL context.
 * @env       None.
 * @action    Call edhoc_export_prk_exporter(NULL, 0, secret, sizeof(secret)).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, export_prk_exporter_null_ctx)
{
	uint8_t secret[32];
	int ret = edhoc_export_prk_exporter(NULL, 0, secret, sizeof(secret));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_export_oscore_session with NULL context.
 * @env       None.
 * @action    Call edhoc_export_oscore_session(NULL, ...).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
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

/**
 * @scenario  edhoc_export_oscore_session with NULL master_secret buffer.
 * @env       None.
 * @action    Call edhoc_export_oscore_session(&ctx, NULL, ...).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
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

/**
 * @scenario  edhoc_export_oscore_session with NULL salt buffer.
 * @env       None.
 * @action    Call edhoc_export_oscore_session(&ctx, ms, 16, NULL, ...).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
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

/**
 * @scenario  edhoc_export_oscore_session with NULL sender_id buffer.
 * @env       None.
 * @action    Call edhoc_export_oscore_session with NULL sender_id.
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
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

/**
 * @scenario  edhoc_export_oscore_session with NULL sender_id_length.
 * @env       None.
 * @action    Call edhoc_export_oscore_session with NULL sender_id_length.
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
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

/**
 * @scenario  edhoc_export_oscore_session with NULL recipient_id buffer.
 * @env       None.
 * @action    Call edhoc_export_oscore_session with NULL recipient_id.
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
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

/**
 * @scenario  edhoc_export_oscore_session with NULL recipient_id_length.
 * @env       None.
 * @action    Call edhoc_export_oscore_session with NULL recipient_id_length.
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
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

/**
 * @scenario  edhoc_message_1_compose with NULL message_len.
 * @env       None.
 * @action    Call edhoc_message_1_compose(&ctx, buf, sizeof(buf), NULL).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, message_1_compose_null_len)
{
	struct edhoc_context ctx = { 0 };
	uint8_t buf[128];
	int ret = edhoc_message_1_compose(&ctx, buf, sizeof(buf), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_message_1_compose with NULL buffer.
 * @env       None.
 * @action    Call edhoc_message_1_compose(&ctx, NULL, 0, &len).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, message_1_compose_null_buf)
{
	struct edhoc_context ctx = { 0 };
	size_t len;
	int ret = edhoc_message_1_compose(&ctx, NULL, 0, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_message_1_process with NULL buffer.
 * @env       None.
 * @action    Call edhoc_message_1_process(&ctx, NULL, 0).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(api_negative, message_1_process_null_buf)
{
	struct edhoc_context ctx = { 0 };
	int ret = edhoc_message_1_process(&ctx, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_export_key_update with NULL context.
 * @env       None.
 * @action    Call edhoc_export_key_update(NULL, entropy, sizeof(entropy)).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
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

	RUN_TEST_CASE(api_negative, bind_keys_null_ctx);
	RUN_TEST_CASE(api_negative, bind_keys_null_keys);
	RUN_TEST_CASE(api_negative, bind_keys_null_callbacks);
	RUN_TEST_CASE(api_negative, bind_keys_not_initialized);

	RUN_TEST_CASE(api_negative, bind_crypto_null_ctx);
	RUN_TEST_CASE(api_negative, bind_crypto_null_crypto);
	RUN_TEST_CASE(api_negative, bind_crypto_null_callbacks);
	RUN_TEST_CASE(api_negative, bind_crypto_not_initialized);

	RUN_TEST_CASE(api_negative, bind_credentials_null_ctx);
	RUN_TEST_CASE(api_negative, bind_credentials_null_cred);
	RUN_TEST_CASE(api_negative, bind_credentials_null_callbacks);
	RUN_TEST_CASE(api_negative, bind_credentials_not_initialized);

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
