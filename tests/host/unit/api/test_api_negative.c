/**
 * \file    test_api_negative.c
 * \author  Kamil Kielbasa
 * \brief   Negative tests for EDHOC public API error paths.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include <edhoc/cipher_suite.h>
#include "edhoc_context_internal.h"
#include "edhoc_macros_internal.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */

static int stub_ead_compose(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    struct edhoc_ead_token *token, size_t token_size,
			    size_t *token_len);
static int stub_ead_process(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    const struct edhoc_ead_token *token,
			    size_t token_size);
static int stub_cred_select_local(void *user_ctx,
				  const struct edhoc_call_context *call_ctx,
				  struct edhoc_credential_selected *selected);
static int
stub_cred_authenticate_peer(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    const struct edhoc_credential_received *received,
			    struct edhoc_credential_trusted *trusted);
static void stub_zeroize(void *buffer, size_t length);

/* Static variables and constants ------------------------------------------ */

/* A valid (non-NULL callbacks) interface is all the bind() paths inspect, so
 * these self-contained stubs keep the negative tests free of shared fixtures. */
static const struct edhoc_ead stub_ead = {
	.compose = stub_ead_compose,
	.process = stub_ead_process,
};

static const struct edhoc_credentials stub_cred = {
	.select_local = stub_cred_select_local,
	.authenticate_peer = stub_cred_authenticate_peer,
};

static const struct edhoc_platform stub_platform = {
	.zeroize = stub_zeroize,
};

/* Static function definitions --------------------------------------------- */

static int stub_ead_compose(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    struct edhoc_ead_token *token, size_t token_size,
			    size_t *token_len)
{
	(void)user_ctx;
	(void)call_ctx;
	(void)token;
	(void)token_size;
	(void)token_len;

	return EDHOC_SUCCESS;
}

static int stub_ead_process(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    const struct edhoc_ead_token *token,
			    size_t token_size)
{
	(void)user_ctx;
	(void)call_ctx;
	(void)token;
	(void)token_size;

	return EDHOC_SUCCESS;
}

static int stub_cred_select_local(void *user_ctx,
				  const struct edhoc_call_context *call_ctx,
				  struct edhoc_credential_selected *selected)
{
	(void)user_ctx;
	(void)call_ctx;
	(void)selected;

	return EDHOC_SUCCESS;
}

static int
stub_cred_authenticate_peer(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    const struct edhoc_credential_received *received,
			    struct edhoc_credential_trusted *trusted)
{
	(void)user_ctx;
	(void)call_ctx;
	(void)received;
	(void)trusted;

	return EDHOC_SUCCESS;
}

static void stub_zeroize(void *buffer, size_t length)
{
	(void)memset(buffer, 0, length);
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(api_negative);

TEST_SETUP(api_negative)
{
}

TEST_TEAR_DOWN(api_negative)
{
}

TEST(api_negative, context_init_null_ctx)
{
	int ret = edhoc_context_init(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, context_deinit_null_ctx)
{
	int ret = edhoc_context_deinit(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, context_deinit_not_initialized)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST(api_negative, set_methods_null_ctx)
{
	const enum edhoc_method method[] = { EDHOC_METHOD_0 };

	int ret = edhoc_set_methods(NULL, method, ARRAY_SIZE(method));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, set_methods_null_method)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(&ctx, NULL, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, set_methods_zero_length)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const enum edhoc_method method[] = { EDHOC_METHOD_0 };

	ret = edhoc_set_methods(&ctx, method, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, set_methods_too_many)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const enum edhoc_method method[] = { EDHOC_METHOD_0 };

	ret = edhoc_set_methods(&ctx, method,
				CONFIG_LIBEDHOC_MAX_NR_OF_METHODS + 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, set_methods_out_of_range)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const enum edhoc_method method[] = { EDHOC_METHOD_0,
					     (enum edhoc_method)5 };

	ret = edhoc_set_methods(&ctx, method, ARRAY_SIZE(method));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, set_methods_not_initialized)
{
	struct edhoc_context ctx = { 0 };
	const enum edhoc_method method[] = { EDHOC_METHOD_0 };

	int ret = edhoc_set_methods(&ctx, method, ARRAY_SIZE(method));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST(api_negative, set_cipher_suites_null_ctx)
{
	const struct edhoc_cipher_suite suite = { .value = 0 };

	int ret = edhoc_set_cipher_suites(NULL, &suite, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, set_cipher_suites_null_suite)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(&ctx, NULL, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, set_cipher_suites_zero_length)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_cipher_suite suite = { .value = 0 };

	ret = edhoc_set_cipher_suites(&ctx, &suite, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, set_cipher_suites_too_many)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_cipher_suite suite = { .value = 0 };

	ret = edhoc_set_cipher_suites(
		&ctx, &suite, CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES + 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, set_cipher_suites_not_initialized)
{
	struct edhoc_context ctx = { 0 };
	const struct edhoc_cipher_suite suite = { .value = 0 };

	int ret = edhoc_set_cipher_suites(&ctx, &suite, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST(api_negative, set_connection_id_null_ctx)
{
	const struct edhoc_buffer cid = { 0 };

	int ret = edhoc_set_connection_id(NULL, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, set_connection_id_null_cid)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, set_connection_id_not_initialized)
{
	struct edhoc_context ctx = { 0 };

	const uint8_t value[] = { 0x00 };
	const struct edhoc_buffer cid = { .value = value,
					  .length = ARRAY_SIZE(value) };

	int ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST(api_negative, set_user_context_null_ctx)
{
	uint8_t user_ctx = 0;

	int ret = edhoc_set_user_context(NULL, &user_ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, set_user_context_null_user_ctx)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* NULL clears a previously set user context. */
	ret = edhoc_set_user_context(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, set_user_context_not_initialized)
{
	struct edhoc_context ctx = { 0 };
	uint8_t user_ctx = 0;

	int ret = edhoc_set_user_context(&ctx, &user_ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST(api_negative, bind_ead_null_ctx)
{
	int ret = edhoc_bind_ead(NULL, &stub_ead);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, bind_ead_null_ead)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_ead(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, bind_ead_null_callbacks)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_ead ead = { .compose = NULL, .process = NULL };

	ret = edhoc_bind_ead(&ctx, &ead);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, bind_ead_not_initialized)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_bind_ead(&ctx, &stub_ead);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST(api_negative, bind_crypto_null_ctx)
{
	int ret = edhoc_bind_crypto(
		NULL, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_2));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, bind_crypto_null_crypto)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, bind_crypto_null_callbacks)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_crypto crypto = { 0 };

	ret = edhoc_bind_crypto(&ctx, &crypto);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, bind_crypto_not_initialized)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_bind_crypto(
		&ctx, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_2));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST(api_negative, bind_credentials_null_ctx)
{
	int ret = edhoc_bind_credentials(NULL, &stub_cred);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, bind_credentials_null_cred)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, bind_credentials_null_callbacks)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_credentials cred = { .select_local = NULL,
						.authenticate_peer = NULL };

	ret = edhoc_bind_credentials(&ctx, &cred);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, bind_credentials_not_initialized)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_bind_credentials(&ctx, &stub_cred);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST(api_negative, bind_platform_null_ctx)
{
	int ret = edhoc_bind_platform(NULL, &stub_platform);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, bind_platform_null_platform)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, bind_platform_null_zeroize)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_platform platform = { .zeroize = NULL };

	ret = edhoc_bind_platform(&ctx, &platform);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, bind_platform_not_initialized)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_bind_platform(&ctx, &stub_platform);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST(api_negative, message_api_rejects_unconfigured_context)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t buf[64] = { 0 };
	size_t len = 0;

	ret = edhoc_message_1_compose(&ctx, buf, sizeof(buf), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_message_1_process(&ctx, buf, sizeof(buf));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_message_2_compose(&ctx, buf, sizeof(buf), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_message_2_process(&ctx, buf, sizeof(buf));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_message_3_compose(&ctx, buf, sizeof(buf), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_message_3_process(&ctx, buf, sizeof(buf));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_message_4_compose(&ctx, buf, sizeof(buf), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_message_4_process(&ctx, buf, sizeof(buf));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, error_get_code_null_ctx)
{
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;

	int ret = edhoc_error_get_code(NULL, &code);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, error_get_code_null_code)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_error_get_code(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, error_get_code_not_initialized)
{
	struct edhoc_context ctx = { 0 };
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;

	int ret = edhoc_error_get_code(&ctx, &code);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST(api_negative, error_get_cipher_suites_null_ctx)
{
	int32_t suites[3] = { 0 };
	int32_t peer_suites[3] = { 0 };
	size_t suites_len = 0;
	size_t peer_suites_len = 0;

	int ret = edhoc_error_get_cipher_suites(
		NULL, suites, ARRAY_SIZE(suites), &suites_len, peer_suites,
		ARRAY_SIZE(peer_suites), &peer_suites_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, error_get_cipher_suites_null_params)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	size_t suites_len = 0;
	size_t peer_suites_len = 0;

	ret = edhoc_error_get_cipher_suites(&ctx, NULL, 3, &suites_len, NULL, 3,
					    &peer_suites_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, error_get_cipher_suites_not_initialized)
{
	struct edhoc_context ctx = { 0 };
	int32_t suites[3] = { 0 };
	int32_t peer_suites[3] = { 0 };
	size_t suites_len = 0;
	size_t peer_suites_len = 0;

	int ret = edhoc_error_get_cipher_suites(
		&ctx, suites, ARRAY_SIZE(suites), &suites_len, peer_suites,
		ARRAY_SIZE(peer_suites), &peer_suites_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST(api_negative, error_get_cipher_suites_wrong_error_code)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ctx.error_code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;

	int32_t suites[3] = { 0 };
	int32_t peer_suites[3] = { 0 };
	size_t suites_len = 0;
	size_t peer_suites_len = 0;

	ret = edhoc_error_get_cipher_suites(&ctx, suites, ARRAY_SIZE(suites),
					    &suites_len, peer_suites,
					    ARRAY_SIZE(peer_suites),
					    &peer_suites_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, error_get_cipher_suites_buffer_too_small)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ctx.error_code = EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
	ctx.negotiation.cipher_suite.count = 3;

	int32_t suites[1] = { 0 };
	int32_t peer_suites[3] = { 0 };
	size_t suites_len = 0;
	size_t peer_suites_len = 0;

	ret = edhoc_error_get_cipher_suites(&ctx, suites, ARRAY_SIZE(suites),
					    &suites_len, peer_suites,
					    ARRAY_SIZE(peer_suites),
					    &peer_suites_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, error_get_cipher_suites_peer_buffer_too_small)
{
	struct edhoc_context ctx = { 0 };
	int32_t cs[3] = { 0 };
	int32_t peer_cs[1] = { 0 };
	size_t cs_len = 0;
	size_t peer_cs_len = 0;
	int ret = edhoc_context_init(&ctx);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ctx.error_code = EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
	ctx.negotiation.cipher_suite.count = 1;
	ctx.negotiation.cipher_suite.entry[0].value = 0;
	ctx.negotiation.peer_cipher_suite.count = 3;

	ret = edhoc_error_get_cipher_suites(&ctx, cs, ARRAY_SIZE(cs), &cs_len,
					    peer_cs, ARRAY_SIZE(peer_cs),
					    &peer_cs_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api_negative, message_1_compose_null_ctx)
{
	uint8_t buf[256] = { 0 };
	size_t len = 0;

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
	uint8_t buf[256] = { 0 };
	size_t len = 0;

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
	uint8_t buf[256] = { 0 };
	size_t len = 0;

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
	uint8_t buf[256] = { 0 };
	size_t len = 0;

	int ret = edhoc_message_4_compose(NULL, buf, sizeof(buf), &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_4_process_null_ctx)
{
	const uint8_t buf[] = { 0x01 };

	int ret = edhoc_message_4_process(NULL, buf, sizeof(buf));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_error_compose_null_ctx)
{
	uint8_t buf[64] = { 0 };
	size_t len = 0;
	struct edhoc_error_info info = { 0 };

	int ret = edhoc_message_error_compose(NULL, buf, sizeof(buf), &len,
					      EDHOC_ERROR_CODE_SUCCESS, &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_error_compose_uninitialized_ctx)
{
	struct edhoc_context ctx = { 0 };
	uint8_t buf[64] = { 0 };
	size_t len = 0;
	struct edhoc_error_info info = { 0 };

	int ret = edhoc_message_error_compose(&ctx, buf, sizeof(buf), &len,
					      EDHOC_ERROR_CODE_SUCCESS, &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST(api_negative, message_error_compose_null_buf)
{
	struct edhoc_context ctx = { 0 };
	size_t len = 0;
	struct edhoc_error_info info = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_init(&ctx));

	int ret = edhoc_message_error_compose(&ctx, NULL, 0, &len,
					      EDHOC_ERROR_CODE_SUCCESS, &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_error_process_null_ctx)
{
	const uint8_t buf[] = { 0x00 };
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;
	struct edhoc_error_info info = { 0 };

	int ret = edhoc_message_error_process(NULL, buf, sizeof(buf), &code,
					      &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_error_process_uninitialized_ctx)
{
	struct edhoc_context ctx = { 0 };
	const uint8_t buf[] = { 0x00 };
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;
	struct edhoc_error_info info = { 0 };

	int ret = edhoc_message_error_process(&ctx, buf, sizeof(buf), &code,
					      &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST(api_negative, message_error_process_null_buf)
{
	struct edhoc_context ctx = { 0 };
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;
	struct edhoc_error_info info = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_init(&ctx));

	int ret = edhoc_message_error_process(&ctx, NULL, 0, &code, &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, export_raw_null_ctx)
{
	uint8_t secret[32] = { 0 };

	int ret = edhoc_export_raw(NULL, 0, NULL, 0, secret, sizeof(secret));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, export_oscore_context_raw_null_ctx)
{
	uint8_t master_secret[16] = { 0 };
	uint8_t master_salt[8] = { 0 };
	uint8_t sender_id[8] = { 0 };
	uint8_t recipient_id[8] = { 0 };
	size_t sender_id_len = 0;
	size_t recipient_id_len = 0;

	int ret = edhoc_export_oscore_context_raw(
		NULL, master_secret, sizeof(master_secret), master_salt,
		sizeof(master_salt), sender_id, sizeof(sender_id),
		&sender_id_len, recipient_id, sizeof(recipient_id),
		&recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, export_oscore_context_raw_null_master_secret)
{
	struct edhoc_context ctx = { 0 };
	uint8_t master_salt[8] = { 0 };
	uint8_t sender_id[8] = { 0 };
	uint8_t recipient_id[8] = { 0 };
	size_t sender_id_len = 0;
	size_t recipient_id_len = 0;

	int ret = edhoc_export_oscore_context_raw(
		&ctx, NULL, 16, master_salt, sizeof(master_salt), sender_id,
		sizeof(sender_id), &sender_id_len, recipient_id,
		sizeof(recipient_id), &recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, export_oscore_context_raw_null_master_salt)
{
	struct edhoc_context ctx = { 0 };
	uint8_t master_secret[16] = { 0 };
	uint8_t sender_id[8] = { 0 };
	uint8_t recipient_id[8] = { 0 };
	size_t sender_id_len = 0;
	size_t recipient_id_len = 0;

	int ret = edhoc_export_oscore_context_raw(
		&ctx, master_secret, sizeof(master_secret), NULL, 8, sender_id,
		sizeof(sender_id), &sender_id_len, recipient_id,
		sizeof(recipient_id), &recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, export_oscore_context_raw_null_sender_id)
{
	struct edhoc_context ctx = { 0 };
	uint8_t master_secret[16] = { 0 };
	uint8_t master_salt[8] = { 0 };
	uint8_t recipient_id[8] = { 0 };
	size_t sender_id_len = 0;
	size_t recipient_id_len = 0;

	int ret = edhoc_export_oscore_context_raw(
		&ctx, master_secret, sizeof(master_secret), master_salt,
		sizeof(master_salt), NULL, 8, &sender_id_len, recipient_id,
		sizeof(recipient_id), &recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, export_oscore_context_raw_null_sender_id_len)
{
	struct edhoc_context ctx = { 0 };
	uint8_t master_secret[16] = { 0 };
	uint8_t master_salt[8] = { 0 };
	uint8_t sender_id[8] = { 0 };
	uint8_t recipient_id[8] = { 0 };
	size_t recipient_id_len = 0;

	int ret = edhoc_export_oscore_context_raw(
		&ctx, master_secret, sizeof(master_secret), master_salt,
		sizeof(master_salt), sender_id, sizeof(sender_id), NULL,
		recipient_id, sizeof(recipient_id), &recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, export_oscore_context_raw_null_recipient_id)
{
	struct edhoc_context ctx = { 0 };
	uint8_t master_secret[16] = { 0 };
	uint8_t master_salt[8] = { 0 };
	uint8_t sender_id[8] = { 0 };
	size_t sender_id_len = 0;
	size_t recipient_id_len = 0;

	int ret = edhoc_export_oscore_context_raw(
		&ctx, master_secret, sizeof(master_secret), master_salt,
		sizeof(master_salt), sender_id, sizeof(sender_id),
		&sender_id_len, NULL, 8, &recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, export_oscore_context_raw_null_recipient_id_len)
{
	struct edhoc_context ctx = { 0 };
	uint8_t master_secret[16] = { 0 };
	uint8_t master_salt[8] = { 0 };
	uint8_t sender_id[8] = { 0 };
	uint8_t recipient_id[8] = { 0 };
	size_t sender_id_len = 0;

	int ret = edhoc_export_oscore_context_raw(
		&ctx, master_secret, sizeof(master_secret), master_salt,
		sizeof(master_salt), sender_id, sizeof(sender_id),
		&sender_id_len, recipient_id, sizeof(recipient_id), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_1_compose_null_len)
{
	struct edhoc_context ctx = { 0 };
	uint8_t buf[128] = { 0 };

	int ret = edhoc_message_1_compose(&ctx, buf, sizeof(buf), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(api_negative, message_1_compose_null_buf)
{
	struct edhoc_context ctx = { 0 };
	size_t len = 0;

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
	RUN_TEST_CASE(api_negative, context_init_null_ctx);
	RUN_TEST_CASE(api_negative, context_deinit_null_ctx);
	RUN_TEST_CASE(api_negative, context_deinit_not_initialized);

	RUN_TEST_CASE(api_negative, set_methods_null_ctx);
	RUN_TEST_CASE(api_negative, set_methods_null_method);
	RUN_TEST_CASE(api_negative, set_methods_zero_length);
	RUN_TEST_CASE(api_negative, set_methods_too_many);
	RUN_TEST_CASE(api_negative, set_methods_out_of_range);
	RUN_TEST_CASE(api_negative, set_methods_not_initialized);

	RUN_TEST_CASE(api_negative, set_cipher_suites_null_ctx);
	RUN_TEST_CASE(api_negative, set_cipher_suites_null_suite);
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
	RUN_TEST_CASE(api_negative, bind_ead_null_callbacks);
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

	RUN_TEST_CASE(api_negative, message_api_rejects_unconfigured_context);

	RUN_TEST_CASE(api_negative, error_get_code_null_ctx);
	RUN_TEST_CASE(api_negative, error_get_code_null_code);
	RUN_TEST_CASE(api_negative, error_get_code_not_initialized);

	RUN_TEST_CASE(api_negative, error_get_cipher_suites_null_ctx);
	RUN_TEST_CASE(api_negative, error_get_cipher_suites_null_params);
	RUN_TEST_CASE(api_negative, error_get_cipher_suites_not_initialized);
	RUN_TEST_CASE(api_negative, error_get_cipher_suites_wrong_error_code);
	RUN_TEST_CASE(api_negative, error_get_cipher_suites_buffer_too_small);
	RUN_TEST_CASE(api_negative,
		      error_get_cipher_suites_peer_buffer_too_small);

	RUN_TEST_CASE(api_negative, message_1_compose_null_ctx);
	RUN_TEST_CASE(api_negative, message_1_process_null_ctx);
	RUN_TEST_CASE(api_negative, message_2_compose_null_ctx);
	RUN_TEST_CASE(api_negative, message_2_process_null_ctx);
	RUN_TEST_CASE(api_negative, message_3_compose_null_ctx);
	RUN_TEST_CASE(api_negative, message_3_process_null_ctx);
	RUN_TEST_CASE(api_negative, message_4_compose_null_ctx);
	RUN_TEST_CASE(api_negative, message_4_process_null_ctx);
	RUN_TEST_CASE(api_negative, message_error_compose_null_ctx);
	RUN_TEST_CASE(api_negative, message_error_compose_uninitialized_ctx);
	RUN_TEST_CASE(api_negative, message_error_compose_null_buf);
	RUN_TEST_CASE(api_negative, message_error_process_null_ctx);
	RUN_TEST_CASE(api_negative, message_error_process_uninitialized_ctx);
	RUN_TEST_CASE(api_negative, message_error_process_null_buf);

	RUN_TEST_CASE(api_negative, export_raw_null_ctx);
	RUN_TEST_CASE(api_negative, export_oscore_context_raw_null_ctx);
	RUN_TEST_CASE(api_negative,
		      export_oscore_context_raw_null_master_secret);
	RUN_TEST_CASE(api_negative, export_oscore_context_raw_null_master_salt);
	RUN_TEST_CASE(api_negative, export_oscore_context_raw_null_sender_id);
	RUN_TEST_CASE(api_negative,
		      export_oscore_context_raw_null_sender_id_len);
	RUN_TEST_CASE(api_negative,
		      export_oscore_context_raw_null_recipient_id);
	RUN_TEST_CASE(api_negative,
		      export_oscore_context_raw_null_recipient_id_len);

	RUN_TEST_CASE(api_negative, message_1_compose_null_len);
	RUN_TEST_CASE(api_negative, message_1_compose_null_buf);
	RUN_TEST_CASE(api_negative, message_1_process_null_buf);

	RUN_TEST_CASE(api_negative, export_key_update_null_ctx);
}
