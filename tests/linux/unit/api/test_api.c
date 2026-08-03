/**
 * \file    test_api.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for EDHOC public api.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include <edhoc/cipher_suite.h>
#include "edhoc_context_internal.h"
#include "edhoc_values_internal.h"
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

/* Self-contained interfaces so the bindings test stays free of shared fixtures;
 * bind() only stores their (non-NULL) callback pointers, never invokes them. */
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

TEST_GROUP(api);

TEST_SETUP(api)
{
}

TEST_TEAR_DOWN(api)
{
}

TEST(api, context_init)
{
	struct edhoc_context ctx = { 0 };

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(ctx.is_init);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, context_size)
{
	const size_t size = edhoc_context_size();

	TEST_ASSERT_GREATER_THAN(0, size);
	TEST_ASSERT_EQUAL(sizeof(struct edhoc_context), size);
	TEST_ASSERT_EQUAL(size, edhoc_context_size());
}

TEST(api, set_single_method)
{
	struct edhoc_context ctx = { 0 };
	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const enum edhoc_method method[] = { EDHOC_METHOD_3 };

	ret = edhoc_set_methods(&ctx, method, ARRAY_SIZE(method));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(method), ctx.negotiation.method.count);
	TEST_ASSERT_EQUAL(method[0], ctx.negotiation.method.entry[0]);
	TEST_ASSERT_EQUAL(0, ctx.negotiation.method.entry[1]);
	TEST_ASSERT_EQUAL(0, ctx.negotiation.method.entry[2]);
	TEST_ASSERT_EQUAL(0, ctx.negotiation.method.entry[3]);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, set_all_methods)
{
	struct edhoc_context ctx = { 0 };
	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const enum edhoc_method method[] = {
		EDHOC_METHOD_0,
		EDHOC_METHOD_1,
		EDHOC_METHOD_2,
		EDHOC_METHOD_3,
	};

	ret = edhoc_set_methods(&ctx, method, ARRAY_SIZE(method));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(method), ctx.negotiation.method.count);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(method, ctx.negotiation.method.entry,
				      sizeof(method));

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, set_single_cipher_suite)
{
	struct edhoc_context ctx = { 0 };
	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_cipher_suite suite = {
		.value = 1 << 1,
		.supports_dh_nike = true,
		.aead_key_length = 1 << 2,
		.aead_tag_length = 1 << 3,
		.aead_iv_length = 1 << 4,
		.hash_length = 1 << 5,
		.mac_length = 1 << 6,
		.kem_encapsulation_key_length = 1 << 7,
		.kem_ciphertext_length = 1 << 8,
		.nike_key_length = 1 << 9,
		.sign_length = 1 << 10,
	};

	ret = edhoc_set_cipher_suites(&ctx, &suite, 1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(1, ctx.negotiation.cipher_suite.count);

	const struct edhoc_cipher_suite *entry =
		&ctx.negotiation.cipher_suite.entry[0];
	TEST_ASSERT_EQUAL(suite.value, entry->value);
	TEST_ASSERT_EQUAL(suite.supports_dh_nike, entry->supports_dh_nike);
	TEST_ASSERT_EQUAL(suite.aead_key_length, entry->aead_key_length);
	TEST_ASSERT_EQUAL(suite.aead_tag_length, entry->aead_tag_length);
	TEST_ASSERT_EQUAL(suite.aead_iv_length, entry->aead_iv_length);
	TEST_ASSERT_EQUAL(suite.hash_length, entry->hash_length);
	TEST_ASSERT_EQUAL(suite.mac_length, entry->mac_length);
	TEST_ASSERT_EQUAL(suite.kem_encapsulation_key_length,
			  entry->kem_encapsulation_key_length);
	TEST_ASSERT_EQUAL(suite.kem_ciphertext_length,
			  entry->kem_ciphertext_length);
	TEST_ASSERT_EQUAL(suite.nike_key_length, entry->nike_key_length);
	TEST_ASSERT_EQUAL(suite.sign_length, entry->sign_length);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, set_many_cipher_suites)
{
	struct edhoc_context ctx = { 0 };
	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct edhoc_cipher_suite
		suites[ARRAY_SIZE(ctx.negotiation.cipher_suite.entry)] = { 0 };
	for (size_t i = 0; i < ARRAY_SIZE(suites); ++i) {
		const int v = (int)(i + 1);
		suites[i] = (struct edhoc_cipher_suite){
			.value = v << 1,
			.supports_dh_nike = true,
			.aead_key_length = v << 2,
			.aead_tag_length = v << 3,
			.aead_iv_length = v << 4,
			.hash_length = v << 5,
			.mac_length = v << 6,
			.kem_encapsulation_key_length = v << 7,
			.kem_ciphertext_length = v << 8,
			.nike_key_length = v << 9,
			.sign_length = v << 10,
		};
	}

	ret = edhoc_set_cipher_suites(&ctx, suites, ARRAY_SIZE(suites));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(suites),
			  ctx.negotiation.cipher_suite.count);

	for (size_t i = 0; i < ARRAY_SIZE(suites); ++i) {
		const struct edhoc_cipher_suite *entry =
			&ctx.negotiation.cipher_suite.entry[i];
		TEST_ASSERT_EQUAL(suites[i].value, entry->value);
		TEST_ASSERT_EQUAL(suites[i].supports_dh_nike,
				  entry->supports_dh_nike);
		TEST_ASSERT_EQUAL(suites[i].aead_key_length,
				  entry->aead_key_length);
		TEST_ASSERT_EQUAL(suites[i].aead_tag_length,
				  entry->aead_tag_length);
		TEST_ASSERT_EQUAL(suites[i].aead_iv_length,
				  entry->aead_iv_length);
		TEST_ASSERT_EQUAL(suites[i].hash_length, entry->hash_length);
		TEST_ASSERT_EQUAL(suites[i].mac_length, entry->mac_length);
		TEST_ASSERT_EQUAL(suites[i].kem_encapsulation_key_length,
				  entry->kem_encapsulation_key_length);
		TEST_ASSERT_EQUAL(suites[i].kem_ciphertext_length,
				  entry->kem_ciphertext_length);
		TEST_ASSERT_EQUAL(suites[i].nike_key_length,
				  entry->nike_key_length);
		TEST_ASSERT_EQUAL(suites[i].sign_length, entry->sign_length);
	}

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, set_connection_id)
{
	struct edhoc_context ctx = { 0 };
	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t value[CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID] = { 0x01 };
	struct edhoc_buffer cid = { .value = value,
				    .length = ARRAY_SIZE(value) + 1 };

	ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	cid.value = NULL;
	cid.length = 1;
	ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	/* RFC 9528: 3.3 allows the empty identifier. */
	cid.value = NULL;
	cid.length = 0;
	ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_size_t(0, ctx.negotiation.connection_id.length);

	cid.value = value;
	cid.length = ARRAY_SIZE(value);
	ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_size_t(cid.length,
				 ctx.negotiation.connection_id.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(
		value, ctx.negotiation.connection_id.value, cid.length);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, bindings)
{
	struct edhoc_context ctx = { 0 };
	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t *user_ctx = (uint8_t *)0xdeadbeef;
	ret = edhoc_set_user_context(&ctx, user_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(user_ctx, ctx.user_context);

	ret = edhoc_bind_ead(&ctx, &stub_ead);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(stub_ead.compose, ctx.interfaces.ead.compose);
	TEST_ASSERT_EQUAL(stub_ead.process, ctx.interfaces.ead.process);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_2);
	ret = edhoc_bind_crypto(&ctx, crypto);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(crypto->destroy_key,
			  ctx.interfaces.crypto.destroy_key);
	TEST_ASSERT_EQUAL(crypto->generate_key_pair,
			  ctx.interfaces.crypto.generate_key_pair);
	TEST_ASSERT_EQUAL(crypto->encapsulate,
			  ctx.interfaces.crypto.encapsulate);
	TEST_ASSERT_EQUAL(crypto->decapsulate,
			  ctx.interfaces.crypto.decapsulate);
	TEST_ASSERT_EQUAL(crypto->key_agreement,
			  ctx.interfaces.crypto.key_agreement);
	TEST_ASSERT_EQUAL(crypto->sign, ctx.interfaces.crypto.sign);
	TEST_ASSERT_EQUAL(crypto->verify, ctx.interfaces.crypto.verify);
	TEST_ASSERT_EQUAL(crypto->extract, ctx.interfaces.crypto.extract);
	TEST_ASSERT_EQUAL(crypto->expand, ctx.interfaces.crypto.expand);
	TEST_ASSERT_EQUAL(crypto->expand_raw, ctx.interfaces.crypto.expand_raw);
	TEST_ASSERT_EQUAL(crypto->aead_encrypt,
			  ctx.interfaces.crypto.aead_encrypt);
	TEST_ASSERT_EQUAL(crypto->aead_decrypt,
			  ctx.interfaces.crypto.aead_decrypt);
	TEST_ASSERT_EQUAL(crypto->hash_init, ctx.interfaces.crypto.hash_init);
	TEST_ASSERT_EQUAL(crypto->hash_update,
			  ctx.interfaces.crypto.hash_update);
	TEST_ASSERT_EQUAL(crypto->hash_finish,
			  ctx.interfaces.crypto.hash_finish);
	TEST_ASSERT_EQUAL(crypto->hash_abort, ctx.interfaces.crypto.hash_abort);

	ret = edhoc_bind_platform(&ctx, &stub_platform);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(stub_platform.zeroize,
			  ctx.interfaces.platform.zeroize);

	ret = edhoc_bind_credentials(&ctx, &stub_cred);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(stub_cred.select_local,
			  ctx.interfaces.cred.select_local);
	TEST_ASSERT_EQUAL(stub_cred.authenticate_peer,
			  ctx.interfaces.cred.authenticate_peer);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, error_get_code_default_is_success)
{
	struct edhoc_context ctx = { 0 };
	enum edhoc_error_code code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	int ret = edhoc_context_init(&ctx);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_error_get_code(&ctx, &code);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, code);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, error_get_code_reflects_set_code)
{
	struct edhoc_context ctx = { 0 };
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;
	int ret = edhoc_context_init(&ctx);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ctx.error_code = EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;

	ret = edhoc_error_get_code(&ctx, &code);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED, code);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, error_get_cipher_suites_returns_both_lists)
{
	struct edhoc_context ctx = { 0 };
	int32_t cs[3] = { -1, -1, -1 };
	int32_t peer_cs[3] = { -1, -1, -1 };
	size_t cs_len = 0;
	size_t peer_cs_len = 0;
	int ret = edhoc_context_init(&ctx);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ctx.error_code = EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
	ctx.negotiation.cipher_suite.count = 2;
	ctx.negotiation.cipher_suite.entry[0].value = 0;
	ctx.negotiation.cipher_suite.entry[1].value = 2;
	ctx.negotiation.peer_cipher_suite.count = 1;
	ctx.negotiation.peer_cipher_suite.entry[0].value = 3;

	ret = edhoc_error_get_cipher_suites(&ctx, cs, ARRAY_SIZE(cs), &cs_len,
					    peer_cs, ARRAY_SIZE(peer_cs),
					    &peer_cs_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(2, cs_len);
	TEST_ASSERT_EQUAL(0, cs[0]);
	TEST_ASSERT_EQUAL(2, cs[1]);
	TEST_ASSERT_EQUAL(1, peer_cs_len);
	TEST_ASSERT_EQUAL(3, peer_cs[0]);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(api)
{
	RUN_TEST_CASE(api, context_init);
	RUN_TEST_CASE(api, context_size);

	RUN_TEST_CASE(api, set_single_method);
	RUN_TEST_CASE(api, set_all_methods);

	RUN_TEST_CASE(api, set_single_cipher_suite);
	RUN_TEST_CASE(api, set_many_cipher_suites);

	RUN_TEST_CASE(api, set_connection_id);

	RUN_TEST_CASE(api, bindings);

	RUN_TEST_CASE(api, error_get_code_default_is_success);
	RUN_TEST_CASE(api, error_get_code_reflects_set_code);
	RUN_TEST_CASE(api, error_get_cipher_suites_returns_both_lists);
}
