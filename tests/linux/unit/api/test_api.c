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

static int stub_ead_compose(void *user_ctx, enum edhoc_message msg,
			    struct edhoc_ead_token *token, size_t token_size,
			    size_t *token_len);
static int stub_ead_process(void *user_ctx, enum edhoc_message msg,
			    const struct edhoc_ead_token *token,
			    size_t token_size);
static int stub_cred_fetch(void *user_ctx,
			   struct edhoc_auth_credentials *auth_cred);
static int stub_cred_verify(void *user_ctx,
			    struct edhoc_auth_credentials *auth_cred,
			    const uint8_t **pub_key, size_t *pub_key_len);
static void stub_zeroize(void *buffer, size_t length);

/* Static variables and constants ------------------------------------------ */

/* Self-contained interfaces so the bindings test stays free of shared fixtures;
 * bind() only stores their (non-NULL) callback pointers, never invokes them. */
static const struct edhoc_ead stub_ead = {
	.compose = stub_ead_compose,
	.process = stub_ead_process,
};

static const struct edhoc_credentials stub_cred = {
	.fetch = stub_cred_fetch,
	.verify = stub_cred_verify,
};

static const struct edhoc_platform stub_platform = {
	.zeroize = stub_zeroize,
};

/* Static function definitions --------------------------------------------- */

static int stub_ead_compose(void *user_ctx, enum edhoc_message msg,
			    struct edhoc_ead_token *token, size_t token_size,
			    size_t *token_len)
{
	(void)user_ctx;
	(void)msg;
	(void)token;
	(void)token_size;
	(void)token_len;

	return EDHOC_SUCCESS;
}

static int stub_ead_process(void *user_ctx, enum edhoc_message msg,
			    const struct edhoc_ead_token *token,
			    size_t token_size)
{
	(void)user_ctx;
	(void)msg;
	(void)token;
	(void)token_size;

	return EDHOC_SUCCESS;
}

static int stub_cred_fetch(void *user_ctx,
			   struct edhoc_auth_credentials *auth_cred)
{
	(void)user_ctx;
	(void)auth_cred;

	return EDHOC_SUCCESS;
}

static int stub_cred_verify(void *user_ctx,
			    struct edhoc_auth_credentials *auth_cred,
			    const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;
	(void)auth_cred;
	(void)pub_key;
	(void)pub_key_len;

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

TEST(api, set_connection_id_one_byte_integer)
{
	struct edhoc_context ctx = { 0 };
	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
	};

	cid.int_value = ONE_BYTE_CBOR_INT_MIN_VALUE - 1;
	ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	cid.int_value = ONE_BYTE_CBOR_INT_MAX_VALUE + 1;
	ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	cid.int_value =
		ONE_BYTE_CBOR_INT_MIN_VALUE + ONE_BYTE_CBOR_INT_MAX_VALUE;
	ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(cid.encode_type,
			  ctx.negotiation.connection_id.encode_type);
	TEST_ASSERT_EQUAL(cid.int_value,
			  ctx.negotiation.connection_id.int_value);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, set_connection_id_byte_string)
{
	struct edhoc_context ctx = { 0 };
	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
	};

	cid.bstr_length = 0;
	ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	cid.bstr_length = ARRAY_SIZE(cid.bstr_value) + 1;
	ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	cid.bstr_length = ARRAY_SIZE(cid.bstr_value) - 1;
	for (size_t i = 0; i < cid.bstr_length; ++i)
		cid.bstr_value[i] = (uint8_t)(i + 1);

	ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(cid.bstr_length,
			  ctx.negotiation.connection_id.bstr_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(cid.bstr_value,
				      ctx.negotiation.connection_id.bstr_value,
				      sizeof(cid.bstr_value));

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
	TEST_ASSERT_EQUAL(stub_cred.fetch, ctx.interfaces.cred.fetch);
	TEST_ASSERT_EQUAL(stub_cred.verify, ctx.interfaces.cred.verify);

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

	RUN_TEST_CASE(api, set_connection_id_one_byte_integer);
	RUN_TEST_CASE(api, set_connection_id_byte_string);

	RUN_TEST_CASE(api, bindings);
}
