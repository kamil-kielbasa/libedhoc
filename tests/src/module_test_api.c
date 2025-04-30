/**
 * \file    module_test_api.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for EDHOC public api.
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

/* Cipher suite 2 header: */
#include "cipher_suite_2.h"

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

/**
 * \brief Authentication credentials fetch callback for initiator
 *        for single certificate.
 */
static int auth_cred_fetch(void *user_ctx, struct edhoc_auth_creds *auth_cred);

/**
 * \brief Authentication credentials verify callback for initiator
 *        for single certificate.
 */
static int auth_cred_verify(void *user_ctx, struct edhoc_auth_creds *auth_cred,
			    const uint8_t **pub_key, size_t *pub_key_len);

/**
 * \brief Example EAD compose for multiple tokens. 
 */
static int ead_compose(void *user_context, enum edhoc_message message,
		       struct edhoc_ead_token *ead_token, size_t ead_token_size,
		       size_t *ead_token_len);

/**
 * \brief Example EAD process for multiple tokens. 
 */
static int ead_process(void *user_context, enum edhoc_message message,
		       const struct edhoc_ead_token *ead_token,
		       size_t ead_token_size);

/* Static variables and constants ------------------------------------------ */

static const struct edhoc_keys *edhoc_keys = NULL;
static const struct edhoc_crypto *edhoc_crypto = NULL;

static const struct edhoc_credentials edhoc_credentials = {
	.fetch = auth_cred_fetch,
	.verify = auth_cred_verify,
};

static const struct edhoc_ead edhoc_ead = {
	.compose = ead_compose,
	.process = ead_process,
};

/* Static function definitions --------------------------------------------- */

static int auth_cred_fetch(void *user_ctx, struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;
	(void)auth_cred;

	return EDHOC_SUCCESS;
}

static int auth_cred_verify(void *user_ctx, struct edhoc_auth_creds *auth_cred,
			    const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;
	(void)auth_cred;
	(void)pub_key;
	(void)pub_key_len;

	return EDHOC_SUCCESS;
}

static int ead_compose(void *user_context, enum edhoc_message message,
		       struct edhoc_ead_token *ead_token, size_t ead_token_size,
		       size_t *ead_token_len)
{
	(void)user_context;
	(void)message;
	(void)ead_token;
	(void)ead_token_size;
	(void)ead_token_len;

	return EDHOC_SUCCESS;
}

static int ead_process(void *user_context, enum edhoc_message message,
		       const struct edhoc_ead_token *ead_token,
		       size_t ead_token_size)
{
	(void)user_context;
	(void)message;
	(void)ead_token;
	(void)ead_token_size;

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(api);

TEST_SETUP(api)
{
	edhoc_keys = cipher_suite_2_get_keys_callbacks();
	TEST_ASSERT_NOT_NULL(edhoc_keys);

	edhoc_crypto = cipher_suite_2_get_cipher_callbacks();
	TEST_ASSERT_NOT_NULL(edhoc_crypto);
}

TEST_TEAR_DOWN(api)
{
}

TEST(api, context_init)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	struct edhoc_context ctx = { 0 };
	ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(true, ctx.is_init);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, set_mode)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/*
	 * Test setting single method.
	 */
	struct edhoc_context ctx = { 0 };
	ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_mode(&ctx, EDHOC_MODE_CLASSIC_RFC_9528);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_mode(&ctx, EDHOC_MODE_PSK_DRAFT);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_mode(&ctx, EDHOC_MODE_CLASSIC_RFC_9528 - 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_set_mode(&ctx, EDHOC_MODE_PSK_DRAFT + 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, set_methods)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/*
	 * Test setting single method.
	 */
	struct edhoc_context ctx = { 0 };
	ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const enum edhoc_method single_method[] = { EDHOC_METHOD_3 };
	ret = edhoc_set_methods(&ctx, single_method, ARRAY_SIZE(single_method));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(single_method), ctx.method_len);
	TEST_ASSERT_EQUAL(single_method[0], ctx.method[0]);
	TEST_ASSERT_EQUAL(0, ctx.method[1]);
	TEST_ASSERT_EQUAL(0, ctx.method[2]);
	TEST_ASSERT_EQUAL(0, ctx.method[3]);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/*
	 * Test setting all available methods.
	 */

	ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const enum edhoc_method all_method[] = {
		EDHOC_METHOD_0,
		EDHOC_METHOD_1,
		EDHOC_METHOD_2,
		EDHOC_METHOD_3,
	};
	ret = edhoc_set_methods(&ctx, all_method, ARRAY_SIZE(all_method));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(all_method), ctx.method_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(all_method, ctx.method,
				      sizeof(all_method));

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, set_cipher_suites)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/*
	 * Test setting single cipher suite.
	 */

	struct edhoc_context ctx = { 0 };
	ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_cipher_suite single_cipher_suite[] = {
		{
			.value = 1 << 1,
			.aead_key_length = 1 << 2,
			.aead_tag_length = 1 << 3,
			.aead_iv_length = 1 << 4,
			.hash_length = 1 << 5,
			.mac_length = 1 << 6,
			.ecc_key_length = 1 << 7,
			.ecc_sign_length = 1 << 8,
		},
	};
	ret = edhoc_set_cipher_suites(&ctx, single_cipher_suite,
				      ARRAY_SIZE(single_cipher_suite));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(single_cipher_suite), ctx.csuite_len);
	for (size_t i = 0; i < ARRAY_SIZE(single_cipher_suite); ++i) {
		TEST_ASSERT_EQUAL(single_cipher_suite[i].value,
				  ctx.csuite[i].value);
		TEST_ASSERT_EQUAL(single_cipher_suite[i].aead_key_length,
				  ctx.csuite[i].aead_key_length);
		TEST_ASSERT_EQUAL(single_cipher_suite[i].aead_tag_length,
				  ctx.csuite[i].aead_tag_length);
		TEST_ASSERT_EQUAL(single_cipher_suite[i].aead_iv_length,
				  ctx.csuite[i].aead_iv_length);
		TEST_ASSERT_EQUAL(single_cipher_suite[i].hash_length,
				  ctx.csuite[i].hash_length);
		TEST_ASSERT_EQUAL(single_cipher_suite[i].mac_length,
				  ctx.csuite[i].mac_length);
		TEST_ASSERT_EQUAL(single_cipher_suite[i].ecc_key_length,
				  ctx.csuite[i].ecc_key_length);
		TEST_ASSERT_EQUAL(single_cipher_suite[i].ecc_sign_length,
				  ctx.csuite[i].ecc_sign_length);
	}

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/*
	 * Test setting many cipher suites.
	 */

	ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct edhoc_cipher_suite many_cipher_suite[ARRAY_SIZE(ctx.csuite)] = {
		0
	};
	for (size_t i = 0; i < ARRAY_SIZE(many_cipher_suite); ++i) {
		many_cipher_suite[i] = (struct edhoc_cipher_suite){
			.value = (i + 1) << 1,
			.aead_key_length = (i + 1) << 2,
			.aead_tag_length = (i + 1) << 3,
			.aead_iv_length = (i + 1) << 4,
			.hash_length = (i + 1) << 5,
			.mac_length = (i + 1) << 6,
			.ecc_key_length = (i + 1) << 7,
			.ecc_sign_length = (i + 1) << 8,
		};
	}

	ret = edhoc_set_cipher_suites(&ctx, many_cipher_suite,
				      ARRAY_SIZE(many_cipher_suite));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(many_cipher_suite), ctx.csuite_len);
	for (size_t i = 0; i < ARRAY_SIZE(many_cipher_suite); ++i) {
		TEST_ASSERT_EQUAL(many_cipher_suite[i].value,
				  ctx.csuite[i].value);
		TEST_ASSERT_EQUAL(many_cipher_suite[i].aead_key_length,
				  ctx.csuite[i].aead_key_length);
		TEST_ASSERT_EQUAL(many_cipher_suite[i].aead_tag_length,
				  ctx.csuite[i].aead_tag_length);
		TEST_ASSERT_EQUAL(many_cipher_suite[i].aead_iv_length,
				  ctx.csuite[i].aead_iv_length);
		TEST_ASSERT_EQUAL(many_cipher_suite[i].hash_length,
				  ctx.csuite[i].hash_length);
		TEST_ASSERT_EQUAL(many_cipher_suite[i].mac_length,
				  ctx.csuite[i].mac_length);
		TEST_ASSERT_EQUAL(many_cipher_suite[i].ecc_key_length,
				  ctx.csuite[i].ecc_key_length);
		TEST_ASSERT_EQUAL(many_cipher_suite[i].ecc_sign_length,
				  ctx.csuite[i].ecc_sign_length);
	}

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, set_connection_id)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/*
	 * Test setting connection identifier as one byte integer.
	 */

	struct edhoc_context ctx = { 0 };
	ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct edhoc_connection_id one_byte_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER
	};

	one_byte_cid.int_value = ONE_BYTE_CBOR_INT_MIN_VALUE - 1;
	ret = edhoc_set_connection_id(&ctx, &one_byte_cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	one_byte_cid.int_value = ONE_BYTE_CBOR_INT_MAX_VALUE + 1;
	ret = edhoc_set_connection_id(&ctx, &one_byte_cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	one_byte_cid.int_value =
		ONE_BYTE_CBOR_INT_MIN_VALUE + ONE_BYTE_CBOR_INT_MAX_VALUE;
	ret = edhoc_set_connection_id(&ctx, &one_byte_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(one_byte_cid.encode_type, ctx.cid.encode_type);
	TEST_ASSERT_EQUAL(one_byte_cid.int_value, ctx.cid.int_value);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/*
	 * Test setting connection identifier as byte string.
	 */

	ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct edhoc_connection_id bstr_cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING
	};

	bstr_cid.bstr_length = 0;
	ret = edhoc_set_connection_id(&ctx, &bstr_cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	bstr_cid.bstr_length = ARRAY_SIZE(bstr_cid.bstr_value) + 1;
	ret = edhoc_set_connection_id(&ctx, &bstr_cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	bstr_cid.bstr_length = ARRAY_SIZE(bstr_cid.bstr_value) - 1;
	for (size_t i = 0; i < bstr_cid.bstr_length; ++i)
		bstr_cid.bstr_value[i] = i + 1;

	ret = edhoc_set_connection_id(&ctx, &bstr_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(bstr_cid.bstr_length, ctx.cid.bstr_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(bstr_cid.bstr_value, ctx.cid.bstr_value,
				      sizeof(bstr_cid.bstr_value));

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, bindings)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/*
	 * Test setting connection identifier as one byte integer.
	 */

	struct edhoc_context ctx = { 0 };
	ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t *user_ctx = (uint8_t *)0xdeadbeef;
	ret = edhoc_set_user_context(&ctx, user_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_NOT_NULL(ctx.user_ctx);

	ret = edhoc_bind_ead(&ctx, &edhoc_ead);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(edhoc_ead.compose, ctx.ead.compose);
	TEST_ASSERT_EQUAL(edhoc_ead.process, ctx.ead.process);

	ret = edhoc_bind_keys(&ctx, edhoc_keys);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(edhoc_keys->import_key, ctx.keys.import_key);
	TEST_ASSERT_EQUAL(edhoc_keys->destroy_key, ctx.keys.destroy_key);

	ret = edhoc_bind_crypto(&ctx, edhoc_crypto);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(edhoc_crypto->make_key_pair,
			  ctx.crypto.make_key_pair);
	TEST_ASSERT_EQUAL(edhoc_crypto->key_agreement,
			  ctx.crypto.key_agreement);
	TEST_ASSERT_EQUAL(edhoc_crypto->signature, ctx.crypto.signature);
	TEST_ASSERT_EQUAL(edhoc_crypto->verify, ctx.crypto.verify);
	TEST_ASSERT_EQUAL(edhoc_crypto->extract, ctx.crypto.extract);
	TEST_ASSERT_EQUAL(edhoc_crypto->expand, ctx.crypto.expand);
	TEST_ASSERT_EQUAL(edhoc_crypto->encrypt, ctx.crypto.encrypt);
	TEST_ASSERT_EQUAL(edhoc_crypto->decrypt, ctx.crypto.decrypt);
	TEST_ASSERT_EQUAL(edhoc_crypto->hash, ctx.crypto.hash);

	ret = edhoc_bind_credentials(&ctx, &edhoc_credentials);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(edhoc_credentials.fetch, ctx.cred.fetch);
	TEST_ASSERT_EQUAL(edhoc_credentials.verify, ctx.cred.verify);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(api)
{
	RUN_TEST_CASE(api, context_init);
	RUN_TEST_CASE(api, set_mode);
	RUN_TEST_CASE(api, set_methods);
	RUN_TEST_CASE(api, set_cipher_suites);
	RUN_TEST_CASE(api, set_connection_id);
	RUN_TEST_CASE(api, bindings);
}
