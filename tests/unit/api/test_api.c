/**
 * \file    test_api.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for EDHOC public api.
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#include "test_platform.h"
#include "edhoc_context_internal.h"
#include <edhoc/edhoc.h>
#include "edhoc_macros_internal.h"

/* Cipher suite headers: */
#include "edhoc_cipher_suite_0.h"
#include "edhoc_cipher_suite_2.h"
#include "edhoc_cipher_suite_24.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Test helpers: */
#include "test_ead.h"
#include "test_credentials.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
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
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	struct edhoc_context ctx = { 0 };
	ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(true, ctx.is_init);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, context_size)
{
	/* The opaque size must be positive, stable across calls and match the
	 * real layout that white-box code sees. */
	const size_t size = edhoc_context_size();

	TEST_ASSERT_GREATER_THAN(0, size);
	TEST_ASSERT_EQUAL(sizeof(struct edhoc_context), size);
	TEST_ASSERT_EQUAL(size, edhoc_context_size());
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
	TEST_ASSERT_EQUAL(ARRAY_SIZE(single_method),
			  ctx.negotiation.method.count);
	TEST_ASSERT_EQUAL(single_method[0], ctx.negotiation.method.entry[0]);
	TEST_ASSERT_EQUAL(0, ctx.negotiation.method.entry[1]);
	TEST_ASSERT_EQUAL(0, ctx.negotiation.method.entry[2]);
	TEST_ASSERT_EQUAL(0, ctx.negotiation.method.entry[3]);

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
	TEST_ASSERT_EQUAL(ARRAY_SIZE(all_method), ctx.negotiation.method.count);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(all_method, ctx.negotiation.method.entry,
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
			.supports_dh_nike = true,
			.aead_key_length = 1 << 2,
			.aead_tag_length = 1 << 3,
			.aead_iv_length = 1 << 4,
			.hash_length = 1 << 5,
			.mac_length = 1 << 6,
			.kem_public_key_length = 1 << 7,
			.kem_ciphertext_length = 1 << 8,
			.nike_key_length = 1 << 9,
			.sign_length = 1 << 10,
		},
	};
	ret = edhoc_set_cipher_suites(&ctx, single_cipher_suite,
				      ARRAY_SIZE(single_cipher_suite));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(single_cipher_suite),
			  ctx.negotiation.cipher_suite.count);
	for (size_t i = 0; i < ARRAY_SIZE(single_cipher_suite); ++i) {
		TEST_ASSERT_EQUAL(single_cipher_suite[i].value,
				  ctx.negotiation.cipher_suite.entry[i].value);
		TEST_ASSERT_EQUAL(
			single_cipher_suite[i].aead_key_length,
			ctx.negotiation.cipher_suite.entry[i].aead_key_length);
		TEST_ASSERT_EQUAL(
			single_cipher_suite[i].aead_tag_length,
			ctx.negotiation.cipher_suite.entry[i].aead_tag_length);
		TEST_ASSERT_EQUAL(
			single_cipher_suite[i].aead_iv_length,
			ctx.negotiation.cipher_suite.entry[i].aead_iv_length);
		TEST_ASSERT_EQUAL(
			single_cipher_suite[i].hash_length,
			ctx.negotiation.cipher_suite.entry[i].hash_length);
		TEST_ASSERT_EQUAL(
			single_cipher_suite[i].mac_length,
			ctx.negotiation.cipher_suite.entry[i].mac_length);
		TEST_ASSERT_EQUAL(
			single_cipher_suite[i].supports_dh_nike,
			ctx.negotiation.cipher_suite.entry[i].supports_dh_nike);
		TEST_ASSERT_EQUAL(single_cipher_suite[i].kem_public_key_length,
				  ctx.negotiation.cipher_suite.entry[i]
					  .kem_public_key_length);
		TEST_ASSERT_EQUAL(single_cipher_suite[i].kem_ciphertext_length,
				  ctx.negotiation.cipher_suite.entry[i]
					  .kem_ciphertext_length);
		TEST_ASSERT_EQUAL(
			single_cipher_suite[i].nike_key_length,
			ctx.negotiation.cipher_suite.entry[i].nike_key_length);
		TEST_ASSERT_EQUAL(
			single_cipher_suite[i].sign_length,
			ctx.negotiation.cipher_suite.entry[i].sign_length);
	}

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/*
	 * Test setting many cipher suites.
	 */

	ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct edhoc_cipher_suite many_cipher_suite[ARRAY_SIZE(
		ctx.negotiation.cipher_suite.entry)] = { 0 };
	for (size_t i = 0; i < ARRAY_SIZE(many_cipher_suite); ++i) {
		int v = (int)(i + 1);
		many_cipher_suite[i] = (struct edhoc_cipher_suite){
			.value = v << 1,
			.supports_dh_nike = true,
			.aead_key_length = v << 2,
			.aead_tag_length = v << 3,
			.aead_iv_length = v << 4,
			.hash_length = v << 5,
			.mac_length = v << 6,
			.kem_public_key_length = v << 7,
			.kem_ciphertext_length = v << 8,
			.nike_key_length = v << 9,
			.sign_length = v << 10,
		};
	}

	ret = edhoc_set_cipher_suites(&ctx, many_cipher_suite,
				      ARRAY_SIZE(many_cipher_suite));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(many_cipher_suite),
			  ctx.negotiation.cipher_suite.count);
	for (size_t i = 0; i < ARRAY_SIZE(many_cipher_suite); ++i) {
		TEST_ASSERT_EQUAL(many_cipher_suite[i].value,
				  ctx.negotiation.cipher_suite.entry[i].value);
		TEST_ASSERT_EQUAL(
			many_cipher_suite[i].aead_key_length,
			ctx.negotiation.cipher_suite.entry[i].aead_key_length);
		TEST_ASSERT_EQUAL(
			many_cipher_suite[i].aead_tag_length,
			ctx.negotiation.cipher_suite.entry[i].aead_tag_length);
		TEST_ASSERT_EQUAL(
			many_cipher_suite[i].aead_iv_length,
			ctx.negotiation.cipher_suite.entry[i].aead_iv_length);
		TEST_ASSERT_EQUAL(
			many_cipher_suite[i].hash_length,
			ctx.negotiation.cipher_suite.entry[i].hash_length);
		TEST_ASSERT_EQUAL(
			many_cipher_suite[i].mac_length,
			ctx.negotiation.cipher_suite.entry[i].mac_length);
		TEST_ASSERT_EQUAL(
			many_cipher_suite[i].supports_dh_nike,
			ctx.negotiation.cipher_suite.entry[i].supports_dh_nike);
		TEST_ASSERT_EQUAL(many_cipher_suite[i].kem_public_key_length,
				  ctx.negotiation.cipher_suite.entry[i]
					  .kem_public_key_length);
		TEST_ASSERT_EQUAL(many_cipher_suite[i].kem_ciphertext_length,
				  ctx.negotiation.cipher_suite.entry[i]
					  .kem_ciphertext_length);
		TEST_ASSERT_EQUAL(
			many_cipher_suite[i].nike_key_length,
			ctx.negotiation.cipher_suite.entry[i].nike_key_length);
		TEST_ASSERT_EQUAL(
			many_cipher_suite[i].sign_length,
			ctx.negotiation.cipher_suite.entry[i].sign_length);
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
	TEST_ASSERT_EQUAL(one_byte_cid.encode_type,
			  ctx.negotiation.connection_id.encode_type);
	TEST_ASSERT_EQUAL(one_byte_cid.int_value,
			  ctx.negotiation.connection_id.int_value);

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
		bstr_cid.bstr_value[i] = (uint8_t)(i + 1);

	ret = edhoc_set_connection_id(&ctx, &bstr_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(bstr_cid.bstr_length,
			  ctx.negotiation.connection_id.bstr_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(bstr_cid.bstr_value,
				      ctx.negotiation.connection_id.bstr_value,
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
	TEST_ASSERT_NOT_NULL(ctx.user_context);

	ret = edhoc_bind_ead(&ctx, &test_ead_stubs);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(test_ead_stubs.compose, ctx.interfaces.ead.compose);
	TEST_ASSERT_EQUAL(test_ead_stubs.process, ctx.interfaces.ead.process);

	ret = edhoc_bind_crypto(&ctx, edhoc_cipher_suite_2_get_crypto());
	edhoc_bind_platform(&ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_2_get_crypto()->destroy_key,
			  ctx.interfaces.crypto.destroy_key);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_2_get_crypto()->generate_key_pair,
			  ctx.interfaces.crypto.generate_key_pair);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_2_get_crypto()->encapsulate,
			  ctx.interfaces.crypto.encapsulate);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_2_get_crypto()->decapsulate,
			  ctx.interfaces.crypto.decapsulate);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_2_get_crypto()->key_agreement,
			  ctx.interfaces.crypto.key_agreement);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_2_get_crypto()->sign,
			  ctx.interfaces.crypto.sign);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_2_get_crypto()->verify,
			  ctx.interfaces.crypto.verify);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_2_get_crypto()->extract,
			  ctx.interfaces.crypto.extract);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_2_get_crypto()->expand,
			  ctx.interfaces.crypto.expand);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_2_get_crypto()->expand_raw,
			  ctx.interfaces.crypto.expand_raw);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_2_get_crypto()->aead_encrypt,
			  ctx.interfaces.crypto.aead_encrypt);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_2_get_crypto()->aead_decrypt,
			  ctx.interfaces.crypto.aead_decrypt);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_2_get_crypto()->hash_init,
			  ctx.interfaces.crypto.hash_init);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_2_get_crypto()->hash_update,
			  ctx.interfaces.crypto.hash_update);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_2_get_crypto()->hash_finish,
			  ctx.interfaces.crypto.hash_finish);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_2_get_crypto()->hash_abort,
			  ctx.interfaces.crypto.hash_abort);

	ret = edhoc_bind_credentials(&ctx, &test_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(test_cred_stubs.fetch, ctx.interfaces.cred.fetch);
	TEST_ASSERT_EQUAL(test_cred_stubs.verify, ctx.interfaces.cred.verify);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(api, get_cipher_suite_descriptors)
{
	const struct edhoc_cipher_suite *suite;

	suite = edhoc_cipher_suite_0_get_suite();
	TEST_ASSERT_NOT_NULL(suite);
	TEST_ASSERT_EQUAL(0, suite->value);
	TEST_ASSERT_TRUE(suite->supports_dh_nike);
	TEST_ASSERT_EQUAL(16, suite->aead_key_length);
	TEST_ASSERT_EQUAL(8, suite->aead_tag_length);
	TEST_ASSERT_EQUAL(13, suite->aead_iv_length);
	TEST_ASSERT_EQUAL(32, suite->hash_length);
	TEST_ASSERT_EQUAL(8, suite->mac_length);
	TEST_ASSERT_EQUAL(32, suite->kem_public_key_length);
	TEST_ASSERT_EQUAL(32, suite->kem_ciphertext_length);
	TEST_ASSERT_EQUAL(32, suite->nike_key_length);
	TEST_ASSERT_EQUAL(64, suite->sign_length);
	TEST_ASSERT_EQUAL(suite, edhoc_cipher_suite_0_get_suite());

	suite = edhoc_cipher_suite_2_get_suite();
	TEST_ASSERT_NOT_NULL(suite);
	TEST_ASSERT_EQUAL(2, suite->value);
	TEST_ASSERT_TRUE(suite->supports_dh_nike);
	TEST_ASSERT_EQUAL(16, suite->aead_key_length);
	TEST_ASSERT_EQUAL(8, suite->aead_tag_length);
	TEST_ASSERT_EQUAL(13, suite->aead_iv_length);
	TEST_ASSERT_EQUAL(32, suite->hash_length);
	TEST_ASSERT_EQUAL(8, suite->mac_length);
	TEST_ASSERT_EQUAL(32, suite->kem_public_key_length);
	TEST_ASSERT_EQUAL(32, suite->kem_ciphertext_length);
	TEST_ASSERT_EQUAL(32, suite->nike_key_length);
	TEST_ASSERT_EQUAL(64, suite->sign_length);
	TEST_ASSERT_EQUAL(suite, edhoc_cipher_suite_2_get_suite());

	suite = edhoc_cipher_suite_24_get_suite();
	TEST_ASSERT_NOT_NULL(suite);
	TEST_ASSERT_EQUAL(24, suite->value);
	TEST_ASSERT_TRUE(suite->supports_dh_nike);
	TEST_ASSERT_EQUAL(32, suite->aead_key_length);
	TEST_ASSERT_EQUAL(16, suite->aead_tag_length);
	TEST_ASSERT_EQUAL(12, suite->aead_iv_length);
	TEST_ASSERT_EQUAL(48, suite->hash_length);
	TEST_ASSERT_EQUAL(16, suite->mac_length);
	TEST_ASSERT_EQUAL(48, suite->kem_public_key_length);
	TEST_ASSERT_EQUAL(48, suite->kem_ciphertext_length);
	TEST_ASSERT_EQUAL(48, suite->nike_key_length);
	TEST_ASSERT_EQUAL(96, suite->sign_length);
	TEST_ASSERT_EQUAL(suite, edhoc_cipher_suite_24_get_suite());
}

TEST_GROUP_RUNNER(api)
{
	RUN_TEST_CASE(api, context_init);
	RUN_TEST_CASE(api, context_size);
	RUN_TEST_CASE(api, set_methods);
	RUN_TEST_CASE(api, set_cipher_suites);
	RUN_TEST_CASE(api, set_connection_id);
	RUN_TEST_CASE(api, bindings);
	RUN_TEST_CASE(api, get_cipher_suite_descriptors);
}
