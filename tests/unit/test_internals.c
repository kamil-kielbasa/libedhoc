/**
 * \file    test_internals.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for internal static functions exposed via LIBEDHOC_TEST_HOOKS.
 * \version 1.0
 * \date    2025-04-14
 *
 * \copyright Copyright (c) 2025
 *
 */

/* Include files ----------------------------------------------------------- */

#include "test_common.h"
#include "edhoc_test_hooks.h"
#include "edhoc_cipher_suite_0.h"
#include "test_cipher_suites.h"
#include "edhoc_common.h"
#include "edhoc_helpers.h"

#include <psa/crypto.h>

static const struct edhoc_keys *keys;
static const struct edhoc_crypto *crypto;

static void setup_crypto_context(struct edhoc_context *ctx)
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

TEST_GROUP(internals);

TEST_SETUP(internals)
{
	psa_crypto_init();
	keys = edhoc_cipher_suite_0_get_keys();
	crypto = edhoc_cipher_suite_0_get_crypto();
}

TEST_TEAR_DOWN(internals)
{
	mbedtls_psa_crypto_free();
}

/**
 * @scenario  comp_cid_len with ONE_BYTE_INTEGER encode type.
 * @env       Valid connection ID with encode_type EDHOC_CID_TYPE_ONE_BYTE_INTEGER.
 * @action    Call edhoc_test_comp_cid_len(&cid, &len).
 * @expected  EDHOC_SUCCESS, len=1.
 */
TEST(internals, comp_cid_len_one_byte_int)
{
	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5,
	};
	size_t len = 0;

	int ret = edhoc_test_comp_cid_len(&cid, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(1, len);
}

/**
 * @scenario  comp_cid_len with BYTE_STRING encode type.
 * @env       Valid connection ID with bstr_length=3.
 * @action    Call edhoc_test_comp_cid_len(&cid, &len).
 * @expected  EDHOC_SUCCESS, len=6 (3+1+edhoc_cbor_bstr_oh(3)).
 */
TEST(internals, comp_cid_len_byte_string)
{
	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3,
	};
	size_t len = 0;

	int ret = edhoc_test_comp_cid_len(&cid, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(6, len);
}

/**
 * @scenario  comp_cid_len with NULL arguments.
 * @env       NULL cid or NULL len pointer.
 * @action    Call edhoc_test_comp_cid_len with NULL args.
 * @expected  EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(internals, comp_cid_len_null_args)
{
	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
	};
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_cid_len(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_cid_len(&cid, NULL));
}

/**
 * @scenario  comp_cid_len with invalid encode type.
 * @env       Connection ID with encode_type=99.
 * @action    Call edhoc_test_comp_cid_len(&cid, &len).
 * @expected  EDHOC_ERROR_NOT_PERMITTED.
 */
TEST(internals, comp_cid_len_invalid_type)
{
	struct edhoc_connection_id cid = {
		.encode_type = 99,
	};
	size_t len = 0;

	int ret = edhoc_test_comp_cid_len(&cid, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

/**
 * @scenario  comp_id_cred_len with KID integer encoding.
 * @env       Cred with label=KID, encode_type=INTEGER, key_id_int=5.
 * @action    Call edhoc_test_comp_id_cred_len(&cred, &len).
 * @expected  EDHOC_SUCCESS, len includes map_oh(1)+int_mem_req(5).
 */
TEST(internals, comp_id_cred_len_kid_int)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.key_id.key_id_int = 5;
	size_t len = 0;

	int ret = edhoc_test_comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(4, len);
}

/**
 * @scenario  comp_id_cred_len with KID byte string encoding.
 * @env       Cred with label=KID, encode_type=BYTE_STRING, key_id_bstr_length=1.
 * @action    Call edhoc_test_comp_id_cred_len(&cred, &len).
 * @expected  EDHOC_SUCCESS.
 */
TEST(internals, comp_id_cred_len_kid_bstr)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.key_id.key_id_bstr_length = 1;
	size_t len = 0;

	int ret = edhoc_test_comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

/**
 * @scenario  comp_id_cred_len with X509 chain single cert.
 * @env       Cred with label=X509_CHAIN, nr_of_certs=1, cert_len[0]=100.
 * @action    Call edhoc_test_comp_id_cred_len(&cred, &len).
 * @expected  EDHOC_SUCCESS.
 */
TEST(internals, comp_id_cred_len_x509_chain_single)
{
	static uint8_t cert_buf[100];
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 1;
	cred.x509_chain.cert[0] = cert_buf;
	cred.x509_chain.cert_len[0] = 100;
	size_t len = 0;

	int ret = edhoc_test_comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

/**
 * @scenario  comp_id_cred_len with X509 chain multiple certs.
 * @env       Cred with label=X509_CHAIN, nr_of_certs=2.
 * @action    Call edhoc_test_comp_id_cred_len(&cred, &len).
 * @expected  EDHOC_SUCCESS, len includes array_oh.
 */
TEST(internals, comp_id_cred_len_x509_chain_multi)
{
	static uint8_t cert0[50];
	static uint8_t cert1[60];
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 2;
	cred.x509_chain.cert[0] = cert0;
	cred.x509_chain.cert_len[0] = 50;
	cred.x509_chain.cert[1] = cert1;
	cred.x509_chain.cert_len[1] = 60;
	size_t len = 0;

	int ret = edhoc_test_comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

/**
 * @scenario  comp_id_cred_len with X509 hash integer encoding.
 * @env       Cred with label=X509_HASH, encode_type=INTEGER.
 * @action    Call edhoc_test_comp_id_cred_len(&cred, &len).
 * @expected  EDHOC_SUCCESS.
 */
TEST(internals, comp_id_cred_len_x509_hash_int)
{
	static uint8_t cert_fp[32];
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.x509_hash.alg_int = -8;
	cred.x509_hash.cert_fp = cert_fp;
	cred.x509_hash.cert_fp_len = 32;
	size_t len = 0;

	int ret = edhoc_test_comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

/**
 * @scenario  comp_id_cred_len with X509 hash byte string encoding.
 * @env       Cred with label=X509_HASH, encode_type=BYTE_STRING.
 * @action    Call edhoc_test_comp_id_cred_len(&cred, &len).
 * @expected  EDHOC_SUCCESS.
 */
TEST(internals, comp_id_cred_len_x509_hash_bstr)
{
	static uint8_t cert_fp[32];
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.x509_hash.alg_bstr_length = sizeof(cred.x509_hash.alg_bstr);
	cred.x509_hash.alg_bstr[0] = 'S';
	cred.x509_hash.alg_bstr[1] = 'H';
	cred.x509_hash.cert_fp = cert_fp;
	cred.x509_hash.cert_fp_len = 32;
	size_t len = 0;

	int ret = edhoc_test_comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

/**
 * @scenario  comp_id_cred_len with unsupported label.
 * @env       Cred with label=99.
 * @action    Call edhoc_test_comp_id_cred_len(&cred, &len).
 * @expected  EDHOC_ERROR_NOT_SUPPORTED.
 */
TEST(internals, comp_id_cred_len_unsupported)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = 99;
	size_t len = 0;

	int ret = edhoc_test_comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);
}

/**
 * @scenario  comp_id_cred_len with NULL arguments.
 * @env       NULL cred or NULL len.
 * @action    Call edhoc_test_comp_id_cred_len with NULL args.
 * @expected  EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(internals, comp_id_cred_len_null)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_id_cred_len(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_id_cred_len(&cred, NULL));
}

/**
 * @scenario  comp_th_len with valid th_len.
 * @env       th_len=32.
 * @action    Call edhoc_test_comp_th_len(32, &len).
 * @expected  EDHOC_SUCCESS, len=32+bstr_oh(32).
 */
TEST(internals, comp_th_len_success)
{
	size_t len = 0;

	int ret = edhoc_test_comp_th_len(32, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(34, len);
}

/**
 * @scenario  comp_th_len with zero th_len.
 * @env       th_len=0.
 * @action    Call edhoc_test_comp_th_len(0, &len).
 * @expected  EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(internals, comp_th_len_zero)
{
	size_t len = 0;

	int ret = edhoc_test_comp_th_len(0, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  comp_cred_len with ANY label.
 * @env       Cred with label=ANY, any.cred_len=50.
 * @action    Call edhoc_test_comp_cred_len(&cred, &len).
 * @expected  EDHOC_SUCCESS, len includes 50.
 */
TEST(internals, comp_cred_len_any)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_ANY;
	cred.any.cred_len = 50;
	size_t len = 0;

	int ret = edhoc_test_comp_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(50, len);
}

/**
 * @scenario  comp_cred_len with KID label.
 * @env       Cred with label=KID, key_id.cred_len=100.
 * @action    Call edhoc_test_comp_cred_len(&cred, &len).
 * @expected  EDHOC_SUCCESS, len includes 100+bstr_oh(100).
 */
TEST(internals, comp_cred_len_kid)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.cred_len = 100;
	size_t len = 0;

	int ret = edhoc_test_comp_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(100, len);
}

/**
 * @scenario  comp_cred_len with X509 chain label.
 * @env       Cred with label=X509_CHAIN, cert_len[0]=200.
 * @action    Call edhoc_test_comp_cred_len(&cred, &len).
 * @expected  EDHOC_SUCCESS.
 */
TEST(internals, comp_cred_len_x509_chain)
{
	static uint8_t cert_buf[200];
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 1;
	cred.x509_chain.cert[0] = cert_buf;
	cred.x509_chain.cert_len[0] = 200;
	size_t len = 0;

	int ret = edhoc_test_comp_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

/**
 * @scenario  comp_cred_len with X509 hash label.
 * @env       Cred with label=X509_HASH, cert_len=150.
 * @action    Call edhoc_test_comp_cred_len(&cred, &len).
 * @expected  EDHOC_SUCCESS.
 */
TEST(internals, comp_cred_len_x509_hash)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.cert_len = 150;
	size_t len = 0;

	int ret = edhoc_test_comp_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

/**
 * @scenario  comp_cred_len with unsupported label.
 * @env       Cred with label=99.
 * @action    Call edhoc_test_comp_cred_len(&cred, &len).
 * @expected  EDHOC_ERROR_NOT_SUPPORTED.
 */
TEST(internals, comp_cred_len_unsupported)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = 99;
	size_t len = 0;

	int ret = edhoc_test_comp_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);
}

/**
 * @scenario  comp_ead_len with no EAD tokens.
 * @env       Context with nr_of_ead_tokens=0.
 * @action    Call edhoc_test_comp_ead_len(&ctx, &len).
 * @expected  EDHOC_SUCCESS, len=0.
 */
TEST(internals, comp_ead_len_no_tokens)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	ctx.nr_of_ead_tokens = 0;
	size_t len = 0;

	int ret = edhoc_test_comp_ead_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(0, len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  comp_ead_len with EAD tokens.
 * @env       Context with 2 tokens (labels and values).
 * @action    Call edhoc_test_comp_ead_len(&ctx, &len).
 * @expected  EDHOC_SUCCESS, len>0.
 */
TEST(internals, comp_ead_len_with_tokens)
{
	static uint8_t val0[4] = { 0x01, 0x02, 0x03, 0x04 };
	static uint8_t val1[2] = { 0xAA, 0xBB };
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	ctx.nr_of_ead_tokens = 2;
	ctx.ead_token[0].label = 1;
	ctx.ead_token[0].value = val0;
	ctx.ead_token[0].value_len = 4;
	ctx.ead_token[1].label = 2;
	ctx.ead_token[1].value = val1;
	ctx.ead_token[1].value_len = 2;
	size_t len = 0;

	int ret = edhoc_test_comp_ead_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  kid_compact_encoding with INTEGER encode type and CBOR cred.
 * @env       Cred with KID, encode_type=INTEGER, cred_is_cbor=true.
 * @action    Call edhoc_test_kid_compact_encoding(&cred, mac_ctx).
 * @expected  EDHOC_SUCCESS, id_cred_enc_type=INTEGER, id_cred_int set.
 */
TEST(internals, kid_compact_enc_int_cbor)
{
	uint8_t buf[512];
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	memset(buf, 0, sizeof(buf));
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.key_id.key_id_int = 7;
	cred.key_id.cred_is_cbor = true;

	int ret = edhoc_test_kid_compact_encoding(&cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(mac_ctx->id_cred_is_comp_enc);
	TEST_ASSERT_EQUAL(EDHOC_ENCODE_TYPE_INTEGER, mac_ctx->id_cred_enc_type);
	TEST_ASSERT_EQUAL(7, mac_ctx->id_cred_int);
}

/**
 * @scenario  kid_compact_encoding with INTEGER encode type and non-CBOR cred.
 * @env       Cred with KID, encode_type=INTEGER, cred_is_cbor=false.
 * @action    Call edhoc_test_kid_compact_encoding(&cred, mac_ctx).
 * @expected  EDHOC_SUCCESS, CBOR encode.
 */
TEST(internals, kid_compact_enc_int_non_cbor)
{
	uint8_t buf[512];
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	memset(buf, 0, sizeof(buf));
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.key_id.key_id_int = 5;
	cred.key_id.cred_is_cbor = false;

	int ret = edhoc_test_kid_compact_encoding(&cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(mac_ctx->id_cred_is_comp_enc);
}

/**
 * @scenario  kid_compact_encoding with BYTE_STRING, CBOR, one-byte that decodes to one-byte int.
 * @env       Cred with key_id_bstr[0]=0x05 (CBOR int 5).
 * @action    Call edhoc_test_kid_compact_encoding(&cred, mac_ctx).
 * @expected  EDHOC_SUCCESS, id_cred_enc_type=INTEGER.
 */
TEST(internals, kid_compact_enc_bstr_cbor_one_byte)
{
	uint8_t buf[512];
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	memset(buf, 0, sizeof(buf));
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.key_id.cred_is_cbor = true;
	cred.key_id.key_id_bstr_length = 1;
	cred.key_id.key_id_bstr[0] = 0x05;

	int ret = edhoc_test_kid_compact_encoding(&cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(mac_ctx->id_cred_is_comp_enc);
	TEST_ASSERT_EQUAL(EDHOC_ENCODE_TYPE_INTEGER, mac_ctx->id_cred_enc_type);
	TEST_ASSERT_EQUAL(5, mac_ctx->id_cred_int);
}

/**
 * @scenario  kid_compact_encoding with BYTE_STRING, CBOR, multi-byte length.
 * @env       Cred with key_id_bstr_length=2.
 * @action    Call edhoc_test_kid_compact_encoding(&cred, mac_ctx).
 * @expected  EDHOC_SUCCESS, stays bstr.
 */
TEST(internals, kid_compact_enc_bstr_cbor_multi_byte)
{
	uint8_t buf[512];
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	memset(buf, 0, sizeof(buf));
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.key_id.cred_is_cbor = true;
	cred.key_id.key_id_bstr_length = 2;
	cred.key_id.key_id_bstr[0] = 0x18;
	cred.key_id.key_id_bstr[1] = 0x64;

	int ret = edhoc_test_kid_compact_encoding(&cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(mac_ctx->id_cred_is_comp_enc);
	TEST_ASSERT_EQUAL(EDHOC_ENCODE_TYPE_BYTE_STRING,
			  mac_ctx->id_cred_enc_type);
	TEST_ASSERT_EQUAL(2, mac_ctx->id_cred_bstr_len);
}

/**
 * @scenario  kid_compact_encoding with BYTE_STRING and non-CBOR cred.
 * @env       Cred with encode_type=BYTE_STRING, cred_is_cbor=false.
 * @action    Call edhoc_test_kid_compact_encoding(&cred, mac_ctx).
 * @expected  EDHOC_SUCCESS, CBOR encode to bstr.
 */
TEST(internals, kid_compact_enc_bstr_non_cbor)
{
	uint8_t buf[512];
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	memset(buf, 0, sizeof(buf));
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.key_id.cred_is_cbor = false;
	cred.key_id.key_id_bstr_length = 0;

	int ret = edhoc_test_kid_compact_encoding(&cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(mac_ctx->id_cred_is_comp_enc);
	TEST_ASSERT_EQUAL(EDHOC_ENCODE_TYPE_BYTE_STRING,
			  mac_ctx->id_cred_enc_type);
}

/**
 * @scenario  compute_prk_out with bad th_state.
 * @env       Context with th_state != EDHOC_TH_STATE_4.
 * @action    Call edhoc_test_compute_prk_out(&ctx).
 * @expected  EDHOC_ERROR_BAD_STATE.
 */
TEST(internals, compute_prk_out_bad_th_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	int ret = edhoc_test_compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  compute_prk_out with bad prk_state.
 * @env       Context with prk_state != EDHOC_PRK_STATE_4E3M.
 * @action    Call edhoc_test_compute_prk_out(&ctx).
 * @expected  EDHOC_ERROR_BAD_STATE.
 */
TEST(internals, compute_prk_out_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_4;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	int ret = edhoc_test_compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  compute_prk_out with NULL context.
 * @env       NULL ctx.
 * @action    Call edhoc_test_compute_prk_out(NULL).
 * @expected  EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(internals, compute_prk_out_null)
{
	int ret = edhoc_test_compute_prk_out(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  compute_prk_out success with real crypto.
 * @env       Context with th_state=4, prk_state=4E3M, valid th/prk, cipher suite 0.
 * @action    Call edhoc_test_compute_prk_out(&ctx).
 * @expected  EDHOC_SUCCESS, prk_state becomes EDHOC_PRK_STATE_OUT.
 */
TEST(internals, compute_prk_out_success)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_4;
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.th_len = 32;
	ctx.prk_len = 32;
	for (size_t i = 0; i < 32; i++) {
		ctx.th[i] = (uint8_t)(i + 1);
		ctx.prk[i] = (uint8_t)(i + 0x20);
	}

	int ret = edhoc_test_compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, ctx.prk_state);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  compute_new_prk_out with bad prk_state.
 * @env       Context with prk_state != EDHOC_PRK_STATE_OUT.
 * @action    Call edhoc_test_compute_new_prk_out(&ctx, entropy, len).
 * @expected  EDHOC_ERROR_BAD_STATE.
 */
TEST(internals, compute_new_prk_out_bad_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.prk_len = 32;

	uint8_t entropy[16] = { 0xAA };
	int ret =
		edhoc_test_compute_new_prk_out(&ctx, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  compute_new_prk_out success after compute_prk_out.
 * @env       Context after compute_prk_out (prk_state=OUT).
 * @action    Call edhoc_test_compute_new_prk_out(&ctx, entropy, len).
 * @expected  EDHOC_SUCCESS.
 */
TEST(internals, compute_new_prk_out_success)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_4;
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.th_len = 32;
	ctx.prk_len = 32;
	for (size_t i = 0; i < 32; i++) {
		ctx.th[i] = (uint8_t)(i + 1);
		ctx.prk[i] = (uint8_t)(i + 0x20);
	}

	int ret = edhoc_test_compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t entropy[16] = { 0xBB };
	ret = edhoc_test_compute_new_prk_out(&ctx, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  compute_prk_exporter with bad prk_state.
 * @env       Context with prk_state != EDHOC_PRK_STATE_OUT.
 * @action    Call edhoc_test_compute_prk_exporter(&ctx, buf, len).
 * @expected  EDHOC_ERROR_BAD_STATE.
 */
TEST(internals, compute_prk_exporter_bad_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.prk_len = 32;

	uint8_t prk_exp[32];
	int ret =
		edhoc_test_compute_prk_exporter(&ctx, prk_exp, sizeof(prk_exp));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  compute_prk_exporter success after compute_prk_out.
 * @env       Context after compute_prk_out.
 * @action    Call edhoc_test_compute_prk_exporter(&ctx, buf, len).
 * @expected  EDHOC_SUCCESS.
 */
TEST(internals, compute_prk_exporter_success)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_4;
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.th_len = 32;
	ctx.prk_len = 32;
	for (size_t i = 0; i < 32; i++) {
		ctx.th[i] = (uint8_t)(i + 1);
		ctx.prk[i] = (uint8_t)(i + 0x20);
	}

	int ret = edhoc_test_compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t prk_exp[32];
	ret = edhoc_test_compute_prk_exporter(&ctx, prk_exp, sizeof(prk_exp));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  comp_salt_3e2m with bad th_state.
 * @env       Context with th_state != EDHOC_TH_STATE_2.
 * @action    Call edhoc_test_comp_salt_3e2m(&ctx, salt, len).
 * @expected  EDHOC_ERROR_BAD_STATE.
 */
TEST(internals, comp_salt_3e2m_bad_th_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_1;
	ctx.prk_state = EDHOC_PRK_STATE_2E;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	uint8_t salt[32];
	int ret = edhoc_test_comp_salt_3e2m(&ctx, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  comp_salt_3e2m with bad prk_state.
 * @env       Context with prk_state != EDHOC_PRK_STATE_2E.
 * @action    Call edhoc_test_comp_salt_3e2m(&ctx, salt, len).
 * @expected  EDHOC_ERROR_BAD_STATE.
 */
TEST(internals, comp_salt_3e2m_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	uint8_t salt[32];
	int ret = edhoc_test_comp_salt_3e2m(&ctx, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  comp_salt_4e3m with bad th_state.
 * @env       Context with th_state != EDHOC_TH_STATE_3.
 * @action    Call edhoc_test_comp_salt_4e3m(&ctx, salt, len).
 * @expected  EDHOC_ERROR_BAD_STATE.
 */
TEST(internals, comp_salt_4e3m_bad_th_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	uint8_t salt[32];
	int ret = edhoc_test_comp_salt_4e3m(&ctx, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  comp_salt_4e3m with bad prk_state.
 * @env       Context with prk_state != EDHOC_PRK_STATE_3E2M.
 * @action    Call edhoc_test_comp_salt_4e3m(&ctx, salt, len).
 * @expected  EDHOC_ERROR_BAD_STATE.
 */
TEST(internals, comp_salt_4e3m_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.prk_state = EDHOC_PRK_STATE_2E;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	uint8_t salt[32];
	int ret = edhoc_test_comp_salt_4e3m(&ctx, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  comp_prk_3e2m with method 0 (sig/sig for responder).
 * @env       Context with method 0, prk_state=2E, th_state=2.
 * @action    Call edhoc_test_comp_prk_3e2m(&ctx, auth_cred, NULL, 0).
 * @expected  EDHOC_SUCCESS, prk_3e2m = prk_2e (no DH).
 */
TEST(internals, comp_prk_3e2m_method_0)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.chosen_method = EDHOC_METHOD_0;
	ctx.prk_state = EDHOC_PRK_STATE_2E;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	struct edhoc_auth_creds auth_cred = { 0 };
	auth_cred.label = EDHOC_COSE_HEADER_KID;

	int ret = edhoc_test_comp_prk_3e2m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, ctx.prk_state);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  comp_prk_3e2m with method 1 (sig/DH for responder).
 * @env       Context with method 1, prk_state=2E, th_state=2, DH keys, auth_cred.
 * @action    Call edhoc_test_comp_prk_3e2m(&ctx, auth_cred, pub_key, 32).
 * @expected  EDHOC_SUCCESS, DH computation.
 */
TEST(internals, comp_prk_3e2m_method_1)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.chosen_method = EDHOC_METHOD_1;
	ctx.prk_state = EDHOC_PRK_STATE_2E;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	ctx.prk_len = 32;
	for (size_t i = 0; i < 32; i++) {
		ctx.th[i] = (uint8_t)(i + 1);
		ctx.prk[i] = (uint8_t)(i + 0x20);
	}

	uint8_t dh_priv[32];
	uint8_t dh_peer_pub[32];
	for (size_t i = 0; i < 32; i++) {
		dh_priv[i] = (uint8_t)(i + 0x40);
		dh_peer_pub[i] = (uint8_t)(i + 0x60);
	}
	memcpy(ctx.dh_priv_key, dh_priv, 32);
	ctx.dh_priv_key_len = 32;
	memcpy(ctx.dh_peer_pub_key, dh_peer_pub, 32);
	ctx.dh_peer_pub_key_len = 32;

	struct edhoc_auth_creds auth_cred = { 0 };
	auth_cred.label = EDHOC_COSE_HEADER_KID;
	edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_KEY_AGREEMENT, dh_priv,
					32, auth_cred.priv_key_id);

	uint8_t pub_key[32];
	for (size_t i = 0; i < 32; i++)
		pub_key[i] = (uint8_t)(i + 0x80);

	int ret = edhoc_test_comp_prk_3e2m(&ctx, &auth_cred, pub_key, 32);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, ctx.prk_state);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  comp_prk_3e2m with METHOD_MAX.
 * @env       Context with chosen_method=EDHOC_METHOD_MAX.
 * @action    Call edhoc_test_comp_prk_3e2m(&ctx, auth_cred, NULL, 0).
 * @expected  EDHOC_ERROR_NOT_PERMITTED.
 */
TEST(internals, comp_prk_3e2m_method_max)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.chosen_method = EDHOC_METHOD_MAX;
	ctx.prk_state = EDHOC_PRK_STATE_2E;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	struct edhoc_auth_creds auth_cred = { 0 };
	auth_cred.label = EDHOC_COSE_HEADER_KID;

	int ret = edhoc_test_comp_prk_3e2m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  comp_prk_4e3m with method 0.
 * @env       Context with method 0, prk_state=3E2M, th_state=3.
 * @action    Call edhoc_test_comp_prk_4e3m(&ctx, auth_cred, NULL, 0).
 * @expected  EDHOC_SUCCESS, prk_4e3m = prk_3e2m.
 */
TEST(internals, comp_prk_4e3m_method_0)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.chosen_method = EDHOC_METHOD_0;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	struct edhoc_auth_creds auth_cred = { 0 };
	auth_cred.label = EDHOC_COSE_HEADER_KID;

	int ret = edhoc_test_comp_prk_4e3m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, ctx.prk_state);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  comp_prk_4e3m with method 2 (DH/sig for initiator).
 * @env       Context with method 2, prk_state=3E2M, th_state=3, DH keys.
 * @action    Call edhoc_test_comp_prk_4e3m(&ctx, auth_cred, pub_key, 32).
 * @expected  EDHOC_SUCCESS, DH computation.
 */
TEST(internals, comp_prk_4e3m_method_2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.chosen_method = EDHOC_METHOD_2;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.th_len = 32;
	ctx.prk_len = 32;
	for (size_t i = 0; i < 32; i++) {
		ctx.th[i] = (uint8_t)(i + 1);
		ctx.prk[i] = (uint8_t)(i + 0x20);
	}

	uint8_t dh_priv[32];
	uint8_t dh_peer_pub[32];
	for (size_t i = 0; i < 32; i++) {
		dh_priv[i] = (uint8_t)(i + 0x40);
		dh_peer_pub[i] = (uint8_t)(i + 0x60);
	}
	memcpy(ctx.dh_priv_key, dh_priv, 32);
	ctx.dh_priv_key_len = 32;
	memcpy(ctx.dh_peer_pub_key, dh_peer_pub, 32);
	ctx.dh_peer_pub_key_len = 32;

	struct edhoc_auth_creds auth_cred = { 0 };
	auth_cred.label = EDHOC_COSE_HEADER_KID;
	edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_KEY_AGREEMENT, dh_priv,
					32, auth_cred.priv_key_id);

	uint8_t pub_key[32];
	for (size_t i = 0; i < 32; i++)
		pub_key[i] = (uint8_t)(i + 0x80);

	int ret = edhoc_test_comp_prk_4e3m(&ctx, &auth_cred, pub_key, 32);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, ctx.prk_state);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  comp_prk_4e3m with METHOD_MAX.
 * @env       Context with chosen_method=EDHOC_METHOD_MAX.
 * @action    Call edhoc_test_comp_prk_4e3m(&ctx, auth_cred, NULL, 0).
 * @expected  EDHOC_ERROR_NOT_PERMITTED.
 */
TEST(internals, comp_prk_4e3m_method_max)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.chosen_method = EDHOC_METHOD_MAX;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	struct edhoc_auth_creds auth_cred = { 0 };
	auth_cred.label = EDHOC_COSE_HEADER_KID;

	int ret = edhoc_test_comp_prk_4e3m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	edhoc_context_deinit(&ctx);
}

/* ---- edhoc_comp_mac_context tests (edhoc_common.c coverage) ---- */

/**
 * @scenario  edhoc_comp_mac_context_length with X509_CHAIN single cert, MSG_2.
 * @env       Context for MSG_2, X509_CHAIN credentials with one cert.
 * @action    Call edhoc_comp_mac_context_length and assert success.
 * @expected  EDHOC_SUCCESS, non-zero mac_ctx_len.
 */
TEST(internals, mac_ctx_x509_chain_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 1;
	cred.x509_chain.cert[0] = dummy_cert;
	cred.x509_chain.cert_len[0] = sizeof(dummy_cert);

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_mac_context_length with X509_CHAIN multi cert, MSG_2.
 * @env       Context for MSG_2, X509_CHAIN with nr_of_certs=2.
 * @action    Call edhoc_comp_mac_context_length and assert success.
 * @expected  EDHOC_SUCCESS, non-zero mac_ctx_len.
 */
TEST(internals, mac_ctx_x509_chain_multi_cert)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	static const uint8_t cert0[50] = { 0 };
	static const uint8_t cert1[60] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 2;
	cred.x509_chain.cert[0] = cert0;
	cred.x509_chain.cert_len[0] = 50;
	cred.x509_chain.cert[1] = cert1;
	cred.x509_chain.cert_len[1] = 60;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_mac_context_length with X509_HASH integer alg, MSG_2.
 * @env       Context for MSG_2, X509_HASH with encode_type INTEGER.
 * @action    Call edhoc_comp_mac_context_length and assert success.
 * @expected  EDHOC_SUCCESS, non-zero mac_ctx_len.
 */
TEST(internals, mac_ctx_x509_hash_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	static const uint8_t dummy_cert[100] = { 0 };
	static const uint8_t dummy_fp[32] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.x509_hash.alg_int = -16;
	cred.x509_hash.cert_fp = dummy_fp;
	cred.x509_hash.cert_fp_len = 32;
	cred.x509_hash.cert = dummy_cert;
	cred.x509_hash.cert_len = 100;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_mac_context_length with X509_HASH byte_string alg, MSG_2.
 * @env       Context for MSG_2, X509_HASH with encode_type BYTE_STRING.
 * @action    Call edhoc_comp_mac_context_length and assert success.
 * @expected  EDHOC_SUCCESS, non-zero mac_ctx_len.
 */
TEST(internals, mac_ctx_x509_hash_bstr_alg)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	static const uint8_t dummy_cert[100] = { 0 };
	static const uint8_t dummy_fp[32] = { 0 };
	static const uint8_t alg_bstr[4] = { 'S', 'H', 'A', '-' };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.x509_hash.alg_bstr_length = 4;
	memcpy(cred.x509_hash.alg_bstr, alg_bstr, 4);
	cred.x509_hash.cert_fp = dummy_fp;
	cred.x509_hash.cert_fp_len = 32;
	cred.x509_hash.cert = dummy_cert;
	cred.x509_hash.cert_len = 100;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_mac_context_length with KID integer, MSG_3.
 * @env       Context for MSG_3, KID with integer encode_type, cred_is_cbor.
 * @action    Call edhoc_comp_mac_context_length and assert success.
 * @expected  EDHOC_SUCCESS, non-zero mac_ctx_len.
 */
TEST(internals, mac_ctx_kid_int_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);

	static const uint8_t dummy_cred[50] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.key_id.key_id_int = 4;
	cred.key_id.cred_is_cbor = true;
	cred.key_id.cred = dummy_cred;
	cred.key_id.cred_len = 50;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_mac_context_length with KID byte_string, MSG_2.
 * @env       Context for MSG_2, KID with byte_string encode_type.
 * @action    Call edhoc_comp_mac_context_length and assert success.
 * @expected  EDHOC_SUCCESS, non-zero mac_ctx_len.
 */
TEST(internals, mac_ctx_kid_bstr_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	static const uint8_t dummy_cred[50] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.key_id.key_id_bstr_length = 2;
	cred.key_id.key_id_bstr[0] = 0x11;
	cred.key_id.key_id_bstr[1] = 0x22;
	cred.key_id.cred = dummy_cred;
	cred.key_id.cred_len = 50;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_mac_context_length with byte-string CID, MSG_2.
 * @env       Context for MSG_2, CID encode_type BYTE_STRING.
 * @action    Call edhoc_comp_mac_context_length and assert success.
 * @expected  EDHOC_SUCCESS, non-zero mac_ctx_len.
 */
TEST(internals, mac_ctx_bstr_cid_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_BYTE_STRING;
	ctx.cid.bstr_value[0] = 0x01;
	ctx.cid.bstr_value[1] = 0x02;
	ctx.cid.bstr_length = 2;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 1;
	cred.x509_chain.cert[0] = dummy_cert;
	cred.x509_chain.cert_len[0] = sizeof(dummy_cert);

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_mac_context_length with EAD tokens.
 * @env       Context with nr_of_ead_tokens=1 and EAD token.
 * @action    Call edhoc_comp_mac_context_length and assert success.
 * @expected  EDHOC_SUCCESS, non-zero mac_ctx_len.
 */
TEST(internals, mac_ctx_with_ead)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;
	ctx.nr_of_ead_tokens = 1;
	ctx.ead_token[0].label = 100;
	static const uint8_t ead_val[4] = { 1, 2, 3, 4 };
	ctx.ead_token[0].value = ead_val;
	ctx.ead_token[0].value_len = 4;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 1;
	cred.x509_chain.cert[0] = dummy_cert;
	cred.x509_chain.cert_len[0] = sizeof(dummy_cert);

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_mac_context_length with COSE_ANY credential type.
 * @env       Context for MSG_2, cred label EDHOC_COSE_ANY.
 * @action    Call edhoc_comp_mac_context_length and assert success.
 * @expected  EDHOC_SUCCESS, non-zero mac_ctx_len.
 */
TEST(internals, mac_ctx_any_cred)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	static const uint8_t any_id_cred[10] = { 0xA1, 0x04, 0x42, 0x11, 0x22 };
	static const uint8_t any_cred[20] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_ANY;
	cred.any.id_cred = any_id_cred;
	cred.any.id_cred_len = 5;
	cred.any.cred = any_cred;
	cred.any.cred_len = 20;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	edhoc_context_deinit(&ctx);
}

/* ---- edhoc_comp_mac_length and edhoc_comp_sign_or_mac_length tests ---- */

/**
 * @scenario  edhoc_comp_mac_length with method 1, MSG_2.
 * @env       Context with chosen_method=1 (MAC-only), message=MSG_2.
 * @action    Call edhoc_comp_mac_length.
 * @expected  EDHOC_SUCCESS, mac_len = csuite.mac_length (8).
 */
TEST(internals, mac_length_method_1_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_1;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, mac_len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_mac_length with method 2, MSG_3.
 * @env       Context with chosen_method=2 (MAC-only for initiator), message=MSG_3.
 * @action    Call edhoc_comp_mac_length.
 * @expected  EDHOC_SUCCESS, mac_len = csuite.mac_length (8).
 */
TEST(internals, mac_length_method_2_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.chosen_method = EDHOC_METHOD_2;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, mac_len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_sign_or_mac_length with method 1, MSG_2.
 * @env       Context with chosen_method=1, message=MSG_2.
 * @action    Call edhoc_comp_sign_or_mac_length.
 * @expected  EDHOC_SUCCESS, sign_or_mac_len = csuite.mac_length (8).
 */
TEST(internals, sign_or_mac_length_method_1_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_1;

	size_t sign_or_mac_len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &sign_or_mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, sign_or_mac_len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_sign_or_mac_length with method 3, MSG_3.
 * @env       Context with chosen_method=3, message=MSG_3.
 * @action    Call edhoc_comp_sign_or_mac_length.
 * @expected  EDHOC_SUCCESS, sign_or_mac_len = csuite.mac_length (8).
 */
TEST(internals, sign_or_mac_length_method_3_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.chosen_method = EDHOC_METHOD_3;

	size_t sign_or_mac_len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &sign_or_mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, sign_or_mac_len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_mac_length with METHOD_MAX, MSG_2.
 * @env       Context with chosen_method=EDHOC_METHOD_MAX.
 * @action    Call edhoc_comp_mac_length.
 * @expected  EDHOC_ERROR_NOT_PERMITTED.
 */
TEST(internals, mac_length_method_max_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_MAX;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	edhoc_context_deinit(&ctx);
}

/* ---- Full mac_context computation tests ---- */

/**
 * @scenario  Full edhoc_comp_mac_context with X509_CHAIN single cert, MSG_2.
 * @env       Context for MSG_2, X509_CHAIN credentials.
 * @action    Compute length, allocate buffer, call edhoc_comp_mac_context.
 * @expected  EDHOC_SUCCESS, mac_ctx has non-zero id_cred_len, th_len, cred_len.
 */
TEST(internals, full_mac_ctx_x509_chain)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 1;
	cred.x509_chain.cert[0] = dummy_cert;
	cred.x509_chain.cert_len[0] = sizeof(dummy_cert);

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);
	ret = edhoc_comp_mac_context(&ctx, &cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT(mac_ctx->id_cred_len > 0);
	TEST_ASSERT(mac_ctx->th_len > 0);
	TEST_ASSERT(mac_ctx->cred_len > 0);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Full edhoc_comp_mac_context with X509_HASH int alg, MSG_2.
 * @env       Context for MSG_2, X509_HASH with integer alg.
 * @action    Compute length, allocate buffer, call edhoc_comp_mac_context.
 * @expected  EDHOC_SUCCESS, mac_ctx has non-zero id_cred_len, th_len, cred_len.
 */
TEST(internals, full_mac_ctx_x509_hash_int)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	static const uint8_t dummy_cert[100] = { 0 };
	static const uint8_t dummy_fp[32] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.x509_hash.alg_int = -16;
	cred.x509_hash.cert_fp = dummy_fp;
	cred.x509_hash.cert_fp_len = 32;
	cred.x509_hash.cert = dummy_cert;
	cred.x509_hash.cert_len = 100;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);
	ret = edhoc_comp_mac_context(&ctx, &cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT(mac_ctx->id_cred_len > 0);
	TEST_ASSERT(mac_ctx->th_len > 0);
	TEST_ASSERT(mac_ctx->cred_len > 0);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Full edhoc_comp_mac_context with KID int, cred_is_cbor, MSG_3.
 * @env       Context for MSG_3, KID with integer encode_type, cred_is_cbor.
 * @action    Compute length, allocate buffer, call edhoc_comp_mac_context.
 * @expected  EDHOC_SUCCESS, mac_ctx has non-zero id_cred_len, th_len, cred_len.
 */
TEST(internals, full_mac_ctx_kid_int_cbor)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);

	static const uint8_t dummy_cred[50] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.key_id.key_id_int = 4;
	cred.key_id.cred_is_cbor = true;
	cred.key_id.cred = dummy_cred;
	cred.key_id.cred_len = 50;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);
	ret = edhoc_comp_mac_context(&ctx, &cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT(mac_ctx->id_cred_len > 0);
	TEST_ASSERT(mac_ctx->th_len > 0);
	TEST_ASSERT(mac_ctx->cred_len > 0);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Full edhoc_comp_mac_context with KID byte_string, MSG_2.
 * @env       Context for MSG_2, KID with byte_string encode_type.
 * @action    Compute length, allocate buffer, call edhoc_comp_mac_context.
 * @expected  EDHOC_SUCCESS, mac_ctx has non-zero id_cred_len, th_len, cred_len.
 */
TEST(internals, full_mac_ctx_kid_bstr)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	static const uint8_t dummy_cred[50] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.key_id.cred_is_cbor = true;
	cred.key_id.key_id_bstr_length = 2;
	cred.key_id.key_id_bstr[0] = 0x18;
	cred.key_id.key_id_bstr[1] = 0x64;
	cred.key_id.cred = dummy_cred;
	cred.key_id.cred_len = 50;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);
	ret = edhoc_comp_mac_context(&ctx, &cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT(mac_ctx->id_cred_len > 0);
	TEST_ASSERT(mac_ctx->th_len > 0);
	TEST_ASSERT(mac_ctx->cred_len > 0);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Full edhoc_comp_mac_context with byte-string CID, MSG_2.
 * @env       Context for MSG_2, CID encode_type BYTE_STRING, X509_CHAIN.
 * @action    Compute length, allocate buffer, call edhoc_comp_mac_context.
 * @expected  EDHOC_SUCCESS, mac_ctx has non-zero id_cred_len, th_len, cred_len.
 */
TEST(internals, full_mac_ctx_bstr_cid)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_BYTE_STRING;
	ctx.cid.bstr_value[0] = 0x01;
	ctx.cid.bstr_value[1] = 0x02;
	ctx.cid.bstr_length = 2;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 1;
	cred.x509_chain.cert[0] = dummy_cert;
	cred.x509_chain.cert_len[0] = sizeof(dummy_cert);

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);
	ret = edhoc_comp_mac_context(&ctx, &cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT(mac_ctx->id_cred_len > 0);
	TEST_ASSERT(mac_ctx->th_len > 0);
	TEST_ASSERT(mac_ctx->cred_len > 0);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Full edhoc_comp_mac_context with EAD tokens.
 * @env       Context with EAD tokens, MSG_2.
 * @action    Compute length, allocate buffer, call edhoc_comp_mac_context.
 * @expected  EDHOC_SUCCESS, mac_ctx has non-zero id_cred_len, th_len, cred_len.
 */
TEST(internals, full_mac_ctx_with_ead)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;
	ctx.nr_of_ead_tokens = 1;
	ctx.ead_token[0].label = 100;
	static const uint8_t ead_val[4] = { 1, 2, 3, 4 };
	ctx.ead_token[0].value = ead_val;
	ctx.ead_token[0].value_len = 4;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 1;
	cred.x509_chain.cert[0] = dummy_cert;
	cred.x509_chain.cert_len[0] = sizeof(dummy_cert);

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);
	ret = edhoc_comp_mac_context(&ctx, &cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT(mac_ctx->id_cred_len > 0);
	TEST_ASSERT(mac_ctx->th_len > 0);
	TEST_ASSERT(mac_ctx->cred_len > 0);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  Full edhoc_comp_mac_context with COSE_ANY credential type.
 * @env       Context for MSG_2, cred label EDHOC_COSE_ANY.
 * @action    Compute length, allocate buffer, call edhoc_comp_mac_context.
 * @expected  EDHOC_SUCCESS, mac_ctx has non-zero id_cred_len, th_len, cred_len.
 */
TEST(internals, full_mac_ctx_any)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	static const uint8_t any_id_cred[10] = { 0xA1, 0x04, 0x42, 0x11, 0x22 };
	static const uint8_t any_cred[20] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_ANY;
	cred.any.id_cred = any_id_cred;
	cred.any.id_cred_len = 5;
	cred.any.cred = any_cred;
	cred.any.cred_len = 20;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);
	ret = edhoc_comp_mac_context(&ctx, &cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT(mac_ctx->id_cred_len > 0);
	TEST_ASSERT(mac_ctx->th_len > 0);
	TEST_ASSERT(mac_ctx->cred_len > 0);

	edhoc_context_deinit(&ctx);
}

/* ---- edhoc_comp_sign_or_mac and edhoc_verify_sign_or_mac for MAC-only methods ---- */

/**
 * @scenario  edhoc_comp_sign_or_mac with method 1, MSG_2 - memcpy MAC.
 * @env       Context message=MSG_2, chosen_method=1, precomputed mac_ctx.
 * @action    Call edhoc_comp_sign_or_mac with mac and assert sign_len=8, sign==mac.
 * @expected  EDHOC_SUCCESS, sign_len=8, sign equals mac.
 */
TEST(internals, comp_sign_or_mac_method1_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_1;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	memset(ctx.th, 0xAA, 32);
	memset(ctx.prk, 0xBB, 32);
	ctx.prk_len = 32;
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 1;
	cred.x509_chain.cert[0] = dummy_cert;
	cred.x509_chain.cert_len[0] = sizeof(dummy_cert);

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);
	ret = edhoc_comp_mac_context(&ctx, &cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t mac[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t sign[64] = { 0 };
	size_t sign_len = 0;
	ret = edhoc_comp_sign_or_mac(&ctx, &cred, mac_ctx, mac, 8, sign,
				     sizeof(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, sign_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(mac, sign, 8);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_verify_sign_or_mac with method 1, MSG_2 - memcmp success.
 * @env       Context message=MSG_2, chosen_method=1, matching MAC.
 * @action    Call edhoc_verify_sign_or_mac with matching sign and mac.
 * @expected  EDHOC_SUCCESS.
 */
TEST(internals, verify_sign_or_mac_method1_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_1;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = 64;

	uint8_t pub_key[32] = { 0 };
	uint8_t mac[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	int ret = edhoc_verify_sign_or_mac(&ctx, mac_ctx, pub_key, 32, mac, 8,
					   mac, 8);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_verify_sign_or_mac with method 1, MSG_2 - MAC mismatch.
 * @env       Context message=MSG_2, chosen_method=1, wrong sign_or_mac.
 * @action    Call edhoc_verify_sign_or_mac with mismatching sign and mac.
 * @expected  EDHOC_ERROR_INVALID_SIGN_OR_MAC_2.
 */
TEST(internals, verify_sign_or_mac_method1_msg2_mismatch)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_1;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = 64;

	uint8_t pub_key[32] = { 0 };
	uint8_t mac[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t wrong_mac[8] = { 9, 9, 9, 9, 9, 9, 9, 9 };

	int ret = edhoc_verify_sign_or_mac(&ctx, mac_ctx, pub_key, 32,
					   wrong_mac, 8, mac, 8);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_SIGN_OR_MAC_2, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_sign_or_mac with method 2, MSG_3 - memcpy MAC.
 * @env       Context message=MSG_3, chosen_method=2, precomputed mac_ctx.
 * @action    Call edhoc_comp_sign_or_mac with mac and assert sign_len=8.
 * @expected  EDHOC_SUCCESS, sign_len=8, sign equals mac.
 */
TEST(internals, comp_sign_or_mac_method2_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.chosen_method = EDHOC_METHOD_2;
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.th_len = 32;
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	memset(ctx.th, 0xAA, 32);
	memset(ctx.prk, 0xBB, 32);
	ctx.prk_len = 32;

	static const uint8_t dummy_cred[50] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.key_id.key_id_int = 4;
	cred.key_id.cred = dummy_cred;
	cred.key_id.cred_len = 50;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);
	ret = edhoc_comp_mac_context(&ctx, &cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t mac[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t sign[64] = { 0 };
	size_t sign_len = 0;
	ret = edhoc_comp_sign_or_mac(&ctx, &cred, mac_ctx, mac, 8, sign,
				     sizeof(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, sign_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(mac, sign, 8);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_verify_sign_or_mac with method 3, MSG_3 - memcmp success.
 * @env       Context message=MSG_3, chosen_method=3, matching MAC.
 * @action    Call edhoc_verify_sign_or_mac with matching sign and mac.
 * @expected  EDHOC_SUCCESS.
 */
TEST(internals, verify_sign_or_mac_method3_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.chosen_method = EDHOC_METHOD_3;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = 64;

	uint8_t pub_key[32] = { 0 };
	uint8_t mac[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	int ret = edhoc_verify_sign_or_mac(&ctx, mac_ctx, pub_key, 32, mac, 8,
					   mac, 8);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/* ---- Targeted tests for uncovered branches ---- */

TEST(internals, comp_id_cred_len_kid_invalid_encode)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = 99;
	size_t len = 0;

	int ret = edhoc_test_comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals, comp_id_cred_len_x509_hash_invalid_encode)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.encode_type = 99;
	size_t len = 0;

	int ret = edhoc_test_comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals, comp_cred_len_null)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_cred_len(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_cred_len(&cred, NULL));
}

TEST(internals, comp_ead_len_null)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_ead_len(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_ead_len(&ctx, NULL));

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_ctx_len_null_args)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	struct edhoc_auth_creds cred = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac_context_length(NULL, &cred, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac_context_length(&ctx, NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac_context_length(&ctx, &cred, NULL));

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_ctx_len_invalid_role)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = 99;
	ctx.message = EDHOC_MSG_2;
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	size_t len = 0;

	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_ctx_len_invalid_message)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_4;
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	size_t len = 0;

	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, cbor_tstr_oh_large)
{
	TEST_ASSERT_EQUAL(2, edhoc_cbor_tstr_oh(200));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_tstr_oh(300));
	TEST_ASSERT_EQUAL(4, edhoc_cbor_tstr_oh(70000));
	TEST_ASSERT_EQUAL(5, edhoc_cbor_tstr_oh((size_t)UINT32_MAX + 1));
}

TEST(internals, cbor_bstr_oh_large)
{
	TEST_ASSERT_EQUAL(2, edhoc_cbor_bstr_oh(200));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_bstr_oh(300));
	TEST_ASSERT_EQUAL(4, edhoc_cbor_bstr_oh(70000));
	TEST_ASSERT_EQUAL(5, edhoc_cbor_bstr_oh((size_t)UINT32_MAX + 1));
}

TEST(internals, cbor_array_oh_large)
{
	TEST_ASSERT_EQUAL(1, edhoc_cbor_array_oh(1));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_array_oh(100));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_array_oh(1000));
	TEST_ASSERT_EQUAL(4, edhoc_cbor_array_oh(70000));
}

TEST(internals, mac_ctx_small_buffer)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 1;
	cred.x509_chain.cert[0] = dummy_cert;
	cred.x509_chain.cert_len[0] = sizeof(dummy_cert);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = 4;
	int ret = edhoc_comp_mac_context(&ctx, &cred, mac_ctx);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_ctx_len_unsupported_cred)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	struct edhoc_auth_creds cred = { 0 };
	cred.label = 99;
	size_t len = 0;

	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, set_connection_id_invalid_type)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);

	struct edhoc_connection_id cid = { .encode_type = 99 };
	int ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, comp_th_2_null)
{
	int ret = edhoc_test_comp_th_2(NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, comp_th_2_bad_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.th_state = EDHOC_TH_STATE_2;

	int ret = edhoc_test_comp_th_2(&ctx);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, comp_prk_2e_null)
{
	int ret = edhoc_test_comp_prk_2e(NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, comp_prk_2e_bad_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;

	int ret = edhoc_test_comp_prk_2e(&ctx);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, comp_prk_3e2m_null)
{
	struct edhoc_auth_creds auth_cred = { 0 };
	int ret = edhoc_test_comp_prk_3e2m(NULL, &auth_cred, NULL, 0);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, comp_prk_3e2m_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.chosen_method = EDHOC_METHOD_0;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.th_state = EDHOC_TH_STATE_2;

	struct edhoc_auth_creds auth_cred = { 0 };
	int ret = edhoc_test_comp_prk_3e2m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, comp_prk_4e3m_null)
{
	struct edhoc_auth_creds auth_cred = { 0 };
	int ret = edhoc_test_comp_prk_4e3m(NULL, &auth_cred, NULL, 0);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, comp_prk_4e3m_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.chosen_method = EDHOC_METHOD_0;
	ctx.prk_state = EDHOC_PRK_STATE_2E;
	ctx.th_state = EDHOC_TH_STATE_3;

	struct edhoc_auth_creds auth_cred = { 0 };
	int ret = edhoc_test_comp_prk_4e3m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, comp_salt_3e2m_null)
{
	uint8_t salt[32];
	int ret = edhoc_test_comp_salt_3e2m(NULL, salt, sizeof(salt));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, comp_salt_4e3m_null)
{
	uint8_t salt[32];
	int ret = edhoc_test_comp_salt_4e3m(NULL, salt, sizeof(salt));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, compute_prk_exporter_null)
{
	uint8_t prk_exp[32];
	int ret =
		edhoc_test_compute_prk_exporter(NULL, prk_exp, sizeof(prk_exp));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, compute_new_prk_out_null)
{
	uint8_t entropy[16] = { 0 };
	int ret =
		edhoc_test_compute_new_prk_out(NULL, entropy, sizeof(entropy));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, mac_ctx_x509_hash_bstr_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);

	static const uint8_t dummy_cert[100] = { 0 };
	static const uint8_t dummy_fp[32] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.x509_hash.alg_bstr_length = 4;
	memcpy(cred.x509_hash.alg_bstr, "SHA-", 4);
	cred.x509_hash.cert_fp = dummy_fp;
	cred.x509_hash.cert_fp_len = 32;
	cred.x509_hash.cert = dummy_cert;
	cred.x509_hash.cert_len = 100;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);
	ret = edhoc_comp_mac_context(&ctx, &cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT(mac_ctx->id_cred_len > 0);

	edhoc_context_deinit(&ctx);
}

TEST(internals, full_mac_ctx_x509_hash_bstr)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	static const uint8_t dummy_cert[100] = { 0 };
	static const uint8_t dummy_fp[32] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.x509_hash.alg_bstr_length = 4;
	memcpy(cred.x509_hash.alg_bstr, "SHA-", 4);
	cred.x509_hash.cert_fp = dummy_fp;
	cred.x509_hash.cert_fp_len = 32;
	cred.x509_hash.cert = dummy_cert;
	cred.x509_hash.cert_len = 100;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);
	ret = edhoc_comp_mac_context(&ctx, &cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT(mac_ctx->id_cred_len > 0);
	TEST_ASSERT(mac_ctx->th_len > 0);
	TEST_ASSERT(mac_ctx->cred_len > 0);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_ctx_invalid_cid_type)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = 99;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 1;
	cred.x509_chain.cert[0] = dummy_cert;
	cred.x509_chain.cert_len[0] = sizeof(dummy_cert);

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_ctx_null_args)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	struct edhoc_auth_creds cred = { 0 };
	uint8_t buf[2048] = { 0 };
	struct mac_context *mac = (struct mac_context *)buf;
	mac->buf_len = sizeof(buf) - sizeof(struct mac_context);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac_context(NULL, &cred, mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac_context(&ctx, NULL, mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac_context(&ctx, &cred, NULL));

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_ctx_invalid_role)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = 99;
	ctx.message = EDHOC_MSG_2;
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	uint8_t buf[2048] = { 0 };
	struct mac_context *mac = (struct mac_context *)buf;
	mac->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_comp_mac_context(&ctx, &cred, mac);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_ctx_invalid_message)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_4;
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	uint8_t buf[2048] = { 0 };
	struct mac_context *mac = (struct mac_context *)buf;
	mac->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_comp_mac_context(&ctx, &cred, mac);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_ctx_bad_th_state_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	uint8_t buf[2048] = { 0 };
	struct mac_context *mac = (struct mac_context *)buf;
	mac->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_comp_mac_context(&ctx, &cred, mac);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_ctx_bad_th_state_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);

	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	uint8_t buf[2048] = { 0 };
	struct mac_context *mac = (struct mac_context *)buf;
	mac->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_comp_mac_context(&ctx, &cred, mac);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_ctx_unsupported_cred_label)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	struct edhoc_auth_creds cred = { 0 };
	cred.label = 99;
	uint8_t buf[2048] = { 0 };
	struct mac_context *mac = (struct mac_context *)buf;
	mac->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_comp_mac_context(&ctx, &cred, mac);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_ctx_invalid_cid_type_compose)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = 99;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 1;
	cred.x509_chain.cert[0] = dummy_cert;
	cred.x509_chain.cert_len[0] = sizeof(dummy_cert);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac = (struct mac_context *)buf;
	mac->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_comp_mac_context(&ctx, &cred, mac);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_ctx_invalid_kid_encode_in_length)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	memset(ctx.th, 0xAA, 32);
	ctx.cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	ctx.cid.int_value = 5;

	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = 99;
	size_t len = 0;

	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, error_message_compose_null)
{
	uint8_t buf[64];
	size_t len;
	int ret = edhoc_message_error_compose(NULL, sizeof(buf), &len,
					      EDHOC_ERROR_CODE_SUCCESS, NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_message_error_compose(buf, 0, &len,
					  EDHOC_ERROR_CODE_SUCCESS, NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_message_error_compose(buf, sizeof(buf), NULL,
					  EDHOC_ERROR_CODE_SUCCESS, NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, error_message_process_null)
{
	uint8_t buf[64] = { 0 };
	enum edhoc_error_code code;
	int ret = edhoc_message_error_process(NULL, sizeof(buf), &code, NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_message_error_process(buf, 0, &code, NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_message_error_process(buf, sizeof(buf), NULL, NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, export_oscore_null)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);

	uint8_t ms[16], salt[8], sid[8], rid[8];
	size_t sid_len, rid_len;

	int ret = edhoc_export_oscore_session(NULL, ms, sizeof(ms), salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, rid, sizeof(rid),
					      &rid_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_export_oscore_session(&ctx, NULL, sizeof(ms), salt,
					  sizeof(salt), sid, sizeof(sid),
					  &sid_len, rid, sizeof(rid), &rid_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_export_oscore_session(&ctx, ms, sizeof(ms), salt,
					  sizeof(salt), sid, sizeof(sid),
					  &sid_len, rid, sizeof(rid), NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, export_oscore_bad_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.status = 0; /* Not completed */
	ctx.prk_state = EDHOC_PRK_STATE_INVALID;
	ctx.is_oscore_export_allowed = true;

	uint8_t ms[16], salt[8], sid[8], rid[8];
	size_t sid_len, rid_len;

	int ret = edhoc_export_oscore_session(&ctx, ms, sizeof(ms), salt,
					      sizeof(salt), sid, sizeof(sid),
					      &sid_len, rid, sizeof(rid),
					      &rid_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, key_update_null)
{
	struct edhoc_context ctx = { 0 };
	uint8_t entropy[16] = { 0 };

	int ret = edhoc_export_key_update(NULL, entropy, sizeof(entropy));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_export_key_update(&ctx, NULL, 0);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

/* ---- edhoc_message_2.c hook tests ---- */

TEST(internals, gen_dh_keys_null)
{
	int ret = edhoc_test_gen_dh_keys(NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, comp_dh_secret_null)
{
	int ret = edhoc_test_comp_dh_secret(NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, comp_keystream_null)
{
	uint8_t ks[64];
	int ret = edhoc_test_comp_keystream(NULL, NULL, 0, ks, sizeof(ks));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, comp_keystream_bad_th_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_1;
	ctx.prk_state = EDHOC_PRK_STATE_2E;
	ctx.prk_len = 32;

	uint8_t prk[32] = { 0 };
	uint8_t ks[64];
	int ret = edhoc_test_comp_keystream(&ctx, prk, 32, ks, sizeof(ks));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, comp_th_3_null)
{
	int ret = edhoc_test_comp_th_3(NULL, NULL, NULL, 0);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, comp_th_3_bad_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_1;

	uint8_t buf[512] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	mc->th_len = 32;

	uint8_t ptxt[32] = { 0 };
	int ret = edhoc_test_comp_th_3(&ctx, mc, ptxt, sizeof(ptxt));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, comp_grx_null)
{
	uint8_t grx[32];
	struct edhoc_auth_creds ac = { 0 };
	int ret = edhoc_test_comp_grx(NULL, &ac, NULL, 0, grx, sizeof(grx));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, comp_grx_invalid_role)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = 99;
	ctx.chosen_method = EDHOC_METHOD_1;
	ctx.prk_state = EDHOC_PRK_STATE_2E;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.prk_len = 32;

	struct edhoc_auth_creds ac = { 0 };
	uint8_t grx[32];
	int ret = edhoc_test_comp_grx(&ctx, &ac, NULL, 0, grx, sizeof(grx));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/* ---- edhoc_message_3.c hook tests ---- */

TEST(internals, comp_key_iv_aad_3_null)
{
	uint8_t key[16], iv[13], aad[256];
	int ret = edhoc_test_comp_key_iv_aad_3(NULL, key, 16, iv, 13, aad, 256);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, comp_key_iv_aad_3_bad_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_1;
	ctx.prk_state = EDHOC_PRK_STATE_INVALID;

	uint8_t key[16], iv[13], aad[256];
	int ret = edhoc_test_comp_key_iv_aad_3(&ctx, key, 16, iv, 13, aad, 256);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, comp_th_4_null)
{
	int ret = edhoc_test_comp_th_4(NULL, NULL, NULL, 0);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, comp_th_4_bad_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_1;

	uint8_t buf[512] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	mc->th_len = 32;

	uint8_t ptxt[32] = { 0 };
	int ret = edhoc_test_comp_th_4(&ctx, mc, ptxt, sizeof(ptxt));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, comp_giy_null)
{
	uint8_t giy[32];
	struct edhoc_auth_creds ac = { 0 };
	int ret = edhoc_test_comp_giy(NULL, &ac, NULL, 0, giy, sizeof(giy));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, comp_giy_invalid_role)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = 99;
	ctx.chosen_method = EDHOC_METHOD_2;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.prk_len = 32;

	struct edhoc_auth_creds ac = { 0 };
	uint8_t giy[32];
	int ret = edhoc_test_comp_giy(&ctx, &ac, NULL, 0, giy, sizeof(giy));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/* ---- edhoc_message_4.c hook tests ---- */

TEST(internals, compute_plaintext_4_len_null)
{
	size_t len;
	int ret = edhoc_test_compute_plaintext_4_len(NULL, &len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, compute_key_iv_aad_4_null)
{
	uint8_t key[16], iv[13], aad[256];
	int ret = edhoc_test_compute_key_iv_aad_4(NULL, key, 16, iv, 13, aad,
						  256);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, compute_key_iv_aad_4_bad_state)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_1;
	ctx.prk_state = EDHOC_PRK_STATE_INVALID;

	uint8_t key[16], iv[13], aad[256];
	int ret = edhoc_test_compute_key_iv_aad_4(&ctx, key, 16, iv, 13, aad,
						  256);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/* ---- edhoc_common.c public API coverage ---- */

TEST(internals, mac_length_null_args)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	size_t mac_len = 0;

	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS,
			      edhoc_comp_mac_length(NULL, &mac_len));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, edhoc_comp_mac_length(&ctx, NULL));

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_length_invalid_role)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = 99;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_0;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_length_invalid_message)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_4;
	ctx.chosen_method = EDHOC_METHOD_0;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_length_method_max_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.chosen_method = EDHOC_METHOD_MAX;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, comp_mac_invalid_message)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_4;
	ctx.chosen_method = EDHOC_METHOD_0;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.prk_len = 32;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[32];
	int ret = edhoc_comp_mac(&ctx, mc, mac, sizeof(mac));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, comp_mac_bad_prk_state_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_0;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.prk_state = EDHOC_PRK_STATE_2E;
	ctx.prk_len = 32;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[32];
	int ret = edhoc_comp_mac(&ctx, mc, mac, sizeof(mac));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, comp_mac_bad_prk_state_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.chosen_method = EDHOC_METHOD_0;
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.prk_state = EDHOC_PRK_STATE_2E;
	ctx.prk_len = 32;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[32];
	int ret = edhoc_comp_mac(&ctx, mc, mac, sizeof(mac));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, sign_or_mac_length_invalid_role)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = 99;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_0;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, sign_or_mac_length_method_max)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_MAX;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, sign_or_mac_length_invalid_msg)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_4;
	ctx.chosen_method = EDHOC_METHOD_0;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, comp_sign_or_mac_invalid_msg)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_4;
	ctx.chosen_method = EDHOC_METHOD_0;

	struct edhoc_auth_creds cred = { 0 };
	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[8] = { 0 };
	uint8_t sign[64];
	size_t sign_len;
	int ret = edhoc_comp_sign_or_mac(&ctx, &cred, mc, mac, 8, sign,
					 sizeof(sign), &sign_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, comp_sign_or_mac_method_max)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_MAX;

	struct edhoc_auth_creds cred = { 0 };
	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[8] = { 0 };
	uint8_t sign[64];
	size_t sign_len;
	int ret = edhoc_comp_sign_or_mac(&ctx, &cred, mc, mac, 8, sign,
					 sizeof(sign), &sign_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, verify_sign_or_mac_null_mac)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_1;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = 64;

	uint8_t pub[32] = { 0 };
	uint8_t sign[8] = { 0 };
	int ret = edhoc_verify_sign_or_mac(&ctx, mc, pub, 32, sign, 8, NULL, 0);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, verify_sign_or_mac_invalid_msg)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_4;
	ctx.chosen_method = EDHOC_METHOD_1;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = 64;

	uint8_t pub[32] = { 0 };
	uint8_t mac[8] = { 0 };
	int ret = edhoc_verify_sign_or_mac(&ctx, mc, pub, 32, mac, 8, mac, 8);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, verify_sign_or_mac_method_max)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_MAX;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = 64;

	uint8_t pub[32] = { 0 };
	uint8_t mac[8] = { 0 };
	int ret = edhoc_verify_sign_or_mac(&ctx, mc, pub, 32, mac, 8, mac, 8);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/* ---- edhoc_helpers.c public API coverage ---- */

TEST(internals, conn_id_equal_invalid_type)
{
	struct edhoc_connection_id a = { .encode_type = 99, .int_value = 1 };
	struct edhoc_connection_id b = { .encode_type = 99, .int_value = 1 };
	TEST_ASSERT_FALSE(edhoc_connection_id_equal(&a, &b));
}

TEST(internals, conn_id_equal_null)
{
	struct edhoc_connection_id a = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 1,
	};
	TEST_ASSERT_FALSE(edhoc_connection_id_equal(NULL, &a));
	TEST_ASSERT_FALSE(edhoc_connection_id_equal(&a, NULL));
}

TEST(internals, conn_id_equal_type_mismatch)
{
	struct edhoc_connection_id a = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 1,
	};
	struct edhoc_connection_id b = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 1,
	};
	TEST_ASSERT_FALSE(edhoc_connection_id_equal(&a, &b));
}

TEST(internals, conn_id_equal_bstr_success)
{
	struct edhoc_connection_id a = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 2,
	};
	a.bstr_value[0] = 0xAA;
	a.bstr_value[1] = 0xBB;

	struct edhoc_connection_id b = a;
	TEST_ASSERT_TRUE(edhoc_connection_id_equal(&a, &b));
}

TEST(internals, prepend_conn_id_null)
{
	int ret = edhoc_prepend_connection_id(NULL, NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, prepend_conn_id_zero_buf)
{
	uint8_t buf[32];
	struct edhoc_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = 0,
	};
	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5,
	};
	int ret = edhoc_prepend_connection_id(&pf, &cid);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, prepend_conn_id_invalid_type)
{
	uint8_t buf[32];
	struct edhoc_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = sizeof(buf),
	};
	struct edhoc_connection_id cid = { .encode_type = 99 };
	int ret = edhoc_prepend_connection_id(&pf, &cid);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, prepend_conn_id_bstr_zero_len)
{
	uint8_t buf[32];
	struct edhoc_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = sizeof(buf),
	};
	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 0,
	};
	int ret = edhoc_prepend_connection_id(&pf, &cid);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, prepend_conn_id_bstr_success)
{
	uint8_t buf[32];
	struct edhoc_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = sizeof(buf),
	};
	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 2,
	};
	cid.bstr_value[0] = 0xAA;
	cid.bstr_value[1] = 0xBB;
	int ret = edhoc_prepend_connection_id(&pf, &cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_NOT_NULL(pf.edhoc_message_ptr);
}

TEST(internals, prepend_flow_null)
{
	int ret = edhoc_prepend_flow(NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, prepend_flow_success)
{
	uint8_t buf[32];
	struct edhoc_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = sizeof(buf),
	};
	int ret = edhoc_prepend_flow(&pf);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(0xF5, buf[0]);
}

TEST(internals, prepend_flow_tiny_buf)
{
	struct edhoc_prepended_fields pf = {
		.buffer = NULL,
		.buffer_size = 0,
	};
	int ret = edhoc_prepend_flow(&pf);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, prepend_recalculate_null)
{
	int ret = edhoc_prepend_recalculate_size(NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, prepend_recalculate_null_buf)
{
	struct edhoc_prepended_fields pf = {
		.buffer = NULL,
		.buffer_size = 0,
	};
	int ret = edhoc_prepend_recalculate_size(&pf);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, prepend_recalculate_null_msg_ptr)
{
	uint8_t buf[32];
	struct edhoc_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = sizeof(buf),
		.edhoc_message_ptr = NULL,
		.edhoc_message_size = 0,
	};
	int ret = edhoc_prepend_recalculate_size(&pf);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, extract_flow_info_null)
{
	int ret = edhoc_extract_flow_info(NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, extract_flow_info_null_buf)
{
	struct edhoc_extracted_fields ef = {
		.buffer = NULL,
		.buffer_size = 0,
	};
	int ret = edhoc_extract_flow_info(&ef);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(ef.is_reverse_flow);
}

TEST(internals, extract_flow_info_forward)
{
	uint8_t buf[32] = { 0xF5, 0x01, 0x02 };
	struct edhoc_extracted_fields ef = {
		.buffer = buf,
		.buffer_size = 3,
	};
	int ret = edhoc_extract_flow_info(&ef);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(ef.is_forward_flow);
	TEST_ASSERT_EQUAL(2, ef.edhoc_message_size);
}

TEST(internals, extract_conn_id_null)
{
	int ret = edhoc_extract_connection_id(NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, extract_conn_id_int)
{
	uint8_t buf[32] = { 0x05, 0x01, 0x02 };
	struct edhoc_extracted_fields ef = {
		.buffer = buf,
		.buffer_size = 3,
	};
	int ret = edhoc_extract_connection_id(&ef);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
			  ef.extracted_conn_id.encode_type);
}

TEST(internals, extract_conn_id_bstr)
{
	uint8_t buf[32] = { 0x42, 0xAA, 0xBB, 0x01 };
	struct edhoc_extracted_fields ef = {
		.buffer = buf,
		.buffer_size = 4,
	};
	int ret = edhoc_extract_connection_id(&ef);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_BYTE_STRING,
			  ef.extracted_conn_id.encode_type);
	TEST_ASSERT_EQUAL(2, ef.extracted_conn_id.bstr_length);
}

/* ---- Additional edhoc_common.c sign/verify coverage for method 0 (signature) ---- */

TEST(internals, sign_or_mac_length_method0_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_0;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(64, len);

	edhoc_context_deinit(&ctx);
}

TEST(internals, sign_or_mac_length_method0_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.chosen_method = EDHOC_METHOD_0;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(64, len);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_length_method0_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_0;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(32, mac_len);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_length_method0_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.chosen_method = EDHOC_METHOD_0;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(32, mac_len);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_length_method3_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_3;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, mac_len);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_length_method3_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.chosen_method = EDHOC_METHOD_3;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, mac_len);

	edhoc_context_deinit(&ctx);
}

TEST(internals, sign_or_mac_length_method2_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_2;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(64, len);

	edhoc_context_deinit(&ctx);
}

/* ---- edhoc_message_error.c coverage ---- */

TEST(internals, error_compose_tiny_buffer)
{
	uint8_t buf[1];
	size_t len;
	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len, EDHOC_ERROR_CODE_UNSPECIFIED_ERROR,
		NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, error_compose_unspecified_null_info)
{
	uint8_t buf[64];
	size_t len;
	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len, EDHOC_ERROR_CODE_UNSPECIFIED_ERROR,
		NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals, error_compose_success_code)
{
	uint8_t buf[64];
	size_t len;
	int ret = edhoc_message_error_compose(buf, sizeof(buf), &len,
					      EDHOC_ERROR_CODE_SUCCESS, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, error_compose_unknown_cred)
{
	uint8_t buf[64];
	size_t len;
	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len,
		EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, error_compose_invalid_code)
{
	uint8_t buf[64];
	size_t len;
	int ret = edhoc_message_error_compose(buf, sizeof(buf), &len, 99, NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, error_compose_unspecified_with_info)
{
	uint8_t buf[64];
	size_t len;
	char text[] = "test error";
	struct edhoc_error_info info = {
		.text_string = text,
		.total_entries = 10,
		.written_entries = 10,
	};
	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len, EDHOC_ERROR_CODE_UNSPECIFIED_ERROR,
		&info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals, error_compose_wrong_csuite_single)
{
	uint8_t buf[64];
	size_t len;
	int32_t suites[] = { 0 };
	struct edhoc_error_info info = {
		.cipher_suites = suites,
		.total_entries = 1,
		.written_entries = 1,
	};
	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len,
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, &info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, error_compose_wrong_csuite_multi)
{
	uint8_t buf[64];
	size_t len;
	int32_t suites[] = { 0, 2 };
	struct edhoc_error_info info = {
		.cipher_suites = suites,
		.total_entries = 2,
		.written_entries = 2,
	};
	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len,
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, &info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, error_process_roundtrip)
{
	uint8_t buf[64];
	size_t len;
	int ret = edhoc_message_error_compose(buf, sizeof(buf), &len,
					      EDHOC_ERROR_CODE_SUCCESS, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	enum edhoc_error_code code;
	ret = edhoc_message_error_process(buf, len, &code, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, code);
}

TEST(internals, error_process_unspecified_roundtrip)
{
	uint8_t buf[64];
	size_t len;
	char text[] = "err";
	struct edhoc_error_info info = {
		.text_string = text,
		.total_entries = 3,
		.written_entries = 3,
	};
	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len, EDHOC_ERROR_CODE_UNSPECIFIED_ERROR,
		&info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	enum edhoc_error_code code;
	struct edhoc_error_info info_out = { 0 };
	ret = edhoc_message_error_process(buf, len, &code, &info_out);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_UNSPECIFIED_ERROR, code);
}

TEST(internals, error_process_wrong_csuite_roundtrip)
{
	uint8_t buf[64];
	size_t len;
	int32_t suites[] = { 0, 2 };
	struct edhoc_error_info info = {
		.cipher_suites = suites,
		.total_entries = 2,
		.written_entries = 2,
	};
	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len,
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, &info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	enum edhoc_error_code code;
	struct edhoc_error_info info_out = { 0 };
	ret = edhoc_message_error_process(buf, len, &code, &info_out);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, code);
}

TEST(internals, error_process_malformed)
{
	uint8_t garbage[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
	enum edhoc_error_code code;
	int ret = edhoc_message_error_process(garbage, sizeof(garbage), &code,
					      NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

/* ---- edhoc_message_1.c coverage ---- */

TEST(internals, msg1_compose_invalid_cid_type)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.cid.encode_type = 99;

	uint8_t msg1[256];
	size_t msg1_len;
	int ret = edhoc_message_1_compose(&ctx, msg1, sizeof(msg1), &msg1_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, msg1_compose_zero_csuites)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.status = EDHOC_SM_START;

	const enum edhoc_method method[] = { EDHOC_METHOD_0 };
	edhoc_set_methods(&ctx, method, 1);

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 1,
	};
	edhoc_set_connection_id(&ctx, &cid);
	edhoc_bind_keys(&ctx, keys);
	edhoc_bind_crypto(&ctx, crypto);

	uint8_t msg1[256];
	size_t msg1_len;
	int ret = edhoc_message_1_compose(&ctx, msg1, sizeof(msg1), &msg1_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, msg1_compose_tiny_buffer)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.status = EDHOC_SM_START;

	uint8_t msg1[2];
	size_t msg1_len;
	int ret = edhoc_message_1_compose(&ctx, msg1, sizeof(msg1), &msg1_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, msg1_process_malformed)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.status = EDHOC_SM_START;

	uint8_t garbage[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
	int ret = edhoc_message_1_process(&ctx, garbage, sizeof(garbage));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

TEST(internals, msg1_process_truncated)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.status = EDHOC_SM_START;

	uint8_t tiny[1] = { 0x00 };
	int ret = edhoc_message_1_process(&ctx, tiny, sizeof(tiny));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/* ---- edhoc_helpers.c edge cases ---- */

TEST(internals, prepend_conn_id_bstr_tiny_buf)
{
	uint8_t buf[1];
	struct edhoc_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = 1,
	};
	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 2,
	};
	cid.bstr_value[0] = 0xAA;
	cid.bstr_value[1] = 0xBB;
	int ret = edhoc_prepend_connection_id(&pf, &cid);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, extract_conn_id_invalid_cbor)
{
	uint8_t garbage[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
	struct edhoc_extracted_fields ef = {
		.buffer = garbage,
		.buffer_size = sizeof(garbage),
	};
	int ret = edhoc_extract_connection_id(&ef);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals, extract_conn_id_null_buf)
{
	struct edhoc_extracted_fields ef = {
		.buffer = NULL,
		.buffer_size = 0,
	};
	int ret = edhoc_extract_connection_id(&ef);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

/* ---- Additional method/message coverage for edhoc_common.c ---- */

TEST(internals, mac_length_method1_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.chosen_method = EDHOC_METHOD_1;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(32, mac_len);

	edhoc_context_deinit(&ctx);
}

TEST(internals, mac_length_method2_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_2;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(32, mac_len);

	edhoc_context_deinit(&ctx);
}

TEST(internals, sign_or_mac_length_method3_msg2)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_3;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, len);

	edhoc_context_deinit(&ctx);
}

TEST(internals, sign_or_mac_length_method1_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.chosen_method = EDHOC_METHOD_1;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(64, len);

	edhoc_context_deinit(&ctx);
}

TEST(internals, sign_or_mac_length_method2_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.chosen_method = EDHOC_METHOD_2;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, len);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_mac_context with x509_chain and nr_of_certs == 0.
 * @env       Context set for MSG_3, credential has X509_CHAIN label
 *            but zero certificates.
 * @action    Call edhoc_comp_mac_context.
 * @expected  Returns EDHOC_ERROR_BAD_STATE (line 872 in edhoc_common.c).
 */
TEST(internals, mac_ctx_x509chain_zero_certs)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_3;
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.th_len = 32;
	memset(ctx.th, 0x11, 32);

	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 0;

	uint8_t buf[sizeof(struct mac_context) + 256];
	struct mac_context *mc = (struct mac_context *)buf;
	memset(mc, 0, sizeof(buf));
	mc->buf_len = 256;

	int ret = edhoc_comp_mac_context(&ctx, &cred, mc);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_mac_context_length with th_len == 0.
 * @env       Context set for MSG_3, th_len forced to 0.
 * @action    Call edhoc_comp_mac_context_length.
 * @expected  Returns error from comp_th_len failure (line 701).
 */
TEST(internals, mac_ctx_length_th_zero)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_3;
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.th_len = 0;

	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 1;
	static const uint8_t fake_cert[] = { 0x30, 0x00 };
	cred.x509_chain.cert[0] = fake_cert;
	cred.x509_chain.cert_len[0] = sizeof(fake_cert);

	size_t len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  kid_compact_encoding CBOR decode failure for bstr KID.
 * @env       Context set for MSG_3, credential is KID with bstr encode
 *            containing invalid CBOR data (0x40 = byte string, not integer).
 * @action    Call edhoc_comp_mac_context.
 * @expected  Returns EDHOC_ERROR_CBOR_FAILURE from kid_compact_encoding.
 */
TEST(internals, mac_ctx_kid_bad_cbor_compact)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_3;
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.th_len = 32;
	memset(ctx.th, 0x11, 32);

	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.key_id.cred_is_cbor = true;
	cred.key_id.key_id_bstr_length = 1;
	cred.key_id.key_id_bstr[0] = 0x40;
	static const uint8_t fake_cred[] = { 0x30, 0x00 };
	cred.key_id.cred = fake_cred;
	cred.key_id.cred_len = sizeof(fake_cred);

	uint8_t buf[sizeof(struct mac_context) + 256];
	struct mac_context *mc = (struct mac_context *)buf;
	memset(mc, 0, sizeof(buf));
	mc->buf_len = 256;

	int ret = edhoc_comp_mac_context(&ctx, &cred, mc);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  kid_compact_encoding with an unsupported encode_type.
 * @env       KID credential with encode_type = 99 (invalid).
 * @action    Call edhoc_test_kid_compact_encoding.
 * @expected  EDHOC_ERROR_NOT_PERMITTED (default branch).
 */
TEST(internals, kid_compact_enc_invalid_type)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = 99;
	cred.key_id.key_id_int = 5;

	struct mac_context mc = { 0 };
	int ret = edhoc_test_kid_compact_encoding(&cred, &mc);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

/**
 * @scenario  edhoc_comp_mac with all NULL / zero-length arguments.
 * @env       Valid context for msg_2 with correct PRK state.
 * @action    Call edhoc_comp_mac with NULL ctx, NULL mac_ctx, NULL mac, or mac_len=0.
 * @expected  EDHOC_ERROR_INVALID_ARGUMENT in each case.
 */
TEST(internals, comp_mac_null_args)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.prk_len = 32;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	uint8_t mac[32];

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac(NULL, mc, mac, 8));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac(&ctx, NULL, mac, 8));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac(&ctx, mc, NULL, 8));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac(&ctx, mc, mac, 0));

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_mac with message = EDHOC_MSG_1.
 * @env       Context with message set to MSG_1, valid PRK state.
 * @action    Call edhoc_comp_mac.
 * @expected  EDHOC_ERROR_NOT_PERMITTED (MSG_1/default branch in logging switch).
 */
TEST(internals, comp_mac_msg1)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_0;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.prk_len = 32;
	memset(ctx.prk, 0xAB, 32);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	mc->buf[0] = 0x40;
	mc->buf_len = 1;

	uint8_t mac[8];
	ctx.message = EDHOC_MSG_1;
	int ret = edhoc_comp_mac(&ctx, mc, mac, sizeof(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_sign_or_mac_length with NULL arguments.
 * @env       Default context.
 * @action    Call edhoc_comp_sign_or_mac_length(NULL, &len) and (&ctx, NULL).
 * @expected  EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(internals, comp_sign_or_mac_len_null_args)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_sign_or_mac_length(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_sign_or_mac_length(&ctx, NULL));

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_sign_or_mac_length with METHOD_MAX for MSG_3.
 * @env       Context set to MSG_3, INITIATOR role, METHOD_MAX.
 * @action    Call edhoc_comp_sign_or_mac_length.
 * @expected  EDHOC_ERROR_NOT_PERMITTED (METHOD_MAX branch for MSG_3).
 */
TEST(internals, sign_or_mac_length_method_max_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.chosen_method = EDHOC_METHOD_MAX;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_sign_or_mac with NULL arguments.
 * @env       Default context.
 * @action    Call edhoc_comp_sign_or_mac with NULL ctx, cred, mac_ctx, mac, sign, sign_len.
 * @expected  EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(internals, comp_sign_or_mac_null_args)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.message = EDHOC_MSG_2;
	ctx.chosen_method = EDHOC_METHOD_0;

	struct edhoc_auth_creds cred = { 0 };
	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[8] = { 0 };
	uint8_t sign[64];
	size_t sign_len;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_sign_or_mac(NULL, &cred, mc, mac, 8, sign,
						 64, &sign_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_sign_or_mac(&ctx, NULL, mc, mac, 8, sign,
						 64, &sign_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_sign_or_mac(&ctx, &cred, mc, mac, 8, NULL,
						 64, &sign_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_sign_or_mac(&ctx, &cred, mc, mac, 0, sign,
						 64, &sign_len));

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_comp_sign_or_mac with METHOD_MAX for MSG_3.
 * @env       Context set to MSG_3, INITIATOR role, METHOD_MAX.
 * @action    Call edhoc_comp_sign_or_mac.
 * @expected  EDHOC_ERROR_NOT_PERMITTED (METHOD_MAX branch for MSG_3).
 */
TEST(internals, comp_sign_or_mac_method_max_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.chosen_method = EDHOC_METHOD_MAX;

	struct edhoc_auth_creds cred = { 0 };
	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[8] = { 0 };
	uint8_t sign[64];
	size_t sign_len;
	int ret = edhoc_comp_sign_or_mac(&ctx, &cred, mc, mac, 8, sign,
					 sizeof(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_verify_sign_or_mac with MAC mismatch for MSG_3 (method 2/3).
 * @env       Context set to MSG_3, INITIATOR role, METHOD_2.
 * @action    Call edhoc_verify_sign_or_mac with different mac and sign_or_mac bytes.
 * @expected  EDHOC_ERROR_INVALID_SIGN_OR_MAC_2 (MAC mismatch branch for MSG_3).
 */
TEST(internals, verify_sign_or_mac_mismatch_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.chosen_method = EDHOC_METHOD_2;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = 64;

	uint8_t pub[32] = { 0 };
	uint8_t mac[8] = { 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44 };
	uint8_t fake_sign[8] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	int ret = edhoc_verify_sign_or_mac(&ctx, mc, pub, 32, fake_sign, 8, mac,
					   8);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_SIGN_OR_MAC_2, ret);

	edhoc_context_deinit(&ctx);
}

/**
 * @scenario  edhoc_verify_sign_or_mac with METHOD_MAX for MSG_3.
 * @env       Context set to MSG_3, INITIATOR role, METHOD_MAX.
 * @action    Call edhoc_verify_sign_or_mac.
 * @expected  EDHOC_ERROR_NOT_PERMITTED.
 */
TEST(internals, verify_sign_or_mac_method_max_msg3)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.message = EDHOC_MSG_3;
	ctx.chosen_method = EDHOC_METHOD_MAX;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = 64;

	uint8_t pub[32] = { 0 };
	uint8_t mac[8] = { 0 };

	int ret = edhoc_verify_sign_or_mac(&ctx, mc, pub, 32, mac, 8, mac, 8);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	edhoc_context_deinit(&ctx);
}

/* ---- msg4 internal function NULL arg tests ---- */

TEST(internals, prepare_plaintext_4_null)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	uint8_t ptxt[64];
	size_t ptxt_len;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_prepare_plaintext_4(NULL, ptxt, 64,
							 &ptxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_prepare_plaintext_4(&ctx, NULL, 64,
							 &ptxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_prepare_plaintext_4(&ctx, ptxt, 64, NULL));
	edhoc_context_deinit(&ctx);
}

TEST(internals, gen_msg_4_null)
{
	uint8_t ctxt[] = { 0x40 };
	uint8_t msg[64];
	size_t msg_len;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_gen_msg_4(NULL, 1, msg, 64, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_gen_msg_4(ctxt, 0, msg, 64, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_gen_msg_4(ctxt, 1, NULL, 64, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_gen_msg_4(ctxt, 1, msg, 0, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_gen_msg_4(ctxt, 1, msg, 64, NULL));
}

TEST(internals, parse_msg_4_null)
{
	uint8_t msg[] = { 0x40 };
	const uint8_t *ctxt;
	size_t ctxt_len;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_msg_4(NULL, 1, &ctxt, &ctxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_msg_4(msg, 0, &ctxt, &ctxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_msg_4(msg, 1, NULL, &ctxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_msg_4(msg, 1, &ctxt, NULL));
}

TEST(internals, parse_plaintext_4_null)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	uint8_t ptxt[] = { 0x40 };

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_plaintext_4(NULL, ptxt, 1));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_plaintext_4(&ctx, NULL, 1));
	edhoc_context_deinit(&ctx);
}

TEST(internals, parse_plaintext_4_empty)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	uint8_t empty[] = { 0x00 };

	int ret = edhoc_test_parse_plaintext_4(&ctx, empty, 0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	edhoc_context_deinit(&ctx);
}

/* ---- msg4 CBOR helper tests via compute_plaintext_4_len ---- */

TEST(internals, compute_plaintext_4_len_large_ead_label)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);

	struct edhoc_ead_token tok = { .label = 70000,
				       .value = NULL,
				       .value_len = 0 };
	ctx.nr_of_ead_tokens = 1;
	ctx.ead_token[0] = tok;

	size_t len = 0;
	int ret = edhoc_test_compute_plaintext_4_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(len > 0);
	edhoc_context_deinit(&ctx);
}

TEST(internals, compute_plaintext_4_len_large_ead_value)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);

	struct edhoc_ead_token tok = { .label = 1,
				       .value = NULL,
				       .value_len = 60000 };
	ctx.nr_of_ead_tokens = 1;
	ctx.ead_token[0] = tok;

	size_t len = 0;
	int ret = edhoc_test_compute_plaintext_4_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(len > 60000);
	edhoc_context_deinit(&ctx);
}

TEST(internals, compute_plaintext_4_len_very_large_ead_value)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);

	struct edhoc_ead_token tok = { .label = 1,
				       .value = NULL,
				       .value_len = 70000 };
	ctx.nr_of_ead_tokens = 1;
	ctx.ead_token[0] = tok;

	size_t len = 0;
	int ret = edhoc_test_compute_plaintext_4_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(len > 70000);
	edhoc_context_deinit(&ctx);
}

/* ---- msg3 internal function NULL arg tests ---- */

TEST(internals, comp_plaintext_3_len_null)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	uint8_t buf[256] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_plaintext_3_len(NULL, mc, 8, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_plaintext_3_len(&ctx, NULL, 8, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_plaintext_3_len(&ctx, mc, 0, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_plaintext_3_len(&ctx, mc, 8, NULL));
	edhoc_context_deinit(&ctx);
}

TEST(internals, prepare_plaintext_3_null)
{
	uint8_t buf[256] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	uint8_t sign[8] = { 0 };
	uint8_t ptxt[256];
	size_t ptxt_len;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_prepare_plaintext_3(NULL, sign, 8, ptxt,
							 256, &ptxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_prepare_plaintext_3(mc, NULL, 8, ptxt, 256,
							 &ptxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_prepare_plaintext_3(mc, sign, 0, ptxt, 256,
							 &ptxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_prepare_plaintext_3(mc, sign, 8, NULL, 256,
							 &ptxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_prepare_plaintext_3(mc, sign, 8, ptxt, 0,
							 &ptxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_prepare_plaintext_3(mc, sign, 8, ptxt, 256,
							 NULL));
}

TEST(internals, comp_aad_3_len_null)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_aad_3_len(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_aad_3_len(&ctx, NULL));
	edhoc_context_deinit(&ctx);
}

TEST(internals, gen_msg_3_null)
{
	uint8_t ctxt[] = { 0x40 };
	uint8_t msg[64];
	size_t msg_len;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_gen_msg_3(NULL, 1, msg, 64, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_gen_msg_3(ctxt, 0, msg, 64, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_gen_msg_3(ctxt, 1, NULL, 64, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_gen_msg_3(ctxt, 1, msg, 0, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_gen_msg_3(ctxt, 1, msg, 64, NULL));
}

TEST(internals, parse_msg_3_null)
{
	uint8_t msg[] = { 0x40 };
	const uint8_t *ctxt;
	size_t ctxt_len;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_msg_3(NULL, 1, &ctxt, &ctxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_msg_3(msg, 0, &ctxt, &ctxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_msg_3(msg, 1, NULL, &ctxt_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_msg_3(msg, 1, &ctxt, NULL));
}

TEST(internals, decrypt_ciphertext_3_null)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	uint8_t key[16] = { 0 }, iv[13] = { 0 }, aad[32] = { 0 };
	uint8_t ctxt[16] = { 0 }, ptxt[16] = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_decrypt_ciphertext_3(NULL, key, 16, iv, 13,
							  aad, 32, ctxt, 16,
							  ptxt, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_decrypt_ciphertext_3(&ctx, NULL, 16, iv,
							  13, aad, 32, ctxt, 16,
							  ptxt, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_decrypt_ciphertext_3(&ctx, key, 0, iv, 13,
							  aad, 32, ctxt, 16,
							  ptxt, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_decrypt_ciphertext_3(&ctx, key, 16, NULL,
							  13, aad, 32, ctxt, 16,
							  ptxt, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_decrypt_ciphertext_3(&ctx, key, 16, iv, 0,
							  aad, 32, ctxt, 16,
							  ptxt, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_decrypt_ciphertext_3(&ctx, key, 16, iv, 13,
							  NULL, 32, ctxt, 16,
							  ptxt, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_decrypt_ciphertext_3(&ctx, key, 16, iv, 13,
							  aad, 0, ctxt, 16,
							  ptxt, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_decrypt_ciphertext_3(&ctx, key, 16, iv, 13,
							  aad, 32, ctxt, 0,
							  ptxt, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_decrypt_ciphertext_3(&ctx, key, 16, iv, 13,
							  aad, 32, ctxt, 16,
							  NULL, 16));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_decrypt_ciphertext_3(&ctx, key, 16, iv, 13,
							  aad, 32, ctxt, 16,
							  ptxt, 0));
	edhoc_context_deinit(&ctx);
}

TEST(internals, parse_plaintext_3_null)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	uint8_t ptxt[] = { 0x40 };
	struct plaintext parsed = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_plaintext_3(NULL, ptxt, 1, &parsed));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_plaintext_3(&ctx, NULL, 1, &parsed));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_plaintext_3(&ctx, ptxt, 0, &parsed));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_plaintext_3(&ctx, ptxt, 1, NULL));
	edhoc_context_deinit(&ctx);
}

TEST(internals, parse_plaintext_3_garbage)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	uint8_t garbage[] = { 0xFF, 0xFE, 0xFD };
	struct plaintext parsed = { 0 };

	int ret = edhoc_test_parse_plaintext_3(&ctx, garbage, sizeof(garbage),
					       &parsed);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	edhoc_context_deinit(&ctx);
}

/* ---- msg2 internal function NULL arg tests ---- */

TEST(internals, comp_plaintext_2_len_null)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	uint8_t buf[256] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_plaintext_2_len(NULL, mc, 8, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_plaintext_2_len(&ctx, NULL, 8, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_plaintext_2_len(&ctx, mc, 0, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_comp_plaintext_2_len(&ctx, mc, 8, NULL));
	edhoc_context_deinit(&ctx);
}

TEST(internals, prepare_message_2_null)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	uint8_t ctxt[64] = { 0 };
	uint8_t msg[128];
	size_t msg_len;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_prepare_message_2(NULL, ctxt, 64, msg, 128,
						       &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_prepare_message_2(&ctx, NULL, 64, msg, 128,
						       &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_prepare_message_2(&ctx, ctxt, 0, msg, 128,
						       &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_prepare_message_2(&ctx, ctxt, 64, NULL,
						       128, &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_prepare_message_2(&ctx, ctxt, 64, msg, 0,
						       &msg_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_prepare_message_2(&ctx, ctxt, 64, msg, 128,
						       NULL));
	edhoc_context_deinit(&ctx);
}

TEST(internals, parse_plaintext_2_null)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	uint8_t ptxt[] = { 0x40 };
	struct plaintext parsed = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_plaintext_2(NULL, ptxt, 1, &parsed));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_plaintext_2(&ctx, NULL, 1, &parsed));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_plaintext_2(&ctx, ptxt, 0, &parsed));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_test_parse_plaintext_2(&ctx, ptxt, 1, NULL));
	edhoc_context_deinit(&ctx);
}

TEST(internals, parse_plaintext_2_garbage)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	uint8_t garbage[] = { 0xFF, 0xFE, 0xFD };
	struct plaintext parsed = { 0 };

	int ret = edhoc_test_parse_plaintext_2(&ctx, garbage, sizeof(garbage),
					       &parsed);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	edhoc_context_deinit(&ctx);
}

/* ---- msg2 parse_msg_2 + prepare_plaintext_2 hooks ---- */

TEST(internals, parse_msg_2_garbage)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	uint8_t garbage[] = { 0x18 };
	uint8_t ctxt[64];

	int ret = edhoc_test_parse_msg_2(&ctx, garbage, sizeof(garbage), ctxt,
					 sizeof(ctxt));
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
	edhoc_context_deinit(&ctx);
}

TEST(internals, prepare_plaintext_2_invalid_cid)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);
	ctx.cid.encode_type = 99;

	uint8_t buf[256] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	mc->id_cred_is_comp_enc = true;
	mc->id_cred_enc_type = EDHOC_ENCODE_TYPE_INTEGER;
	mc->id_cred_int = 5;

	uint8_t sign[8] = { 0 };
	uint8_t ptxt[256];
	size_t ptxt_len;

	int ret = edhoc_test_prepare_plaintext_2(&ctx, mc, sign, 8, ptxt,
						 sizeof(ptxt), &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
	edhoc_context_deinit(&ctx);
}

TEST(internals, prepare_plaintext_2_invalid_id_cred)
{
	struct edhoc_context ctx = { 0 };
	setup_crypto_context(&ctx);

	uint8_t buf[256] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	mc->id_cred_is_comp_enc = true;
	mc->id_cred_enc_type = 99;

	uint8_t sign[8] = { 0 };
	uint8_t ptxt[256];
	size_t ptxt_len;

	int ret = edhoc_test_prepare_plaintext_2(&ctx, mc, sign, 8, ptxt,
						 sizeof(ptxt), &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
	edhoc_context_deinit(&ctx);
}

/* ---- msg_error: compose with out-of-range error code ---- */

TEST(internals, error_compose_out_of_range_code)
{
	uint8_t buf[64];
	size_t len = 0;

	int ret = edhoc_message_error_compose(buf, sizeof(buf), &len, 99, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST_GROUP_RUNNER(internals)
{
	RUN_TEST_CASE(internals, comp_cid_len_one_byte_int);
	RUN_TEST_CASE(internals, comp_cid_len_byte_string);
	RUN_TEST_CASE(internals, comp_cid_len_null_args);
	RUN_TEST_CASE(internals, comp_cid_len_invalid_type);
	RUN_TEST_CASE(internals, comp_id_cred_len_kid_int);
	RUN_TEST_CASE(internals, comp_id_cred_len_kid_bstr);
	RUN_TEST_CASE(internals, comp_id_cred_len_x509_chain_single);
	RUN_TEST_CASE(internals, comp_id_cred_len_x509_chain_multi);
	RUN_TEST_CASE(internals, comp_id_cred_len_x509_hash_int);
	RUN_TEST_CASE(internals, comp_id_cred_len_x509_hash_bstr);
	RUN_TEST_CASE(internals, comp_id_cred_len_unsupported);
	RUN_TEST_CASE(internals, comp_id_cred_len_null);
	RUN_TEST_CASE(internals, comp_th_len_success);
	RUN_TEST_CASE(internals, comp_th_len_zero);
	RUN_TEST_CASE(internals, comp_cred_len_any);
	RUN_TEST_CASE(internals, comp_cred_len_kid);
	RUN_TEST_CASE(internals, comp_cred_len_x509_chain);
	RUN_TEST_CASE(internals, comp_cred_len_x509_hash);
	RUN_TEST_CASE(internals, comp_cred_len_unsupported);
	RUN_TEST_CASE(internals, comp_ead_len_no_tokens);
	RUN_TEST_CASE(internals, comp_ead_len_with_tokens);
	RUN_TEST_CASE(internals, kid_compact_enc_int_cbor);
	RUN_TEST_CASE(internals, kid_compact_enc_int_non_cbor);
	RUN_TEST_CASE(internals, kid_compact_enc_bstr_cbor_one_byte);
	RUN_TEST_CASE(internals, kid_compact_enc_bstr_cbor_multi_byte);
	RUN_TEST_CASE(internals, kid_compact_enc_bstr_non_cbor);
	RUN_TEST_CASE(internals, compute_prk_out_bad_th_state);
	RUN_TEST_CASE(internals, compute_prk_out_bad_prk_state);
	RUN_TEST_CASE(internals, compute_prk_out_null);
	RUN_TEST_CASE(internals, compute_prk_out_success);
	RUN_TEST_CASE(internals, compute_new_prk_out_bad_state);
	RUN_TEST_CASE(internals, compute_new_prk_out_success);
	RUN_TEST_CASE(internals, compute_prk_exporter_bad_state);
	RUN_TEST_CASE(internals, compute_prk_exporter_success);
	RUN_TEST_CASE(internals, comp_salt_3e2m_bad_th_state);
	RUN_TEST_CASE(internals, comp_salt_3e2m_bad_prk_state);
	RUN_TEST_CASE(internals, comp_salt_4e3m_bad_th_state);
	RUN_TEST_CASE(internals, comp_salt_4e3m_bad_prk_state);
	RUN_TEST_CASE(internals, comp_prk_3e2m_method_0);
	RUN_TEST_CASE(internals, comp_prk_3e2m_method_1);
	RUN_TEST_CASE(internals, comp_prk_3e2m_method_max);
	RUN_TEST_CASE(internals, comp_prk_4e3m_method_0);
	RUN_TEST_CASE(internals, comp_prk_4e3m_method_2);
	RUN_TEST_CASE(internals, comp_prk_4e3m_method_max);
	RUN_TEST_CASE(internals, mac_ctx_x509_chain_msg2);
	RUN_TEST_CASE(internals, mac_ctx_x509_chain_multi_cert);
	RUN_TEST_CASE(internals, mac_ctx_x509_hash_msg2);
	RUN_TEST_CASE(internals, mac_ctx_x509_hash_bstr_alg);
	RUN_TEST_CASE(internals, mac_ctx_kid_int_msg3);
	RUN_TEST_CASE(internals, mac_ctx_kid_bstr_msg2);
	RUN_TEST_CASE(internals, mac_ctx_bstr_cid_msg2);
	RUN_TEST_CASE(internals, mac_ctx_with_ead);
	RUN_TEST_CASE(internals, mac_ctx_any_cred);
	RUN_TEST_CASE(internals, mac_length_method_1_msg2);
	RUN_TEST_CASE(internals, mac_length_method_2_msg3);
	RUN_TEST_CASE(internals, sign_or_mac_length_method_1_msg2);
	RUN_TEST_CASE(internals, sign_or_mac_length_method_3_msg3);
	RUN_TEST_CASE(internals, mac_length_method_max_msg2);
	RUN_TEST_CASE(internals, full_mac_ctx_x509_chain);
	RUN_TEST_CASE(internals, full_mac_ctx_x509_hash_int);
	RUN_TEST_CASE(internals, full_mac_ctx_kid_int_cbor);
	RUN_TEST_CASE(internals, full_mac_ctx_kid_bstr);
	RUN_TEST_CASE(internals, full_mac_ctx_bstr_cid);
	RUN_TEST_CASE(internals, full_mac_ctx_with_ead);
	RUN_TEST_CASE(internals, full_mac_ctx_any);
	RUN_TEST_CASE(internals, comp_sign_or_mac_method1_msg2);
	RUN_TEST_CASE(internals, verify_sign_or_mac_method1_msg2);
	RUN_TEST_CASE(internals, verify_sign_or_mac_method1_msg2_mismatch);
	RUN_TEST_CASE(internals, comp_sign_or_mac_method2_msg3);
	RUN_TEST_CASE(internals, verify_sign_or_mac_method3_msg3);
	RUN_TEST_CASE(internals, comp_id_cred_len_kid_invalid_encode);
	RUN_TEST_CASE(internals, comp_id_cred_len_x509_hash_invalid_encode);
	RUN_TEST_CASE(internals, comp_cred_len_null);
	RUN_TEST_CASE(internals, comp_ead_len_null);
	RUN_TEST_CASE(internals, mac_ctx_len_null_args);
	RUN_TEST_CASE(internals, mac_ctx_len_invalid_role);
	RUN_TEST_CASE(internals, mac_ctx_len_invalid_message);
	RUN_TEST_CASE(internals, cbor_tstr_oh_large);
	RUN_TEST_CASE(internals, cbor_bstr_oh_large);
	RUN_TEST_CASE(internals, cbor_array_oh_large);
	RUN_TEST_CASE(internals, mac_ctx_small_buffer);
	RUN_TEST_CASE(internals, mac_ctx_len_unsupported_cred);
	RUN_TEST_CASE(internals, set_connection_id_invalid_type);
	RUN_TEST_CASE(internals, comp_th_2_null);
	RUN_TEST_CASE(internals, comp_th_2_bad_state);
	RUN_TEST_CASE(internals, comp_prk_2e_null);
	RUN_TEST_CASE(internals, comp_prk_2e_bad_state);
	RUN_TEST_CASE(internals, comp_prk_3e2m_null);
	RUN_TEST_CASE(internals, comp_prk_3e2m_bad_prk_state);
	RUN_TEST_CASE(internals, comp_prk_4e3m_null);
	RUN_TEST_CASE(internals, comp_prk_4e3m_bad_prk_state);
	RUN_TEST_CASE(internals, comp_salt_3e2m_null);
	RUN_TEST_CASE(internals, comp_salt_4e3m_null);
	RUN_TEST_CASE(internals, compute_prk_exporter_null);
	RUN_TEST_CASE(internals, compute_new_prk_out_null);
	RUN_TEST_CASE(internals, mac_ctx_x509_hash_bstr_msg3);
	RUN_TEST_CASE(internals, full_mac_ctx_x509_hash_bstr);
	RUN_TEST_CASE(internals, mac_ctx_invalid_cid_type);
	RUN_TEST_CASE(internals, mac_ctx_invalid_kid_encode_in_length);
	RUN_TEST_CASE(internals, mac_ctx_null_args);
	RUN_TEST_CASE(internals, mac_ctx_invalid_role);
	RUN_TEST_CASE(internals, mac_ctx_invalid_message);
	RUN_TEST_CASE(internals, mac_ctx_bad_th_state_msg2);
	RUN_TEST_CASE(internals, mac_ctx_bad_th_state_msg3);
	RUN_TEST_CASE(internals, mac_ctx_unsupported_cred_label);
	RUN_TEST_CASE(internals, mac_ctx_invalid_cid_type_compose);
	RUN_TEST_CASE(internals, error_message_compose_null);
	RUN_TEST_CASE(internals, error_message_process_null);
	RUN_TEST_CASE(internals, export_oscore_null);
	RUN_TEST_CASE(internals, export_oscore_bad_state);
	RUN_TEST_CASE(internals, key_update_null);
	/* edhoc_message_2.c hooks */
	RUN_TEST_CASE(internals, gen_dh_keys_null);
	RUN_TEST_CASE(internals, comp_dh_secret_null);
	RUN_TEST_CASE(internals, comp_keystream_null);
	RUN_TEST_CASE(internals, comp_keystream_bad_th_state);
	RUN_TEST_CASE(internals, comp_th_3_null);
	RUN_TEST_CASE(internals, comp_th_3_bad_state);
	RUN_TEST_CASE(internals, comp_grx_null);
	RUN_TEST_CASE(internals, comp_grx_invalid_role);
	/* edhoc_message_3.c hooks */
	RUN_TEST_CASE(internals, comp_key_iv_aad_3_null);
	RUN_TEST_CASE(internals, comp_key_iv_aad_3_bad_state);
	RUN_TEST_CASE(internals, comp_th_4_null);
	RUN_TEST_CASE(internals, comp_th_4_bad_state);
	RUN_TEST_CASE(internals, comp_giy_null);
	RUN_TEST_CASE(internals, comp_giy_invalid_role);
	/* edhoc_message_4.c hooks */
	RUN_TEST_CASE(internals, compute_plaintext_4_len_null);
	RUN_TEST_CASE(internals, compute_key_iv_aad_4_null);
	RUN_TEST_CASE(internals, compute_key_iv_aad_4_bad_state);
	/* edhoc_common.c public API */
	RUN_TEST_CASE(internals, mac_length_null_args);
	RUN_TEST_CASE(internals, mac_length_invalid_role);
	RUN_TEST_CASE(internals, mac_length_invalid_message);
	RUN_TEST_CASE(internals, mac_length_method_max_msg3);
	RUN_TEST_CASE(internals, comp_mac_invalid_message);
	RUN_TEST_CASE(internals, comp_mac_bad_prk_state_msg2);
	RUN_TEST_CASE(internals, comp_mac_bad_prk_state_msg3);
	RUN_TEST_CASE(internals, sign_or_mac_length_invalid_role);
	RUN_TEST_CASE(internals, sign_or_mac_length_method_max);
	RUN_TEST_CASE(internals, sign_or_mac_length_invalid_msg);
	RUN_TEST_CASE(internals, comp_sign_or_mac_invalid_msg);
	RUN_TEST_CASE(internals, comp_sign_or_mac_method_max);
	RUN_TEST_CASE(internals, verify_sign_or_mac_null_mac);
	RUN_TEST_CASE(internals, verify_sign_or_mac_invalid_msg);
	RUN_TEST_CASE(internals, verify_sign_or_mac_method_max);
	/* edhoc_helpers.c */
	RUN_TEST_CASE(internals, conn_id_equal_invalid_type);
	RUN_TEST_CASE(internals, conn_id_equal_null);
	RUN_TEST_CASE(internals, conn_id_equal_type_mismatch);
	RUN_TEST_CASE(internals, conn_id_equal_bstr_success);
	RUN_TEST_CASE(internals, prepend_conn_id_null);
	RUN_TEST_CASE(internals, prepend_conn_id_zero_buf);
	RUN_TEST_CASE(internals, prepend_conn_id_invalid_type);
	RUN_TEST_CASE(internals, prepend_conn_id_bstr_zero_len);
	RUN_TEST_CASE(internals, prepend_conn_id_bstr_success);
	RUN_TEST_CASE(internals, prepend_flow_null);
	RUN_TEST_CASE(internals, prepend_flow_success);
	RUN_TEST_CASE(internals, prepend_flow_tiny_buf);
	RUN_TEST_CASE(internals, prepend_recalculate_null);
	RUN_TEST_CASE(internals, prepend_recalculate_null_buf);
	RUN_TEST_CASE(internals, prepend_recalculate_null_msg_ptr);
	RUN_TEST_CASE(internals, extract_flow_info_null);
	RUN_TEST_CASE(internals, extract_flow_info_null_buf);
	RUN_TEST_CASE(internals, extract_flow_info_forward);
	RUN_TEST_CASE(internals, extract_conn_id_null);
	RUN_TEST_CASE(internals, extract_conn_id_int);
	RUN_TEST_CASE(internals, extract_conn_id_bstr);
	/* Additional mac/sign method coverage */
	RUN_TEST_CASE(internals, sign_or_mac_length_method0_msg2);
	RUN_TEST_CASE(internals, sign_or_mac_length_method0_msg3);
	RUN_TEST_CASE(internals, mac_length_method0_msg2);
	RUN_TEST_CASE(internals, mac_length_method0_msg3);
	RUN_TEST_CASE(internals, mac_length_method3_msg2);
	RUN_TEST_CASE(internals, mac_length_method3_msg3);
	RUN_TEST_CASE(internals, sign_or_mac_length_method2_msg2);
	/* edhoc_message_error.c */
	RUN_TEST_CASE(internals, error_compose_tiny_buffer);
	RUN_TEST_CASE(internals, error_compose_unspecified_null_info);
	RUN_TEST_CASE(internals, error_compose_success_code);
	RUN_TEST_CASE(internals, error_compose_unknown_cred);
	RUN_TEST_CASE(internals, error_compose_invalid_code);
	RUN_TEST_CASE(internals, error_compose_unspecified_with_info);
	RUN_TEST_CASE(internals, error_compose_wrong_csuite_single);
	RUN_TEST_CASE(internals, error_compose_wrong_csuite_multi);
	RUN_TEST_CASE(internals, error_process_roundtrip);
	RUN_TEST_CASE(internals, error_process_unspecified_roundtrip);
	RUN_TEST_CASE(internals, error_process_wrong_csuite_roundtrip);
	RUN_TEST_CASE(internals, error_process_malformed);
	/* edhoc_message_1.c */
	RUN_TEST_CASE(internals, msg1_compose_invalid_cid_type);
	RUN_TEST_CASE(internals, msg1_compose_zero_csuites);
	RUN_TEST_CASE(internals, msg1_compose_tiny_buffer);
	RUN_TEST_CASE(internals, msg1_process_malformed);
	RUN_TEST_CASE(internals, msg1_process_truncated);
	/* edhoc_helpers.c edge cases */
	RUN_TEST_CASE(internals, prepend_conn_id_bstr_tiny_buf);
	RUN_TEST_CASE(internals, extract_conn_id_invalid_cbor);
	RUN_TEST_CASE(internals, extract_conn_id_null_buf);
	/* Additional method/message coverage */
	RUN_TEST_CASE(internals, mac_length_method1_msg3);
	RUN_TEST_CASE(internals, mac_length_method2_msg2);
	RUN_TEST_CASE(internals, sign_or_mac_length_method3_msg2);
	RUN_TEST_CASE(internals, sign_or_mac_length_method1_msg3);
	RUN_TEST_CASE(internals, sign_or_mac_length_method2_msg3);
	/* edhoc_comp_mac_context direct tests */
	RUN_TEST_CASE(internals, mac_ctx_x509chain_zero_certs);
	RUN_TEST_CASE(internals, mac_ctx_length_th_zero);
	RUN_TEST_CASE(internals, mac_ctx_kid_bad_cbor_compact);
	/* edhoc_common.c: kid_compact_encoding default */
	RUN_TEST_CASE(internals, kid_compact_enc_invalid_type);
	/* edhoc_common.c: edhoc_comp_mac edge cases */
	RUN_TEST_CASE(internals, comp_mac_null_args);
	RUN_TEST_CASE(internals, comp_mac_msg1);
	/* edhoc_common.c: edhoc_comp_sign_or_mac_length edge cases */
	RUN_TEST_CASE(internals, comp_sign_or_mac_len_null_args);
	RUN_TEST_CASE(internals, sign_or_mac_length_method_max_msg3);
	/* edhoc_common.c: edhoc_comp_sign_or_mac edge cases */
	RUN_TEST_CASE(internals, comp_sign_or_mac_null_args);
	RUN_TEST_CASE(internals, comp_sign_or_mac_method_max_msg3);
	/* edhoc_common.c: edhoc_verify_sign_or_mac edge cases */
	RUN_TEST_CASE(internals, verify_sign_or_mac_mismatch_msg3);
	RUN_TEST_CASE(internals, verify_sign_or_mac_method_max_msg3);
	/* msg4 internal function hooks */
	RUN_TEST_CASE(internals, prepare_plaintext_4_null);
	RUN_TEST_CASE(internals, gen_msg_4_null);
	RUN_TEST_CASE(internals, parse_msg_4_null);
	RUN_TEST_CASE(internals, parse_plaintext_4_null);
	RUN_TEST_CASE(internals, parse_plaintext_4_empty);
	/* msg4 CBOR helper coverage */
	RUN_TEST_CASE(internals, compute_plaintext_4_len_large_ead_label);
	RUN_TEST_CASE(internals, compute_plaintext_4_len_large_ead_value);
	RUN_TEST_CASE(internals, compute_plaintext_4_len_very_large_ead_value);
	/* msg3 internal function hooks */
	RUN_TEST_CASE(internals, comp_plaintext_3_len_null);
	RUN_TEST_CASE(internals, prepare_plaintext_3_null);
	RUN_TEST_CASE(internals, comp_aad_3_len_null);
	RUN_TEST_CASE(internals, gen_msg_3_null);
	RUN_TEST_CASE(internals, parse_msg_3_null);
	RUN_TEST_CASE(internals, decrypt_ciphertext_3_null);
	RUN_TEST_CASE(internals, parse_plaintext_3_null);
	RUN_TEST_CASE(internals, parse_plaintext_3_garbage);
	/* msg2 internal function hooks */
	RUN_TEST_CASE(internals, comp_plaintext_2_len_null);
	RUN_TEST_CASE(internals, prepare_message_2_null);
	RUN_TEST_CASE(internals, parse_plaintext_2_null);
	RUN_TEST_CASE(internals, parse_plaintext_2_garbage);
	RUN_TEST_CASE(internals, parse_msg_2_garbage);
	RUN_TEST_CASE(internals, prepare_plaintext_2_invalid_cid);
	RUN_TEST_CASE(internals, prepare_plaintext_2_invalid_id_cred);
	/* msg_error edge cases */
	RUN_TEST_CASE(internals, error_compose_out_of_range_code);
}
