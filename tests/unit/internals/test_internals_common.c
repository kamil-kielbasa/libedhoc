/**
 * \file    test_internals_common.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for common internal length and PRK helpers.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#include "internals_common.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(internals_common);

TEST_SETUP(internals_common)
{
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, psa_crypto_init());
	internals_keys = edhoc_cipher_suite_0_get_keys();
	internals_crypto = edhoc_cipher_suite_0_get_crypto();
}

TEST_TEAR_DOWN(internals_common)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_common, comp_cid_len_one_byte_int)
{
	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5,
	};
	size_t len = 0;

	int ret = comp_cid_len(&cid, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(1, len);
}

TEST(internals_common, comp_cid_len_byte_string)
{
	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3,
	};
	size_t len = 0;

	int ret = comp_cid_len(&cid, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(4, len);
}

TEST(internals_common, comp_cid_len_null_args)
{
	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
	};
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_cid_len(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_cid_len(&cid, NULL));
}

TEST(internals_common, comp_cid_len_invalid_type)
{
	struct edhoc_connection_id cid = {
		.encode_type = 99,
	};
	size_t len = 0;

	int ret = comp_cid_len(&cid, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_common, comp_id_cred_len_kid_int)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.key_id.key_id_int = 5;
	size_t len = 0;

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(4, len);
}

TEST(internals_common, comp_id_cred_len_kid_bstr)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.key_id.key_id_bstr_length = 1;
	size_t len = 0;

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_common, comp_id_cred_len_x509_chain_single)
{
	static uint8_t cert_buf[100];
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 1;
	cred.x509_chain.cert[0] = cert_buf;
	cred.x509_chain.cert_len[0] = 100;
	size_t len = 0;

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_common, comp_id_cred_len_x509_chain_multi)
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

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_common, comp_id_cred_len_x509_hash_int)
{
	static uint8_t cert_fp[32];
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.x509_hash.alg_int = -8;
	cred.x509_hash.cert_fp = cert_fp;
	cred.x509_hash.cert_fp_len = 32;
	size_t len = 0;

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_common, comp_id_cred_len_x509_hash_bstr)
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

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_common, comp_id_cred_len_unsupported)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = 99;
	size_t len = 0;

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);
}

TEST(internals_common, comp_id_cred_len_null)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_id_cred_len(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_id_cred_len(&cred, NULL));
}

TEST(internals_common, comp_th_len_success)
{
	size_t len = 0;

	int ret = comp_th_len(32, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(34, len);
}

TEST(internals_common, comp_th_len_zero)
{
	size_t len = 0;

	int ret = comp_th_len(0, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, comp_cred_len_any)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_ANY;
	cred.any.cred_len = 50;
	size_t len = 0;

	int ret = comp_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(50, len);
}

TEST(internals_common, comp_cred_len_kid)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.cred_len = 100;
	size_t len = 0;

	int ret = comp_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(100, len);
}

TEST(internals_common, comp_cred_len_x509_chain)
{
	static uint8_t cert_buf[200];
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.nr_of_certs = 1;
	cred.x509_chain.cert[0] = cert_buf;
	cred.x509_chain.cert_len[0] = 200;
	size_t len = 0;

	int ret = comp_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_common, comp_cred_len_x509_hash)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.cert_len = 150;
	size_t len = 0;

	int ret = comp_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_common, comp_cred_len_unsupported)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = 99;
	size_t len = 0;

	int ret = comp_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);
}

TEST(internals_common, comp_ead_len_no_tokens)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	ctx.nr_of_ead_tokens = 0;
	size_t len = 0;

	int ret = comp_ead_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(0, len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, comp_ead_len_with_tokens)
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

	int ret = comp_ead_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, kid_compact_enc_int_cbor)
{
	uint8_t buf[512] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.key_id.key_id_int = 7;
	cred.key_id.cred_is_cbor = true;

	int ret = kid_compact_encoding(&cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(mac_ctx->id_cred_is_comp_enc);
	TEST_ASSERT_EQUAL(EDHOC_ENCODE_TYPE_INTEGER, mac_ctx->id_cred_enc_type);
	TEST_ASSERT_EQUAL(7, mac_ctx->id_cred_int);
}

TEST(internals_common, kid_compact_enc_int_non_cbor)
{
	uint8_t buf[512] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.key_id.key_id_int = 5;
	cred.key_id.cred_is_cbor = false;

	int ret = kid_compact_encoding(&cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(mac_ctx->id_cred_is_comp_enc);
}

TEST(internals_common, kid_compact_enc_bstr_cbor_one_byte)
{
	uint8_t buf[512] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.key_id.cred_is_cbor = true;
	cred.key_id.key_id_bstr_length = 1;
	cred.key_id.key_id_bstr[0] = 0x05;

	int ret = kid_compact_encoding(&cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(mac_ctx->id_cred_is_comp_enc);
	TEST_ASSERT_EQUAL(EDHOC_ENCODE_TYPE_INTEGER, mac_ctx->id_cred_enc_type);
	TEST_ASSERT_EQUAL(5, mac_ctx->id_cred_int);
}

TEST(internals_common, kid_compact_enc_bstr_cbor_multi_byte)
{
	uint8_t buf[512] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.key_id.cred_is_cbor = true;
	cred.key_id.key_id_bstr_length = 2;
	cred.key_id.key_id_bstr[0] = 0x18;
	cred.key_id.key_id_bstr[1] = 0x64;

	int ret = kid_compact_encoding(&cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(mac_ctx->id_cred_is_comp_enc);
	TEST_ASSERT_EQUAL(EDHOC_ENCODE_TYPE_BYTE_STRING,
			  mac_ctx->id_cred_enc_type);
	TEST_ASSERT_EQUAL(2, mac_ctx->id_cred_bstr_len);
}

TEST(internals_common, kid_compact_enc_bstr_non_cbor)
{
	uint8_t buf[512] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.key_id.cred_is_cbor = false;
	cred.key_id.key_id_bstr_length = 0;

	int ret = kid_compact_encoding(&cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(mac_ctx->id_cred_is_comp_enc);
	TEST_ASSERT_EQUAL(EDHOC_ENCODE_TYPE_BYTE_STRING,
			  mac_ctx->id_cred_enc_type);
}

TEST(internals_common, compute_prk_out_bad_th_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	int ret = compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, compute_prk_out_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_4;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	int ret = compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, compute_prk_out_null)
{
	int ret = compute_prk_out(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, compute_prk_out_success)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_4;
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.th_len = 32;
	ctx.prk_len = 32;
	for (size_t i = 0; i < 32; i++) {
		ctx.th[i] = (uint8_t)(i + 1);
		ctx.prk[i] = (uint8_t)(i + 0x20);
	}

	int ret = compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, ctx.prk_state);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, compute_new_prk_out_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.prk_len = 32;

	uint8_t entropy[16] = { 0xAA };
	int ret = compute_new_prk_out(&ctx, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, compute_new_prk_out_success)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_4;
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.th_len = 32;
	ctx.prk_len = 32;
	for (size_t i = 0; i < 32; i++) {
		ctx.th[i] = (uint8_t)(i + 1);
		ctx.prk[i] = (uint8_t)(i + 0x20);
	}

	int ret = compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t entropy[16] = { 0xBB };
	ret = compute_new_prk_out(&ctx, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, compute_prk_exporter_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.prk_len = 32;

	uint8_t prk_exp[32] = { 0 };
	int ret = compute_prk_exporter(&ctx, prk_exp, sizeof(prk_exp));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, compute_prk_exporter_success)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_4;
	ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.th_len = 32;
	ctx.prk_len = 32;
	for (size_t i = 0; i < 32; i++) {
		ctx.th[i] = (uint8_t)(i + 1);
		ctx.prk[i] = (uint8_t)(i + 0x20);
	}

	int ret = compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t prk_exp[32] = { 0 };
	ret = compute_prk_exporter(&ctx, prk_exp, sizeof(prk_exp));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, comp_salt_3e2m_bad_th_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_1;
	ctx.prk_state = EDHOC_PRK_STATE_2E;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	uint8_t salt[32] = { 0 };
	int ret = comp_salt_3e2m(&ctx, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, comp_salt_3e2m_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	uint8_t salt[32] = { 0 };
	int ret = comp_salt_3e2m(&ctx, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, comp_salt_4e3m_bad_th_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	uint8_t salt[32] = { 0 };
	int ret = comp_salt_4e3m(&ctx, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, comp_salt_4e3m_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.prk_state = EDHOC_PRK_STATE_2E;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	uint8_t salt[32] = { 0 };
	int ret = comp_salt_4e3m(&ctx, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, comp_prk_3e2m_method_0)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.chosen_method = EDHOC_METHOD_0;
	ctx.prk_state = EDHOC_PRK_STATE_2E;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	struct edhoc_auth_creds auth_cred = { 0 };
	auth_cred.label = EDHOC_COSE_HEADER_KID;

	int ret = comp_prk_3e2m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, ctx.prk_state);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, comp_prk_3e2m_method_1)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
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

	int ret = comp_prk_3e2m(&ctx, &auth_cred, pub_key, 32);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, ctx.prk_state);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, comp_prk_3e2m_method_max)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.chosen_method = EDHOC_METHOD_MAX;
	ctx.prk_state = EDHOC_PRK_STATE_2E;
	ctx.th_state = EDHOC_TH_STATE_2;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	struct edhoc_auth_creds auth_cred = { 0 };
	auth_cred.label = EDHOC_COSE_HEADER_KID;

	int ret = comp_prk_3e2m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, comp_prk_4e3m_method_0)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.chosen_method = EDHOC_METHOD_0;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	struct edhoc_auth_creds auth_cred = { 0 };
	auth_cred.label = EDHOC_COSE_HEADER_KID;

	int ret = comp_prk_4e3m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, ctx.prk_state);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, comp_prk_4e3m_method_2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
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

	int ret = comp_prk_4e3m(&ctx, &auth_cred, pub_key, 32);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, ctx.prk_state);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, comp_prk_4e3m_method_max)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.chosen_method = EDHOC_METHOD_MAX;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.th_state = EDHOC_TH_STATE_3;
	ctx.th_len = 32;
	ctx.prk_len = 32;

	struct edhoc_auth_creds auth_cred = { 0 };
	auth_cred.label = EDHOC_COSE_HEADER_KID;

	int ret = comp_prk_4e3m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, comp_id_cred_len_kid_invalid_encode)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = 99;
	size_t len = 0;

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_common, comp_id_cred_len_x509_hash_invalid_encode)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.encode_type = 99;
	size_t len = 0;

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_common, comp_cred_len_null)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_cred_len(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_cred_len(&cred, NULL));
}

TEST(internals_common, comp_ead_len_null)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_ead_len(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  comp_ead_len(&ctx, NULL));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, comp_prk_2e_null)
{
	int ret = comp_prk_2e(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, comp_prk_2e_bad_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;

	int ret = comp_prk_2e(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, comp_prk_3e2m_null)
{
	struct edhoc_auth_creds auth_cred = { 0 };
	int ret = comp_prk_3e2m(NULL, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, comp_prk_3e2m_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.role = EDHOC_RESPONDER;
	ctx.chosen_method = EDHOC_METHOD_0;
	ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.th_state = EDHOC_TH_STATE_2;

	struct edhoc_auth_creds auth_cred = { 0 };
	int ret = comp_prk_3e2m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, comp_prk_4e3m_null)
{
	struct edhoc_auth_creds auth_cred = { 0 };
	int ret = comp_prk_4e3m(NULL, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, comp_prk_4e3m_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.role = EDHOC_INITIATOR;
	ctx.chosen_method = EDHOC_METHOD_0;
	ctx.prk_state = EDHOC_PRK_STATE_2E;
	ctx.th_state = EDHOC_TH_STATE_3;

	struct edhoc_auth_creds auth_cred = { 0 };
	int ret = comp_prk_4e3m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_common, comp_salt_3e2m_null)
{
	uint8_t salt[32] = { 0 };
	int ret = comp_salt_3e2m(NULL, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, comp_salt_4e3m_null)
{
	uint8_t salt[32] = { 0 };
	int ret = comp_salt_4e3m(NULL, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, compute_prk_exporter_null)
{
	uint8_t prk_exp[32] = { 0 };
	int ret = compute_prk_exporter(NULL, prk_exp, sizeof(prk_exp));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, compute_new_prk_out_null)
{
	uint8_t entropy[16] = { 0 };
	int ret = compute_new_prk_out(NULL, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, kid_compact_enc_invalid_type)
{
	struct edhoc_auth_creds cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = 99;
	cred.key_id.key_id_int = 5;

	struct mac_context mc = { 0 };
	int ret = kid_compact_encoding(&cred, &mc);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST_GROUP_RUNNER(internals_common)
{
	RUN_TEST_CASE(internals_common, comp_cid_len_one_byte_int);
	RUN_TEST_CASE(internals_common, comp_cid_len_byte_string);
	RUN_TEST_CASE(internals_common, comp_cid_len_null_args);
	RUN_TEST_CASE(internals_common, comp_cid_len_invalid_type);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_kid_int);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_kid_bstr);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_x509_chain_single);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_x509_chain_multi);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_x509_hash_int);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_x509_hash_bstr);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_unsupported);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_null);
	RUN_TEST_CASE(internals_common, comp_th_len_success);
	RUN_TEST_CASE(internals_common, comp_th_len_zero);
	RUN_TEST_CASE(internals_common, comp_cred_len_any);
	RUN_TEST_CASE(internals_common, comp_cred_len_kid);
	RUN_TEST_CASE(internals_common, comp_cred_len_x509_chain);
	RUN_TEST_CASE(internals_common, comp_cred_len_x509_hash);
	RUN_TEST_CASE(internals_common, comp_cred_len_unsupported);
	RUN_TEST_CASE(internals_common, comp_ead_len_no_tokens);
	RUN_TEST_CASE(internals_common, comp_ead_len_with_tokens);
	RUN_TEST_CASE(internals_common, kid_compact_enc_int_cbor);
	RUN_TEST_CASE(internals_common, kid_compact_enc_int_non_cbor);
	RUN_TEST_CASE(internals_common, kid_compact_enc_bstr_cbor_one_byte);
	RUN_TEST_CASE(internals_common, kid_compact_enc_bstr_cbor_multi_byte);
	RUN_TEST_CASE(internals_common, kid_compact_enc_bstr_non_cbor);
	RUN_TEST_CASE(internals_common, compute_prk_out_bad_th_state);
	RUN_TEST_CASE(internals_common, compute_prk_out_bad_prk_state);
	RUN_TEST_CASE(internals_common, compute_prk_out_null);
	RUN_TEST_CASE(internals_common, compute_prk_out_success);
	RUN_TEST_CASE(internals_common, compute_new_prk_out_bad_state);
	RUN_TEST_CASE(internals_common, compute_new_prk_out_success);
	RUN_TEST_CASE(internals_common, compute_prk_exporter_bad_state);
	RUN_TEST_CASE(internals_common, compute_prk_exporter_success);
	RUN_TEST_CASE(internals_common, comp_salt_3e2m_bad_th_state);
	RUN_TEST_CASE(internals_common, comp_salt_3e2m_bad_prk_state);
	RUN_TEST_CASE(internals_common, comp_salt_4e3m_bad_th_state);
	RUN_TEST_CASE(internals_common, comp_salt_4e3m_bad_prk_state);
	RUN_TEST_CASE(internals_common, comp_prk_3e2m_method_0);
	RUN_TEST_CASE(internals_common, comp_prk_3e2m_method_1);
	RUN_TEST_CASE(internals_common, comp_prk_3e2m_method_max);
	RUN_TEST_CASE(internals_common, comp_prk_4e3m_method_0);
	RUN_TEST_CASE(internals_common, comp_prk_4e3m_method_2);
	RUN_TEST_CASE(internals_common, comp_prk_4e3m_method_max);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_kid_invalid_encode);
	RUN_TEST_CASE(internals_common,
		      comp_id_cred_len_x509_hash_invalid_encode);
	RUN_TEST_CASE(internals_common, comp_cred_len_null);
	RUN_TEST_CASE(internals_common, comp_ead_len_null);
	RUN_TEST_CASE(internals_common, comp_prk_2e_null);
	RUN_TEST_CASE(internals_common, comp_prk_2e_bad_state);
	RUN_TEST_CASE(internals_common, comp_prk_3e2m_null);
	RUN_TEST_CASE(internals_common, comp_prk_3e2m_bad_prk_state);
	RUN_TEST_CASE(internals_common, comp_prk_4e3m_null);
	RUN_TEST_CASE(internals_common, comp_prk_4e3m_bad_prk_state);
	RUN_TEST_CASE(internals_common, comp_salt_3e2m_null);
	RUN_TEST_CASE(internals_common, comp_salt_4e3m_null);
	RUN_TEST_CASE(internals_common, compute_prk_exporter_null);
	RUN_TEST_CASE(internals_common, compute_new_prk_out_null);
	RUN_TEST_CASE(internals_common, kid_compact_enc_invalid_type);
}
