/**
 * \file    test_internals_mac.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for MAC context and sign/MAC internals.
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

TEST_GROUP(internals_mac);

TEST_SETUP(internals_mac)
{
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, psa_crypto_init());
	internals_crypto = edhoc_cipher_suite_0_get_crypto();
}

TEST_TEAR_DOWN(internals_mac)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_mac, mac_ctx_x509_chain_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.certificate_count = 1;
	cred.x509_chain.certificate[0] = dummy_cert;
	cred.x509_chain.certificate_length[0] = sizeof(dummy_cert);

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_x509_chain_multi_cert)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	static const uint8_t cert0[50] = { 0 };
	static const uint8_t cert1[60] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.certificate_count = 2;
	cred.x509_chain.certificate[0] = cert0;
	cred.x509_chain.certificate_length[0] = 50;
	cred.x509_chain.certificate[1] = cert1;
	cred.x509_chain.certificate_length[1] = 60;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_x509_hash_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	static const uint8_t dummy_cert[100] = { 0 };
	static const uint8_t dummy_fp[32] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.x509_hash.algorithm_int = -16;
	cred.x509_hash.certificate_fingerprint = dummy_fp;
	cred.x509_hash.certificate_fingerprint_length = 32;
	cred.x509_hash.certificate = dummy_cert;
	cred.x509_hash.certificate_length = 100;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_x509_hash_bstr_alg)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	static const uint8_t dummy_cert[100] = { 0 };
	static const uint8_t dummy_fp[32] = { 0 };
	static const uint8_t alg_bytes[4] = { 'S', 'H', 'A', '-' };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.x509_hash.algorithm_bstr.length = 4;
	memcpy(cred.x509_hash.algorithm_bstr.value, alg_bytes, 4);
	cred.x509_hash.certificate_fingerprint = dummy_fp;
	cred.x509_hash.certificate_fingerprint_length = 32;
	cred.x509_hash.certificate = dummy_cert;
	cred.x509_hash.certificate_length = 100;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_kid_int_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);

	static const uint8_t dummy_cred[50] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.key_id.key_id_int = 4;
	cred.key_id.is_credential_cbor_encoded = true;
	cred.key_id.credential = dummy_cred;
	cred.key_id.credential_length = 50;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_kid_bstr_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	static const uint8_t dummy_cred[50] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.key_id.key_id_bstr.length = 2;
	cred.key_id.key_id_bstr.value[0] = 0x11;
	cred.key_id.key_id_bstr.value[1] = 0x22;
	cred.key_id.credential = dummy_cred;
	cred.key_id.credential_length = 50;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_bstr_cid_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_BYTE_STRING;
	ctx.negotiation.connection_id.bstr_value[0] = 0x01;
	ctx.negotiation.connection_id.bstr_value[1] = 0x02;
	ctx.negotiation.connection_id.bstr_length = 2;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.certificate_count = 1;
	cred.x509_chain.certificate[0] = dummy_cert;
	cred.x509_chain.certificate_length[0] = sizeof(dummy_cert);

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_with_ead)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;
	ctx.ead.count = 1;
	ctx.ead.token[0].label = 100;
	static const uint8_t ead_val[4] = { 1, 2, 3, 4 };
	ctx.ead.token[0].value = ead_val;
	ctx.ead.token[0].value_length = 4;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.certificate_count = 1;
	cred.x509_chain.certificate[0] = dummy_cert;
	cred.x509_chain.certificate_length[0] = sizeof(dummy_cert);

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_any_cred)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	static const uint8_t any_id_cred[10] = { 0xA1, 0x04, 0x42, 0x11, 0x22 };
	static const uint8_t any_cred[20] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_CUSTOM;
	cred.custom.id_credential = any_id_cred;
	cred.custom.id_credential_length = 5;
	cred.custom.credential = any_cred;
	cred.custom.credential_length = 20;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_length_method_1_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, mac_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_length_method_2_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_2;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, mac_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, sign_or_mac_length_method_1_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;

	size_t sign_or_mac_len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &sign_or_mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, sign_or_mac_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, sign_or_mac_length_method_3_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_3;

	size_t sign_or_mac_len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &sign_or_mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, sign_or_mac_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_length_method_max_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_MAX;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, full_mac_ctx_x509_chain)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.certificate_count = 1;
	cred.x509_chain.certificate[0] = dummy_cert;
	cred.x509_chain.certificate_length[0] = sizeof(dummy_cert);

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

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, full_mac_ctx_x509_hash_int)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	static const uint8_t dummy_cert[100] = { 0 };
	static const uint8_t dummy_fp[32] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.x509_hash.algorithm_int = -16;
	cred.x509_hash.certificate_fingerprint = dummy_fp;
	cred.x509_hash.certificate_fingerprint_length = 32;
	cred.x509_hash.certificate = dummy_cert;
	cred.x509_hash.certificate_length = 100;

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

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, full_mac_ctx_kid_int_cbor)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);

	static const uint8_t dummy_cred[50] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.key_id.key_id_int = 4;
	cred.key_id.is_credential_cbor_encoded = true;
	cred.key_id.credential = dummy_cred;
	cred.key_id.credential_length = 50;

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

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, full_mac_ctx_kid_bstr)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	static const uint8_t dummy_cred[50] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.key_id.is_credential_cbor_encoded = true;
	cred.key_id.key_id_bstr.length = 2;
	cred.key_id.key_id_bstr.value[0] = 0x18;
	cred.key_id.key_id_bstr.value[1] = 0x64;
	cred.key_id.credential = dummy_cred;
	cred.key_id.credential_length = 50;

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

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, full_mac_ctx_bstr_cid)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_BYTE_STRING;
	ctx.negotiation.connection_id.bstr_value[0] = 0x01;
	ctx.negotiation.connection_id.bstr_value[1] = 0x02;
	ctx.negotiation.connection_id.bstr_length = 2;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.certificate_count = 1;
	cred.x509_chain.certificate[0] = dummy_cert;
	cred.x509_chain.certificate_length[0] = sizeof(dummy_cert);

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

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, full_mac_ctx_with_ead)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;
	ctx.ead.count = 1;
	ctx.ead.token[0].label = 100;
	static const uint8_t ead_val[4] = { 1, 2, 3, 4 };
	ctx.ead.token[0].value = ead_val;
	ctx.ead.token[0].value_length = 4;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.certificate_count = 1;
	cred.x509_chain.certificate[0] = dummy_cert;
	cred.x509_chain.certificate_length[0] = sizeof(dummy_cert);

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

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, full_mac_ctx_any)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	static const uint8_t any_id_cred[10] = { 0xA1, 0x04, 0x42, 0x11, 0x22 };
	static const uint8_t any_cred[20] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_CUSTOM;
	cred.custom.id_credential = any_id_cred;
	cred.custom.id_credential_length = 5;
	cred.custom.credential = any_cred;
	cred.custom.credential_length = 20;

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

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, comp_sign_or_mac_method1_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.certificate_count = 1;
	cred.x509_chain.certificate[0] = dummy_cert;
	cred.x509_chain.certificate_length[0] = sizeof(dummy_cert);

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

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, verify_sign_or_mac_method1_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = 64;

	uint8_t pub_key[32] = { 0 };
	uint8_t mac[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	int ret = edhoc_verify_sign_or_mac(&ctx, mac_ctx, pub_key, 32, mac, 8,
					   mac, 8);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, verify_sign_or_mac_method1_msg2_mismatch)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = 64;

	uint8_t pub_key[32] = { 0 };
	uint8_t mac[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t wrong_mac[8] = { 9, 9, 9, 9, 9, 9, 9, 9 };

	int ret = edhoc_verify_sign_or_mac(&ctx, mac_ctx, pub_key, 32,
					   wrong_mac, 8, mac, 8);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_SIGN_OR_MAC_2, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, comp_sign_or_mac_method2_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_2;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 32;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	memset(ctx.state.th.value, 0xAA, 32);

	static const uint8_t dummy_cred[50] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	cred.key_id.key_id_int = 4;
	cred.key_id.credential = dummy_cred;
	cred.key_id.credential_length = 50;

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

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, verify_sign_or_mac_method3_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_3;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = 64;

	uint8_t pub_key[32] = { 0 };
	uint8_t mac[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	int ret = edhoc_verify_sign_or_mac(&ctx, mac_ctx, pub_key, 32, mac, 8,
					   mac, 8);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_len_null_args)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	struct edhoc_auth_credentials cred = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac_context_length(NULL, &cred, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac_context_length(&ctx, NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac_context_length(&ctx, &cred, NULL));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_len_invalid_role)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = 99;
	ctx.state.message = EDHOC_MESSAGE_2;
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	size_t len = 0;

	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_len_invalid_message)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_4;
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	size_t len = 0;

	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_small_buffer)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.certificate_count = 1;
	cred.x509_chain.certificate[0] = dummy_cert;
	cred.x509_chain.certificate_length[0] = sizeof(dummy_cert);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = 4;
	int ret = edhoc_comp_mac_context(&ctx, &cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_len_unsupported_cred)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	struct edhoc_auth_credentials cred = { 0 };
	cred.label = 99;
	size_t len = 0;

	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_x509_hash_bstr_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);

	static const uint8_t dummy_cert[100] = { 0 };
	static const uint8_t dummy_fp[32] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.x509_hash.algorithm_bstr.length = 4;
	memcpy(cred.x509_hash.algorithm_bstr.value, "SHA-", 4);
	cred.x509_hash.certificate_fingerprint = dummy_fp;
	cred.x509_hash.certificate_fingerprint_length = 32;
	cred.x509_hash.certificate = dummy_cert;
	cred.x509_hash.certificate_length = 100;

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);
	ret = edhoc_comp_mac_context(&ctx, &cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT(mac_ctx->id_cred_len > 0);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, full_mac_ctx_x509_hash_bstr)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	static const uint8_t dummy_cert[100] = { 0 };
	static const uint8_t dummy_fp[32] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_HASH;
	cred.x509_hash.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.x509_hash.algorithm_bstr.length = 4;
	memcpy(cred.x509_hash.algorithm_bstr.value, "SHA-", 4);
	cred.x509_hash.certificate_fingerprint = dummy_fp;
	cred.x509_hash.certificate_fingerprint_length = 32;
	cred.x509_hash.certificate = dummy_cert;
	cred.x509_hash.certificate_length = 100;

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

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_invalid_cid_type)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type = 99;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.certificate_count = 1;
	cred.x509_chain.certificate[0] = dummy_cert;
	cred.x509_chain.certificate_length[0] = sizeof(dummy_cert);

	size_t mac_ctx_len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_null_args)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	struct edhoc_auth_credentials cred = { 0 };
	uint8_t buf[2048] = { 0 };
	struct mac_context *mac = (struct mac_context *)buf;
	mac->buf_len = sizeof(buf) - sizeof(struct mac_context);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac_context(NULL, &cred, mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac_context(&ctx, NULL, mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac_context(&ctx, &cred, NULL));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_invalid_role)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = 99;
	ctx.state.message = EDHOC_MESSAGE_2;
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	uint8_t buf[2048] = { 0 };
	struct mac_context *mac = (struct mac_context *)buf;
	mac->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_comp_mac_context(&ctx, &cred, mac);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_invalid_message)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_4;
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	uint8_t buf[2048] = { 0 };
	struct mac_context *mac = (struct mac_context *)buf;
	mac->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_comp_mac_context(&ctx, &cred, mac);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_bad_th_state_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	uint8_t buf[2048] = { 0 };
	struct mac_context *mac = (struct mac_context *)buf;
	mac->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_comp_mac_context(&ctx, &cred, mac);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_bad_th_state_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);

	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	uint8_t buf[2048] = { 0 };
	struct mac_context *mac = (struct mac_context *)buf;
	mac->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_comp_mac_context(&ctx, &cred, mac);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_unsupported_cred_label)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	struct edhoc_auth_credentials cred = { 0 };
	cred.label = 99;
	uint8_t buf[2048] = { 0 };
	struct mac_context *mac = (struct mac_context *)buf;
	mac->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_comp_mac_context(&ctx, &cred, mac);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_invalid_cid_type_compose)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type = 99;

	static const uint8_t dummy_cert[100] = { 0 };
	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.certificate_count = 1;
	cred.x509_chain.certificate[0] = dummy_cert;
	cred.x509_chain.certificate_length[0] = sizeof(dummy_cert);

	uint8_t buf[2048] = { 0 };
	struct mac_context *mac = (struct mac_context *)buf;
	mac->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_comp_mac_context(&ctx, &cred, mac);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_invalid_kid_encode_in_length)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0xAA, 32);
	ctx.negotiation.connection_id.encode_type =
		EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER;
	ctx.negotiation.connection_id.int_value = 5;

	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = 99;
	size_t len = 0;

	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_length_null_args)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	size_t mac_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac_length(NULL, &mac_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_mac_length(&ctx, NULL));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_length_invalid_role)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = 99;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_length_invalid_message)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_4;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_length_method_max_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_MAX;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, comp_mac_invalid_message)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_4;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[32];
	int ret = edhoc_comp_mac(&ctx, mc, mac, sizeof(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, comp_mac_bad_prk_state_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[32];
	int ret = edhoc_comp_mac(&ctx, mc, mac, sizeof(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, comp_mac_bad_prk_state_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[32];
	int ret = edhoc_comp_mac(&ctx, mc, mac, sizeof(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, sign_or_mac_length_invalid_role)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = 99;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, sign_or_mac_length_method_max)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_MAX;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, sign_or_mac_length_invalid_msg)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_4;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, comp_sign_or_mac_invalid_msg)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_4;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	struct edhoc_auth_credentials cred = { 0 };
	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[8] = { 0 };
	uint8_t sign[64];
	size_t sign_len;
	int ret = edhoc_comp_sign_or_mac(&ctx, &cred, mc, mac, 8, sign,
					 sizeof(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, comp_sign_or_mac_method_max)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_MAX;

	struct edhoc_auth_credentials cred = { 0 };
	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[8] = { 0 };
	uint8_t sign[64];
	size_t sign_len;
	int ret = edhoc_comp_sign_or_mac(&ctx, &cred, mc, mac, 8, sign,
					 sizeof(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, verify_sign_or_mac_null_mac)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = 64;

	uint8_t pub[32] = { 0 };
	uint8_t sign[8] = { 0 };
	int ret = edhoc_verify_sign_or_mac(&ctx, mc, pub, 32, sign, 8, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, verify_sign_or_mac_invalid_msg)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_4;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = 64;

	uint8_t pub[32] = { 0 };
	uint8_t mac[8] = { 0 };
	int ret = edhoc_verify_sign_or_mac(&ctx, mc, pub, 32, mac, 8, mac, 8);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, verify_sign_or_mac_method_max)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_MAX;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = 64;

	uint8_t pub[32] = { 0 };
	uint8_t mac[8] = { 0 };
	int ret = edhoc_verify_sign_or_mac(&ctx, mc, pub, 32, mac, 8, mac, 8);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, sign_or_mac_length_method0_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(64, len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, sign_or_mac_length_method0_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(64, len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_length_method0_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(32, mac_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_length_method0_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(32, mac_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_length_method3_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_3;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, mac_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_length_method3_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_3;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, mac_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, sign_or_mac_length_method2_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_2;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(64, len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_length_method1_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(32, mac_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_length_method2_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_2;

	size_t mac_len = 0;
	int ret = edhoc_comp_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(32, mac_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, sign_or_mac_length_method3_msg2)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_3;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, sign_or_mac_length_method1_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(64, len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, sign_or_mac_length_method2_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_2;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(8, len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_x509chain_zero_certs)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0x11, 32);

	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.certificate_count = 0;

	uint8_t buf[sizeof(struct mac_context) + 256];
	struct mac_context *mc = (struct mac_context *)buf;
	memset(mc, 0, sizeof(buf));
	mc->buf_len = 256;

	int ret = edhoc_comp_mac_context(&ctx, &cred, mc);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_length_th_zero)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 0;

	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_X509_CHAIN;
	cred.x509_chain.certificate_count = 1;
	static const uint8_t fake_cert[] = { 0x30, 0x00 };
	cred.x509_chain.certificate[0] = fake_cert;
	cred.x509_chain.certificate_length[0] = sizeof(fake_cert);

	size_t len = 0;
	int ret = edhoc_comp_mac_context_length(&ctx, &cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, mac_ctx_kid_bad_cbor_compact)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 32;
	memset(ctx.state.th.value, 0x11, 32);

	struct edhoc_auth_credentials cred = { 0 };
	cred.label = EDHOC_COSE_HEADER_KID;
	cred.key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	cred.key_id.is_credential_cbor_encoded = true;
	cred.key_id.key_id_bstr.length = 1;
	cred.key_id.key_id_bstr.value[0] = 0x40;
	static const uint8_t fake_cred[] = { 0x30, 0x00 };
	cred.key_id.credential = fake_cred;
	cred.key_id.credential_length = sizeof(fake_cred);

	uint8_t buf[sizeof(struct mac_context) + 256];
	struct mac_context *mc = (struct mac_context *)buf;
	memset(mc, 0, sizeof(buf));
	mc->buf_len = 256;

	int ret = edhoc_comp_mac_context(&ctx, &cred, mc);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, comp_mac_null_args)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;

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

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, comp_mac_msg1)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);
	mc->buf[0] = 0x40;
	mc->buf_len = 1;

	uint8_t mac[8];
	ctx.state.message = EDHOC_MESSAGE_1;
	int ret = edhoc_comp_mac(&ctx, mc, mac, sizeof(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, comp_sign_or_mac_len_null_args)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_sign_or_mac_length(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_comp_sign_or_mac_length(&ctx, NULL));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, sign_or_mac_length_method_max_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_MAX;

	size_t len = 0;
	int ret = edhoc_comp_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, comp_sign_or_mac_null_args)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	struct edhoc_auth_credentials cred = { 0 };
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

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, comp_sign_or_mac_method_max_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_MAX;

	struct edhoc_auth_credentials cred = { 0 };
	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[8] = { 0 };
	uint8_t sign[64];
	size_t sign_len;
	int ret = edhoc_comp_sign_or_mac(&ctx, &cred, mc, mac, 8, sign,
					 sizeof(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, verify_sign_or_mac_mismatch_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_2;

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
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_SIGN_OR_MAC_3, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_mac, verify_sign_or_mac_method_max_msg3)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_MAX;

	uint8_t buf[2048] = { 0 };
	struct mac_context *mc = (struct mac_context *)buf;
	mc->buf_len = 64;

	uint8_t pub[32] = { 0 };
	uint8_t mac[8] = { 0 };

	int ret = edhoc_verify_sign_or_mac(&ctx, mc, pub, 32, mac, 8, mac, 8);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST_GROUP_RUNNER(internals_mac)
{
	RUN_TEST_CASE(internals_mac, mac_ctx_x509_chain_msg2);
	RUN_TEST_CASE(internals_mac, mac_ctx_x509_chain_multi_cert);
	RUN_TEST_CASE(internals_mac, mac_ctx_x509_hash_msg2);
	RUN_TEST_CASE(internals_mac, mac_ctx_x509_hash_bstr_alg);
	RUN_TEST_CASE(internals_mac, mac_ctx_kid_int_msg3);
	RUN_TEST_CASE(internals_mac, mac_ctx_kid_bstr_msg2);
	RUN_TEST_CASE(internals_mac, mac_ctx_bstr_cid_msg2);
	RUN_TEST_CASE(internals_mac, mac_ctx_with_ead);
	RUN_TEST_CASE(internals_mac, mac_ctx_any_cred);
	RUN_TEST_CASE(internals_mac, mac_length_method_1_msg2);
	RUN_TEST_CASE(internals_mac, mac_length_method_2_msg3);
	RUN_TEST_CASE(internals_mac, sign_or_mac_length_method_1_msg2);
	RUN_TEST_CASE(internals_mac, sign_or_mac_length_method_3_msg3);
	RUN_TEST_CASE(internals_mac, mac_length_method_max_msg2);
	RUN_TEST_CASE(internals_mac, full_mac_ctx_x509_chain);
	RUN_TEST_CASE(internals_mac, full_mac_ctx_x509_hash_int);
	RUN_TEST_CASE(internals_mac, full_mac_ctx_kid_int_cbor);
	RUN_TEST_CASE(internals_mac, full_mac_ctx_kid_bstr);
	RUN_TEST_CASE(internals_mac, full_mac_ctx_bstr_cid);
	RUN_TEST_CASE(internals_mac, full_mac_ctx_with_ead);
	RUN_TEST_CASE(internals_mac, full_mac_ctx_any);
	RUN_TEST_CASE(internals_mac, comp_sign_or_mac_method1_msg2);
	RUN_TEST_CASE(internals_mac, verify_sign_or_mac_method1_msg2);
	RUN_TEST_CASE(internals_mac, verify_sign_or_mac_method1_msg2_mismatch);
	RUN_TEST_CASE(internals_mac, comp_sign_or_mac_method2_msg3);
	RUN_TEST_CASE(internals_mac, verify_sign_or_mac_method3_msg3);
	RUN_TEST_CASE(internals_mac, mac_ctx_len_null_args);
	RUN_TEST_CASE(internals_mac, mac_ctx_len_invalid_role);
	RUN_TEST_CASE(internals_mac, mac_ctx_len_invalid_message);
	RUN_TEST_CASE(internals_mac, mac_ctx_small_buffer);
	RUN_TEST_CASE(internals_mac, mac_ctx_len_unsupported_cred);
	RUN_TEST_CASE(internals_mac, mac_ctx_x509_hash_bstr_msg3);
	RUN_TEST_CASE(internals_mac, full_mac_ctx_x509_hash_bstr);
	RUN_TEST_CASE(internals_mac, mac_ctx_invalid_cid_type);
	RUN_TEST_CASE(internals_mac, mac_ctx_null_args);
	RUN_TEST_CASE(internals_mac, mac_ctx_invalid_role);
	RUN_TEST_CASE(internals_mac, mac_ctx_invalid_message);
	RUN_TEST_CASE(internals_mac, mac_ctx_bad_th_state_msg2);
	RUN_TEST_CASE(internals_mac, mac_ctx_bad_th_state_msg3);
	RUN_TEST_CASE(internals_mac, mac_ctx_unsupported_cred_label);
	RUN_TEST_CASE(internals_mac, mac_ctx_invalid_cid_type_compose);
	RUN_TEST_CASE(internals_mac, mac_ctx_invalid_kid_encode_in_length);
	RUN_TEST_CASE(internals_mac, mac_length_null_args);
	RUN_TEST_CASE(internals_mac, mac_length_invalid_role);
	RUN_TEST_CASE(internals_mac, mac_length_invalid_message);
	RUN_TEST_CASE(internals_mac, mac_length_method_max_msg3);
	RUN_TEST_CASE(internals_mac, comp_mac_invalid_message);
	RUN_TEST_CASE(internals_mac, comp_mac_bad_prk_state_msg2);
	RUN_TEST_CASE(internals_mac, comp_mac_bad_prk_state_msg3);
	RUN_TEST_CASE(internals_mac, sign_or_mac_length_invalid_role);
	RUN_TEST_CASE(internals_mac, sign_or_mac_length_method_max);
	RUN_TEST_CASE(internals_mac, sign_or_mac_length_invalid_msg);
	RUN_TEST_CASE(internals_mac, comp_sign_or_mac_invalid_msg);
	RUN_TEST_CASE(internals_mac, comp_sign_or_mac_method_max);
	RUN_TEST_CASE(internals_mac, verify_sign_or_mac_null_mac);
	RUN_TEST_CASE(internals_mac, verify_sign_or_mac_invalid_msg);
	RUN_TEST_CASE(internals_mac, verify_sign_or_mac_method_max);
	RUN_TEST_CASE(internals_mac, sign_or_mac_length_method0_msg2);
	RUN_TEST_CASE(internals_mac, sign_or_mac_length_method0_msg3);
	RUN_TEST_CASE(internals_mac, mac_length_method0_msg2);
	RUN_TEST_CASE(internals_mac, mac_length_method0_msg3);
	RUN_TEST_CASE(internals_mac, mac_length_method3_msg2);
	RUN_TEST_CASE(internals_mac, mac_length_method3_msg3);
	RUN_TEST_CASE(internals_mac, sign_or_mac_length_method2_msg2);
	RUN_TEST_CASE(internals_mac, mac_length_method1_msg3);
	RUN_TEST_CASE(internals_mac, mac_length_method2_msg2);
	RUN_TEST_CASE(internals_mac, sign_or_mac_length_method3_msg2);
	RUN_TEST_CASE(internals_mac, sign_or_mac_length_method1_msg3);
	RUN_TEST_CASE(internals_mac, sign_or_mac_length_method2_msg3);
	RUN_TEST_CASE(internals_mac, mac_ctx_x509chain_zero_certs);
	RUN_TEST_CASE(internals_mac, mac_ctx_length_th_zero);
	RUN_TEST_CASE(internals_mac, mac_ctx_kid_bad_cbor_compact);
	RUN_TEST_CASE(internals_mac, comp_mac_null_args);
	RUN_TEST_CASE(internals_mac, comp_mac_msg1);
	RUN_TEST_CASE(internals_mac, comp_sign_or_mac_len_null_args);
	RUN_TEST_CASE(internals_mac, sign_or_mac_length_method_max_msg3);
	RUN_TEST_CASE(internals_mac, comp_sign_or_mac_null_args);
	RUN_TEST_CASE(internals_mac, comp_sign_or_mac_method_max_msg3);
	RUN_TEST_CASE(internals_mac, verify_sign_or_mac_mismatch_msg3);
	RUN_TEST_CASE(internals_mac, verify_sign_or_mac_method_max_msg3);
}
