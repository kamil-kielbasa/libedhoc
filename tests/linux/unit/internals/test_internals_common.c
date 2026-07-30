/**
 * \file    test_internals_common.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for common internal length and PRK helpers.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Internal headers: */
#include "internals_common.h"
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(internals_common);

TEST_SETUP(internals_common)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(internals_common)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_common, comp_cid_len_one_byte_int)
{
	size_t len = 0;

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5,
	};

	int ret = comp_cid_len(&cid, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(1, len);
}

TEST(internals_common, comp_cid_len_byte_string)
{
	size_t len = 0;

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = 3,
	};

	int ret = comp_cid_len(&cid, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(4, len);
}

TEST(internals_common, comp_cid_len_invalid_type)
{
	size_t len = 0;

	const struct edhoc_connection_id cid = {
		.encode_type = 99,
	};

	int ret = comp_cid_len(&cid, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_common, comp_cid_len_null_args)
{
	size_t len = 0;

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
	};

	int ret = comp_cid_len(NULL, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = comp_cid_len(&cid, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, comp_id_cred_len_kid_int)
{
	size_t len = 0;

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_KID,
		.key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER,
		.key_id.key_id_int = 5,
	};

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(4, len);
}

TEST(internals_common, comp_id_cred_len_kid_bstr)
{
	size_t len = 0;

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_KID,
		.key_id.encode_type = EDHOC_ENCODE_TYPE_STRING,
		.key_id.key_id_bstr.length = 1,
	};

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_common, comp_id_cred_len_x509_chain_single)
{
	uint8_t cert[100] = { 0 };
	size_t len = 0;

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_chain.certificate_count = 1,
		.x509_chain.certificate[0] = cert,
		.x509_chain.certificate_length[0] = sizeof(cert),
	};

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_common, comp_id_cred_len_x509_chain_multi)
{
	uint8_t cert0[50] = { 0 };
	uint8_t cert1[60] = { 0 };
	size_t len = 0;

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_chain.certificate_count = 2,
		.x509_chain.certificate[0] = cert0,
		.x509_chain.certificate_length[0] = sizeof(cert0),
		.x509_chain.certificate[1] = cert1,
		.x509_chain.certificate_length[1] = sizeof(cert1),
	};

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_common, comp_id_cred_len_x509_hash_int)
{
	uint8_t fingerprint[32] = { 0 };
	size_t len = 0;

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_X509_HASH,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_hash.encode_type = EDHOC_ENCODE_TYPE_INTEGER,
		.x509_hash.algorithm_int = -8,
		.x509_hash.certificate_fingerprint = fingerprint,
		.x509_hash.certificate_fingerprint_length = sizeof(fingerprint),
	};

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_common, comp_id_cred_len_x509_hash_bstr)
{
	uint8_t fingerprint[32] = { 0 };
	size_t len = 0;

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_X509_HASH,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_hash.encode_type = EDHOC_ENCODE_TYPE_STRING,
		.x509_hash.algorithm_bstr.length = 2,
		.x509_hash.algorithm_bstr.value[0] = 'S',
		.x509_hash.algorithm_bstr.value[1] = 'H',
		.x509_hash.certificate_fingerprint = fingerprint,
		.x509_hash.certificate_fingerprint_length = sizeof(fingerprint),
	};

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_common, comp_id_cred_len_kid_invalid_encode)
{
	size_t len = 0;

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_KID,
		.key_id.encode_type = 99,
	};

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_common, comp_id_cred_len_x509_hash_invalid_encode)
{
	size_t len = 0;

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_X509_HASH,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_hash.encode_type = 99,
	};

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_common, comp_id_cred_len_unsupported)
{
	size_t len = 0;

	const struct edhoc_auth_credentials cred = {
		.label = 99,
	};

	int ret = comp_id_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);
}

TEST(internals_common, comp_id_cred_len_null_args)
{
	size_t len = 0;

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_KID,
	};

	int ret = comp_id_cred_len(NULL, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = comp_id_cred_len(&cred, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
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

TEST(internals_common, comp_cred_len_kid)
{
	size_t len = 0;

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_KID,
		.key_id.credential_length = 100,
	};

	int ret = comp_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(100, len);
}

TEST(internals_common, comp_cred_len_x509_chain)
{
	uint8_t cert[200] = { 0 };
	size_t len = 0;

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_chain.certificate_count = 1,
		.x509_chain.certificate[0] = cert,
		.x509_chain.certificate_length[0] = sizeof(cert),
	};

	int ret = comp_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_common, comp_cred_len_x509_hash)
{
	size_t len = 0;

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_X509_HASH,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_hash.certificate_length = 150,
	};

	int ret = comp_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_common, comp_cred_len_unsupported)
{
	size_t len = 0;

	const struct edhoc_auth_credentials cred = {
		.label = 99,
	};

	int ret = comp_cred_len(&cred, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);
}

TEST(internals_common, comp_cred_len_null_args)
{
	size_t len = 0;

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_KID,
	};

	int ret = comp_cred_len(NULL, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = comp_cred_len(&cred, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, comp_ead_len_no_tokens)
{
	struct edhoc_context ctx = { 0 };
	size_t len = 0;

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ctx.ead.count = 0;

	ret = comp_ead_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(0, len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_ead_len_with_tokens)
{
	uint8_t val0[4] = { 0x01, 0x02, 0x03, 0x04 };
	uint8_t val1[2] = { 0xAA, 0xBB };
	struct edhoc_context ctx = { 0 };
	size_t len = 0;

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ctx.ead.count = 2;
	ctx.ead.token[0].label = 1;
	ctx.ead.token[0].value.value = val0;
	ctx.ead.token[0].value.length = sizeof(val0);
	ctx.ead.token[1].label = 2;
	ctx.ead.token[1].value.value = val1;
	ctx.ead.token[1].value.length = sizeof(val1);

	ret = comp_ead_len(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, validate_ead_composed_accepts)
{
	static const uint8_t val[3] = { 0x01, 0x02, 0x03 };
	const struct edhoc_ead_token tokens[] = {
		{ .label = 1,
		  .value = { .value = val, .length = sizeof(val) } },
		{ .label = 2, .value = { .value = NULL, .length = 0 } },
	};

	const int ret = edhoc_validate_ead_composed(tokens, ARRAY_SIZE(tokens));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, validate_ead_composed_no_tokens)
{
	const int ret = edhoc_validate_ead_composed(NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, validate_ead_composed_null_tokens)
{
	const int ret = edhoc_validate_ead_composed(NULL, 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, validate_ead_composed_value_without_buffer)
{
	const struct edhoc_ead_token tokens[] = {
		{ .label = 1, .value = { .value = NULL, .length = 4 } },
	};

	const int ret = edhoc_validate_ead_composed(tokens, ARRAY_SIZE(tokens));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_EAD_COMPOSE_FAILURE, ret);
}

TEST(internals_common, comp_ead_len_null_args)
{
	struct edhoc_context ctx = { 0 };
	size_t len = 0;

	int ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = comp_ead_len(NULL, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = comp_ead_len(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, kid_compact_enc_int_cbor)
{
	uint8_t buf[512] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_KID,
		.key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER,
		.key_id.key_id_int = 7,
		.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED,
	};

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

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_KID,
		.key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER,
		.key_id.key_id_int = 5,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
	};

	int ret = kid_compact_encoding(&cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(mac_ctx->id_cred_is_comp_enc);
}

TEST(internals_common, kid_compact_enc_bstr_cbor_one_byte)
{
	uint8_t buf[512] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_KID,
		.key_id.encode_type = EDHOC_ENCODE_TYPE_STRING,
		.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED,
		.key_id.key_id_bstr.length = 1,
		.key_id.key_id_bstr.value[0] = 0x05,
	};

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

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_KID,
		.key_id.encode_type = EDHOC_ENCODE_TYPE_STRING,
		.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED,
		.key_id.key_id_bstr.length = 2,
		.key_id.key_id_bstr.value[0] = 0x18,
		.key_id.key_id_bstr.value[1] = 0x64,
	};

	int ret = kid_compact_encoding(&cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(mac_ctx->id_cred_is_comp_enc);
	TEST_ASSERT_EQUAL(EDHOC_ENCODE_TYPE_STRING, mac_ctx->id_cred_enc_type);
	TEST_ASSERT_EQUAL(2, mac_ctx->id_cred_bstr_len);
}

TEST(internals_common, kid_compact_enc_bstr_non_cbor)
{
	uint8_t buf[512] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_KID,
		.key_id.encode_type = EDHOC_ENCODE_TYPE_STRING,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.key_id.key_id_bstr.length = 0,
	};

	int ret = kid_compact_encoding(&cred, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(mac_ctx->id_cred_is_comp_enc);
	TEST_ASSERT_EQUAL(EDHOC_ENCODE_TYPE_STRING, mac_ctx->id_cred_enc_type);
}

TEST(internals_common, kid_compact_enc_invalid_type)
{
	struct mac_context mac_ctx = { 0 };

	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_KID,
		.key_id.encode_type = 99,
		.key_id.key_id_int = 5,
	};

	int ret = kid_compact_encoding(&cred, &mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_common, comp_prk_2e_bad_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;

	int ret = comp_prk_2e(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_2e_null_args)
{
	int ret = comp_prk_2e(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, comp_prk_3e2m_method_0)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;

	const struct edhoc_auth_credentials auth_cred = {
		.label = EDHOC_COSE_HEADER_KID,
	};

	int ret = comp_prk_3e2m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, ctx.state.prk_state);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_3e2m_method_1)
{
	uint8_t prk_2e[32] = { 0 };
	uint8_t dh_priv[32] = { 0 };
	uint8_t pub_key[32] = { 0 };
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;

	for (size_t i = 0; i < 32; i++) {
		ctx.state.th.value[i] = (uint8_t)(i + 1);
		prk_2e[i] = (uint8_t)(i + 0x20);
		dh_priv[i] = (uint8_t)(i + 0x40);
		pub_key[i] = (uint8_t)(i + 0x80);
	}

	internals_inject_prk(&ctx, EDHOC_KEY_SLOT_PRK_2E, prk_2e,
			     sizeof(prk_2e));

	/* Responder G_RX = key_agreement(its static key, peer ephemeral G_X). */
	internals_make_ecdh_peer_pub(ctx.ephemeral.peer.value,
				     sizeof(ctx.ephemeral.peer.value),
				     &ctx.ephemeral.peer.length);

	struct edhoc_auth_credentials auth_cred = {
		.label = EDHOC_COSE_HEADER_KID,
	};
	internals_inject_ecdh_key(auth_cred.private_key_id, dh_priv,
				  sizeof(dh_priv));

	int ret = comp_prk_3e2m(&ctx, &auth_cred, pub_key, sizeof(pub_key));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, ctx.state.prk_state);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_3e2m_method_max)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.negotiation.selected_method = EDHOC_METHOD_MAX;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = 32;

	const struct edhoc_auth_credentials auth_cred = {
		.label = EDHOC_COSE_HEADER_KID,
	};

	int ret = comp_prk_3e2m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_3e2m_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.state.th.stage = EDHOC_TH_STATE_2;

	const struct edhoc_auth_credentials auth_cred = { 0 };

	int ret = comp_prk_3e2m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_3e2m_null_args)
{
	const struct edhoc_auth_credentials auth_cred = { 0 };

	int ret = comp_prk_3e2m(NULL, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, comp_prk_4e3m_method_0)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 32;

	const struct edhoc_auth_credentials auth_cred = {
		.label = EDHOC_COSE_HEADER_KID,
	};

	int ret = comp_prk_4e3m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, ctx.state.prk_state);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_4e3m_method_2)
{
	uint8_t prk_3e2m[32] = { 0 };
	uint8_t dh_priv[32] = { 0 };
	uint8_t pub_key[32] = { 0 };
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.negotiation.selected_method = EDHOC_METHOD_2;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 32;

	for (size_t i = 0; i < 32; i++) {
		ctx.state.th.value[i] = (uint8_t)(i + 1);
		prk_3e2m[i] = (uint8_t)(i + 0x20);
		dh_priv[i] = (uint8_t)(i + 0x40);
		pub_key[i] = (uint8_t)(i + 0x80);
	}

	internals_inject_prk(&ctx, EDHOC_KEY_SLOT_PRK_3E2M, prk_3e2m,
			     sizeof(prk_3e2m));

	/* Initiator G_IY = key_agreement(its static key, peer ephemeral G_Y). */
	internals_make_ecdh_peer_pub(ctx.ephemeral.peer.value,
				     sizeof(ctx.ephemeral.peer.value),
				     &ctx.ephemeral.peer.length);

	struct edhoc_auth_credentials auth_cred = {
		.label = EDHOC_COSE_HEADER_KID,
	};
	internals_inject_ecdh_key(auth_cred.private_key_id, dh_priv,
				  sizeof(dh_priv));

	int ret = comp_prk_4e3m(&ctx, &auth_cred, pub_key, sizeof(pub_key));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, ctx.state.prk_state);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_4e3m_method_max)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.negotiation.selected_method = EDHOC_METHOD_MAX;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 32;

	const struct edhoc_auth_credentials auth_cred = {
		.label = EDHOC_COSE_HEADER_KID,
	};

	int ret = comp_prk_4e3m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_4e3m_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;
	ctx.state.th.stage = EDHOC_TH_STATE_3;

	const struct edhoc_auth_credentials auth_cred = { 0 };

	int ret = comp_prk_4e3m(&ctx, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_prk_4e3m_null_args)
{
	const struct edhoc_auth_credentials auth_cred = { 0 };

	int ret = comp_prk_4e3m(NULL, &auth_cred, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, compute_prk_out_success)
{
	uint8_t prk[32] = { 0 };
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_4;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.state.th.length = 32;

	for (size_t i = 0; i < 32; i++) {
		ctx.state.th.value[i] = (uint8_t)(i + 1);
		prk[i] = (uint8_t)(i + 0x20);
	}

	internals_inject_prk(&ctx, EDHOC_KEY_SLOT_PRK_4E3M, prk, sizeof(prk));

	int ret = compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, ctx.state.prk_state);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, compute_prk_out_bad_th_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.state.th.length = 32;

	int ret = compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, compute_prk_out_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_4;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.state.th.length = 32;

	int ret = compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, compute_prk_out_null_args)
{
	int ret = compute_prk_out(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, compute_new_prk_out_success)
{
	uint8_t prk[32] = { 0 };
	uint8_t entropy[16] = { 0xBB };
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_4;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.state.th.length = 32;

	for (size_t i = 0; i < 32; i++) {
		ctx.state.th.value[i] = (uint8_t)(i + 1);
		prk[i] = (uint8_t)(i + 0x20);
	}

	internals_inject_prk(&ctx, EDHOC_KEY_SLOT_PRK_4E3M, prk, sizeof(prk));

	int ret = compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = compute_new_prk_out(&ctx, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, compute_new_prk_out_bad_state)
{
	uint8_t entropy[16] = { 0xAA };
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;

	int ret = compute_new_prk_out(&ctx, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, compute_new_prk_out_null_args)
{
	uint8_t entropy[16] = { 0 };

	int ret = compute_new_prk_out(NULL, entropy, sizeof(entropy));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, compute_prk_exporter_success)
{
	uint8_t prk[32] = { 0 };
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_4;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	ctx.state.th.length = 32;

	for (size_t i = 0; i < 32; i++) {
		ctx.state.th.value[i] = (uint8_t)(i + 1);
		prk[i] = (uint8_t)(i + 0x20);
	}

	internals_inject_prk(&ctx, EDHOC_KEY_SLOT_PRK_4E3M, prk, sizeof(prk));

	int ret = compute_prk_out(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = compute_prk_exporter(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(
		edhoc_key_slot_present(&ctx, EDHOC_KEY_SLOT_PRK_EXPORTER));

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, compute_prk_exporter_bad_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;

	int ret = compute_prk_exporter(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, compute_prk_exporter_null_args)
{
	int ret = compute_prk_exporter(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_common, comp_salt_3e2m_bad_th_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_1;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;
	ctx.state.th.length = 32;

	uint8_t salt[32] = { 0 };
	int ret = comp_salt_3e2m(&ctx, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_salt_3e2m_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.state.th.length = 32;

	uint8_t salt[32] = { 0 };
	int ret = comp_salt_3e2m(&ctx, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_salt_3e2m_null_args)
{
	uint8_t salt[32] = { 0 };

	int ret = comp_salt_3e2m(NULL, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/* comp_salt_4e3m ---------------------------------------------------------- */

TEST(internals_common, comp_salt_4e3m_bad_th_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	ctx.state.th.length = 32;

	uint8_t salt[32] = { 0 };
	int ret = comp_salt_4e3m(&ctx, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_salt_4e3m_bad_prk_state)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.prk_state = EDHOC_PRK_STATE_2E;
	ctx.state.th.length = 32;

	uint8_t salt[32] = { 0 };
	int ret = comp_salt_4e3m(&ctx, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_common, comp_salt_4e3m_null_args)
{
	uint8_t salt[32] = { 0 };

	int ret = comp_salt_4e3m(NULL, salt, sizeof(salt));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST_GROUP_RUNNER(internals_common)
{
	/* comp_cid_len */
	RUN_TEST_CASE(internals_common, comp_cid_len_one_byte_int);
	RUN_TEST_CASE(internals_common, comp_cid_len_byte_string);
	RUN_TEST_CASE(internals_common, comp_cid_len_invalid_type);
	RUN_TEST_CASE(internals_common, comp_cid_len_null_args);

	/* comp_id_cred_len */
	RUN_TEST_CASE(internals_common, comp_id_cred_len_kid_int);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_kid_bstr);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_x509_chain_single);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_x509_chain_multi);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_x509_hash_int);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_x509_hash_bstr);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_kid_invalid_encode);
	RUN_TEST_CASE(internals_common,
		      comp_id_cred_len_x509_hash_invalid_encode);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_unsupported);
	RUN_TEST_CASE(internals_common, comp_id_cred_len_null_args);

	/* comp_th_len */
	RUN_TEST_CASE(internals_common, comp_th_len_success);
	RUN_TEST_CASE(internals_common, comp_th_len_zero);

	/* comp_cred_len */
	RUN_TEST_CASE(internals_common, comp_cred_len_kid);
	RUN_TEST_CASE(internals_common, comp_cred_len_x509_chain);
	RUN_TEST_CASE(internals_common, comp_cred_len_x509_hash);
	RUN_TEST_CASE(internals_common, comp_cred_len_unsupported);
	RUN_TEST_CASE(internals_common, comp_cred_len_null_args);

	/* comp_ead_len */
	RUN_TEST_CASE(internals_common, comp_ead_len_no_tokens);
	RUN_TEST_CASE(internals_common, comp_ead_len_with_tokens);
	RUN_TEST_CASE(internals_common, validate_ead_composed_accepts);
	RUN_TEST_CASE(internals_common, validate_ead_composed_no_tokens);
	RUN_TEST_CASE(internals_common, validate_ead_composed_null_tokens);
	RUN_TEST_CASE(internals_common,
		      validate_ead_composed_value_without_buffer);
	RUN_TEST_CASE(internals_common, comp_ead_len_null_args);

	/* kid_compact_encoding */
	RUN_TEST_CASE(internals_common, kid_compact_enc_int_cbor);
	RUN_TEST_CASE(internals_common, kid_compact_enc_int_non_cbor);
	RUN_TEST_CASE(internals_common, kid_compact_enc_bstr_cbor_one_byte);
	RUN_TEST_CASE(internals_common, kid_compact_enc_bstr_cbor_multi_byte);
	RUN_TEST_CASE(internals_common, kid_compact_enc_bstr_non_cbor);
	RUN_TEST_CASE(internals_common, kid_compact_enc_invalid_type);

	/* comp_prk_2e */
	RUN_TEST_CASE(internals_common, comp_prk_2e_bad_state);
	RUN_TEST_CASE(internals_common, comp_prk_2e_null_args);

	/* comp_prk_3e2m */
	RUN_TEST_CASE(internals_common, comp_prk_3e2m_method_0);
	RUN_TEST_CASE(internals_common, comp_prk_3e2m_method_1);
	RUN_TEST_CASE(internals_common, comp_prk_3e2m_method_max);
	RUN_TEST_CASE(internals_common, comp_prk_3e2m_bad_prk_state);
	RUN_TEST_CASE(internals_common, comp_prk_3e2m_null_args);

	/* comp_prk_4e3m */
	RUN_TEST_CASE(internals_common, comp_prk_4e3m_method_0);
	RUN_TEST_CASE(internals_common, comp_prk_4e3m_method_2);
	RUN_TEST_CASE(internals_common, comp_prk_4e3m_method_max);
	RUN_TEST_CASE(internals_common, comp_prk_4e3m_bad_prk_state);
	RUN_TEST_CASE(internals_common, comp_prk_4e3m_null_args);

	/* compute_prk_out */
	RUN_TEST_CASE(internals_common, compute_prk_out_success);
	RUN_TEST_CASE(internals_common, compute_prk_out_bad_th_state);
	RUN_TEST_CASE(internals_common, compute_prk_out_bad_prk_state);
	RUN_TEST_CASE(internals_common, compute_prk_out_null_args);

	/* compute_new_prk_out */
	RUN_TEST_CASE(internals_common, compute_new_prk_out_success);
	RUN_TEST_CASE(internals_common, compute_new_prk_out_bad_state);
	RUN_TEST_CASE(internals_common, compute_new_prk_out_null_args);

	/* compute_prk_exporter */
	RUN_TEST_CASE(internals_common, compute_prk_exporter_success);
	RUN_TEST_CASE(internals_common, compute_prk_exporter_bad_state);
	RUN_TEST_CASE(internals_common, compute_prk_exporter_null_args);

	/* comp_salt_3e2m */
	RUN_TEST_CASE(internals_common, comp_salt_3e2m_bad_th_state);
	RUN_TEST_CASE(internals_common, comp_salt_3e2m_bad_prk_state);
	RUN_TEST_CASE(internals_common, comp_salt_3e2m_null_args);

	/* comp_salt_4e3m */
	RUN_TEST_CASE(internals_common, comp_salt_4e3m_bad_th_state);
	RUN_TEST_CASE(internals_common, comp_salt_4e3m_bad_prk_state);
	RUN_TEST_CASE(internals_common, comp_salt_4e3m_null_args);
}
