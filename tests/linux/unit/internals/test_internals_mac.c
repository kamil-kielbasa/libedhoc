/**
 * \file    test_internals_mac.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for MAC context and sign/MAC internals.
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
#include <string.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */

/** \brief SHA-256 transcript hash / MAC length in bytes. */
#define TH_LEN 32
/** \brief P-256 ephemeral public key (X-coordinate) length in bytes. */
#define PUB_KEY_LEN 32
/** \brief MAC length for static Diffie-Hellman authentication in bytes. */
#define MAC_LEN 8
/** \brief ES256 signature length in bytes. */
#define SIGN_LEN 64
/** \brief Scratch buffer size holding a struct mac_context. */
#define MAC_CTX_BUF_LEN 2048

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(internals_mac);

TEST_SETUP(internals_mac)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(internals_mac)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_mac, mac_ctx_len_x509_chain)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0xAA, TH_LEN);
	ctx.negotiation.connection_id.value[0] = 0x05;
	ctx.negotiation.connection_id.length = 1;

	const uint8_t dummy_cert[100] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_chain.count = 1,
		.x509_chain.certificate[0] = { .value = dummy_cert,
					       .length = sizeof(dummy_cert) },
		.credential = { .value = dummy_cert,
				.length = sizeof(dummy_cert) },
	};

	size_t mac_ctx_len = 0;
	int ret = edhoc_mac_context_length(&ctx, &material, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_len_kid)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0xAA, TH_LEN);

	const uint8_t kid[] = { 0x04 };
	const uint8_t dummy_cred[50] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
		.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED,
		.kid = { .value = kid, .length = ARRAY_SIZE(kid) },
		.credential = { .value = dummy_cred,
				.length = sizeof(dummy_cred) },
	};

	size_t mac_ctx_len = 0;
	int ret = edhoc_mac_context_length(&ctx, &material, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_len_with_ead)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0xAA, TH_LEN);
	ctx.negotiation.connection_id.value[0] = 0x05;
	ctx.negotiation.connection_id.length = 1;

	const uint8_t ead_val[4] = { 1, 2, 3, 4 };
	ctx.ead.count = 1;
	ctx.ead.token[0].label = 100;
	ctx.ead.token[0].value.value = ead_val;
	ctx.ead.token[0].value.length = ARRAY_SIZE(ead_val);

	const uint8_t dummy_cert[100] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_chain.count = 1,
		.x509_chain.certificate[0] = { .value = dummy_cert,
					       .length = sizeof(dummy_cert) },
		.credential = { .value = dummy_cert,
				.length = sizeof(dummy_cert) },
	};

	size_t mac_ctx_len = 0;
	int ret = edhoc_mac_context_length(&ctx, &material, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_len_initiator_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0xAA, TH_LEN);
	ctx.negotiation.peer_connection_id.value[0] = 0x05;
	ctx.negotiation.peer_connection_id.length = 1;

	const uint8_t dummy_cert[100] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_chain.count = 1,
		.x509_chain.certificate[0] = { .value = dummy_cert,
					       .length = sizeof(dummy_cert) },
		.credential = { .value = dummy_cert,
				.length = sizeof(dummy_cert) },
	};

	size_t mac_ctx_len = 0;
	int ret = edhoc_mac_context_length(&ctx, &material, &mac_ctx_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_len_null_args)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);

	const struct edhoc_credential_material_asymmetric material = { 0 };
	size_t len = 0;

	int ret = edhoc_mac_context_length(NULL, &material, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_mac_context_length(&ctx, NULL, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_mac_context_length(&ctx, &material, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_len_invalid_role)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = 99;
	ctx.state.message = EDHOC_MESSAGE_2;

	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
	};
	size_t len = 0;

	int ret = edhoc_mac_context_length(&ctx, &material, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_len_invalid_message)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_4;

	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
	};
	size_t len = 0;

	int ret = edhoc_mac_context_length(&ctx, &material, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_len_unsupported_cred)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = TH_LEN;
	ctx.negotiation.connection_id.value[0] = 0x05;
	ctx.negotiation.connection_id.length = 1;

	const struct edhoc_credential_material_asymmetric material = {
		.label = 99,
	};
	size_t len = 0;

	int ret = edhoc_mac_context_length(&ctx, &material, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_len_invalid_kid_encode)
{
	const struct edhoc_credential_selected cred = {
		.asymmetric.label = (enum edhoc_cose_header)99,
	};

	struct edhoc_credential_material_asymmetric material = { 0 };
	const int ret = edhoc_credential_asymmetric_material_from_selected(
		&cred, &material);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);
}

TEST(internals_mac, mac_ctx_len_th_zero)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = 0;

	const uint8_t fake_cert[] = { 0x30, 0x00 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_chain.count = 1,
		.x509_chain.certificate[0] = { .value = fake_cert,
					       .length = sizeof(fake_cert) },
		.credential = { .value = fake_cert,
				.length = sizeof(fake_cert) },
	};

	size_t len = 0;
	int ret = edhoc_mac_context_length(&ctx, &material, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_x509_chain)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0xAA, TH_LEN);
	ctx.negotiation.connection_id.value[0] = 0x05;
	ctx.negotiation.connection_id.length = 1;

	const uint8_t dummy_cert[100] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_chain.count = 1,
		.x509_chain.certificate[0] = { .value = dummy_cert,
					       .length = sizeof(dummy_cert) },
		.credential = { .value = dummy_cert,
				.length = sizeof(dummy_cert) },
	};

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->id_cred_len);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->th_len);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->cred_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_x509_hash_int)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0xAA, TH_LEN);
	ctx.negotiation.connection_id.value[0] = 0x05;
	ctx.negotiation.connection_id.length = 1;

	const uint8_t dummy_cert[100] = { 0 };
	const uint8_t dummy_fp[32] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_HASH,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_hash.algorithm = { .encode_type =
						 EDHOC_ENCODE_TYPE_INTEGER,
					 .integer = -16 },
		.x509_hash.fingerprint = { .value = dummy_fp,
					   .length = sizeof(dummy_fp) },
		.credential = { .value = dummy_cert,
				.length = sizeof(dummy_cert) },
	};

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->id_cred_len);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->th_len);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->cred_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_x509_hash_bstr)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0xAA, TH_LEN);
	ctx.negotiation.connection_id.value[0] = 0x05;
	ctx.negotiation.connection_id.length = 1;

	const uint8_t alg[] = { 'S', 'H', 'A', '-' };
	const uint8_t dummy_cert[100] = { 0 };
	const uint8_t dummy_fp[32] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_HASH,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_hash.algorithm = { .encode_type =
						 EDHOC_ENCODE_TYPE_STRING,
					 .string = { .value = alg,
						     .length = sizeof(alg) } },
		.x509_hash.fingerprint = { .value = dummy_fp,
					   .length = sizeof(dummy_fp) },
		.credential = { .value = dummy_cert,
				.length = sizeof(dummy_cert) },
	};

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->id_cred_len);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->th_len);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->cred_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_kid_int)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0xAA, TH_LEN);

	const uint8_t kid[] = { 0x04 };
	const uint8_t dummy_cred[50] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
		.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED,
		.kid = { .value = kid, .length = ARRAY_SIZE(kid) },
		.credential = { .value = dummy_cred,
				.length = sizeof(dummy_cred) },
	};

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->id_cred_len);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->th_len);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->cred_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_kid_bstr)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0xAA, TH_LEN);
	ctx.negotiation.connection_id.value[0] = 0x05;
	ctx.negotiation.connection_id.length = 1;

	const uint8_t dummy_cred[50] = { 0 };
	const uint8_t kid_bstr[2] = { 0x18, 0x64 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
		.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED,
		.kid = { .value = kid_bstr, .length = ARRAY_SIZE(kid_bstr) },
		.credential = { .value = dummy_cred,
				.length = sizeof(dummy_cred) },
	};

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->id_cred_len);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->th_len);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->cred_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_bstr_cid)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0xAA, TH_LEN);
	ctx.negotiation.connection_id.value[0] = 0x01;
	ctx.negotiation.connection_id.value[1] = 0x02;
	ctx.negotiation.connection_id.length = 2;

	const uint8_t dummy_cert[100] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_chain.count = 1,
		.x509_chain.certificate[0] = { .value = dummy_cert,
					       .length = sizeof(dummy_cert) },
		.credential = { .value = dummy_cert,
				.length = sizeof(dummy_cert) },
	};

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->id_cred_len);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->th_len);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->cred_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_with_ead)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0xAA, TH_LEN);
	ctx.negotiation.connection_id.value[0] = 0x05;
	ctx.negotiation.connection_id.length = 1;

	const uint8_t ead_val[4] = { 1, 2, 3, 4 };
	ctx.ead.count = 1;
	ctx.ead.token[0].label = 100;
	ctx.ead.token[0].value.value = ead_val;
	ctx.ead.token[0].value.length = ARRAY_SIZE(ead_val);

	const uint8_t dummy_cert[100] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_chain.count = 1,
		.x509_chain.certificate[0] = { .value = dummy_cert,
					       .length = sizeof(dummy_cert) },
		.credential = { .value = dummy_cert,
				.length = sizeof(dummy_cert) },
	};

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->id_cred_len);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->th_len);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->cred_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_initiator_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0xAA, TH_LEN);
	ctx.negotiation.peer_connection_id.value[0] = 0x05;
	ctx.negotiation.peer_connection_id.length = 1;

	const uint8_t dummy_cert[100] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_chain.count = 1,
		.x509_chain.certificate[0] = { .value = dummy_cert,
					       .length = sizeof(dummy_cert) },
		.credential = { .value = dummy_cert,
				.length = sizeof(dummy_cert) },
	};

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->id_cred_len);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->th_len);
	TEST_ASSERT_GREATER_THAN(0, mac_ctx->cred_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_null_args)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);

	const struct edhoc_credential_material_asymmetric material = { 0 };

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_mac_context_compose(NULL, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_mac_context_compose(&ctx, NULL, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_mac_context_compose(&ctx, &material, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_invalid_role)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = 99;
	ctx.state.message = EDHOC_MESSAGE_2;

	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
	};

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_invalid_message)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_4;

	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
	};

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_bad_th_state_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0xAA, TH_LEN);
	ctx.negotiation.connection_id.value[0] = 0x05;
	ctx.negotiation.connection_id.length = 1;

	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
	};

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_bad_th_state_msg3)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0xAA, TH_LEN);

	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
	};

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_unsupported_cred)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0xAA, TH_LEN);
	ctx.negotiation.connection_id.value[0] = 0x05;
	ctx.negotiation.connection_id.length = 1;

	const struct edhoc_credential_material_asymmetric material = {
		.label = 99,
	};

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	int ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_buffer_too_small)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0xAA, TH_LEN);
	ctx.negotiation.connection_id.value[0] = 0x05;
	ctx.negotiation.connection_id.length = 1;

	const uint8_t dummy_cert[100] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_chain.count = 1,
		.x509_chain.certificate[0] = { .value = dummy_cert,
					       .length = sizeof(dummy_cert) },
		.credential = { .value = dummy_cert,
				.length = sizeof(dummy_cert) },
	};

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = 4;

	int ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_ctx_x509_chain_zero_certs)
{
	const struct edhoc_credential_selected cred = {
		.asymmetric.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.asymmetric.x509_chain.count = 0,
	};

	struct edhoc_credential_material_asymmetric material = { 0 };
	const int ret = edhoc_credential_asymmetric_material_from_selected(
		&cred, &material);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_mac, mac_ctx_kid_bstr_short_form)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = TH_LEN;
	memset(ctx.state.th.value, 0x11, TH_LEN);

	const uint8_t fake_cred[] = { 0x30, 0x00 };
	const uint8_t kid[] = { 0x2b };
	const struct edhoc_credential_selected cred = {
		.asymmetric.label = EDHOC_COSE_HEADER_KID,
		.asymmetric.kid.identifier = { .value = kid,
					       .length = ARRAY_SIZE(kid) },
		.asymmetric.kid.credential = { .value = fake_cred,
					       .length =
						       ARRAY_SIZE(fake_cred) },
		.asymmetric.kid.format = EDHOC_CREDENTIAL_FORMAT_RAW,
	};

	struct edhoc_credential_material_asymmetric material = { 0 };
	int ret = edhoc_credential_asymmetric_material_from_selected(&cred,
								     &material);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* h'2b' is one byte and reads as a CBOR integer, so RFC 9528: 3.3.2
	 * shortens it to that byte. */
	TEST_ASSERT_EQUAL_size_t(1, mac_ctx->id_cred_comp_len);
	TEST_ASSERT_EQUAL_HEX8(0x2b, mac_ctx->id_cred_comp[0]);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_len_method0_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	size_t mac_len = 0;
	int ret = edhoc_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(TH_LEN, mac_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_len_method0_msg3)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	size_t mac_len = 0;
	int ret = edhoc_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(TH_LEN, mac_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_len_method1_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;

	size_t mac_len = 0;
	int ret = edhoc_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(MAC_LEN, mac_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_len_method1_msg3)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;

	size_t mac_len = 0;
	int ret = edhoc_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(TH_LEN, mac_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_len_method2_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_2;

	size_t mac_len = 0;
	int ret = edhoc_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(TH_LEN, mac_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_len_method2_msg3)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_2;

	size_t mac_len = 0;
	int ret = edhoc_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(MAC_LEN, mac_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_len_method3_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_3;

	size_t mac_len = 0;
	int ret = edhoc_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(MAC_LEN, mac_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_len_method3_msg3)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_3;

	size_t mac_len = 0;
	int ret = edhoc_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(MAC_LEN, mac_len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_len_null_args)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);

	size_t mac_len = 0;
	int ret = edhoc_mac_length(NULL, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_mac_length(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_len_invalid_role)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = 99;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	size_t mac_len = 0;
	int ret = edhoc_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_len_invalid_message)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_4;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	size_t mac_len = 0;
	int ret = edhoc_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_len_method_max_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = (enum edhoc_method)4;

	size_t mac_len = 0;
	int ret = edhoc_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, mac_len_method_max_msg3)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = (enum edhoc_method)4;

	size_t mac_len = 0;
	int ret = edhoc_mac_length(&ctx, &mac_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, sign_or_mac_len_method0_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	size_t len = 0;
	int ret = edhoc_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(SIGN_LEN, len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, sign_or_mac_len_method0_msg3)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	size_t len = 0;
	int ret = edhoc_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(SIGN_LEN, len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, sign_or_mac_len_method1_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;

	size_t len = 0;
	int ret = edhoc_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(MAC_LEN, len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, sign_or_mac_len_method1_msg3)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;

	size_t len = 0;
	int ret = edhoc_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(SIGN_LEN, len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, sign_or_mac_len_method2_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_2;

	size_t len = 0;
	int ret = edhoc_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(SIGN_LEN, len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, sign_or_mac_len_method2_msg3)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_2;

	size_t len = 0;
	int ret = edhoc_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(MAC_LEN, len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, sign_or_mac_len_method3_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_3;

	size_t len = 0;
	int ret = edhoc_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(MAC_LEN, len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, sign_or_mac_len_method3_msg3)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_3;

	size_t len = 0;
	int ret = edhoc_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(MAC_LEN, len);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, sign_or_mac_len_null_args)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);

	size_t len = 0;
	int ret = edhoc_sign_or_mac_length(NULL, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_sign_or_mac_length(&ctx, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, sign_or_mac_len_invalid_role)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = 99;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	size_t len = 0;
	int ret = edhoc_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, sign_or_mac_len_invalid_message)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_4;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	size_t len = 0;
	int ret = edhoc_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, sign_or_mac_len_method_max_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = (enum edhoc_method)4;

	size_t len = 0;
	int ret = edhoc_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, sign_or_mac_len_method_max_msg3)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = (enum edhoc_method)4;

	size_t len = 0;
	int ret = edhoc_sign_or_mac_length(&ctx, &len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, comp_mac_null_args)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[TH_LEN] = { 0 };

	int ret = edhoc_mac_compute(NULL, mac_ctx, mac, ARRAY_SIZE(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_mac_compute(&ctx, NULL, mac, ARRAY_SIZE(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_mac_compute(&ctx, mac_ctx, NULL, ARRAY_SIZE(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_mac_compute(&ctx, mac_ctx, mac, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, comp_mac_msg1)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_1;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[TH_LEN] = { 0 };

	int ret = edhoc_mac_compute(&ctx, mac_ctx, mac, ARRAY_SIZE(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
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

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[TH_LEN] = { 0 };

	int ret = edhoc_mac_compute(&ctx, mac_ctx, mac, ARRAY_SIZE(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
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

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[TH_LEN] = { 0 };

	int ret = edhoc_mac_compute(&ctx, mac_ctx, mac, ARRAY_SIZE(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
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

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	uint8_t mac[TH_LEN] = { 0 };

	int ret = edhoc_mac_compute(&ctx, mac_ctx, mac, ARRAY_SIZE(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, comp_sign_or_mac_method1_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;
	ctx.state.th.stage = EDHOC_TH_STATE_2;
	ctx.state.th.length = TH_LEN;
	ctx.state.prk_state = EDHOC_PRK_STATE_3E2M;
	memset(ctx.state.th.value, 0xAA, TH_LEN);
	ctx.negotiation.connection_id.value[0] = 0x05;
	ctx.negotiation.connection_id.length = 1;

	const uint8_t dummy_cert[100] = { 0 };
	const struct edhoc_credential_selected cred = {
		.asymmetric.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.asymmetric.x509_chain.count = 1,
		.asymmetric.x509_chain.certificate[0] = { .value = dummy_cert,
							  .length = ARRAY_SIZE(
								  dummy_cert) },
	};

	struct edhoc_credential_material_asymmetric material = { 0 };
	int ret = edhoc_credential_asymmetric_material_from_selected(&cred,
								     &material);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	const uint8_t mac[MAC_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t sign[SIGN_LEN] = { 0 };
	size_t sign_len = 0;

	ret = edhoc_sign_or_mac_compute(&ctx, key_id, mac_ctx, mac,
					ARRAY_SIZE(mac), sign, ARRAY_SIZE(sign),
					&sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(MAC_LEN, sign_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(mac, sign, MAC_LEN);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, comp_sign_or_mac_method2_msg3)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_2;
	ctx.state.th.stage = EDHOC_TH_STATE_3;
	ctx.state.th.length = TH_LEN;
	ctx.state.prk_state = EDHOC_PRK_STATE_4E3M;
	memset(ctx.state.th.value, 0xAA, TH_LEN);

	const uint8_t dummy_cred[50] = { 0 };
	const uint8_t kid[] = { 0x04 };
	const struct edhoc_credential_selected cred = {
		.asymmetric.label = EDHOC_COSE_HEADER_KID,
		.asymmetric.kid.identifier = { .value = kid,
					       .length = ARRAY_SIZE(kid) },
		.asymmetric.kid.credential = { .value = dummy_cred,
					       .length =
						       ARRAY_SIZE(dummy_cred) },
		.asymmetric.kid.format = EDHOC_CREDENTIAL_FORMAT_RAW,
	};

	struct edhoc_credential_material_asymmetric material = { 0 };
	int ret = edhoc_credential_asymmetric_material_from_selected(&cred,
								     &material);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	ret = edhoc_mac_context_compose(&ctx, &material, mac_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };
	const uint8_t mac[MAC_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t sign[SIGN_LEN] = { 0 };
	size_t sign_len = 0;

	ret = edhoc_sign_or_mac_compute(&ctx, key_id, mac_ctx, mac,
					ARRAY_SIZE(mac), sign, ARRAY_SIZE(sign),
					&sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(MAC_LEN, sign_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(mac, sign, MAC_LEN);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, comp_sign_or_mac_null_args)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	const uint8_t mac[MAC_LEN] = { 0 };
	uint8_t sign[SIGN_LEN] = { 0 };
	size_t sign_len = 0;

	int ret = edhoc_sign_or_mac_compute(NULL, key_id, mac_ctx, mac,
					    ARRAY_SIZE(mac), sign,
					    ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_sign_or_mac_compute(&ctx, NULL, mac_ctx, mac,
					ARRAY_SIZE(mac), sign, ARRAY_SIZE(sign),
					&sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_sign_or_mac_compute(&ctx, key_id, mac_ctx, mac,
					ARRAY_SIZE(mac), NULL, ARRAY_SIZE(sign),
					&sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_sign_or_mac_compute(&ctx, key_id, mac_ctx, mac, 0, sign,
					ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, comp_sign_or_mac_invalid_message)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_4;
	ctx.negotiation.selected_method = EDHOC_METHOD_0;

	const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	const uint8_t mac[MAC_LEN] = { 0 };
	uint8_t sign[SIGN_LEN] = { 0 };
	size_t sign_len = 0;

	int ret = edhoc_sign_or_mac_compute(&ctx, key_id, mac_ctx, mac,
					    ARRAY_SIZE(mac), sign,
					    ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, comp_sign_or_mac_method_max_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = (enum edhoc_method)4;

	const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	const uint8_t mac[MAC_LEN] = { 0 };
	uint8_t sign[SIGN_LEN] = { 0 };
	size_t sign_len = 0;

	int ret = edhoc_sign_or_mac_compute(&ctx, key_id, mac_ctx, mac,
					    ARRAY_SIZE(mac), sign,
					    ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, comp_sign_or_mac_method_max_msg3)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = (enum edhoc_method)4;

	const uint8_t key_id[CONFIG_LIBEDHOC_KEY_ID_LEN] = { 0 };

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	const uint8_t mac[MAC_LEN] = { 0 };
	uint8_t sign[SIGN_LEN] = { 0 };
	size_t sign_len = 0;

	int ret = edhoc_sign_or_mac_compute(&ctx, key_id, mac_ctx, mac,
					    ARRAY_SIZE(mac), sign,
					    ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, verify_sign_or_mac_method1_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	const uint8_t pub_key[PUB_KEY_LEN] = { 0 };
	const uint8_t mac[MAC_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	int ret = edhoc_sign_or_mac_verify(&ctx, mac_ctx, pub_key,
					   ARRAY_SIZE(pub_key), mac,
					   ARRAY_SIZE(mac), mac,
					   ARRAY_SIZE(mac));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, verify_sign_or_mac_method3_msg3)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_3;

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	const uint8_t pub_key[PUB_KEY_LEN] = { 0 };
	const uint8_t mac[MAC_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	int ret = edhoc_sign_or_mac_verify(&ctx, mac_ctx, pub_key,
					   ARRAY_SIZE(pub_key), mac,
					   ARRAY_SIZE(mac), mac,
					   ARRAY_SIZE(mac));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, verify_sign_or_mac_mismatch_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	const uint8_t pub_key[PUB_KEY_LEN] = { 0 };
	const uint8_t mac[MAC_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	const uint8_t wrong_mac[MAC_LEN] = { 9, 9, 9, 9, 9, 9, 9, 9 };

	int ret = edhoc_sign_or_mac_verify(&ctx, mac_ctx, pub_key,
					   ARRAY_SIZE(pub_key), wrong_mac,
					   ARRAY_SIZE(wrong_mac), mac,
					   ARRAY_SIZE(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_SIGN_OR_MAC_2, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, verify_sign_or_mac_mismatch_msg3)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = EDHOC_METHOD_2;

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	const uint8_t pub_key[PUB_KEY_LEN] = { 0 };
	const uint8_t mac[MAC_LEN] = { 0xAA, 0xBB, 0xCC, 0xDD,
				       0x11, 0x22, 0x33, 0x44 };
	const uint8_t fake_sign[MAC_LEN] = { 0 };

	int ret = edhoc_sign_or_mac_verify(&ctx, mac_ctx, pub_key,
					   ARRAY_SIZE(pub_key), fake_sign,
					   ARRAY_SIZE(fake_sign), mac,
					   ARRAY_SIZE(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_SIGN_OR_MAC_3, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, verify_sign_or_mac_null_mac)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	const uint8_t pub_key[PUB_KEY_LEN] = { 0 };
	const uint8_t sign[MAC_LEN] = { 0 };

	int ret = edhoc_sign_or_mac_verify(&ctx, mac_ctx, pub_key,
					   ARRAY_SIZE(pub_key), sign,
					   ARRAY_SIZE(sign), NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, verify_sign_or_mac_invalid_message)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_4;
	ctx.negotiation.selected_method = EDHOC_METHOD_1;

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	const uint8_t pub_key[PUB_KEY_LEN] = { 0 };
	const uint8_t mac[MAC_LEN] = { 0 };

	int ret = edhoc_sign_or_mac_verify(&ctx, mac_ctx, pub_key,
					   ARRAY_SIZE(pub_key), mac,
					   ARRAY_SIZE(mac), mac,
					   ARRAY_SIZE(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, verify_sign_or_mac_method_max_msg2)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.message = EDHOC_MESSAGE_2;
	ctx.negotiation.selected_method = (enum edhoc_method)4;

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	const uint8_t pub_key[PUB_KEY_LEN] = { 0 };
	const uint8_t mac[MAC_LEN] = { 0 };

	int ret = edhoc_sign_or_mac_verify(&ctx, mac_ctx, pub_key,
					   ARRAY_SIZE(pub_key), mac,
					   ARRAY_SIZE(mac), mac,
					   ARRAY_SIZE(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_mac, verify_sign_or_mac_method_max_msg3)
{
	struct edhoc_context ctx = { 0 };

	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.message = EDHOC_MESSAGE_3;
	ctx.negotiation.selected_method = (enum edhoc_method)4;

	_Alignas(struct mac_context) uint8_t buf[MAC_CTX_BUF_LEN] = { 0 };
	struct mac_context *mac_ctx = (struct mac_context *)buf;
	mac_ctx->buf_len = sizeof(buf) - sizeof(struct mac_context);

	const uint8_t pub_key[PUB_KEY_LEN] = { 0 };
	const uint8_t mac[MAC_LEN] = { 0 };

	int ret = edhoc_sign_or_mac_verify(&ctx, mac_ctx, pub_key,
					   ARRAY_SIZE(pub_key), mac,
					   ARRAY_SIZE(mac), mac,
					   ARRAY_SIZE(mac));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(internals_mac)
{
	/* edhoc_mac_context_length */
	RUN_TEST_CASE(internals_mac, mac_ctx_len_x509_chain);
	RUN_TEST_CASE(internals_mac, mac_ctx_len_kid);
	RUN_TEST_CASE(internals_mac, mac_ctx_len_with_ead);
	RUN_TEST_CASE(internals_mac, mac_ctx_len_initiator_msg2);
	RUN_TEST_CASE(internals_mac, mac_ctx_len_null_args);
	RUN_TEST_CASE(internals_mac, mac_ctx_len_invalid_role);
	RUN_TEST_CASE(internals_mac, mac_ctx_len_invalid_message);
	RUN_TEST_CASE(internals_mac, mac_ctx_len_unsupported_cred);
	RUN_TEST_CASE(internals_mac, mac_ctx_len_invalid_kid_encode);
	RUN_TEST_CASE(internals_mac, mac_ctx_len_th_zero);

	/* edhoc_mac_context_compose */
	RUN_TEST_CASE(internals_mac, mac_ctx_x509_chain);
	RUN_TEST_CASE(internals_mac, mac_ctx_x509_hash_int);
	RUN_TEST_CASE(internals_mac, mac_ctx_x509_hash_bstr);
	RUN_TEST_CASE(internals_mac, mac_ctx_kid_int);
	RUN_TEST_CASE(internals_mac, mac_ctx_kid_bstr);
	RUN_TEST_CASE(internals_mac, mac_ctx_bstr_cid);
	RUN_TEST_CASE(internals_mac, mac_ctx_with_ead);
	RUN_TEST_CASE(internals_mac, mac_ctx_initiator_msg2);
	RUN_TEST_CASE(internals_mac, mac_ctx_null_args);
	RUN_TEST_CASE(internals_mac, mac_ctx_invalid_role);
	RUN_TEST_CASE(internals_mac, mac_ctx_invalid_message);
	RUN_TEST_CASE(internals_mac, mac_ctx_bad_th_state_msg2);
	RUN_TEST_CASE(internals_mac, mac_ctx_bad_th_state_msg3);
	RUN_TEST_CASE(internals_mac, mac_ctx_unsupported_cred);
	RUN_TEST_CASE(internals_mac, mac_ctx_buffer_too_small);
	RUN_TEST_CASE(internals_mac, mac_ctx_x509_chain_zero_certs);
	RUN_TEST_CASE(internals_mac, mac_ctx_kid_bstr_short_form);

	/* edhoc_mac_length */
	RUN_TEST_CASE(internals_mac, mac_len_method0_msg2);
	RUN_TEST_CASE(internals_mac, mac_len_method0_msg3);
	RUN_TEST_CASE(internals_mac, mac_len_method1_msg2);
	RUN_TEST_CASE(internals_mac, mac_len_method1_msg3);
	RUN_TEST_CASE(internals_mac, mac_len_method2_msg2);
	RUN_TEST_CASE(internals_mac, mac_len_method2_msg3);
	RUN_TEST_CASE(internals_mac, mac_len_method3_msg2);
	RUN_TEST_CASE(internals_mac, mac_len_method3_msg3);
	RUN_TEST_CASE(internals_mac, mac_len_null_args);
	RUN_TEST_CASE(internals_mac, mac_len_invalid_role);
	RUN_TEST_CASE(internals_mac, mac_len_invalid_message);
	RUN_TEST_CASE(internals_mac, mac_len_method_max_msg2);
	RUN_TEST_CASE(internals_mac, mac_len_method_max_msg3);

	/* edhoc_sign_or_mac_length */
	RUN_TEST_CASE(internals_mac, sign_or_mac_len_method0_msg2);
	RUN_TEST_CASE(internals_mac, sign_or_mac_len_method0_msg3);
	RUN_TEST_CASE(internals_mac, sign_or_mac_len_method1_msg2);
	RUN_TEST_CASE(internals_mac, sign_or_mac_len_method1_msg3);
	RUN_TEST_CASE(internals_mac, sign_or_mac_len_method2_msg2);
	RUN_TEST_CASE(internals_mac, sign_or_mac_len_method2_msg3);
	RUN_TEST_CASE(internals_mac, sign_or_mac_len_method3_msg2);
	RUN_TEST_CASE(internals_mac, sign_or_mac_len_method3_msg3);
	RUN_TEST_CASE(internals_mac, sign_or_mac_len_null_args);
	RUN_TEST_CASE(internals_mac, sign_or_mac_len_invalid_role);
	RUN_TEST_CASE(internals_mac, sign_or_mac_len_invalid_message);
	RUN_TEST_CASE(internals_mac, sign_or_mac_len_method_max_msg2);
	RUN_TEST_CASE(internals_mac, sign_or_mac_len_method_max_msg3);

	/* edhoc_mac_compute */
	RUN_TEST_CASE(internals_mac, comp_mac_null_args);
	RUN_TEST_CASE(internals_mac, comp_mac_msg1);
	RUN_TEST_CASE(internals_mac, comp_mac_invalid_message);
	RUN_TEST_CASE(internals_mac, comp_mac_bad_prk_state_msg2);
	RUN_TEST_CASE(internals_mac, comp_mac_bad_prk_state_msg3);

	/* edhoc_sign_or_mac_compute */
	RUN_TEST_CASE(internals_mac, comp_sign_or_mac_method1_msg2);
	RUN_TEST_CASE(internals_mac, comp_sign_or_mac_method2_msg3);
	RUN_TEST_CASE(internals_mac, comp_sign_or_mac_null_args);
	RUN_TEST_CASE(internals_mac, comp_sign_or_mac_invalid_message);
	RUN_TEST_CASE(internals_mac, comp_sign_or_mac_method_max_msg2);
	RUN_TEST_CASE(internals_mac, comp_sign_or_mac_method_max_msg3);

	/* edhoc_sign_or_mac_verify */
	RUN_TEST_CASE(internals_mac, verify_sign_or_mac_method1_msg2);
	RUN_TEST_CASE(internals_mac, verify_sign_or_mac_method3_msg3);
	RUN_TEST_CASE(internals_mac, verify_sign_or_mac_mismatch_msg2);
	RUN_TEST_CASE(internals_mac, verify_sign_or_mac_mismatch_msg3);
	RUN_TEST_CASE(internals_mac, verify_sign_or_mac_null_mac);
	RUN_TEST_CASE(internals_mac, verify_sign_or_mac_invalid_message);
	RUN_TEST_CASE(internals_mac, verify_sign_or_mac_method_max_msg2);
	RUN_TEST_CASE(internals_mac, verify_sign_or_mac_method_max_msg3);
}
