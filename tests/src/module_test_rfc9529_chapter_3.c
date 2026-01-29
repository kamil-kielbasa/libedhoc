/**
 * \file    module_test_rfc9529_chapter_3.c
 * \author  Kamil Kielbasa
 * \brief   Module tests according to RFC 9529, chapter 3.
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Test vector header: */
#include "test_vector_rfc9529_chapter_3.h"

/* Cipher suite 2 header: */
#include "edhoc_cipher_suite_2.h"

/* Standard library headers: */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

/* EDHOC header: */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include <edhoc.h>

/* PSA crypto header: */
#include <psa/crypto.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Mocked EDHOC crypto function ECDH make key pair for initiator.
 */
static int edhoc_cipher_suite_2_make_key_pair_init(
	void *user_context, const void *key_id, uint8_t *private_key,
	size_t private_key_size, size_t *private_key_length,
	uint8_t *public_key, size_t public_key_size, size_t *public_key_length);

/**
 * \brief Mocked EDHOC crypto function ECDH make key pair for responder.
 */
static int edhoc_cipher_suite_2_make_key_pair_resp(
	void *user_context, const void *key_id, uint8_t *private_key,
	size_t private_key_size, size_t *private_key_length,
	uint8_t *public_key, size_t public_key_size, size_t *public_key_length);

/**
 * \brief Authentication credentials fetch callback for initiator.
 */
static int auth_cred_fetch_init(void *user_ctx,
				struct edhoc_auth_creds *auth_cred);

/**
 * \brief Authentication credentials fetch callback for initiator.
 * 
 * \note It will use already cborised credentials.
 */
static int auth_cred_fetch_init_any(void *user_ctx,
				    struct edhoc_auth_creds *auth_cred);

/**
 * \brief Authentication credentials fetch callback for responder.
 */
static int auth_cred_fetch_resp(void *user_ctx,
				struct edhoc_auth_creds *auth_cred);

/**
 * \brief Authentication credentials fetch callback for responder.
 * 
 * \note It will use already cborised credentials.
 */
static int auth_cred_fetch_resp_any(void *user_ctx,
				    struct edhoc_auth_creds *auth_cred);

/**
 * \brief Authentication credentials verify callback for initiator.
 */
static int auth_cred_verify_init(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred,
				 const uint8_t **pub_key_ref,
				 size_t *pub_key_len);

/**
 * \brief Authentication credentials verify callback for responder.
 */
static int auth_cred_verify_resp(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred,
				 const uint8_t **pub_key_ref,
				 size_t *pub_key_len);

/* Static variables and constants ------------------------------------------ */

static int ret = EDHOC_ERROR_GENERIC_ERROR;
static enum edhoc_error_code error_code_recv =
	EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;

static struct edhoc_context edhoc_initiator_context = { 0 };
static struct edhoc_context *init_ctx = &edhoc_initiator_context;

static struct edhoc_context edhoc_responder_context = { 0 };
static struct edhoc_context *resp_ctx = &edhoc_responder_context;

static const struct edhoc_cipher_suite edhoc_cipher_suites_init[] = {
	{
		.value = 6,
		.aead_key_length = 16,
		.aead_tag_length = 8,
		.aead_iv_length = 13,
		.hash_length = 32,
		.mac_length = 8,
		.ecc_key_length = 32,
		.ecc_sign_length = 64,
	},
	{
		.value = 2,
		.aead_key_length = 16,
		.aead_tag_length = 8,
		.aead_iv_length = 13,
		.hash_length = 32,
		.mac_length = 8,
		.ecc_key_length = 32,
		.ecc_sign_length = 64,
	},
};

static const struct edhoc_cipher_suite edhoc_cipher_suites_resp[] = {
	{
		.value = 2,
		.aead_key_length = 16,
		.aead_tag_length = 8,
		.aead_iv_length = 13,
		.hash_length = 32,
		.mac_length = 8,
		.ecc_key_length = 32,
		.ecc_sign_length = 64,
	},
};

static const struct edhoc_keys edhoc_keys = {
	.import_key = edhoc_cipher_suite_2_key_import,
	.destroy_key = edhoc_cipher_suite_2_key_destroy,
};

static const struct edhoc_crypto edhoc_crypto_mocked_init = {
	.make_key_pair = edhoc_cipher_suite_2_make_key_pair_init,
	.key_agreement = edhoc_cipher_suite_2_key_agreement,
	.signature = edhoc_cipher_suite_2_signature,
	.verify = edhoc_cipher_suite_2_verify,
	.extract = edhoc_cipher_suite_2_extract,
	.expand = edhoc_cipher_suite_2_expand,
	.encrypt = edhoc_cipher_suite_2_encrypt,
	.decrypt = edhoc_cipher_suite_2_decrypt,
	.hash = edhoc_cipher_suite_2_hash,
};

static const struct edhoc_crypto edhoc_crypto_mocked_resp = {
	.make_key_pair = edhoc_cipher_suite_2_make_key_pair_resp,
	.key_agreement = edhoc_cipher_suite_2_key_agreement,
	.signature = edhoc_cipher_suite_2_signature,
	.verify = edhoc_cipher_suite_2_verify,
	.extract = edhoc_cipher_suite_2_extract,
	.expand = edhoc_cipher_suite_2_expand,
	.encrypt = edhoc_cipher_suite_2_encrypt,
	.decrypt = edhoc_cipher_suite_2_decrypt,
	.hash = edhoc_cipher_suite_2_hash,
};

static const struct edhoc_crypto edhoc_crypto = {
	.make_key_pair = edhoc_cipher_suite_2_make_key_pair,
	.key_agreement = edhoc_cipher_suite_2_key_agreement,
	.signature = edhoc_cipher_suite_2_signature,
	.verify = edhoc_cipher_suite_2_verify,
	.extract = edhoc_cipher_suite_2_extract,
	.expand = edhoc_cipher_suite_2_expand,
	.encrypt = edhoc_cipher_suite_2_encrypt,
	.decrypt = edhoc_cipher_suite_2_decrypt,
	.hash = edhoc_cipher_suite_2_hash,
};

static const struct edhoc_credentials edhoc_auth_cred_mocked_init = {
	.fetch = auth_cred_fetch_init,
	.verify = auth_cred_verify_init,
};

static const struct edhoc_credentials edhoc_auth_cred_mocked_init_any = {
	.fetch = auth_cred_fetch_init_any,
	.verify = auth_cred_verify_init,
};

static const struct edhoc_credentials edhoc_auth_cred_mocked_resp = {
	.fetch = auth_cred_fetch_resp,
	.verify = auth_cred_verify_resp,
};

static const struct edhoc_credentials edhoc_auth_cred_mocked_resp_any = {
	.fetch = auth_cred_fetch_resp_any,
	.verify = auth_cred_verify_resp,
};

/* Static function definitions --------------------------------------------- */

static int
edhoc_cipher_suite_2_make_key_pair_init(void *user_ctx, const void *kid,
				  uint8_t *priv_key, size_t priv_key_size,
				  size_t *priv_key_len, uint8_t *pub_key,
				  size_t pub_key_size, size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == kid || NULL == priv_key || 0 == priv_key_size ||
	    NULL == priv_key_len || NULL == pub_key || 0 == pub_key_size ||
	    NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	*priv_key_len = ARRAY_SIZE(X);
	memcpy(priv_key, X, ARRAY_SIZE(X));

	*pub_key_len = ARRAY_SIZE(G_X);
	memcpy(pub_key, G_X, ARRAY_SIZE(G_X));

	return EDHOC_SUCCESS;
}

static int
edhoc_cipher_suite_2_make_key_pair_resp(void *user_ctx, const void *kid,
				  uint8_t *priv_key, size_t priv_key_size,
				  size_t *priv_key_len, uint8_t *pub_key,
				  size_t pub_key_size, size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == kid || NULL == priv_key || 0 == priv_key_size ||
	    NULL == priv_key_len || NULL == pub_key || 0 == pub_key_size ||
	    NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	*priv_key_len = ARRAY_SIZE(Y);
	memcpy(priv_key, Y, ARRAY_SIZE(Y));

	*pub_key_len = ARRAY_SIZE(G_X);
	memcpy(pub_key, G_Y, ARRAY_SIZE(G_Y));

	return EDHOC_SUCCESS;
}

static int auth_cred_fetch_init(void *user_ctx,
				struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	auth_cred->label = EDHOC_COSE_HEADER_KID;
	auth_cred->key_id.cred = CRED_I_cborised;
	auth_cred->key_id.cred_len = ARRAY_SIZE(CRED_I_cborised);
	auth_cred->key_id.cred_is_cbor = true;
	auth_cred->key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	memcpy(auth_cred->key_id.key_id_bstr, ID_CRED_I_raw_cborised,
	       ARRAY_SIZE(ID_CRED_I_raw_cborised));
	auth_cred->key_id.key_id_bstr_length =
		ARRAY_SIZE(ID_CRED_I_raw_cborised);

	const int res = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
						  SK_I, ARRAY_SIZE(SK_I),
						  auth_cred->priv_key_id);

	if (EDHOC_SUCCESS != res)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

static int auth_cred_fetch_init_any(void *user_ctx,
				    struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	auth_cred->label = EDHOC_COSE_ANY;
	auth_cred->any.id_cred = ID_CRED_I_cborised;
	auth_cred->any.id_cred_len = ARRAY_SIZE(ID_CRED_I_cborised);
	auth_cred->any.is_id_cred_comp_enc = true;
	auth_cred->any.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	auth_cred->any.id_cred_comp_enc = ID_CRED_I_raw_cborised;
	auth_cred->any.id_cred_comp_enc_length =
		ARRAY_SIZE(ID_CRED_I_raw_cborised);
	auth_cred->any.cred = CRED_I_cborised;
	auth_cred->any.cred_len = ARRAY_SIZE(CRED_I_cborised);

	const int res = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
						  SK_I, ARRAY_SIZE(SK_I),
						  auth_cred->priv_key_id);

	if (EDHOC_SUCCESS != res)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

static int auth_cred_fetch_resp(void *user_ctx,
				struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	auth_cred->label = EDHOC_COSE_HEADER_KID;
	auth_cred->key_id.cred = CRED_R_cborised;
	auth_cred->key_id.cred_len = ARRAY_SIZE(CRED_R_cborised);
	auth_cred->key_id.cred_is_cbor = true;
	auth_cred->key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	memcpy(auth_cred->key_id.key_id_bstr, ID_CRED_R_raw_cborised,
	       ARRAY_SIZE(ID_CRED_R_raw_cborised));
	auth_cred->key_id.key_id_bstr_length =
		ARRAY_SIZE(ID_CRED_R_raw_cborised);

	const int res = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
						  SK_R, ARRAY_SIZE(SK_R),
						  auth_cred->priv_key_id);

	if (EDHOC_SUCCESS != res)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

static int auth_cred_fetch_resp_any(void *user_ctx,
				    struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	auth_cred->label = EDHOC_COSE_ANY;
	auth_cred->any.id_cred = ID_CRED_R_cborised;
	auth_cred->any.id_cred_len = ARRAY_SIZE(ID_CRED_R_cborised);
	auth_cred->any.is_id_cred_comp_enc = true;
	auth_cred->any.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	auth_cred->any.id_cred_comp_enc = ID_CRED_R_raw_cborised;
	auth_cred->any.id_cred_comp_enc_length =
		ARRAY_SIZE(ID_CRED_R_raw_cborised);
	auth_cred->any.cred = CRED_R_cborised;
	auth_cred->any.cred_len = ARRAY_SIZE(CRED_R_cborised);

	const int res = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
						  SK_R, ARRAY_SIZE(SK_R),
						  auth_cred->priv_key_id);

	if (EDHOC_SUCCESS != res)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

static int auth_cred_verify_init(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred,
				 const uint8_t **pub_key_ref,
				 size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_COSE_HEADER_KID != auth_cred->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (EDHOC_ENCODE_TYPE_INTEGER != auth_cred->key_id.encode_type)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (ID_CRED_R_raw != auth_cred->key_id.key_id_int)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	auth_cred->key_id.key_id_bstr_length =
		ARRAY_SIZE(ID_CRED_R_raw_cborised);
	memcpy(auth_cred->key_id.key_id_bstr, ID_CRED_R_raw_cborised,
	       ARRAY_SIZE(ID_CRED_R_raw_cborised));

	auth_cred->key_id.cred = CRED_R_cborised;
	auth_cred->key_id.cred_len = ARRAY_SIZE(CRED_R_cborised);
	auth_cred->key_id.cred_is_cbor = true;

	*pub_key_ref = PK_R;
	*pub_key_len = ARRAY_SIZE(PK_R);

	return EDHOC_SUCCESS;
}

static int auth_cred_verify_resp(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred,
				 const uint8_t **pub_key_ref,
				 size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_COSE_HEADER_KID != auth_cred->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (EDHOC_ENCODE_TYPE_INTEGER != auth_cred->key_id.encode_type)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (ID_CRED_I_raw != auth_cred->key_id.key_id_int)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
	auth_cred->key_id.key_id_bstr_length =
		ARRAY_SIZE(ID_CRED_I_raw_cborised);
	memcpy(auth_cred->key_id.key_id_bstr, ID_CRED_I_raw_cborised,
	       ARRAY_SIZE(ID_CRED_I_raw_cborised));

	auth_cred->key_id.cred = CRED_I_cborised;
	auth_cred->key_id.cred_len = ARRAY_SIZE(CRED_I_cborised);
	auth_cred->key_id.cred_is_cbor = true;

	*pub_key_ref = PK_I;
	*pub_key_len = ARRAY_SIZE(PK_I);

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(rfc9529_chapter_3);

TEST_SETUP(rfc9529_chapter_3)
{
	ret = psa_crypto_init();
	TEST_ASSERT_EQUAL(PSA_SUCCESS, ret);

	const enum edhoc_method methods[] = { METHOD };

	const struct edhoc_connection_id init_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_I[0],
	};

	const struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_R[0],
	};

	ret = edhoc_context_init(init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(init_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(init_ctx, edhoc_cipher_suites_init,
				      ARRAY_SIZE(edhoc_cipher_suites_init));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(init_ctx, &init_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_keys(init_ctx, &edhoc_keys);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(init_ctx, &edhoc_crypto_mocked_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(init_ctx, &edhoc_auth_cred_mocked_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_init(resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(resp_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(resp_ctx, edhoc_cipher_suites_resp,
				      ARRAY_SIZE(edhoc_cipher_suites_resp));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(resp_ctx, &resp_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_keys(resp_ctx, &edhoc_keys);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(resp_ctx, &edhoc_crypto_mocked_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(resp_ctx, &edhoc_auth_cred_mocked_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_TEAR_DOWN(rfc9529_chapter_3)
{
	mbedtls_psa_crypto_free();

	ret = edhoc_context_deinit(init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(rfc9529_chapter_3, message_1_compose)
{
	size_t msg_1_len = 0;
	uint8_t msg_1[ARRAY_SIZE(message_1)] = { 0 };

	ret = edhoc_message_1_compose(init_ctx, msg_1, ARRAY_SIZE(msg_1),
				      &msg_1_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M2, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_1), msg_1_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(message_1, msg_1, msg_1_len);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, init_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(H_message_1), init_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(H_message_1, init_ctx->th,
				      init_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_INVALID, init_ctx->prk_state);
	TEST_ASSERT_EQUAL(0, init_ctx->prk_len);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(X), init_ctx->dh_priv_key_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(X, init_ctx->dh_priv_key,
				      init_ctx->dh_priv_key_len);
}

TEST(rfc9529_chapter_3, message_1_process)
{
	ret = edhoc_message_1_process(resp_ctx, message_1,
				      ARRAY_SIZE(message_1));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_RECEIVED_M1, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(H_message_1), resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(H_message_1, resp_ctx->th,
				      resp_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_INVALID, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(0, resp_ctx->prk_len);

	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
			  resp_ctx->peer_cid.encode_type);
	TEST_ASSERT_EQUAL((int8_t)C_I[0], resp_ctx->peer_cid.int_value);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_X), resp_ctx->dh_peer_pub_key_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(G_X, resp_ctx->dh_peer_pub_key,
				      resp_ctx->dh_peer_pub_key_len);
}

TEST(rfc9529_chapter_3, message_2_compose)
{
	/* Required injections. */
	resp_ctx->status = EDHOC_SM_RECEIVED_M1;
	resp_ctx->chosen_method = METHOD;

	resp_ctx->th_state = EDHOC_TH_STATE_1;
	resp_ctx->th_len = ARRAY_SIZE(H_message_1);
	memcpy(resp_ctx->th, H_message_1, sizeof(H_message_1));

	resp_ctx->dh_peer_pub_key_len = ARRAY_SIZE(G_X);
	memcpy(resp_ctx->dh_peer_pub_key, G_X, ARRAY_SIZE(G_X));

	resp_ctx->peer_cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	resp_ctx->peer_cid.int_value = (int8_t)C_I[0];

	size_t msg_2_len = 0;
	uint8_t msg_2[ARRAY_SIZE(message_2)] = { 0 };

	ret = edhoc_message_2_compose(resp_ctx, msg_2, ARRAY_SIZE(msg_2),
				      &msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M3, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_2), msg_2_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(msg_2, message_2, msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_3), resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(resp_ctx->th, TH_3, resp_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_3e2m), resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_3e2m, resp_ctx->prk,
				      resp_ctx->prk_len);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_XY), resp_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(G_XY, resp_ctx->dh_secret,
				      resp_ctx->dh_secret_len);
}

TEST(rfc9529_chapter_3, message_2_compose_any)
{
	/* Required injections. */
	ret = edhoc_bind_credentials(resp_ctx,
				     &edhoc_auth_cred_mocked_resp_any);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	resp_ctx->status = EDHOC_SM_RECEIVED_M1;
	resp_ctx->chosen_method = METHOD;

	resp_ctx->th_state = EDHOC_TH_STATE_1;
	resp_ctx->th_len = ARRAY_SIZE(H_message_1);
	memcpy(resp_ctx->th, H_message_1, sizeof(H_message_1));

	resp_ctx->dh_peer_pub_key_len = ARRAY_SIZE(G_X);
	memcpy(resp_ctx->dh_peer_pub_key, G_X, ARRAY_SIZE(G_X));

	resp_ctx->peer_cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	resp_ctx->peer_cid.int_value = (int8_t)C_I[0];

	size_t msg_2_len = 0;
	uint8_t msg_2[ARRAY_SIZE(message_2)] = { 0 };

	ret = edhoc_message_2_compose(resp_ctx, msg_2, ARRAY_SIZE(msg_2),
				      &msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M3, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_2), msg_2_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(msg_2, message_2, msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_3), resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(resp_ctx->th, TH_3, resp_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_3e2m), resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_3e2m, resp_ctx->prk,
				      resp_ctx->prk_len);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_XY), resp_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(G_XY, resp_ctx->dh_secret,
				      resp_ctx->dh_secret_len);
}

TEST(rfc9529_chapter_3, message_2_process)
{
	/* Required injections. */
	init_ctx->status = EDHOC_SM_WAIT_M2;
	init_ctx->chosen_method = METHOD;

	init_ctx->th_state = EDHOC_TH_STATE_1;
	init_ctx->th_len = ARRAY_SIZE(H_message_1);
	memcpy(init_ctx->th, H_message_1, ARRAY_SIZE(H_message_1));

	init_ctx->dh_priv_key_len = ARRAY_SIZE(X);
	memcpy(init_ctx->dh_priv_key, X, ARRAY_SIZE(X));

	ret = edhoc_message_2_process(init_ctx, message_2,
				      ARRAY_SIZE(message_2));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_VERIFIED_M2, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, init_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_3), init_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->th, TH_3, init_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, init_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_3e2m), init_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_3e2m, init_ctx->prk,
				      init_ctx->prk_len);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_XY), init_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->dh_secret, G_XY,
				      sizeof(init_ctx->dh_secret));

	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
			  init_ctx->peer_cid.encode_type);
	TEST_ASSERT_EQUAL((int8_t)C_R[0], init_ctx->peer_cid.int_value);
}

TEST(rfc9529_chapter_3, message_3_compose)
{
	/* Required injections. */
	init_ctx->status = EDHOC_SM_VERIFIED_M2;
	init_ctx->chosen_method = METHOD;

	init_ctx->th_state = EDHOC_TH_STATE_3;
	init_ctx->th_len = ARRAY_SIZE(TH_3);
	memcpy(init_ctx->th, TH_3, ARRAY_SIZE(TH_3));

	init_ctx->prk_state = EDHOC_PRK_STATE_3E2M;
	init_ctx->prk_len = ARRAY_SIZE(PRK_3e2m);
	memcpy(init_ctx->prk, PRK_3e2m, ARRAY_SIZE(PRK_3e2m));

	init_ctx->dh_peer_pub_key_len = ARRAY_SIZE(G_Y);
	memcpy(init_ctx->dh_peer_pub_key, G_Y, ARRAY_SIZE(G_Y));

	init_ctx->dh_secret_len = ARRAY_SIZE(G_XY);
	memcpy(init_ctx->dh_secret, G_XY, ARRAY_SIZE(G_XY));

	size_t msg_3_len = 0;
	uint8_t msg_3[ARRAY_SIZE(message_3)] = { 0 };

	ret = edhoc_message_3_compose(init_ctx, msg_3, ARRAY_SIZE(msg_3),
				      &msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, init_ctx->status);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_3), msg_3_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(message_3, msg_3, msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_4), init_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_4, init_ctx->th, init_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, init_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_4e3m), init_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_4e3m, init_ctx->prk,
				      init_ctx->prk_len);
}

TEST(rfc9529_chapter_3, message_3_compose_any)
{
	ret = edhoc_bind_credentials(init_ctx,
				     &edhoc_auth_cred_mocked_init_any);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Required injections. */
	init_ctx->status = EDHOC_SM_VERIFIED_M2;
	init_ctx->chosen_method = METHOD;

	init_ctx->th_state = EDHOC_TH_STATE_3;
	init_ctx->th_len = ARRAY_SIZE(TH_3);
	memcpy(init_ctx->th, TH_3, ARRAY_SIZE(TH_3));

	init_ctx->prk_state = EDHOC_PRK_STATE_3E2M;
	init_ctx->prk_len = ARRAY_SIZE(PRK_3e2m);
	memcpy(init_ctx->prk, PRK_3e2m, ARRAY_SIZE(PRK_3e2m));

	init_ctx->dh_peer_pub_key_len = ARRAY_SIZE(G_Y);
	memcpy(init_ctx->dh_peer_pub_key, G_Y, ARRAY_SIZE(G_Y));

	init_ctx->dh_secret_len = ARRAY_SIZE(G_XY);
	memcpy(init_ctx->dh_secret, G_XY, ARRAY_SIZE(G_XY));

	size_t msg_3_len = 0;
	uint8_t msg_3[ARRAY_SIZE(message_3)] = { 0 };

	ret = edhoc_message_3_compose(init_ctx, msg_3, ARRAY_SIZE(msg_3),
				      &msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, init_ctx->status);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_3), msg_3_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(message_3, msg_3, msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_4), init_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_4, init_ctx->th, init_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, init_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_4e3m), init_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_4e3m, init_ctx->prk,
				      init_ctx->prk_len);
}

TEST(rfc9529_chapter_3, message_3_process)
{
	/* Required injections. */
	resp_ctx->status = EDHOC_SM_WAIT_M3;
	resp_ctx->chosen_method = METHOD;

	resp_ctx->th_state = EDHOC_TH_STATE_3;
	resp_ctx->th_len = ARRAY_SIZE(TH_3);
	memcpy(resp_ctx->th, TH_3, ARRAY_SIZE(TH_3));

	resp_ctx->prk_state = EDHOC_PRK_STATE_3E2M;
	resp_ctx->prk_len = ARRAY_SIZE(PRK_3e2m);
	memcpy(resp_ctx->prk, PRK_3e2m, ARRAY_SIZE(PRK_3e2m));

	resp_ctx->dh_priv_key_len = ARRAY_SIZE(Y);
	memcpy(resp_ctx->dh_priv_key, Y, ARRAY_SIZE(Y));

	resp_ctx->dh_secret_len = ARRAY_SIZE(G_XY);
	memcpy(resp_ctx->dh_secret, G_XY, ARRAY_SIZE(G_XY));

	ret = edhoc_message_3_process(resp_ctx, message_3,
				      ARRAY_SIZE(message_3));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, resp_ctx->status);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_4), resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_4, resp_ctx->th, resp_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_4e3m), resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_4e3m, resp_ctx->prk,
				      resp_ctx->prk_len);
}

TEST(rfc9529_chapter_3, message_4_compose)
{
	/* Required injections. */
	resp_ctx->status = EDHOC_SM_COMPLETED;
	resp_ctx->is_oscore_export_allowed = true;

	resp_ctx->th_state = EDHOC_TH_STATE_4;
	resp_ctx->th_len = ARRAY_SIZE(TH_4);
	memcpy(resp_ctx->th, TH_4, ARRAY_SIZE(TH_4));

	resp_ctx->prk_state = EDHOC_PRK_STATE_4E3M;
	resp_ctx->prk_len = ARRAY_SIZE(PRK_4e3m);
	memcpy(resp_ctx->prk, PRK_4e3m, ARRAY_SIZE(PRK_4e3m));

	size_t msg_4_len = 0;
	uint8_t msg_4[ARRAY_SIZE(message_4) + 1] = { 0 };

	ret = edhoc_message_4_compose(resp_ctx, msg_4, ARRAY_SIZE(msg_4),
				      &msg_4_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->status);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_4), msg_4_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(message_4, msg_4, msg_4_len);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_4), resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_4, resp_ctx->th, resp_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_4e3m), resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_4e3m, resp_ctx->prk,
				      resp_ctx->prk_len);
}

TEST(rfc9529_chapter_3, message_4_process)
{
	/* Required injections. */
	init_ctx->status = EDHOC_SM_COMPLETED;
	init_ctx->is_oscore_export_allowed = true;

	init_ctx->th_state = EDHOC_TH_STATE_4;
	init_ctx->th_len = ARRAY_SIZE(TH_4);
	memcpy(init_ctx->th, TH_4, ARRAY_SIZE(TH_4));

	init_ctx->prk_state = EDHOC_PRK_STATE_4E3M;
	init_ctx->prk_len = ARRAY_SIZE(PRK_4e3m);
	memcpy(init_ctx->prk, PRK_4e3m, ARRAY_SIZE(PRK_4e3m));

	ret = edhoc_message_4_process(init_ctx, message_4,
				      ARRAY_SIZE(message_4));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->status);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_4), init_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_4, init_ctx->th, init_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, init_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_4e3m), init_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_4e3m, init_ctx->prk,
				      init_ctx->prk_len);
}

TEST(rfc9529_chapter_3, handshake)
{
	uint8_t buffer[200] = { 0 };

	memset(buffer, 0, sizeof(buffer));
	size_t msg_1_len = 0;
	uint8_t *msg_1 = buffer;

	/* EDHOC message 1 compose. */
	ret = edhoc_message_1_compose(init_ctx, msg_1, ARRAY_SIZE(buffer),
				      &msg_1_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M2, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_1), msg_1_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(message_1, msg_1, msg_1_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_INVALID, init_ctx->prk_state);
	TEST_ASSERT_EQUAL(0, init_ctx->prk_len);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, init_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(H_message_1), init_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(H_message_1, init_ctx->th,
				      init_ctx->th_len);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(X), init_ctx->dh_priv_key_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(X, init_ctx->dh_priv_key,
				      init_ctx->dh_priv_key_len);

	/* EDHOC message 1 process. */
	ret = edhoc_message_1_process(resp_ctx, msg_1, msg_1_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_RECEIVED_M1, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(H_message_1), resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(H_message_1, resp_ctx->th,
				      resp_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_INVALID, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(0, resp_ctx->prk_len);

	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
			  resp_ctx->peer_cid.encode_type);
	TEST_ASSERT_EQUAL((int8_t)C_I[0], resp_ctx->peer_cid.int_value);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_X), resp_ctx->dh_peer_pub_key_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(G_X, resp_ctx->dh_peer_pub_key,
				      resp_ctx->dh_peer_pub_key_len);

	memset(buffer, 0, sizeof(buffer));
	size_t msg_2_len = 0;
	uint8_t *msg_2 = buffer;

	/* EDHOC message 2 compose. */
	ret = edhoc_message_2_compose(resp_ctx, msg_2, ARRAY_SIZE(buffer),
				      &msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M3, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_2), msg_2_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(message_2, msg_2, msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_3), resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_3, resp_ctx->th, resp_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_3e2m), resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_3e2m, resp_ctx->prk,
				      resp_ctx->prk_len);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_XY), resp_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(G_XY, resp_ctx->dh_secret,
				      resp_ctx->dh_secret_len);

	/* EDHOC message 2 process. */
	ret = edhoc_message_2_process(init_ctx, msg_2, msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_VERIFIED_M2, init_ctx->status);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, init_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_3), init_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_3, init_ctx->th, init_ctx->th_len);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, init_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_3e2m), init_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_3e2m, init_ctx->prk,
				      init_ctx->prk_len);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_XY), init_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(G_XY, init_ctx->dh_secret,
				      init_ctx->dh_secret_len);

	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
			  init_ctx->peer_cid.encode_type);
	TEST_ASSERT_EQUAL((int8_t)C_R[0], init_ctx->peer_cid.int_value);

	memset(buffer, 0, sizeof(buffer));
	size_t msg_3_len = 0;
	uint8_t *msg_3 = buffer;

	/* EDHOC message 3 compose. */
	ret = edhoc_message_3_compose(init_ctx, msg_3, ARRAY_SIZE(buffer),
				      &msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, init_ctx->status);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_3), msg_3_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(message_3, msg_3, msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_4), init_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_4, init_ctx->th, init_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, init_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_4e3m), init_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_4e3m, init_ctx->prk,
				      init_ctx->prk_len);

	/* EDHOC message 3 process. */
	ret = edhoc_message_3_process(resp_ctx, msg_3, msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, resp_ctx->status);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_4), resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_4, resp_ctx->th, resp_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_4e3m), resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_4e3m, resp_ctx->prk,
				      resp_ctx->prk_len);

	memset(buffer, 0, sizeof(buffer));
	size_t msg_4_len = 0;
	uint8_t *msg_4 = buffer;

	/* EDHOC message 4 compose. */
	ret = edhoc_message_4_compose(resp_ctx, msg_4, ARRAY_SIZE(buffer),
				      &msg_4_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->status);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(message_4), msg_4_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(message_4, msg_4, msg_4_len);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_4), resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_4, resp_ctx->th, resp_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_4e3m), resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_4e3m, resp_ctx->prk,
				      resp_ctx->prk_len);

	/* EDHOC message 4 process. */
	ret = edhoc_message_4_process(init_ctx, msg_4, msg_4_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->status);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(TH_4), init_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(TH_4, init_ctx->th, init_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, init_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_4e3m), init_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_4e3m, init_ctx->prk,
				      init_ctx->prk_len);

	/* Derive OSCORE master secret and master salt. */
	uint8_t init_master_secret[ARRAY_SIZE(OSCORE_Master_Secret)] = { 0 };
	uint8_t init_master_salt[ARRAY_SIZE(OSCORE_Master_Salt)] = { 0 };
	size_t init_sender_id_len = 0;
	uint8_t init_sender_id[ARRAY_SIZE(OSCORE_C_R)] = { 0 };
	size_t init_recipient_id_len = 0;
	uint8_t init_recipient_id[ARRAY_SIZE(OSCORE_C_I)] = { 0 };

	ret = edhoc_export_oscore_session(
		init_ctx, init_master_secret, ARRAY_SIZE(init_master_secret),
		init_master_salt, ARRAY_SIZE(init_master_salt), init_sender_id,
		ARRAY_SIZE(init_sender_id), &init_sender_id_len,
		init_recipient_id, ARRAY_SIZE(init_recipient_id),
		&init_recipient_id_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, init_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_out), init_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_out, init_ctx->prk,
				      init_ctx->prk_len);

	/* Derive OSCORE master secret and master salt. */
	uint8_t resp_master_secret[ARRAY_SIZE(OSCORE_Master_Secret)] = { 0 };
	uint8_t resp_master_salt[ARRAY_SIZE(OSCORE_Master_Salt)] = { 0 };
	size_t resp_sender_id_len = 0;
	uint8_t resp_sender_id[ARRAY_SIZE(OSCORE_C_I)] = { 0 };
	size_t resp_recipient_id_len = 0;
	uint8_t resp_recipient_id[ARRAY_SIZE(OSCORE_C_R)] = { 0 };

	ret = edhoc_export_oscore_session(
		resp_ctx, resp_master_secret, ARRAY_SIZE(resp_master_secret),
		resp_master_salt, ARRAY_SIZE(resp_master_salt), resp_sender_id,
		ARRAY_SIZE(resp_sender_id), &resp_sender_id_len,
		resp_recipient_id, ARRAY_SIZE(resp_recipient_id),
		&resp_recipient_id_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_out), resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_out, resp_ctx->prk,
				      resp_ctx->prk_len);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_master_secret, resp_master_secret,
				      sizeof(resp_master_secret));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_Master_Secret, init_master_secret,
				      sizeof(init_master_secret));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_Master_Secret, resp_master_secret,
				      sizeof(resp_master_secret));

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_master_salt, resp_master_salt,
				      sizeof(resp_master_salt));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_Master_Salt, init_master_salt,
				      sizeof(init_master_salt));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_Master_Salt, resp_master_salt,
				      sizeof(resp_master_salt));

	TEST_ASSERT_EQUAL(ARRAY_SIZE(OSCORE_C_I), init_recipient_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_C_I, init_recipient_id,
				      init_recipient_id_len);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(OSCORE_C_I), resp_sender_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_C_I, resp_sender_id,
				      resp_sender_id_len);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(OSCORE_C_R), init_sender_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_C_R, init_sender_id,
				      init_sender_id_len);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(OSCORE_C_R), resp_recipient_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_C_R, resp_recipient_id,
				      resp_recipient_id_len);

	TEST_ASSERT_EQUAL(init_sender_id_len, resp_recipient_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_sender_id, resp_recipient_id,
				      init_sender_id_len);
	TEST_ASSERT_EQUAL(init_recipient_id_len, resp_sender_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_recipient_id, resp_sender_id,
				      resp_sender_id_len);

	/* EDHOC key update method. */
	ret = edhoc_export_key_update(init_ctx, keyUpdate_context,
				      ARRAY_SIZE(keyUpdate_context));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->status);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, init_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(keyUpdate_PRK_out), init_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(keyUpdate_PRK_out, init_ctx->prk,
				      init_ctx->prk_len);

	/* EDHOC key update method. */
	ret = edhoc_export_key_update(resp_ctx, keyUpdate_context,
				      ARRAY_SIZE(keyUpdate_context));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->status);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(keyUpdate_PRK_out), resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(keyUpdate_PRK_out, resp_ctx->prk,
				      resp_ctx->prk_len);

	/* Derive OSCORE master secret and master salt. */
	memset(init_master_secret, 0, sizeof(init_master_secret));
	memset(init_master_salt, 0, sizeof(init_master_salt));
	init_sender_id_len = 0;
	memset(init_sender_id, 0, sizeof(init_sender_id));
	init_recipient_id_len = 0;
	memset(init_recipient_id, 0, sizeof(init_recipient_id));

	ret = edhoc_export_oscore_session(
		init_ctx, init_master_secret, ARRAY_SIZE(init_master_secret),
		init_master_salt, ARRAY_SIZE(init_master_salt), init_sender_id,
		ARRAY_SIZE(init_sender_id), &init_sender_id_len,
		init_recipient_id, ARRAY_SIZE(init_recipient_id),
		&init_recipient_id_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);

	/* Derive OSCORE master secret and master salt. */
	memset(resp_master_secret, 0, sizeof(resp_master_secret));
	memset(resp_master_salt, 0, sizeof(resp_master_salt));
	resp_sender_id_len = 0;
	memset(resp_sender_id, 0, sizeof(resp_sender_id));
	resp_recipient_id_len = 0;
	memset(resp_recipient_id, 0, sizeof(resp_recipient_id));

	ret = edhoc_export_oscore_session(
		resp_ctx, resp_master_secret, ARRAY_SIZE(resp_master_secret),
		resp_master_salt, ARRAY_SIZE(resp_master_salt), resp_sender_id,
		ARRAY_SIZE(resp_sender_id), &resp_sender_id_len,
		resp_recipient_id, ARRAY_SIZE(resp_recipient_id),
		&resp_recipient_id_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_master_secret, resp_master_secret,
				      sizeof(resp_master_secret));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(keyUpdate_OSCORE_Master_Secret,
				      init_master_secret,
				      sizeof(init_master_secret));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(keyUpdate_OSCORE_Master_Secret,
				      resp_master_secret,
				      sizeof(resp_master_secret));

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_master_salt, resp_master_salt,
				      sizeof(resp_master_salt));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(keyUpdate_OSCORE_Master_Salt,
				      init_master_salt,
				      sizeof(init_master_salt));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(keyUpdate_OSCORE_Master_Salt,
				      resp_master_salt,
				      sizeof(resp_master_salt));

	TEST_ASSERT_EQUAL(ARRAY_SIZE(OSCORE_C_I), init_recipient_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_C_I, init_recipient_id,
				      init_recipient_id_len);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(OSCORE_C_I), resp_sender_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_C_I, resp_sender_id,
				      resp_sender_id_len);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(OSCORE_C_R), init_sender_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_C_R, init_sender_id,
				      init_sender_id_len);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(OSCORE_C_R), resp_recipient_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_C_R, resp_recipient_id,
				      resp_recipient_id_len);

	TEST_ASSERT_EQUAL(init_sender_id_len, resp_recipient_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_sender_id, resp_recipient_id,
				      init_sender_id_len);
	TEST_ASSERT_EQUAL(init_recipient_id_len, resp_sender_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_recipient_id, resp_sender_id,
				      resp_sender_id_len);
}

TEST(rfc9529_chapter_3, handshake_real_crypto)
{
	uint8_t buffer[200] = { 0 };

	memset(buffer, 0, sizeof(buffer));
	size_t msg_1_len = 0;
	uint8_t *msg_1 = buffer;

	/* EDHOC message 1 compose. */
	ret = edhoc_message_1_compose(init_ctx, msg_1, ARRAY_SIZE(buffer),
				      &msg_1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M2, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_INVALID, init_ctx->prk_state);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, init_ctx->th_state);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	/* EDHOC message 1 process. */
	ret = edhoc_message_1_process(resp_ctx, msg_1, msg_1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_RECEIVED_M1, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_INVALID, resp_ctx->prk_state);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
			  resp_ctx->peer_cid.encode_type);
	TEST_ASSERT_EQUAL((int8_t)C_I[0], resp_ctx->peer_cid.int_value);

	memset(buffer, 0, sizeof(buffer));
	size_t msg_2_len = 0;
	uint8_t *msg_2 = buffer;

	/* EDHOC message 2 compose. */
	ret = edhoc_message_2_compose(resp_ctx, msg_2, ARRAY_SIZE(buffer),
				      &msg_2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M3, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, resp_ctx->prk_state);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	/* EDHOC message 2 process. */
	ret = edhoc_message_2_process(init_ctx, msg_2, msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_VERIFIED_M2, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, init_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, init_ctx->prk_state);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
			  init_ctx->peer_cid.encode_type);
	TEST_ASSERT_EQUAL((int8_t)C_R[0], init_ctx->peer_cid.int_value);

	TEST_ASSERT_EQUAL(edhoc_cipher_suites_init[1].ecc_key_length,
			  init_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL(edhoc_cipher_suites_resp[0].ecc_key_length,
			  resp_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL(init_ctx->dh_secret_len, resp_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(
		init_ctx->dh_secret, resp_ctx->dh_secret,
		edhoc_cipher_suites_resp[0].ecc_key_length);

	memset(buffer, 0, sizeof(buffer));
	size_t msg_3_len = 0;
	uint8_t *msg_3 = buffer;

	/* EDHOC message 3 compose. */
	ret = edhoc_message_3_compose(init_ctx, msg_3, ARRAY_SIZE(buffer),
				      &msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, init_ctx->status);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, init_ctx->prk_state);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	/* EDHOC message 3 process. */
	ret = edhoc_message_3_process(resp_ctx, msg_3, msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, resp_ctx->status);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->prk_state);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	memset(buffer, 0, sizeof(buffer));
	size_t msg_4_len = 0;
	uint8_t *msg_4 = buffer;

	/* EDHOC message 4 compose. */
	ret = edhoc_message_4_compose(resp_ctx, msg_4, ARRAY_SIZE(buffer),
				      &msg_4_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->status);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->prk_state);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	/* EDHOC message 4 process. */
	ret = edhoc_message_4_process(init_ctx, msg_4, msg_4_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->status);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, init_ctx->prk_state);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	/* Derive OSCORE master secret and master salt. */
	uint8_t init_master_secret[ARRAY_SIZE(OSCORE_Master_Secret)] = { 0 };
	uint8_t init_master_salt[ARRAY_SIZE(OSCORE_Master_Salt)] = { 0 };
	size_t init_sender_id_len = 0;
	uint8_t init_sender_id[ARRAY_SIZE(OSCORE_C_R)] = { 0 };
	size_t init_recipient_id_len = 0;
	uint8_t init_recipient_id[ARRAY_SIZE(OSCORE_C_I)] = { 0 };

	ret = edhoc_export_oscore_session(
		init_ctx, init_master_secret, ARRAY_SIZE(init_master_secret),
		init_master_salt, ARRAY_SIZE(init_master_salt), init_sender_id,
		ARRAY_SIZE(init_sender_id), &init_sender_id_len,
		init_recipient_id, ARRAY_SIZE(init_recipient_id),
		&init_recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, init_ctx->prk_state);

	/* Derive OSCORE master secret and master salt. */
	uint8_t resp_master_secret[ARRAY_SIZE(OSCORE_Master_Secret)] = { 0 };
	uint8_t resp_master_salt[ARRAY_SIZE(OSCORE_Master_Salt)] = { 0 };
	size_t resp_sender_id_len = 0;
	uint8_t resp_sender_id[ARRAY_SIZE(OSCORE_C_I)] = { 0 };
	size_t resp_recipient_id_len = 0;
	uint8_t resp_recipient_id[ARRAY_SIZE(OSCORE_C_R)] = { 0 };

	ret = edhoc_export_oscore_session(
		resp_ctx, resp_master_secret, ARRAY_SIZE(resp_master_secret),
		resp_master_salt, ARRAY_SIZE(resp_master_salt), resp_sender_id,
		ARRAY_SIZE(resp_sender_id), &resp_sender_id_len,
		resp_recipient_id, ARRAY_SIZE(resp_recipient_id),
		&resp_recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, resp_ctx->prk_state);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_master_secret, resp_master_secret,
				      sizeof(resp_master_secret));

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_master_salt, resp_master_salt,
				      sizeof(resp_master_salt));

	TEST_ASSERT_EQUAL(init_sender_id_len, resp_recipient_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_sender_id, resp_recipient_id,
				      init_sender_id_len);
	TEST_ASSERT_EQUAL(init_recipient_id_len, resp_sender_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_recipient_id, resp_sender_id,
				      resp_sender_id_len);

	/* EDHOC key update method. */
	ret = edhoc_export_key_update(init_ctx, keyUpdate_context,
				      ARRAY_SIZE(keyUpdate_context));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->status);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);

	/* EDHOC key update method. */
	ret = edhoc_export_key_update(resp_ctx, keyUpdate_context,
				      ARRAY_SIZE(keyUpdate_context));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->status);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);

	TEST_ASSERT_EQUAL(init_ctx->prk_state, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, init_ctx->prk_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, resp_ctx->prk_state);

	TEST_ASSERT_EQUAL(init_ctx->prk_len, resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->prk, resp_ctx->prk,
				      resp_ctx->prk_len);

	/* Derive OSCORE master secret and master salt. */
	memset(init_master_secret, 0, sizeof(init_master_secret));
	memset(init_master_salt, 0, sizeof(init_master_salt));
	init_sender_id_len = 0;
	memset(init_sender_id, 0, sizeof(init_sender_id));
	init_recipient_id_len = 0;
	memset(init_recipient_id, 0, sizeof(init_recipient_id));

	ret = edhoc_export_oscore_session(
		init_ctx, init_master_secret, ARRAY_SIZE(init_master_secret),
		init_master_salt, ARRAY_SIZE(init_master_salt), init_sender_id,
		ARRAY_SIZE(init_sender_id), &init_sender_id_len,
		init_recipient_id, ARRAY_SIZE(init_recipient_id),
		&init_recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, init_ctx->prk_state);

	/* Derive OSCORE master secret and master salt. */
	memset(resp_master_secret, 0, sizeof(resp_master_secret));
	memset(resp_master_salt, 0, sizeof(resp_master_salt));
	resp_sender_id_len = 0;
	memset(resp_sender_id, 0, sizeof(resp_sender_id));
	resp_recipient_id_len = 0;
	memset(resp_recipient_id, 0, sizeof(resp_recipient_id));

	ret = edhoc_export_oscore_session(
		resp_ctx, resp_master_secret, ARRAY_SIZE(resp_master_secret),
		resp_master_salt, ARRAY_SIZE(resp_master_salt), resp_sender_id,
		ARRAY_SIZE(resp_sender_id), &resp_sender_id_len,
		resp_recipient_id, ARRAY_SIZE(resp_recipient_id),
		&resp_recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, resp_ctx->prk_state);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_master_secret, resp_master_secret,
				      sizeof(resp_master_secret));

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_master_salt, resp_master_salt,
				      sizeof(resp_master_salt));

	TEST_ASSERT_EQUAL(init_sender_id_len, resp_recipient_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_sender_id, resp_recipient_id,
				      init_sender_id_len);
	TEST_ASSERT_EQUAL(init_recipient_id_len, resp_sender_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_recipient_id, resp_sender_id,
				      resp_sender_id_len);
}

TEST_GROUP_RUNNER(rfc9529_chapter_3)
{
	RUN_TEST_CASE(rfc9529_chapter_3, message_1_compose);
	RUN_TEST_CASE(rfc9529_chapter_3, message_1_process);
	RUN_TEST_CASE(rfc9529_chapter_3, message_2_compose);
	RUN_TEST_CASE(rfc9529_chapter_3, message_2_compose_any);
	RUN_TEST_CASE(rfc9529_chapter_3, message_2_process);
	RUN_TEST_CASE(rfc9529_chapter_3, message_3_compose);
	RUN_TEST_CASE(rfc9529_chapter_3, message_3_compose_any);
	RUN_TEST_CASE(rfc9529_chapter_3, message_3_process);
	RUN_TEST_CASE(rfc9529_chapter_3, message_4_compose);
	RUN_TEST_CASE(rfc9529_chapter_3, message_4_process);
	RUN_TEST_CASE(rfc9529_chapter_3, handshake);
	RUN_TEST_CASE(rfc9529_chapter_3, handshake_real_crypto);
}
