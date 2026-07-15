/**
 * \file    test_rfc9529_chapter2.c
 * \author  Kamil Kielbasa
 * \brief   Module tests according to RFC 9529, chapter 2.
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Test vector header: */
#include "test_platform.h"
#include "test_rfc9529_support.h"
#include "test_key_agreement.h"
#include "edhoc_context_internal.h"
#include "test_vector_rfc9529_chapter_2.h"

/* Cipher suite 0 header: */
#include "edhoc_cipher_suite_0.h"

/* Standard library headers: */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

/* EDHOC header: */
#include <edhoc/edhoc.h>
#include "test_ead.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */

#define COSE_ALG_SHA_256_64 (-15)
#define CBOR_ENC_COSE_ALG_SHA_256_64 (0x2e)

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */

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
				 const uint8_t **pub_key, size_t *pub_key_len);

/**
 * \brief Authentication credentials verify callback for responder.
 */
static int auth_cred_verify_resp(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred,
				 const uint8_t **pub_key, size_t *pub_key_len);

/* Static variables and constants ------------------------------------------ */

static int ret = EDHOC_ERROR_GENERIC_ERROR;
static enum edhoc_error_code error_code_recv =
	EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;

static struct edhoc_context edhoc_initiator_context = { 0 };
static struct edhoc_context *init_ctx = &edhoc_initiator_context;

static struct edhoc_context edhoc_responder_context = { 0 };
static struct edhoc_context *resp_ctx = &edhoc_responder_context;

static struct edhoc_crypto edhoc_crypto_mocked_init;
static struct edhoc_crypto edhoc_crypto_mocked_resp;

/* Import a 64-byte Ed25519 private key (seed||pub) as an exportable RAW_DATA
 * key: the suite exports it and signs with Compact25519. */
static int import_sign_priv_key(const uint8_t *priv, size_t priv_len,
				uint8_t *key_id)
{
	TEST_ASSERT_NOT_NULL(priv);
	TEST_ASSERT_NOT_EQUAL(0, priv_len);
	TEST_ASSERT_NOT_NULL(key_id);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
	psa_set_key_type(&attr, PSA_KEY_TYPE_RAW_DATA);

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	const psa_status_t status = psa_import_key(&attr, priv, priv_len, &kid);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

	memcpy(key_id, &kid, sizeof(kid));

	return EDHOC_SUCCESS;
}

/* Bind cipher suite 0 to the shared key-agreement probe helper. */
static void assert_peers_share_slot_key(const struct edhoc_context *lhs,
					const struct edhoc_context *rhs,
					enum edhoc_key_slot_id slot)
{
	test_assert_peers_share_slot_key(EDHOC_CIPHER_SUITE_0, lhs, rhs, slot);
}

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

static const struct edhoc_ead edhoc_ead_single_token = {
	.compose = test_ead_compose_single,
	.process = test_ead_process_single,
};

static const struct edhoc_ead edhoc_ead_multiple_tokens = {
	.compose = test_ead_compose_multiple,
	.process = test_ead_process_multiple,
};

/* Static function definitions --------------------------------------------- */

/* Initiator ephemeral: inject the RFC's fixed X / G_X. */
static int mocked_generate_key_pair_init(void *user_ctx, void *decaps_key_id,
					 uint8_t *encaps_key,
					 size_t encaps_key_size,
					 size_t *encaps_key_len)
{
	(void)user_ctx;

	TEST_ASSERT_NOT_NULL(decaps_key_id);
	TEST_ASSERT_NOT_NULL(encaps_key);
	TEST_ASSERT_TRUE(encaps_key_size >= ARRAY_SIZE(G_X));
	TEST_ASSERT_NOT_NULL(encaps_key_len);

	const psa_key_id_t kid = tv_import_x25519(X, ARRAY_SIZE(X));

	memcpy(decaps_key_id, &kid, sizeof(kid));

	memcpy(encaps_key, G_X, ARRAY_SIZE(G_X));
	*encaps_key_len = ARRAY_SIZE(G_X);

	return EDHOC_SUCCESS;
}

/* Responder ephemeral: inject the RFC's fixed Y / G_Y and verify G_XY. */
static int mocked_encapsulate_resp(void *user_ctx, const uint8_t *encaps_key,
				   size_t encaps_key_len, void *decaps_key_id,
				   void *shared_secret_key_id,
				   uint8_t *ciphertext, size_t ciphertext_size,
				   size_t *ciphertext_len)
{
	(void)user_ctx;

	TEST_ASSERT_NOT_NULL(encaps_key);
	TEST_ASSERT_NOT_EQUAL(0, encaps_key_len);
	TEST_ASSERT_NOT_NULL(decaps_key_id);
	TEST_ASSERT_NOT_NULL(shared_secret_key_id);
	TEST_ASSERT_NOT_NULL(ciphertext);
	TEST_ASSERT_TRUE(ciphertext_size >= ARRAY_SIZE(G_Y));
	TEST_ASSERT_NOT_NULL(ciphertext_len);

	/* The library must hand us the initiator's ephemeral public key G_X. */
	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_X), encaps_key_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(G_X, encaps_key, encaps_key_len);

	const psa_key_id_t eph = tv_import_x25519(Y, ARRAY_SIZE(Y));

	tv_check_shared_secret(eph, encaps_key, encaps_key_len, G_XY,
			       ARRAY_SIZE(G_XY));

	memcpy(ciphertext, G_Y, ARRAY_SIZE(G_Y));
	*ciphertext_len = ARRAY_SIZE(G_Y);

	const psa_key_id_t shared = tv_import_derive(G_XY, ARRAY_SIZE(G_XY));

	memcpy(shared_secret_key_id, &shared, sizeof(shared));
	memcpy(decaps_key_id, &eph, sizeof(eph));

	return EDHOC_SUCCESS;
}

/* Initiator side of G_XY: agreement of injected X with peer G_Y. */
static int mocked_decapsulate_init(void *user_ctx, const void *decaps_key_id,
				   const uint8_t *ciphertext,
				   size_t ciphertext_len,
				   void *shared_secret_key_id)
{
	(void)user_ctx;

	TEST_ASSERT_NOT_NULL(decaps_key_id);
	TEST_ASSERT_NOT_NULL(ciphertext);
	TEST_ASSERT_NOT_EQUAL(0, ciphertext_len);
	TEST_ASSERT_NOT_NULL(shared_secret_key_id);

	/* The library must hand us the responder's ephemeral public key G_Y. */
	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_Y), ciphertext_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(G_Y, ciphertext, ciphertext_len);

	psa_key_id_t eph = PSA_KEY_ID_NULL;
	memcpy(&eph, decaps_key_id, sizeof(eph));

	tv_check_shared_secret(eph, ciphertext, ciphertext_len, G_XY,
			       ARRAY_SIZE(G_XY));

	const psa_key_id_t shared = tv_import_derive(G_XY, ARRAY_SIZE(G_XY));

	memcpy(shared_secret_key_id, &shared, sizeof(shared));

	return EDHOC_SUCCESS;
}

static int auth_cred_fetch_init(void *user_ctx,
				struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	if (NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	/**
         * \brief Here we check algorithm for certificate fingerprint. 
         *        - 0x2e is CBOR encoding of the integer -15.
         */
	if (CBOR_ENC_COSE_ALG_SHA_256_64 != ID_CRED_I_cborised[4])
		return EDHOC_ERROR_INVALID_ARGUMENT;

	auth_cred->label = EDHOC_COSE_HEADER_X509_HASH;
	auth_cred->x509_hash.cert = CRED_I;
	auth_cred->x509_hash.cert_len = ARRAY_SIZE(CRED_I);
	auth_cred->x509_hash.cert_fp = &ID_CRED_I_cborised[6];
	auth_cred->x509_hash.cert_fp_len = ARRAY_SIZE(ID_CRED_I_cborised) - 6;
	auth_cred->x509_hash.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	auth_cred->x509_hash.alg_int = COSE_ALG_SHA_256_64;

	const int res = import_sign_priv_key(SK_I, ARRAY_SIZE(SK_I),
					     auth_cred->priv_key_id);

	if (EDHOC_SUCCESS != res)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

static int auth_cred_fetch_init_any(void *user_ctx,
				    struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	if (NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	auth_cred->label = EDHOC_COSE_ANY;
	auth_cred->any.id_cred = ID_CRED_I_cborised;
	auth_cred->any.id_cred_len = ARRAY_SIZE(ID_CRED_I_cborised);
	auth_cred->any.cred = CRED_I_cborised;
	auth_cred->any.cred_len = ARRAY_SIZE(CRED_I_cborised);

	const int res = import_sign_priv_key(SK_I, ARRAY_SIZE(SK_I),
					     auth_cred->priv_key_id);

	if (EDHOC_SUCCESS != res)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

static int auth_cred_fetch_resp(void *user_ctx,
				struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	if (NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	/**
         * \brief Here we check algorithm for certificate fingerprint. 
         *        - 0x2e is CBOR encoding of the integer -15.
         */
	if (CBOR_ENC_COSE_ALG_SHA_256_64 != ID_CRED_R_cborised[4])
		return EDHOC_ERROR_INVALID_ARGUMENT;

	auth_cred->label = EDHOC_COSE_HEADER_X509_HASH;
	auth_cred->x509_hash.cert = CRED_R;
	auth_cred->x509_hash.cert_len = ARRAY_SIZE(CRED_R);
	auth_cred->x509_hash.cert_fp = &ID_CRED_R_cborised[6];
	auth_cred->x509_hash.cert_fp_len = ARRAY_SIZE(ID_CRED_R_cborised) - 6;
	auth_cred->x509_hash.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
	auth_cred->x509_hash.alg_int = COSE_ALG_SHA_256_64;

	const int res = import_sign_priv_key(SK_R, ARRAY_SIZE(SK_R),
					     auth_cred->priv_key_id);

	if (EDHOC_SUCCESS != res)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

static int auth_cred_fetch_resp_any(void *user_ctx,
				    struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	if (NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	auth_cred->label = EDHOC_COSE_ANY;
	auth_cred->any.id_cred = ID_CRED_R_cborised;
	auth_cred->any.id_cred_len = ARRAY_SIZE(ID_CRED_R_cborised);
	auth_cred->any.cred = CRED_R_cborised;
	auth_cred->any.cred_len = ARRAY_SIZE(CRED_R_cborised);

	const int res = import_sign_priv_key(SK_R, ARRAY_SIZE(SK_R),
					     auth_cred->priv_key_id);

	if (EDHOC_SUCCESS != res)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

static int auth_cred_verify_init(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred,
				 const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == auth_cred || NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	/**
         * \brief Verify COSE header label value. 
         */
	if (EDHOC_COSE_HEADER_X509_HASH != auth_cred->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief Verify received COSE IANA hash algorithm value. 
         */
	if (EDHOC_ENCODE_TYPE_INTEGER != auth_cred->x509_hash.encode_type ||
	    COSE_ALG_SHA_256_64 != auth_cred->x509_hash.alg_int)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief Verify if received certificate fingerprint matches. 
         */
	size_t hash_len = 0;
	uint8_t hash[32] = { 0 };
	const psa_status_t status =
		psa_hash_compute(PSA_ALG_SHA_256, CRED_R, ARRAY_SIZE(CRED_R),
				 hash, ARRAY_SIZE(hash), &hash_len);

	if (PSA_SUCCESS != status || ARRAY_SIZE(hash) != hash_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	uint8_t cert_fp[8] = { 0 };
	memcpy(cert_fp, hash, sizeof(cert_fp));

	if (ARRAY_SIZE(cert_fp) != auth_cred->x509_hash.cert_fp_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (0 != memcmp(cert_fp, auth_cred->x509_hash.cert_fp,
			auth_cred->x509_hash.cert_fp_len))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief If successful then assign certificate and public key. 
         */
	auth_cred->x509_hash.cert = CRED_R;
	auth_cred->x509_hash.cert_len = ARRAY_SIZE(CRED_R);

	*pub_key = PK_R;
	*pub_key_len = ARRAY_SIZE(PK_R);

	return EDHOC_SUCCESS;
}

static int auth_cred_verify_resp(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred,
				 const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == auth_cred || NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	/**
         * \brief Verify COSE header label value. 
         */
	if (EDHOC_COSE_HEADER_X509_HASH != auth_cred->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief Verify received COSE IANA hash algorithm value. 
         */
	if (EDHOC_ENCODE_TYPE_INTEGER != auth_cred->x509_hash.encode_type ||
	    COSE_ALG_SHA_256_64 != auth_cred->x509_hash.alg_int)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief Verify if received certificate fingerprint matches. 
         */
	size_t hash_len = 0;
	uint8_t hash[32] = { 0 };
	const psa_status_t status =
		psa_hash_compute(PSA_ALG_SHA_256, CRED_I, ARRAY_SIZE(CRED_I),
				 hash, ARRAY_SIZE(hash), &hash_len);

	if (PSA_SUCCESS != status || ARRAY_SIZE(hash) != hash_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	uint8_t cert_fp[8] = { 0 };
	memcpy(cert_fp, hash, sizeof(cert_fp));

	if (ARRAY_SIZE(cert_fp) != auth_cred->x509_hash.cert_fp_len)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (0 != memcmp(cert_fp, auth_cred->x509_hash.cert_fp,
			auth_cred->x509_hash.cert_fp_len))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief If successful then assign certificate and public key. 
         */
	auth_cred->x509_hash.cert = CRED_I;
	auth_cred->x509_hash.cert_len = ARRAY_SIZE(CRED_I);

	*pub_key = PK_I;
	*pub_key_len = ARRAY_SIZE(PK_I);

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(rfc9529_chapter2);

TEST_SETUP(rfc9529_chapter2)
{
	ret = psa_crypto_init();
	TEST_ASSERT_EQUAL(PSA_SUCCESS, ret);

	edhoc_crypto_mocked_init =
		*edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_0);
	edhoc_crypto_mocked_init.generate_key_pair =
		mocked_generate_key_pair_init;
	edhoc_crypto_mocked_init.decapsulate = mocked_decapsulate_init;

	edhoc_crypto_mocked_resp =
		*edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_0);
	edhoc_crypto_mocked_resp.encapsulate = mocked_encapsulate_resp;

	const enum edhoc_method methods[] = { METHOD };
	const struct edhoc_cipher_suite cipher_suites[] = {
		*edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_0),
	};

	const struct edhoc_connection_id init_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_I[0],
	};

	struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = ARRAY_SIZE(C_R),
	};
	memcpy(&resp_cid.bstr_value, C_R, ARRAY_SIZE(C_R));

	ret = edhoc_context_init(init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(init_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(init_ctx, cipher_suites,
				      ARRAY_SIZE(cipher_suites));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(init_ctx, &init_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(init_ctx, &edhoc_crypto_mocked_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(init_ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(init_ctx, &edhoc_auth_cred_mocked_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_init(resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(resp_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(resp_ctx, cipher_suites,
				      ARRAY_SIZE(cipher_suites));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(resp_ctx, &resp_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(resp_ctx, &edhoc_crypto_mocked_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(resp_ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(resp_ctx, &edhoc_auth_cred_mocked_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_TEAR_DOWN(rfc9529_chapter2)
{
	ret = edhoc_context_deinit(init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mbedtls_psa_crypto_free();
}

TEST(rfc9529_chapter2, message_1_compose)
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
}

TEST(rfc9529_chapter2, message_1_process)
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

	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
			  resp_ctx->peer_cid.encode_type);
	TEST_ASSERT_EQUAL((int8_t)C_I[0], resp_ctx->peer_cid.int_value);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_X), resp_ctx->peer_pub_eph_key_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(G_X, resp_ctx->peer_pub_eph_key,
				      resp_ctx->peer_pub_eph_key_len);
}

TEST(rfc9529_chapter2, message_2_compose)
{
	/* Required injections. */
	resp_ctx->status = EDHOC_SM_RECEIVED_M1;
	resp_ctx->chosen_method = METHOD;

	resp_ctx->th_state = EDHOC_TH_STATE_1;
	resp_ctx->th_len = ARRAY_SIZE(H_message_1);
	memcpy(resp_ctx->th, H_message_1, sizeof(H_message_1));

	resp_ctx->peer_pub_eph_key_len = ARRAY_SIZE(G_X);
	memcpy(resp_ctx->peer_pub_eph_key, G_X, ARRAY_SIZE(G_X));

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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, resp_ctx,
				     EDHOC_KEY_SLOT_PRK_3E2M, PRK_3e2m,
				     ARRAY_SIZE(PRK_3e2m));
}

TEST(rfc9529_chapter2, message_2_compose_any)
{
	ret = edhoc_bind_credentials(resp_ctx,
				     &edhoc_auth_cred_mocked_resp_any);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Required injections. */
	resp_ctx->status = EDHOC_SM_RECEIVED_M1;
	resp_ctx->chosen_method = METHOD;

	resp_ctx->th_state = EDHOC_TH_STATE_1;
	resp_ctx->th_len = ARRAY_SIZE(H_message_1);
	memcpy(resp_ctx->th, H_message_1, sizeof(H_message_1));

	resp_ctx->peer_pub_eph_key_len = ARRAY_SIZE(G_X);
	memcpy(resp_ctx->peer_pub_eph_key, G_X, ARRAY_SIZE(G_X));

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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, resp_ctx,
				     EDHOC_KEY_SLOT_PRK_3E2M, PRK_3e2m,
				     ARRAY_SIZE(PRK_3e2m));
}

TEST(rfc9529_chapter2, message_2_process)
{
	/* Required injections. */
	init_ctx->status = EDHOC_SM_WAIT_M2;
	init_ctx->chosen_method = METHOD;

	init_ctx->th_state = EDHOC_TH_STATE_1;
	init_ctx->th_len = ARRAY_SIZE(H_message_1);
	memcpy(init_ctx->th, H_message_1, ARRAY_SIZE(H_message_1));

	tv_inject_slot(init_ctx, EDHOC_KEY_SLOT_EPHEMERAL,
		       tv_import_x25519(X, ARRAY_SIZE(X)));

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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, init_ctx,
				     EDHOC_KEY_SLOT_PRK_3E2M, PRK_3e2m,
				     ARRAY_SIZE(PRK_3e2m));

	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_BYTE_STRING,
			  init_ctx->peer_cid.encode_type);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(C_R), init_ctx->peer_cid.bstr_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(C_R, init_ctx->peer_cid.bstr_value,
				      init_ctx->peer_cid.bstr_length);
}

TEST(rfc9529_chapter2, message_3_compose)
{
	/* Required injections. */
	init_ctx->status = EDHOC_SM_VERIFIED_M2;
	init_ctx->chosen_method = METHOD;

	init_ctx->th_state = EDHOC_TH_STATE_3;
	init_ctx->th_len = ARRAY_SIZE(TH_3);
	memcpy(init_ctx->th, TH_3, ARRAY_SIZE(TH_3));

	init_ctx->prk_state = EDHOC_PRK_STATE_3E2M;
	tv_inject_slot(init_ctx, EDHOC_KEY_SLOT_PRK_3E2M,
		       tv_import_derive(PRK_3e2m, ARRAY_SIZE(PRK_3e2m)));

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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, init_ctx,
				     EDHOC_KEY_SLOT_PRK_4E3M, PRK_4e3m,
				     ARRAY_SIZE(PRK_4e3m));
}

TEST(rfc9529_chapter2, message_3_compose_any)
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
	tv_inject_slot(init_ctx, EDHOC_KEY_SLOT_PRK_3E2M,
		       tv_import_derive(PRK_3e2m, ARRAY_SIZE(PRK_3e2m)));

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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, init_ctx,
				     EDHOC_KEY_SLOT_PRK_4E3M, PRK_4e3m,
				     ARRAY_SIZE(PRK_4e3m));
}

TEST(rfc9529_chapter2, message_3_process)
{
	/* Required injections. */
	resp_ctx->status = EDHOC_SM_WAIT_M3;
	resp_ctx->chosen_method = METHOD;

	resp_ctx->th_state = EDHOC_TH_STATE_3;
	resp_ctx->th_len = ARRAY_SIZE(TH_3);
	memcpy(resp_ctx->th, TH_3, ARRAY_SIZE(TH_3));

	resp_ctx->prk_state = EDHOC_PRK_STATE_3E2M;
	tv_inject_slot(resp_ctx, EDHOC_KEY_SLOT_PRK_3E2M,
		       tv_import_derive(PRK_3e2m, ARRAY_SIZE(PRK_3e2m)));

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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, resp_ctx,
				     EDHOC_KEY_SLOT_PRK_4E3M, PRK_4e3m,
				     ARRAY_SIZE(PRK_4e3m));
}

TEST(rfc9529_chapter2, message_4_compose)
{
	/* Required injections. */
	resp_ctx->status = EDHOC_SM_COMPLETED;
	resp_ctx->is_oscore_export_allowed = true;

	resp_ctx->th_state = EDHOC_TH_STATE_4;
	resp_ctx->th_len = ARRAY_SIZE(TH_4);
	memcpy(resp_ctx->th, TH_4, ARRAY_SIZE(TH_4));

	resp_ctx->prk_state = EDHOC_PRK_STATE_4E3M;
	tv_inject_slot(resp_ctx, EDHOC_KEY_SLOT_PRK_4E3M,
		       tv_import_derive(PRK_4e3m, ARRAY_SIZE(PRK_4e3m)));

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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, resp_ctx,
				     EDHOC_KEY_SLOT_PRK_4E3M, PRK_4e3m,
				     ARRAY_SIZE(PRK_4e3m));
}

TEST(rfc9529_chapter2, message_4_process)
{
	/* Required injections. */
	init_ctx->status = EDHOC_SM_COMPLETED;
	init_ctx->is_oscore_export_allowed = true;

	init_ctx->th_state = EDHOC_TH_STATE_4;
	init_ctx->th_len = ARRAY_SIZE(TH_4);
	memcpy(init_ctx->th, TH_4, ARRAY_SIZE(TH_4));

	init_ctx->prk_state = EDHOC_PRK_STATE_4E3M;
	tv_inject_slot(init_ctx, EDHOC_KEY_SLOT_PRK_4E3M,
		       tv_import_derive(PRK_4e3m, ARRAY_SIZE(PRK_4e3m)));

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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, init_ctx,
				     EDHOC_KEY_SLOT_PRK_4E3M, PRK_4e3m,
				     ARRAY_SIZE(PRK_4e3m));
}

TEST(rfc9529_chapter2, handshake)
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

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, init_ctx->th_state);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(H_message_1), init_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(H_message_1, init_ctx->th,
				      init_ctx->th_len);

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

	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
			  resp_ctx->peer_cid.encode_type);
	TEST_ASSERT_EQUAL((int8_t)C_I[0], resp_ctx->peer_cid.int_value);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(G_X), resp_ctx->peer_pub_eph_key_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(G_X, resp_ctx->peer_pub_eph_key,
				      resp_ctx->peer_pub_eph_key_len);

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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, resp_ctx,
				     EDHOC_KEY_SLOT_PRK_3E2M, PRK_3e2m,
				     ARRAY_SIZE(PRK_3e2m));

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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, init_ctx,
				     EDHOC_KEY_SLOT_PRK_3E2M, PRK_3e2m,
				     ARRAY_SIZE(PRK_3e2m));

	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_BYTE_STRING,
			  init_ctx->peer_cid.encode_type);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(C_R), init_ctx->peer_cid.bstr_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(C_R, init_ctx->peer_cid.bstr_value,
				      init_ctx->peer_cid.bstr_length);

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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, init_ctx,
				     EDHOC_KEY_SLOT_PRK_4E3M, PRK_4e3m,
				     ARRAY_SIZE(PRK_4e3m));

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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, resp_ctx,
				     EDHOC_KEY_SLOT_PRK_4E3M, PRK_4e3m,
				     ARRAY_SIZE(PRK_4e3m));

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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, resp_ctx,
				     EDHOC_KEY_SLOT_PRK_4E3M, PRK_4e3m,
				     ARRAY_SIZE(PRK_4e3m));

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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, init_ctx,
				     EDHOC_KEY_SLOT_PRK_4E3M, PRK_4e3m,
				     ARRAY_SIZE(PRK_4e3m));

	uint8_t init_master_secret[ARRAY_SIZE(OSCORE_Master_Secret)] = { 0 };
	uint8_t init_master_salt[ARRAY_SIZE(OSCORE_Master_Salt)] = { 0 };
	size_t init_sender_id_len = 0;
	uint8_t init_sender_id[ARRAY_SIZE(OSCORE_C_R)] = { 0 };
	size_t init_recipient_id_len = 0;
	uint8_t init_recipient_id[ARRAY_SIZE(OSCORE_C_I)] = { 0 };

	/* Derive OSCORE master secret and master salt. */
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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, init_ctx,
				     EDHOC_KEY_SLOT_PRK_OUT, PRK_out,
				     ARRAY_SIZE(PRK_out));

	uint8_t resp_master_secret[ARRAY_SIZE(OSCORE_Master_Secret)] = { 0 };
	uint8_t resp_master_salt[ARRAY_SIZE(OSCORE_Master_Salt)] = { 0 };
	size_t resp_sender_id_len = 0;
	uint8_t resp_sender_id[ARRAY_SIZE(OSCORE_C_I)] = { 0 };
	size_t resp_recipient_id_len = 0;
	uint8_t resp_recipient_id[ARRAY_SIZE(OSCORE_C_R)] = { 0 };

	/* Derive OSCORE master secret and master salt. */
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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, resp_ctx,
				     EDHOC_KEY_SLOT_PRK_OUT, PRK_out,
				     ARRAY_SIZE(PRK_out));

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_master_secret, resp_master_secret,
				      ARRAY_SIZE(resp_master_secret));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_Master_Secret, init_master_secret,
				      ARRAY_SIZE(init_master_secret));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_Master_Secret, resp_master_secret,
				      ARRAY_SIZE(resp_master_secret));

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_master_salt, resp_master_salt,
				      ARRAY_SIZE(resp_master_salt));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_Master_Salt, init_master_salt,
				      ARRAY_SIZE(init_master_salt));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_Master_Salt, resp_master_salt,
				      ARRAY_SIZE(resp_master_salt));

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
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, init_ctx,
				     EDHOC_KEY_SLOT_PRK_OUT, keyUpdate_PRK_out,
				     ARRAY_SIZE(keyUpdate_PRK_out));

	/* EDHOC key update method. */
	ret = edhoc_export_key_update(resp_ctx, keyUpdate_context,
				      ARRAY_SIZE(keyUpdate_context));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->status);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, resp_ctx->prk_state);
	tv_assert_slot_equals_vector(EDHOC_CIPHER_SUITE_0, resp_ctx,
				     EDHOC_KEY_SLOT_PRK_OUT, keyUpdate_PRK_out,
				     ARRAY_SIZE(keyUpdate_PRK_out));

	memset(init_master_secret, 0, sizeof(init_master_secret));
	memset(init_master_salt, 0, sizeof(init_master_salt));
	init_sender_id_len = 0;
	memset(init_sender_id, 0, sizeof(init_sender_id));
	init_recipient_id_len = 0;
	memset(init_recipient_id, 0, sizeof(init_recipient_id));

	/* Derive OSCORE master secret and master salt. */
	ret = edhoc_export_oscore_session(
		init_ctx, init_master_secret, ARRAY_SIZE(init_master_secret),
		init_master_salt, ARRAY_SIZE(init_master_salt), init_sender_id,
		ARRAY_SIZE(init_sender_id), &init_sender_id_len,
		init_recipient_id, ARRAY_SIZE(init_recipient_id),
		&init_recipient_id_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);

	memset(resp_master_secret, 0, sizeof(resp_master_secret));
	memset(resp_master_salt, 0, sizeof(resp_master_salt));
	resp_sender_id_len = 0;
	memset(resp_sender_id, 0, sizeof(resp_sender_id));
	resp_recipient_id_len = 0;
	memset(resp_recipient_id, 0, sizeof(resp_recipient_id));

	/* Derive OSCORE master secret and master salt. */
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
				      ARRAY_SIZE(resp_master_secret));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(keyUpdate_OSCORE_Master_Secret,
				      init_master_secret,
				      ARRAY_SIZE(init_master_secret));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(keyUpdate_OSCORE_Master_Secret,
				      resp_master_secret,
				      ARRAY_SIZE(resp_master_secret));

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_master_salt, resp_master_salt,
				      ARRAY_SIZE(resp_master_salt));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(keyUpdate_OSCORE_Master_Salt,
				      init_master_salt,
				      ARRAY_SIZE(init_master_salt));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(keyUpdate_OSCORE_Master_Salt,
				      resp_master_salt,
				      ARRAY_SIZE(resp_master_salt));

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

TEST(rfc9529_chapter2, prk_exporter)
{
	/* Required injections. */
	init_ctx->status = EDHOC_SM_COMPLETED;

	init_ctx->th_state = EDHOC_TH_STATE_4;
	init_ctx->th_len = ARRAY_SIZE(TH_4);
	memcpy(init_ctx->th, TH_4, ARRAY_SIZE(TH_4));

	init_ctx->prk_state = EDHOC_PRK_STATE_4E3M;
	tv_inject_slot(init_ctx, EDHOC_KEY_SLOT_PRK_4E3M,
		       tv_import_derive(PRK_4e3m, ARRAY_SIZE(PRK_4e3m)));

	uint8_t master_secret[ARRAY_SIZE(OSCORE_Master_Secret)] = { 0 };

	/* EDHOC PRK exporter - OSCORE master secret. */
	ret = edhoc_export_prk_exporter(init_ctx,
					OSCORE_EXTRACT_LABEL_MASTER_SECRET, NULL,
					0, master_secret,
					ARRAY_SIZE(master_secret));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_Master_Secret, master_secret,
				      ARRAY_SIZE(OSCORE_Master_Secret));

	uint8_t master_salt[ARRAY_SIZE(OSCORE_Master_Salt)] = { 0 };

	/* EDHOC PRK exporter - OSCORE master salt. */
	ret = edhoc_export_prk_exporter(init_ctx,
					OSCORE_EXTRACT_LABEL_MASTER_SALT, NULL, 0,
					master_salt, ARRAY_SIZE(master_salt));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_Master_Salt, master_salt,
				      ARRAY_SIZE(OSCORE_Master_Salt));

	/* Export private usage secrets (label: minimum, middle, maximum). */
	uint8_t secret_1[13] = { 0 };
	uint8_t secret_2[32] = { 0 };
	uint8_t secret_3[64] = { 0 };

	ret = edhoc_export_prk_exporter(
		init_ctx, EDHOC_PRK_EXPORTER_PRIVATE_LABEL_MINIMUM, NULL, 0,
		secret_1, ARRAY_SIZE(secret_1));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_export_prk_exporter(
		init_ctx, EDHOC_PRK_EXPORTER_PRIVATE_LABEL_MAXIMUM, NULL, 0,
		secret_2, ARRAY_SIZE(secret_2));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const size_t label = 45737;
	ret = edhoc_export_prk_exporter(init_ctx, label, NULL, 0, secret_3,
					ARRAY_SIZE(secret_3));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(rfc9529_chapter2, handshake_real_crypto)
{
	uint8_t buffer[200] = { 0 };

	/* Required injections. */
	ret = edhoc_bind_crypto(
		init_ctx, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(init_ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(
		resp_ctx, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(resp_ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

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

	/* EDHOC message 2 compose. */
	ret = edhoc_message_2_process(init_ctx, msg_2, msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_VERIFIED_M2, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, init_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, init_ctx->prk_state);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_BYTE_STRING,
			  init_ctx->peer_cid.encode_type);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(C_R), init_ctx->peer_cid.bstr_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(C_R, init_ctx->peer_cid.bstr_value,
				      init_ctx->peer_cid.bstr_length);

	assert_peers_share_slot_key(init_ctx, resp_ctx,
				    EDHOC_KEY_SLOT_PRK_3E2M);

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

	const struct edhoc_cipher_suite *suite =
		edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_0);

	TEST_ASSERT_EQUAL(suite->hash_length, init_ctx->th_len);
	TEST_ASSERT_EQUAL(suite->hash_length, resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->th, resp_ctx->th,
				      suite->hash_length);

	assert_peers_share_slot_key(init_ctx, resp_ctx,
				    EDHOC_KEY_SLOT_PRK_4E3M);

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

	uint8_t init_master_secret[ARRAY_SIZE(OSCORE_Master_Secret)] = { 0 };
	uint8_t init_master_salt[ARRAY_SIZE(OSCORE_Master_Salt)] = { 0 };
	size_t init_sender_id_len = 0;
	uint8_t init_sender_id[ARRAY_SIZE(OSCORE_C_R)] = { 0 };
	size_t init_recipient_id_len = 0;
	uint8_t init_recipient_id[ARRAY_SIZE(OSCORE_C_I)] = { 0 };

	/* Derive OSCORE master secret and master salt. */
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

	uint8_t resp_master_secret[ARRAY_SIZE(OSCORE_Master_Secret)] = { 0 };
	uint8_t resp_master_salt[ARRAY_SIZE(OSCORE_Master_Salt)] = { 0 };
	size_t resp_sender_id_len = 0;
	uint8_t resp_sender_id[ARRAY_SIZE(OSCORE_C_I)] = { 0 };
	size_t resp_recipient_id_len = 0;
	uint8_t resp_recipient_id[ARRAY_SIZE(OSCORE_C_R)] = { 0 };

	/* Derive OSCORE master secret and master salt. */
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
				      ARRAY_SIZE(resp_master_secret));

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_master_salt, resp_master_salt,
				      ARRAY_SIZE(resp_master_salt));

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

	assert_peers_share_slot_key(init_ctx, resp_ctx,
				    EDHOC_KEY_SLOT_PRK_OUT);

	memset(init_master_secret, 0, sizeof(init_master_secret));
	memset(init_master_salt, 0, sizeof(init_master_salt));
	init_sender_id_len = 0;
	memset(init_sender_id, 0, sizeof(init_sender_id));
	init_recipient_id_len = 0;
	memset(init_recipient_id, 0, sizeof(init_recipient_id));

	/* Derive OSCORE master secret and master salt. */
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

	memset(resp_master_secret, 0, sizeof(resp_master_secret));
	memset(resp_master_salt, 0, sizeof(resp_master_salt));
	resp_sender_id_len = 0;
	memset(resp_sender_id, 0, sizeof(resp_sender_id));
	resp_recipient_id_len = 0;
	memset(resp_recipient_id, 0, sizeof(resp_recipient_id));

	/* Derive OSCORE master secret and master salt. */
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
				      ARRAY_SIZE(resp_master_secret));

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_master_salt, resp_master_salt,
				      ARRAY_SIZE(resp_master_salt));

	TEST_ASSERT_EQUAL(init_sender_id_len, resp_recipient_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_sender_id, resp_recipient_id,
				      init_sender_id_len);
	TEST_ASSERT_EQUAL(init_recipient_id_len, resp_sender_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_recipient_id, resp_sender_id,
				      resp_sender_id_len);
}

TEST(rfc9529_chapter2, handshake_real_crypto_ead_single)
{
	uint8_t buffer[500] = { 0 };

	/* Required injections. */
	ret = edhoc_bind_crypto(
		init_ctx, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(
		resp_ctx, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct ead_context init_ead_ctx = { 0 };
	ret = edhoc_set_user_context(init_ctx, &init_ead_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_ead(init_ctx, &edhoc_ead_single_token);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct ead_context resp_ead_ctx = { 0 };
	ret = edhoc_set_user_context(resp_ctx, &resp_ead_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_ead(resp_ctx, &edhoc_ead_single_token);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

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

	/* Verify EAD_1 compose. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_1, init_ead_ctx.msg);
	TEST_ASSERT_EQUAL(1, init_ead_ctx.recv_tokens);
	TEST_ASSERT_EQUAL(ead_single_token_msg_1.label,
			  init_ead_ctx.token[0].label);
	TEST_ASSERT_EQUAL(ead_single_token_msg_1.value_len,
			  init_ead_ctx.token[0].value_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(ead_single_token_msg_1.value,
				      init_ead_ctx.token[0].value,
				      init_ead_ctx.token[0].value_len);

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

	/* Verify EAD_1 process. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_1, resp_ead_ctx.msg);
	TEST_ASSERT_EQUAL(1, resp_ead_ctx.recv_tokens);
	TEST_ASSERT_EQUAL(ead_single_token_msg_1.label,
			  resp_ead_ctx.token[0].label);
	TEST_ASSERT_EQUAL(ead_single_token_msg_1.value_len,
			  resp_ead_ctx.token[0].value_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(ead_single_token_msg_1.value,
				      resp_ead_ctx.token[0].value,
				      resp_ead_ctx.token[0].value_len);

	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

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

	/* Verify EAD_2 compose. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_2, resp_ead_ctx.msg);
	TEST_ASSERT_EQUAL(1, resp_ead_ctx.recv_tokens);
	TEST_ASSERT_EQUAL(ead_single_token_msg_2.label,
			  resp_ead_ctx.token[0].label);
	TEST_ASSERT_EQUAL(ead_single_token_msg_2.value_len,
			  resp_ead_ctx.token[0].value_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(ead_single_token_msg_2.value,
				      resp_ead_ctx.token[0].value,
				      resp_ead_ctx.token[0].value_len);

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

	/* Verify EAD_2 process. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_2, init_ead_ctx.msg);
	TEST_ASSERT_EQUAL(1, init_ead_ctx.recv_tokens);
	TEST_ASSERT_EQUAL(ead_single_token_msg_2.label,
			  init_ead_ctx.token[0].label);
	TEST_ASSERT_EQUAL(ead_single_token_msg_2.value_len,
			  init_ead_ctx.token[0].value_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(ead_single_token_msg_2.value,
				      init_ead_ctx.token[0].value,
				      init_ead_ctx.token[0].value_len);

	assert_peers_share_slot_key(init_ctx, resp_ctx,
				    EDHOC_KEY_SLOT_PRK_3E2M);

	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

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

	/* Verify EAD_3 compose. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_3, init_ead_ctx.msg);
	TEST_ASSERT_EQUAL(1, init_ead_ctx.recv_tokens);
	TEST_ASSERT_EQUAL(ead_single_token_msg_3.label,
			  init_ead_ctx.token[0].label);
	TEST_ASSERT_EQUAL(ead_single_token_msg_3.value_len,
			  init_ead_ctx.token[0].value_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(ead_single_token_msg_3.value,
				      init_ead_ctx.token[0].value,
				      init_ead_ctx.token[0].value_len);

	/* EDHOC message 3 process. */
	ret = edhoc_message_3_process(resp_ctx, msg_3, msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, resp_ctx->status);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->prk_state);

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	/* Verify EAD_3 process. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_3, resp_ead_ctx.msg);
	TEST_ASSERT_EQUAL(1, resp_ead_ctx.recv_tokens);
	TEST_ASSERT_EQUAL(ead_single_token_msg_3.label,
			  resp_ead_ctx.token[0].label);
	TEST_ASSERT_EQUAL(ead_single_token_msg_3.value_len,
			  resp_ead_ctx.token[0].value_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(ead_single_token_msg_3.value,
				      resp_ead_ctx.token[0].value,
				      resp_ead_ctx.token[0].value_len);

	assert_peers_share_slot_key(init_ctx, resp_ctx,
				    EDHOC_KEY_SLOT_PRK_4E3M);

	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

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

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	/* Verify EAD_4 compose. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_4, resp_ead_ctx.msg);
	TEST_ASSERT_EQUAL(1, resp_ead_ctx.recv_tokens);
	TEST_ASSERT_EQUAL(ead_single_token_msg_4.label,
			  resp_ead_ctx.token[0].label);
	TEST_ASSERT_EQUAL(ead_single_token_msg_4.value_len,
			  resp_ead_ctx.token[0].value_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(ead_single_token_msg_4.value,
				      resp_ead_ctx.token[0].value,
				      resp_ead_ctx.token[0].value_len);

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

	/* Verify EAD_4 process. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_4, init_ead_ctx.msg);
	TEST_ASSERT_EQUAL(1, init_ead_ctx.recv_tokens);

	TEST_ASSERT_EQUAL(ead_single_token_msg_4.label,
			  init_ead_ctx.token[0].label);
	TEST_ASSERT_EQUAL(ead_single_token_msg_4.value_len,
			  init_ead_ctx.token[0].value_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(ead_single_token_msg_4.value,
				      init_ead_ctx.token[0].value,
				      init_ead_ctx.token[0].value_len);

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
				      ARRAY_SIZE(resp_master_secret));

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_master_salt, resp_master_salt,
				      ARRAY_SIZE(resp_master_salt));

	TEST_ASSERT_EQUAL(init_sender_id_len, resp_recipient_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_sender_id, resp_recipient_id,
				      init_sender_id_len);
	TEST_ASSERT_EQUAL(init_recipient_id_len, resp_sender_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_recipient_id, resp_sender_id,
				      resp_sender_id_len);

	assert_peers_share_slot_key(init_ctx, resp_ctx,
				    EDHOC_KEY_SLOT_PRK_OUT);
}

TEST(rfc9529_chapter2, handshake_real_crypto_ead_many)
{
	uint8_t buffer[1000] = { 0 };

	/* Required injections. */
	ret = edhoc_bind_crypto(
		init_ctx, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(
		resp_ctx, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_0));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct ead_context init_ead_ctx = { 0 };
	struct ead_context resp_ead_ctx = { 0 };

	ret = edhoc_set_user_context(init_ctx, &init_ead_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_ead(init_ctx, &edhoc_ead_multiple_tokens);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_user_context(resp_ctx, &resp_ead_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_ead(resp_ctx, &edhoc_ead_multiple_tokens);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

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

	/* Verify EAD_1 compose. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_1, init_ead_ctx.msg);
	TEST_ASSERT_EQUAL(EAD_MULTIPLE_TOKENS_MSG_1_LEN,
			  init_ead_ctx.recv_tokens);

	for (size_t i = 0; i < init_ead_ctx.recv_tokens; ++i) {
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_1[i].label,
				  init_ead_ctx.token[i].label);
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_1[i].value_len,
				  init_ead_ctx.token[i].value_len);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(
			ead_multiple_tokens_msg_1[i].value,
			init_ead_ctx.token[i].value,
			init_ead_ctx.token[i].value_len);
	}

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

	/* Verify EAD_1 process. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_1, resp_ead_ctx.msg);
	TEST_ASSERT_EQUAL(EAD_MULTIPLE_TOKENS_MSG_1_LEN,
			  resp_ead_ctx.recv_tokens);

	for (size_t i = 0; i < resp_ead_ctx.recv_tokens; ++i) {
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_1[i].label,
				  resp_ead_ctx.token[i].label);
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_1[i].value_len,
				  resp_ead_ctx.token[i].value_len);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(
			ead_multiple_tokens_msg_1[i].value,
			resp_ead_ctx.token[i].value,
			resp_ead_ctx.token[i].value_len);
	}

	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

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

	/* Verify EAD_2 compose. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_2, resp_ead_ctx.msg);
	TEST_ASSERT_EQUAL(EAD_MULTIPLE_TOKENS_MSG_2_LEN,
			  resp_ead_ctx.recv_tokens);

	for (size_t i = 0; i < resp_ead_ctx.recv_tokens; ++i) {
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_2[i].label,
				  resp_ead_ctx.token[i].label);
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_2[i].value_len,
				  resp_ead_ctx.token[i].value_len);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(
			ead_multiple_tokens_msg_2[i].value,
			resp_ead_ctx.token[i].value,
			resp_ead_ctx.token[i].value_len);
	}

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

	/* Verify EAD_2 process. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_2, init_ead_ctx.msg);
	TEST_ASSERT_EQUAL(EAD_MULTIPLE_TOKENS_MSG_2_LEN,
			  init_ead_ctx.recv_tokens);

	for (size_t i = 0; i < init_ead_ctx.recv_tokens; ++i) {
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_2[i].label,
				  init_ead_ctx.token[i].label);
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_2[i].value_len,
				  init_ead_ctx.token[i].value_len);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(
			ead_multiple_tokens_msg_2[i].value,
			init_ead_ctx.token[i].value,
			init_ead_ctx.token[i].value_len);
	}

	assert_peers_share_slot_key(init_ctx, resp_ctx,
				    EDHOC_KEY_SLOT_PRK_3E2M);

	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

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

	/* Verify EAD_3 compose. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_3, init_ead_ctx.msg);
	TEST_ASSERT_EQUAL(EAD_MULTIPLE_TOKENS_MSG_3_LEN,
			  init_ead_ctx.recv_tokens);

	for (size_t i = 0; i < init_ead_ctx.recv_tokens; ++i) {
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_3[i].label,
				  init_ead_ctx.token[i].label);
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_3[i].value_len,
				  init_ead_ctx.token[i].value_len);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(
			ead_multiple_tokens_msg_3[i].value,
			init_ead_ctx.token[i].value,
			init_ead_ctx.token[i].value_len);
	}

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

	/* Verify EAD_3 process. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_3, resp_ead_ctx.msg);
	TEST_ASSERT_EQUAL(EAD_MULTIPLE_TOKENS_MSG_3_LEN,
			  resp_ead_ctx.recv_tokens);

	for (size_t i = 0; i < resp_ead_ctx.recv_tokens; ++i) {
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_3[i].label,
				  resp_ead_ctx.token[i].label);
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_3[i].value_len,
				  resp_ead_ctx.token[i].value_len);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(
			ead_multiple_tokens_msg_3[i].value,
			resp_ead_ctx.token[i].value,
			resp_ead_ctx.token[i].value_len);
	}

	assert_peers_share_slot_key(init_ctx, resp_ctx,
				    EDHOC_KEY_SLOT_PRK_4E3M);

	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

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

	/* Verify EAD_4 compose. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_4, resp_ead_ctx.msg);
	TEST_ASSERT_EQUAL(EAD_MULTIPLE_TOKENS_MSG_4_LEN,
			  resp_ead_ctx.recv_tokens);

	for (size_t i = 0; i < resp_ead_ctx.recv_tokens; ++i) {
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_4[i].label,
				  resp_ead_ctx.token[i].label);
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_4[i].value_len,
				  resp_ead_ctx.token[i].value_len);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(
			ead_multiple_tokens_msg_4[i].value,
			resp_ead_ctx.token[i].value,
			resp_ead_ctx.token[i].value_len);
	}

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

	/* Verify EAD_4 process. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_4, init_ead_ctx.msg);
	TEST_ASSERT_EQUAL(EAD_MULTIPLE_TOKENS_MSG_4_LEN,
			  init_ead_ctx.recv_tokens);

	for (size_t i = 0; i < init_ead_ctx.recv_tokens; ++i) {
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_4[i].label,
				  init_ead_ctx.token[i].label);
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_4[i].value_len,
				  init_ead_ctx.token[i].value_len);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(
			ead_multiple_tokens_msg_4[i].value,
			init_ead_ctx.token[i].value,
			init_ead_ctx.token[i].value_len);
	}

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
				      ARRAY_SIZE(resp_master_secret));

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_master_salt, resp_master_salt,
				      ARRAY_SIZE(resp_master_salt));

	TEST_ASSERT_EQUAL(init_sender_id_len, resp_recipient_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_sender_id, resp_recipient_id,
				      init_sender_id_len);
	TEST_ASSERT_EQUAL(init_recipient_id_len, resp_sender_id_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_recipient_id, resp_sender_id,
				      resp_sender_id_len);

	assert_peers_share_slot_key(init_ctx, resp_ctx,
				    EDHOC_KEY_SLOT_PRK_OUT);
}

TEST_GROUP_RUNNER(rfc9529_chapter2)
{
	RUN_TEST_CASE(rfc9529_chapter2, message_1_compose);
	RUN_TEST_CASE(rfc9529_chapter2, message_1_process);
	RUN_TEST_CASE(rfc9529_chapter2, message_2_compose);
	RUN_TEST_CASE(rfc9529_chapter2, message_2_compose_any);
	RUN_TEST_CASE(rfc9529_chapter2, message_2_process);
	RUN_TEST_CASE(rfc9529_chapter2, message_3_compose);
	RUN_TEST_CASE(rfc9529_chapter2, message_3_compose_any);
	RUN_TEST_CASE(rfc9529_chapter2, message_3_process);
	RUN_TEST_CASE(rfc9529_chapter2, message_4_compose);
	RUN_TEST_CASE(rfc9529_chapter2, message_4_process);
	RUN_TEST_CASE(rfc9529_chapter2, handshake);
	RUN_TEST_CASE(rfc9529_chapter2, prk_exporter);
	RUN_TEST_CASE(rfc9529_chapter2, handshake_real_crypto);
	RUN_TEST_CASE(rfc9529_chapter2, handshake_real_crypto_ead_single);
	RUN_TEST_CASE(rfc9529_chapter2, handshake_real_crypto_ead_many);
}
