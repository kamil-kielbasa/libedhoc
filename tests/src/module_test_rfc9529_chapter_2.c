/**
 * \file    module_test_rfc9529_chapter_2.c
 * \author  Kamil Kielbasa
 * \brief   Module tests according to RFC 9529, chapter 2.
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Test vector header: */
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
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include <edhoc.h>

/* PSA crypto header: */
#include <psa/crypto.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */

#define COSE_ALG_SHA_256_64 (-15)
#define CBOR_ENC_COSE_ALG_SHA_256_64 (0x2e)

#define EAD_TOKEN_BUFFER_LEN (300)
#define MAX_NR_OF_EAD_TOKENS (3)

/* Module types and type definitiones -------------------------------------- */

struct ead_token_buf {
	int32_t label;
	uint8_t value[EAD_TOKEN_BUFFER_LEN];
	size_t value_len;
};

struct ead_context {
	enum edhoc_message msg;
	size_t recv_tokens;
	struct ead_token_buf token[MAX_NR_OF_EAD_TOKENS];
};

/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Mocked EDHOC crypto function ECDH make key pair for initiator.
 */
static int edhoc_cipher_suite_0_make_key_pair_init(
	void *user_context, const void *key_id, uint8_t *private_key,
	size_t private_key_size, size_t *private_key_length,
	uint8_t *public_key, size_t public_key_size, size_t *public_key_length);

/**
 * \brief Mocked EDHOC crypto function ECDH make key pair for responder.
 */
static int edhoc_cipher_suite_0_make_key_pair_resp(
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
				 const uint8_t **pub_key, size_t *pub_key_len);

/**
 * \brief Authentication credentials verify callback for responder.
 */
static int auth_cred_verify_resp(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred,
				 const uint8_t **pub_key, size_t *pub_key_len);

/**
 * \brief Example EAD compose for single token. 
 */
static int ead_compose_single_token(void *user_context,
				    enum edhoc_message message,
				    struct edhoc_ead_token *ead_token,
				    size_t ead_token_size,
				    size_t *ead_token_len);

/**
 * \brief Example EAD process for single token. 
 */
static int ead_process_single_token(void *user_context,
				    enum edhoc_message message,
				    const struct edhoc_ead_token *ead_token,
				    size_t ead_token_size);

/**
 * \brief Example EAD compose for multiple tokens. 
 */
static int ead_compose_multiple_tokens(void *user_context,
				       enum edhoc_message message,
				       struct edhoc_ead_token *ead_token,
				       size_t ead_token_size,
				       size_t *ead_token_len);

/**
 * \brief Example EAD process for multiple tokens. 
 */
static int ead_process_multiple_tokens(void *user_context,
				       enum edhoc_message message,
				       const struct edhoc_ead_token *ead_token,
				       size_t ead_token_size);

/* Static variables and constants ------------------------------------------ */

static int ret = EDHOC_ERROR_GENERIC_ERROR;
static enum edhoc_error_code error_code_recv =
	EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;

static struct edhoc_context edhoc_initiator_context = { 0 };
static struct edhoc_context *init_ctx = &edhoc_initiator_context;

static struct edhoc_context edhoc_responder_context = { 0 };
static struct edhoc_context *resp_ctx = &edhoc_responder_context;

static const struct edhoc_cipher_suite edhoc_cipher_suite_0 = {
	.value = 0,
	.aead_key_length = 16,
	.aead_tag_length = 8,
	.aead_iv_length = 13,
	.hash_length = 32,
	.mac_length = 32,
	.ecc_key_length = 32,
	.ecc_sign_length = 64,
};

static const struct edhoc_keys *edhoc_keys;

static const struct edhoc_crypto edhoc_crypto_mocked_init = {
	.make_key_pair = edhoc_cipher_suite_0_make_key_pair_init,
	.key_agreement = edhoc_cipher_suite_0_key_agreement,
	.signature = edhoc_cipher_suite_0_signature,
	.verify = edhoc_cipher_suite_0_verify,
	.extract = edhoc_cipher_suite_0_extract,
	.expand = edhoc_cipher_suite_0_expand,
	.encrypt = edhoc_cipher_suite_0_encrypt,
	.decrypt = edhoc_cipher_suite_0_decrypt,
	.hash = edhoc_cipher_suite_0_hash,
};

static const struct edhoc_crypto edhoc_crypto_mocked_resp = {
	.make_key_pair = edhoc_cipher_suite_0_make_key_pair_resp,
	.key_agreement = edhoc_cipher_suite_0_key_agreement,
	.signature = edhoc_cipher_suite_0_signature,
	.verify = edhoc_cipher_suite_0_verify,
	.extract = edhoc_cipher_suite_0_extract,
	.expand = edhoc_cipher_suite_0_expand,
	.encrypt = edhoc_cipher_suite_0_encrypt,
	.decrypt = edhoc_cipher_suite_0_decrypt,
	.hash = edhoc_cipher_suite_0_hash,
};

static const struct edhoc_crypto edhoc_crypto = {
	.make_key_pair = edhoc_cipher_suite_0_make_key_pair,
	.key_agreement = edhoc_cipher_suite_0_key_agreement,
	.signature = edhoc_cipher_suite_0_signature,
	.verify = edhoc_cipher_suite_0_verify,
	.extract = edhoc_cipher_suite_0_extract,
	.expand = edhoc_cipher_suite_0_expand,
	.encrypt = edhoc_cipher_suite_0_encrypt,
	.decrypt = edhoc_cipher_suite_0_decrypt,
	.hash = edhoc_cipher_suite_0_hash,
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

static const struct edhoc_ead edhoc_ead_single_token = {
	.compose = ead_compose_single_token,
	.process = ead_process_single_token,
};

static const struct edhoc_ead edhoc_ead_multiple_tokens = {
	.compose = ead_compose_multiple_tokens,
	.process = ead_process_multiple_tokens,
};

static const uint8_t ead_val_msg_1[] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
};
static const uint8_t ead_val_msg_2[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const uint8_t ead_val_msg_3[] = {
	0x55, 0x9a, 0xea, 0xd0, 0x82, 0x64, 0xd5, 0x79, 0x5d, 0x39, 0x09, 0x71,
	0x8c, 0xdd, 0x05, 0xab, 0xd4, 0x95, 0x72, 0xe8, 0x4f, 0xe5, 0x55, 0x90,
	0xee, 0xf3, 0x1a, 0x88, 0xa0, 0x8f, 0xdf, 0xfd, 0x3c, 0xb2, 0x5f, 0x25,
	0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
	0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
	0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
	0x58, 0x65, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
};

static const uint8_t ead_val_msg_4[] = {
	0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x00,
};

static const struct edhoc_ead_token ead_single_token_msg_1 = {
	.label = 0,
	.value = ead_val_msg_1,
	.value_len = ARRAY_SIZE(ead_val_msg_1),
};

static const struct edhoc_ead_token ead_single_token_msg_2 = {
	.label = 24,
	.value = ead_val_msg_2,
	.value_len = ARRAY_SIZE(ead_val_msg_2),
};

static const struct edhoc_ead_token ead_single_token_msg_3 = {
	.label = 65535,
	.value = ead_val_msg_3,
	.value_len = ARRAY_SIZE(ead_val_msg_3),
};

static const struct edhoc_ead_token ead_single_token_msg_4 = {
	.label = -830,
	.value = ead_val_msg_4,
	.value_len = ARRAY_SIZE(ead_val_msg_4),
};

static const struct edhoc_ead_token ead_multiple_tokens_msg_1[] = {
	ead_single_token_msg_1,
	ead_single_token_msg_2,
	ead_single_token_msg_3,
};

static const struct edhoc_ead_token ead_multiple_tokens_msg_2[] = {
	ead_single_token_msg_3,
	ead_single_token_msg_1,
};

static const struct edhoc_ead_token ead_multiple_tokens_msg_3[] = {
	ead_single_token_msg_3,
	ead_single_token_msg_2,
	ead_single_token_msg_1,
};

static const struct edhoc_ead_token ead_multiple_tokens_msg_4[] = {
	ead_single_token_msg_1,
	ead_single_token_msg_4,
	ead_single_token_msg_3,
};

/* Static function definitions --------------------------------------------- */

static int edhoc_cipher_suite_0_make_key_pair_init(
	void *user_ctx, const void *kid, uint8_t *priv_key,
	size_t priv_key_size, size_t *priv_key_len, uint8_t *pub_key,
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

static int edhoc_cipher_suite_0_make_key_pair_resp(
	void *user_ctx, const void *kid, uint8_t *priv_key,
	size_t priv_key_size, size_t *priv_key_len, uint8_t *pub_key,
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

	const int res = edhoc_cipher_suite_0_key_import(NULL,
							EDHOC_KT_SIGNATURE,
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

	if (NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	auth_cred->label = EDHOC_COSE_ANY;
	auth_cred->any.id_cred = ID_CRED_I_cborised;
	auth_cred->any.id_cred_len = ARRAY_SIZE(ID_CRED_I_cborised);
	auth_cred->any.cred = CRED_I_cborised;
	auth_cred->any.cred_len = ARRAY_SIZE(CRED_I_cborised);

	const int res = edhoc_cipher_suite_0_key_import(NULL,
							EDHOC_KT_SIGNATURE,
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

	const int res = edhoc_cipher_suite_0_key_import(NULL,
							EDHOC_KT_SIGNATURE,
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

	if (NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	auth_cred->label = EDHOC_COSE_ANY;
	auth_cred->any.id_cred = ID_CRED_R_cborised;
	auth_cred->any.id_cred_len = ARRAY_SIZE(ID_CRED_R_cborised);
	auth_cred->any.cred = CRED_R_cborised;
	auth_cred->any.cred_len = ARRAY_SIZE(CRED_R_cborised);

	const int res = edhoc_cipher_suite_0_key_import(NULL,
							EDHOC_KT_SIGNATURE,
							SK_R, ARRAY_SIZE(SK_R),
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

static int ead_compose_single_token(void *user_ctx, enum edhoc_message msg,
				    struct edhoc_ead_token *ead_token,
				    size_t ead_token_size,
				    size_t *ead_token_len)
{
	if (NULL == user_ctx || NULL == ead_token || 0 == ead_token_size ||
	    NULL == ead_token_len)
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;

	const struct edhoc_ead_token *token = NULL;

	switch (msg) {
	case EDHOC_MSG_1:
		token = &ead_single_token_msg_1;
		break;
	case EDHOC_MSG_2:
		token = &ead_single_token_msg_2;
		break;
	case EDHOC_MSG_3:
		token = &ead_single_token_msg_3;
		break;
	case EDHOC_MSG_4:
		token = &ead_single_token_msg_4;
		break;
	default:
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	ead_token[0] = *token;
	*ead_token_len = 1;

	struct ead_context *ead_ctx = user_ctx;

	ead_ctx->msg = msg;
	ead_ctx->recv_tokens = 1;

	for (size_t i = 0; i < ead_ctx->recv_tokens; ++i) {
		ead_ctx->token[i].label = ead_token[i].label;
		ead_ctx->token[i].value_len = ead_token[i].value_len;
		memcpy(ead_ctx->token[i].value, ead_token[i].value,
		       ead_token[i].value_len);
	}

	return EDHOC_SUCCESS;
}

static int ead_process_single_token(void *user_ctx, enum edhoc_message msg,
				    const struct edhoc_ead_token *ead_token,
				    size_t ead_token_size)
{
	if (NULL == user_ctx || NULL == ead_token || 0 == ead_token_size)
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;

	struct ead_context *ead_ctx = user_ctx;

	ead_ctx->msg = msg;
	ead_ctx->recv_tokens = ead_token_size;

	for (size_t i = 0; i < ead_token_size; ++i) {
		ead_ctx->token[i].label = ead_token[i].label;
		ead_ctx->token[i].value_len = ead_token[i].value_len;
		memcpy(ead_ctx->token[i].value, ead_token[i].value,
		       ead_token[i].value_len);
	}

	return EDHOC_SUCCESS;
}

static int ead_compose_multiple_tokens(void *user_ctx, enum edhoc_message msg,
				       struct edhoc_ead_token *ead_token,
				       size_t ead_token_size,
				       size_t *ead_token_len)
{
	if (NULL == user_ctx || NULL == ead_token || 0 == ead_token_size ||
	    NULL == ead_token_len)
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;

	size_t len = 0;
	const struct edhoc_ead_token *token = NULL;

	switch (msg) {
	case EDHOC_MSG_1:
		token = ead_multiple_tokens_msg_1;
		len = ARRAY_SIZE(ead_multiple_tokens_msg_1);
		break;
	case EDHOC_MSG_2:
		token = ead_multiple_tokens_msg_2;
		len = ARRAY_SIZE(ead_multiple_tokens_msg_2);
		break;
	case EDHOC_MSG_3:
		token = ead_multiple_tokens_msg_3;
		len = ARRAY_SIZE(ead_multiple_tokens_msg_3);
		break;
	case EDHOC_MSG_4:
		token = ead_multiple_tokens_msg_4;
		len = ARRAY_SIZE(ead_multiple_tokens_msg_4);
		break;
	default:
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	*ead_token_len = len;

	for (size_t i = 0; i < len; ++i)
		ead_token[i] = token[i];

	struct ead_context *ead_ctx = user_ctx;

	ead_ctx->msg = msg;
	ead_ctx->recv_tokens = len;

	for (size_t i = 0; i < ead_ctx->recv_tokens; ++i) {
		ead_ctx->token[i].label = ead_token[i].label;
		ead_ctx->token[i].value_len = ead_token[i].value_len;
		memcpy(ead_ctx->token[i].value, ead_token[i].value,
		       ead_token[i].value_len);
	}

	return EDHOC_SUCCESS;
}

static int ead_process_multiple_tokens(void *user_ctx, enum edhoc_message msg,
				       const struct edhoc_ead_token *ead_token,
				       size_t ead_token_size)
{
	if (NULL == user_ctx || NULL == ead_token || 0 == ead_token_size)
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;

	struct ead_context *ead_ctx = user_ctx;

	ead_ctx->msg = msg;
	ead_ctx->recv_tokens = ead_token_size;

	for (size_t i = 0; i < ead_token_size; ++i) {
		ead_ctx->token[i].label = ead_token[i].label;
		ead_ctx->token[i].value_len = ead_token[i].value_len;
		memcpy(ead_ctx->token[i].value, ead_token[i].value,
		       ead_token[i].value_len);
	}

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(rfc9529_chapter_2);

TEST_SETUP(rfc9529_chapter_2)
{
	ret = psa_crypto_init();
	TEST_ASSERT_EQUAL(PSA_SUCCESS, ret);
	edhoc_keys = edhoc_cipher_suite_0_get_keys();

	const enum edhoc_method methods[] = { METHOD };
	const struct edhoc_cipher_suite cipher_suites[] = {
		edhoc_cipher_suite_0,
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

	ret = edhoc_bind_keys(init_ctx, edhoc_keys);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(init_ctx, &edhoc_crypto_mocked_init);
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

	ret = edhoc_bind_keys(resp_ctx, edhoc_keys);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(resp_ctx, &edhoc_crypto_mocked_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(resp_ctx, &edhoc_auth_cred_mocked_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_TEAR_DOWN(rfc9529_chapter_2)
{
	mbedtls_psa_crypto_free();

	ret = edhoc_context_deinit(init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(rfc9529_chapter_2, message_1_compose)
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

TEST(rfc9529_chapter_2, message_1_process)
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

TEST(rfc9529_chapter_2, message_2_compose)
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

TEST(rfc9529_chapter_2, message_2_compose_any)
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

TEST(rfc9529_chapter_2, message_2_process)
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

	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_BYTE_STRING,
			  init_ctx->peer_cid.encode_type);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(C_R), init_ctx->peer_cid.bstr_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(C_R, init_ctx->peer_cid.bstr_value,
				      init_ctx->peer_cid.bstr_length);
}

TEST(rfc9529_chapter_2, message_3_compose)
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

TEST(rfc9529_chapter_2, message_3_compose_any)
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

TEST(rfc9529_chapter_2, message_3_process)
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

TEST(rfc9529_chapter_2, message_4_compose)
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

TEST(rfc9529_chapter_2, message_4_process)
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

TEST(rfc9529_chapter_2, handshake)
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
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_out), init_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_out, init_ctx->prk,
				      init_ctx->prk_len);

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
	TEST_ASSERT_EQUAL(ARRAY_SIZE(PRK_out), resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(PRK_out, resp_ctx->prk,
				      resp_ctx->prk_len);

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

TEST(rfc9529_chapter_2, prk_exporter)
{
	/* Required injections. */
	init_ctx->status = EDHOC_SM_COMPLETED;

	init_ctx->th_state = EDHOC_TH_STATE_4;
	init_ctx->th_len = ARRAY_SIZE(TH_4);
	memcpy(init_ctx->th, TH_4, ARRAY_SIZE(TH_4));

	init_ctx->prk_state = EDHOC_PRK_STATE_4E3M;
	init_ctx->prk_len = ARRAY_SIZE(PRK_4e3m);
	memcpy(init_ctx->prk, PRK_4e3m, ARRAY_SIZE(PRK_4e3m));

	uint8_t master_secret[ARRAY_SIZE(OSCORE_Master_Secret)] = { 0 };

	/* EDHOC PRK exporter - OSCORE master secret. */
	ret = edhoc_export_prk_exporter(init_ctx,
					OSCORE_EXTRACT_LABEL_MASTER_SECRET,
					master_secret,
					ARRAY_SIZE(master_secret));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_Master_Secret, master_secret,
				      ARRAY_SIZE(OSCORE_Master_Secret));

	uint8_t master_salt[ARRAY_SIZE(OSCORE_Master_Salt)] = { 0 };

	/* EDHOC PRK exporter - OSCORE master salt. */
	ret = edhoc_export_prk_exporter(init_ctx,
					OSCORE_EXTRACT_LABEL_MASTER_SALT,
					master_salt, ARRAY_SIZE(master_salt));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(OSCORE_Master_Salt, master_salt,
				      ARRAY_SIZE(OSCORE_Master_Salt));

	/* Export private usage secrets (label: minimum, middle, maximum). */
	uint8_t secret_1[13] = { 0 };
	uint8_t secret_2[32] = { 0 };
	uint8_t secret_3[64] = { 0 };

	ret = edhoc_export_prk_exporter(
		init_ctx, EDHOC_PRK_EXPORTER_PRIVATE_LABEL_MINIMUM, secret_1,
		ARRAY_SIZE(secret_1));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_export_prk_exporter(
		init_ctx, EDHOC_PRK_EXPORTER_PRIVATE_LABEL_MAXIMUM, secret_2,
		ARRAY_SIZE(secret_2));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const size_t label = 45737;
	ret = edhoc_export_prk_exporter(init_ctx, label, secret_3,
					ARRAY_SIZE(secret_3));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(rfc9529_chapter_2, handshake_real_crypto)
{
	uint8_t buffer[200] = { 0 };

	/* Required injections. */
	ret = edhoc_bind_crypto(init_ctx, &edhoc_crypto);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(resp_ctx, &edhoc_crypto);
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

	TEST_ASSERT_EQUAL(edhoc_cipher_suite_0.ecc_key_length,
			  init_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_0.ecc_key_length,
			  resp_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL(init_ctx->dh_secret_len, resp_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->dh_secret, resp_ctx->dh_secret,
				      edhoc_cipher_suite_0.ecc_key_length);

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

	TEST_ASSERT_EQUAL(edhoc_cipher_suite_0.hash_length, init_ctx->th_len);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_0.hash_length, resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->th, resp_ctx->th,
				      edhoc_cipher_suite_0.hash_length);

	TEST_ASSERT_EQUAL(edhoc_cipher_suite_0.mac_length, init_ctx->prk_len);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_0.mac_length, resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->prk, resp_ctx->prk,
				      edhoc_cipher_suite_0.mac_length);

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

	TEST_ASSERT_EQUAL(init_ctx->prk_len, resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->prk, resp_ctx->prk,
				      resp_ctx->prk_len);

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

TEST(rfc9529_chapter_2, handshake_real_crypto_ead_single)
{
	uint8_t buffer[500] = { 0 };

	/* Required injections. */
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

	TEST_ASSERT_EQUAL(edhoc_cipher_suite_0.ecc_key_length,
			  init_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_0.ecc_key_length,
			  resp_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL(init_ctx->dh_secret_len, resp_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->dh_secret, resp_ctx->dh_secret,
				      edhoc_cipher_suite_0.ecc_key_length);

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
}

TEST(rfc9529_chapter_2, handshake_real_crypto_ead_many)
{
	uint8_t buffer[1000] = { 0 };

	/* Required injections. */
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
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ead_multiple_tokens_msg_1),
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
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ead_multiple_tokens_msg_1),
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
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ead_multiple_tokens_msg_2),
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
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ead_multiple_tokens_msg_2),
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

	TEST_ASSERT_EQUAL(edhoc_cipher_suite_0.ecc_key_length,
			  init_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL(edhoc_cipher_suite_0.ecc_key_length,
			  resp_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL(init_ctx->dh_secret_len, resp_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->dh_secret, resp_ctx->dh_secret,
				      edhoc_cipher_suite_0.ecc_key_length);

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
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ead_multiple_tokens_msg_3),
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
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ead_multiple_tokens_msg_3),
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
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ead_multiple_tokens_msg_4),
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
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ead_multiple_tokens_msg_4),
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
}

TEST_GROUP_RUNNER(rfc9529_chapter_2)
{
	RUN_TEST_CASE(rfc9529_chapter_2, message_1_compose);
	RUN_TEST_CASE(rfc9529_chapter_2, message_1_process);
	RUN_TEST_CASE(rfc9529_chapter_2, message_2_compose);
	RUN_TEST_CASE(rfc9529_chapter_2, message_2_compose_any);
	RUN_TEST_CASE(rfc9529_chapter_2, message_2_process);
	RUN_TEST_CASE(rfc9529_chapter_2, message_3_compose);
	RUN_TEST_CASE(rfc9529_chapter_2, message_3_compose_any);
	RUN_TEST_CASE(rfc9529_chapter_2, message_3_process);
	RUN_TEST_CASE(rfc9529_chapter_2, message_4_compose);
	RUN_TEST_CASE(rfc9529_chapter_2, message_4_process);
	RUN_TEST_CASE(rfc9529_chapter_2, handshake);
	RUN_TEST_CASE(rfc9529_chapter_2, prk_exporter);
	RUN_TEST_CASE(rfc9529_chapter_2, handshake_real_crypto);
	RUN_TEST_CASE(rfc9529_chapter_2, handshake_real_crypto_ead_single);
	RUN_TEST_CASE(rfc9529_chapter_2, handshake_real_crypto_ead_many);
}
