/**
 * \file    authentication_credentials_1.c
 * \author  Kamil Kielbasa
 * \brief   Example implementation of authentication credentials callbacks.
 * \version 0.3
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Internal test headers: */
#include "edhoc_trace_1/authentication_credentials_1.h"
#include "edhoc_trace_1/test_vector_1.h"
#include "cipher_suites/cipher_suite_0.h"

/* Standard library headers: */
#include <stdio.h>
#include <string.h>

/* EDHOC headers: */
#include "edhoc_credentials.h"
#include "edhoc_values.h"
#include "edhoc_macros.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Module defines ---------------------------------------------------------- */
#define COSE_ALG_SHA_256_64 (-15)
#define CBOR_ENC_COSE_ALG_SHA_256_64 (0x2e)

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Helper function for printing arrays.
 */
static inline void print_array(const char *name, const uint8_t *buffer,
			       size_t buffer_length);

/* Static function definitions --------------------------------------------- */

static inline void print_array(const char *name, const uint8_t *buffer,
			       size_t buffer_length)
{
	printf("%s:\tLEN( %zu )\n", name, buffer_length);

	for (size_t i = 0; i < buffer_length; ++i) {
		if (0 == i % 16 && i > 0) {
			printf("\n");
		}

		printf("%02x ", buffer[i]);
	}

	printf("\n\n");
}

/* Module interface function definitions ----------------------------------- */

int auth_cred_fetch_init(void *user_ctx, struct edhoc_auth_creds *auth_cred)
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

	const int ret = cipher_suite_0_key_generate(EDHOC_KT_SIGNATURE, SK_I,
						    ARRAY_SIZE(SK_I),
						    auth_cred->priv_key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

int auth_cred_fetch_resp(void *user_ctx, struct edhoc_auth_creds *auth_cred)
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

	const int ret = cipher_suite_0_key_generate(EDHOC_KT_SIGNATURE, SK_R,
						    ARRAY_SIZE(SK_R),
						    auth_cred->priv_key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

int auth_cred_verify_init(void *user_ctx, struct edhoc_auth_creds *auth_cred,
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
	printf("Recived alg: %d\n\n", auth_cred->x509_hash.alg_int);
	printf("Expected alg: %d\n\n", COSE_ALG_SHA_256_64);

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

	print_array("Received fingerprint", auth_cred->x509_hash.cert_fp,
		    auth_cred->x509_hash.cert_fp_len);
	print_array("Expected fingerprint", cert_fp, ARRAY_SIZE(cert_fp));

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

int auth_cred_verify_resp(void *user_ctx, struct edhoc_auth_creds *auth_cred,
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
	printf("Recived alg: %d\n\n", auth_cred->x509_hash.alg_int);
	printf("Expected alg: %d\n\n", COSE_ALG_SHA_256_64);

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

	print_array("Received fingerprint", auth_cred->x509_hash.cert_fp,
		    auth_cred->x509_hash.cert_fp_len);
	print_array("Expected fingerprint", cert_fp, ARRAY_SIZE(cert_fp));

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
