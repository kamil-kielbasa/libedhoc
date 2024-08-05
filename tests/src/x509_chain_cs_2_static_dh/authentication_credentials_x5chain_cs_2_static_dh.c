/**
 * \file    authentication_credentials_x5chain_cs_2_static_dh.c
 * \author  Kamil Kielbasa
 * \brief   Example implementation of authentication credentials callbacks.
 * \version 0.5
 * \date    2024-08-05
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Internal test headers: */
#include "x509_chain_cs_2_static_dh/authentication_credentials_x5chain_cs_2_static_dh.h"
#include "x509_chain_cs_2_static_dh/test_vector_x5chain_cs_2_static_dh.h"
#include "cipher_suites/cipher_suite_2.h"

/* Standard library headers: */
#include <stdio.h>
#include <string.h>

/* EDHOC headers: */
#include "edhoc_credentials.h"
#include "edhoc_values.h"
#include "edhoc_macros.h"

/* Module defines ---------------------------------------------------------- */
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

int auth_cred_fetch_init_x5chain_cs_2_static_dh(
	void *user_ctx, struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.nr_of_certs = 1;
	auth_cred->x509_chain.cert[0] = CRED_I;
	auth_cred->x509_chain.cert_len[0] = ARRAY_SIZE(CRED_I);

	const int ret = cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
						  SK_I, ARRAY_SIZE(SK_I),
						  auth_cred->priv_key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

int auth_cred_fetch_resp_x5chain_cs_2_static_dh(
	void *user_ctx, struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.nr_of_certs = 1;
	auth_cred->x509_chain.cert[0] = CRED_R;
	auth_cred->x509_chain.cert_len[0] = ARRAY_SIZE(CRED_R);

	const int ret = cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
						  SK_R, ARRAY_SIZE(SK_R),
						  auth_cred->priv_key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

int auth_cred_verify_init_x5chain_cs_2_static_dh(
	void *user_ctx, struct edhoc_auth_creds *auth_cred,
	const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == auth_cred || NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	/**
         * \brief Verify COSE header label value. 
         */
	if (EDHOC_COSE_HEADER_X509_CHAIN != auth_cred->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief Verify received number of certificates. 
         */
	if (1 != auth_cred->x509_chain.nr_of_certs)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief Verify received peer certificate length. 
         */
	if (auth_cred->x509_chain.cert_len[0] != ARRAY_SIZE(CRED_R))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief Verify received peer certificate. 
         */
	if (0 != memcmp(CRED_R, auth_cred->x509_chain.cert[0],
			auth_cred->x509_chain.cert_len[0]))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief If successful then assign public key. 
         */
	*pub_key = PK_R;
	*pub_key_len = ARRAY_SIZE(PK_R);

	return EDHOC_SUCCESS;
}

int auth_cred_verify_resp_x5chain_cs_2_static_dh(
	void *user_ctx, struct edhoc_auth_creds *auth_cred,
	const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == auth_cred || NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	/**
         * \brief Verify COSE header label value. 
         */
	if (EDHOC_COSE_HEADER_X509_CHAIN != auth_cred->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief Verify received number of certificates. 
         */
	if (1 != auth_cred->x509_chain.nr_of_certs)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief Verify received peer certificate length. 
         */
	if (auth_cred->x509_chain.cert_len[0] != ARRAY_SIZE(CRED_I))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief Verify received peer certificate. 
         */
	if (0 != memcmp(CRED_I, auth_cred->x509_chain.cert[0],
			auth_cred->x509_chain.cert_len[0]))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief If successful then assign public key. 
         */
	*pub_key = PK_I;
	*pub_key_len = ARRAY_SIZE(PK_I);

	return EDHOC_SUCCESS;
}
