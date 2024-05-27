/**
 * \file    authentication_credentials_x5chain.c
 * \author  Kamil Kielbasa
 * \brief   Example implementation of authentication credentials callbacks
 *          for X.509 chain authenticatoon method.
 * \version 0.3
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Internal test headers: */
#include "x509_chain/authentication_credentials_x5chain.h"
#include "x509_chain/test_vector_x5chain.h"
#include "cipher_suites/cipher_suite_0.h"

/* Standard library header: */
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
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

int auth_cred_fetch_init_x5chain(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	if (NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.cert = CRED_I;
	auth_cred->x509_chain.cert_len = ARRAY_SIZE(CRED_I);

	const int ret = cipher_suite_0_key_generate(NULL, EDHOC_KT_SIGNATURE,
						    SK_I, ARRAY_SIZE(SK_I),
						    auth_cred->priv_key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

int auth_cred_fetch_resp_x5chain(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	if (NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.cert = CRED_R;
	auth_cred->x509_chain.cert_len = ARRAY_SIZE(CRED_R);

	const int ret = cipher_suite_0_key_generate(NULL, EDHOC_KT_SIGNATURE,
						    SK_R, ARRAY_SIZE(SK_R),
						    auth_cred->priv_key_id);

	if (EDHOC_SUCCESS != ret)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	return EDHOC_SUCCESS;
}

int auth_cred_verify_init_x5chain(void *user_ctx,
				  struct edhoc_auth_creds *auth_cred,
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
         * \brief Verify received peer certificate length. 
         */
	if (auth_cred->x509_chain.cert_len != ARRAY_SIZE(CRED_R))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief Verify received peer certificate. 
         */
	if (0 != memcmp(CRED_R, auth_cred->x509_chain.cert,
			auth_cred->x509_chain.cert_len))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief If successful then assign public key. 
         */
	*pub_key = PK_R;
	*pub_key_len = ARRAY_SIZE(PK_R);

	return EDHOC_SUCCESS;
}

int auth_cred_verify_resp_x5chain(void *user_ctx,
				  struct edhoc_auth_creds *auth_cred,
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
         * \brief Verify received peer certificate length. 
         */
	if (auth_cred->x509_chain.cert_len != ARRAY_SIZE(CRED_I))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief Verify received peer certificate. 
         */
	if (0 != memcmp(CRED_I, auth_cred->x509_chain.cert,
			auth_cred->x509_chain.cert_len))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	/**
         * \brief If successful then assign public key. 
         */
	*pub_key = PK_I;
	*pub_key_len = ARRAY_SIZE(PK_I);

	return EDHOC_SUCCESS;
}
