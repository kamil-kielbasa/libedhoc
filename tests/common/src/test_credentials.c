/**
 * \file    test_credentials.c
 * \author  Kamil Kielbasa
 * \brief   Shared credential callback stubs for tests.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#include "test_credentials.h"
#include <string.h>

int test_auth_cred_fetch_stub(void *user_ctx,
			      struct edhoc_auth_credentials *auth_cred)
{
	(void)user_ctx;

	if (NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.certificate_count = 1;

	static const uint8_t dummy_cert[] = { 0x30, 0x00 };
	auth_cred->x509_chain.certificate[0] = dummy_cert;
	auth_cred->x509_chain.certificate_length[0] = sizeof(dummy_cert);
	memset(auth_cred->private_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);

	return EDHOC_SUCCESS;
}

int test_auth_cred_verify_stub(void *user_ctx,
			       struct edhoc_auth_credentials *auth_cred,
			       const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;
	(void)auth_cred;

	if (NULL == pub_key || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	static const uint8_t dummy_key[32] = { 0 };
	*pub_key = dummy_key;
	*pub_key_len = sizeof(dummy_key);

	return EDHOC_SUCCESS;
}

const struct edhoc_credentials test_cred_stubs = {
	.fetch = test_auth_cred_fetch_stub,
	.verify = test_auth_cred_verify_stub,
};
