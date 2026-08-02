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
#include "edhoc_macros_internal.h"
#include <string.h>

int test_auth_cred_fetch_stub(void *user_ctx,
			      struct edhoc_auth_credentials *auth_cred)
{
	(void)user_ctx;

	if (NULL == auth_cred) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->format = EDHOC_CREDENTIAL_FORMAT_RAW;
	auth_cred->x509_chain.certificate_count = 1;

	static const uint8_t dummy_cert[] = { 0x30, 0x00 };
	auth_cred->x509_chain.certificate[0] = dummy_cert;
	auth_cred->x509_chain.certificate_length[0] = sizeof(dummy_cert);
	memset(auth_cred->private_key_id, 0, CONFIG_LIBEDHOC_KEY_ID_LEN);

	return EDHOC_SUCCESS;
}

int test_auth_cred_authenticate_peer_stub(
	void *user_ctx, const struct edhoc_call_context *call_ctx,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted)
{
	(void)user_ctx;
	(void)call_ctx;

	if (NULL == received || NULL == trusted) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_COSE_HEADER_X509_CHAIN != received->label ||
	    0 == received->x509_chain.count) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	trusted->credential = received->x509_chain.certificate[0];
	trusted->format = EDHOC_CREDENTIAL_FORMAT_RAW;

	static const uint8_t dummy_key[32] = { 0 };
	trusted->public_key.value = dummy_key;
	trusted->public_key.length = ARRAY_SIZE(dummy_key);

	return EDHOC_SUCCESS;
}

const struct edhoc_credentials test_cred_stubs = {
	.fetch = test_auth_cred_fetch_stub,
	.authenticate_peer = test_auth_cred_authenticate_peer_stub,
};
