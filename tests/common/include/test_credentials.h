/**
 * \file    test_credentials.h
 * \author  Kamil Kielbasa
 * \brief   Shared credential callback stubs for tests.
 *
 * \copyright Copyright (c) 2026
 *
 */

#ifndef TEST_CREDENTIALS_H
#define TEST_CREDENTIALS_H

#include <edhoc/edhoc.h>

/**
 * \brief Credential fetch stub that returns a minimal x509 chain credential.
 */
int test_auth_cred_fetch_stub(void *user_ctx,
			      struct edhoc_auth_credentials *auth_cred);

/**
 * \brief Credential verify stub that returns a dummy 32-byte public key.
 */
int test_auth_cred_verify_stub(void *user_ctx,
			       struct edhoc_auth_credentials *auth_cred,
			       const uint8_t **pub_key, size_t *pub_key_len);

extern const struct edhoc_credentials test_cred_stubs;

#endif /* TEST_CREDENTIALS_H */
