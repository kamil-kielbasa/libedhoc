/**
 * @file    test_credentials.h
 * @author  Kamil Kielbasa
 * @brief   Test credentials for EDHOC.
 * @version 0.1
 * @date    2024-01-01
 * 
 * @copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_CREDENTIALS_H
#define TEST_CREDENTIALS_H

/* Include files ----------------------------------------------------------- */
#include "edhoc_credentials.h"

/* standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Credentials fetch for initiator for X509 chain authentication method.
 */
int test_cred_fetch_init_x509_chain(void *user_ctx,
				    struct edhoc_auth_creds *credentials);

/**
 * \brief Credentials fetch for responder for X509 chain authentication method.
 */
int test_cred_fetch_resp_x509_chain(void *user_ctx,
				    struct edhoc_auth_creds *credentials);

/**
 * \brief Mocked credentials verify for initiator for X509 chain authentication method.
 */
int test_cred_verify_init_mocked_x509_chain(void *user_ctx,
					    struct edhoc_auth_creds *auth_creds,
					    const uint8_t **public_key,
					    size_t *public_key_length);

/**
 * \brief Mocked credentials verify for responder for X509 chain authentication method.
 */
int test_cred_verify_resp_mocked_x509_chain(void *user_ctx,
					    struct edhoc_auth_creds *auth_creds,
					    const uint8_t **public_key,
					    size_t *public_key_length);

/**
 * \brief Credentials verify for initiator for X509 chain authentication method.
 */
int test_cred_verify_init_x509_chain(void *user_ctx,
				     struct edhoc_auth_creds *creds,
				     const uint8_t **pub_key,
				     size_t *pub_key_len);

/**
 * \brief Credentials verify for responder for X509 chain authentication method.
 */
int test_cred_verify_resp_x509_chain(void *user_ctx,
				     struct edhoc_auth_creds *creds,
				     const uint8_t **pub_key,
				     size_t *pub_key_len);

/**
 * \brief Credentials fetch for initiator for X509 hash authentication method.
 */
int test_cred_fetch_init_x509_hash(void *user_ctx,
				   struct edhoc_auth_creds *credentials);

/**
 * \brief Credentials fetch for responder for X509 hash authentication method.
 */
int test_cred_fetch_resp_x509_hash(void *user_ctx,
				   struct edhoc_auth_creds *credentials);

/**
 * \brief Mocked credentials verify for initiator for X509 hash authentication method.
 */
int test_cred_verify_init_mocked_x509_hash(void *user_ctx,
					   struct edhoc_auth_creds *credentials,
					   const uint8_t **public_key,
					   size_t *public_key_length);

/**
 * \brief Mocked credentials verify for responder for X509 hash authentication method.
 */
int test_cred_verify_resp_mocked_x509_hash(void *user_ctx,
					   struct edhoc_auth_creds *credentials,
					   const uint8_t **public_key,
					   size_t *public_key_length);

/**
 * \brief Credentials verify for initiator for X509 hash authentication method.
 */
int test_cred_verify_init_x509_hash(void *user_ctx,
				    struct edhoc_auth_creds *credentials,
				    const uint8_t **public_key,
				    size_t *public_key_length);

/**
 * \brief Credentials verify for initiator for X509 hash authentication method.
 */
int test_cred_verify_resp_x509_hash(void *user_ctx,
				    struct edhoc_auth_creds *credentials,
				    const uint8_t **public_key,
				    size_t *public_key_length);

/**
 * \brief Credentials fetch for initiator for X509 kid authentication method.
 */
int test_cred_fetch_init_x509_kid(void *user_ctx,
				  struct edhoc_auth_creds *credentials);

/**
 * \brief Credentials fetch for responder for X509 kid authentication method.
 */
int test_cred_fetch_resp_x509_kid(void *user_ctx,
				  struct edhoc_auth_creds *credentials);

/**
 * \brief Mocked credentials verify for initiator for X509 kid authentication method.
 */
int test_cred_verify_init_mocked_x509_kid(void *user_ctx,
					  struct edhoc_auth_creds *credentials,
					  const uint8_t **public_key,
					  size_t *public_key_length);

/**
 * \brief Mocked credentials verify for responder for X509 kid authentication method.
 */
int test_cred_verify_resp_mocked_x509_kid(void *user_ctx,
					  struct edhoc_auth_creds *credentials,
					  const uint8_t **public_key,
					  size_t *public_key_length);

/**
 * \brief Mocked credentials verify for initiator for X509 kid authentication method.
 */
int test_cred_verify_init_x509_kid(void *user_ctx,
				   struct edhoc_auth_creds *credentials,
				   const uint8_t **public_key,
				   size_t *public_key_length);

/**
 * \brief Mocked credentials verify for responder for X509 kid authentication method.
 */
int test_cred_verify_resp_x509_kid(void *user_ctx,
				   struct edhoc_auth_creds *credentials,
				   const uint8_t **public_key,
				   size_t *public_key_length);

#endif /* TEST_CREDENTIALS_H */