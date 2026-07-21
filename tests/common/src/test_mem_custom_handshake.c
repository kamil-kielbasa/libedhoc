/**
 * \file    test_mem_custom_handshake.c
 * \author  Kamil Kielbasa
 * \brief   Shared cipher suite 0 handshake harness for the custom memory
 *          backend tests.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Internal test header: */
#include "test_platform.h"
#include "test_mem_custom_handshake.h"

/* Test vector header: */
#include "test_vector_x5chain_sign_keys_suite_0.h"

/* Cipher suite 0 header: */
#include "edhoc_cipher_suite_0.h"

/* EDHOC header: */
#include <edhoc/edhoc.h>
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Memory backend facade: */
#include "edhoc_backend_memory.h"

/* Standard library headers: */
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#if CONFIG_LIBEDHOC_MEM_BACKEND == EDHOC_MEM_BACKEND_CUSTOM

/* Module defines ---------------------------------------------------------- */
#define HANDSHAKE_BUFFER_LENGTH (1000)
#define OSCORE_MASTER_SECRET_LENGTH (16)
#define OSCORE_MASTER_SALT_LENGTH (8)

/* Module types and type definitions --------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

static int import_sign_priv_key(const uint8_t *priv, size_t priv_len,
				uint8_t *key_id);
static int auth_cred_fetch_init(void *user_ctx,
				struct edhoc_auth_creds *auth_cred);
static int auth_cred_fetch_resp(void *user_ctx,
				struct edhoc_auth_creds *auth_cred);
static int auth_cred_verify_init(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred,
				 const uint8_t **pub_key, size_t *pub_key_len);
static int auth_cred_verify_resp(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred,
				 const uint8_t **pub_key, size_t *pub_key_len);

/* Static function definitions --------------------------------------------- */

/* Import a 64-byte Ed25519 private key (seed||pub) as an exportable RAW_DATA
 * key: cipher suite 0 exports it and signs with Compact25519. */
static int import_sign_priv_key(const uint8_t *priv, size_t priv_len,
				uint8_t *key_id)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
	psa_set_key_type(&attr, PSA_KEY_TYPE_RAW_DATA);

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	const psa_status_t status = psa_import_key(&attr, priv, priv_len, &kid);
	if (PSA_SUCCESS != status)
		return EDHOC_ERROR_CRYPTO_FAILURE;

	memcpy(key_id, &kid, sizeof(kid));
	return EDHOC_SUCCESS;
}

static int auth_cred_fetch_init(void *user_ctx,
				struct edhoc_auth_creds *auth_cred)
{
	(void)user_ctx;

	if (NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.nr_of_certs = 1;
	auth_cred->x509_chain.cert[0] = CRED_I;
	auth_cred->x509_chain.cert_len[0] = ARRAY_SIZE(CRED_I);

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

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.nr_of_certs = 1;
	auth_cred->x509_chain.cert[0] = CRED_R;
	auth_cred->x509_chain.cert_len[0] = ARRAY_SIZE(CRED_R);

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

	if (EDHOC_COSE_HEADER_X509_CHAIN != auth_cred->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (1 != auth_cred->x509_chain.nr_of_certs)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (auth_cred->x509_chain.cert_len[0] != ARRAY_SIZE(CRED_R))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (0 != memcmp(CRED_R, auth_cred->x509_chain.cert[0],
			auth_cred->x509_chain.cert_len[0]))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

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

	if (EDHOC_COSE_HEADER_X509_CHAIN != auth_cred->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (1 != auth_cred->x509_chain.nr_of_certs)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (auth_cred->x509_chain.cert_len[0] != ARRAY_SIZE(CRED_I))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (0 != memcmp(CRED_I, auth_cred->x509_chain.cert[0],
			auth_cred->x509_chain.cert_len[0]))
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	*pub_key = PK_I;
	*pub_key_len = ARRAY_SIZE(PK_I);

	return EDHOC_SUCCESS;
}

static const struct edhoc_credentials cred_init = {
	.fetch = auth_cred_fetch_init,
	.verify = auth_cred_verify_init,
};

static const struct edhoc_credentials cred_resp = {
	.fetch = auth_cred_fetch_resp,
	.verify = auth_cred_verify_resp,
};

/* Module interface function definitions ----------------------------------- */

int test_mem_custom_setup_contexts(struct edhoc_context *initiator,
				   struct edhoc_context *responder)
{
	const enum edhoc_method methods[] = { METHOD };
	const struct edhoc_cipher_suite cipher_suites[] = {
		*edhoc_cipher_suite_0_get_suite(),
	};

	const struct edhoc_connection_id init_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_I[0],
	};

	struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = ARRAY_SIZE(C_R),
	};

	int rc = 0;

	memcpy(&resp_cid.bstr_value, C_R, ARRAY_SIZE(C_R));

	rc = edhoc_context_init(initiator);
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_set_methods(initiator, methods, ARRAY_SIZE(methods));
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_set_cipher_suites(initiator, cipher_suites,
				     ARRAY_SIZE(cipher_suites));
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_set_connection_id(initiator, &init_cid);
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_bind_crypto(initiator, edhoc_cipher_suite_0_get_crypto());
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_bind_platform(initiator, test_get_platform());
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_bind_credentials(initiator, &cred_init);
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_context_init(responder);
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_set_methods(responder, methods, ARRAY_SIZE(methods));
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_set_cipher_suites(responder, cipher_suites,
				     ARRAY_SIZE(cipher_suites));
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_set_connection_id(responder, &resp_cid);
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_bind_crypto(responder, edhoc_cipher_suite_0_get_crypto());
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_bind_platform(responder, test_get_platform());
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_bind_credentials(responder, &cred_resp);
	if (EDHOC_SUCCESS != rc)
		return rc;

	return EDHOC_SUCCESS;
}

int test_mem_custom_drive_handshake(struct edhoc_context *initiator,
				    struct edhoc_context *responder)
{
	uint8_t buffer[HANDSHAKE_BUFFER_LENGTH];
	size_t msg_len = 0;
	int rc;

	memset(buffer, 0, sizeof(buffer));
	rc = edhoc_message_1_compose(initiator, buffer, sizeof(buffer),
				     &msg_len);
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_message_1_process(responder, buffer, msg_len);
	if (EDHOC_SUCCESS != rc)
		return rc;

	memset(buffer, 0, sizeof(buffer));
	rc = edhoc_message_2_compose(responder, buffer, sizeof(buffer),
				     &msg_len);
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_message_2_process(initiator, buffer, msg_len);
	if (EDHOC_SUCCESS != rc)
		return rc;

	memset(buffer, 0, sizeof(buffer));
	rc = edhoc_message_3_compose(initiator, buffer, sizeof(buffer),
				     &msg_len);
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_message_3_process(responder, buffer, msg_len);
	if (EDHOC_SUCCESS != rc)
		return rc;

	memset(buffer, 0, sizeof(buffer));
	rc = edhoc_message_4_compose(responder, buffer, sizeof(buffer),
				     &msg_len);
	if (EDHOC_SUCCESS != rc)
		return rc;

	rc = edhoc_message_4_process(initiator, buffer, msg_len);
	if (EDHOC_SUCCESS != rc)
		return rc;

	uint8_t init_master_secret[OSCORE_MASTER_SECRET_LENGTH] = { 0 };
	uint8_t init_master_salt[OSCORE_MASTER_SALT_LENGTH] = { 0 };
	size_t init_sender_id_len = 0;
	uint8_t init_sender_id[ARRAY_SIZE(C_R)] = { 0 };
	size_t init_recipient_id_len = 0;
	uint8_t init_recipient_id[ARRAY_SIZE(C_I)] = { 0 };

	rc = edhoc_export_oscore_session_raw(
		initiator, init_master_secret, ARRAY_SIZE(init_master_secret),
		init_master_salt, ARRAY_SIZE(init_master_salt), init_sender_id,
		ARRAY_SIZE(init_sender_id), &init_sender_id_len,
		init_recipient_id, ARRAY_SIZE(init_recipient_id),
		&init_recipient_id_len);
	if (EDHOC_SUCCESS != rc)
		return rc;

	uint8_t resp_master_secret[OSCORE_MASTER_SECRET_LENGTH] = { 0 };
	uint8_t resp_master_salt[OSCORE_MASTER_SALT_LENGTH] = { 0 };
	size_t resp_sender_id_len = 0;
	uint8_t resp_sender_id[ARRAY_SIZE(C_I)] = { 0 };
	size_t resp_recipient_id_len = 0;
	uint8_t resp_recipient_id[ARRAY_SIZE(C_R)] = { 0 };

	rc = edhoc_export_oscore_session_raw(
		responder, resp_master_secret, ARRAY_SIZE(resp_master_secret),
		resp_master_salt, ARRAY_SIZE(resp_master_salt), resp_sender_id,
		ARRAY_SIZE(resp_sender_id), &resp_sender_id_len,
		resp_recipient_id, ARRAY_SIZE(resp_recipient_id),
		&resp_recipient_id_len);
	if (EDHOC_SUCCESS != rc)
		return rc;

	if (0 != memcmp(init_master_secret, resp_master_secret,
			ARRAY_SIZE(resp_master_secret)))
		return EDHOC_ERROR_GENERIC_ERROR;

	if (0 != memcmp(init_master_salt, resp_master_salt,
			ARRAY_SIZE(resp_master_salt)))
		return EDHOC_ERROR_GENERIC_ERROR;

	if (init_sender_id_len != resp_recipient_id_len)
		return EDHOC_ERROR_GENERIC_ERROR;

	if (0 != memcmp(init_sender_id, resp_recipient_id, init_sender_id_len))
		return EDHOC_ERROR_GENERIC_ERROR;

	if (init_recipient_id_len != resp_sender_id_len)
		return EDHOC_ERROR_GENERIC_ERROR;

	if (0 != memcmp(init_recipient_id, resp_sender_id, resp_sender_id_len))
		return EDHOC_ERROR_GENERIC_ERROR;

	return EDHOC_SUCCESS;
}

#endif /* EDHOC_MEM_BACKEND_CUSTOM */
