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
#include "test_mem_custom_handshake.h"

/* Test vector header: */
#include "test_vector/test_vector.h"

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include <edhoc/cipher_suite.h>
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Standard library headers: */
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* Module defines ---------------------------------------------------------- */

#define HANDSHAKE_BUFFER_LENGTH (1000)
#define OSCORE_MASTER_SECRET_LENGTH (16)
#define OSCORE_MASTER_SALT_LENGTH (8)

/* Module types and type definitions --------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

static inline void test_platform_zeroize(void *buffer, size_t length);
static inline const struct edhoc_platform *test_get_platform(void);

static int import_sign_priv_key(const uint8_t *priv, size_t priv_len,
				uint8_t *key_id);
static int
auth_cred_select_local_init(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    struct edhoc_credential_selected *selected);
static int
auth_cred_select_local_resp(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    struct edhoc_credential_selected *selected);
static int auth_cred_authenticate_peer_init(
	void *user_ctx, const struct edhoc_call_context *call_ctx,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted);
static int auth_cred_authenticate_peer_resp(
	void *user_ctx, const struct edhoc_call_context *call_ctx,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted);

/* Static function definitions --------------------------------------------- */

/*
 * Memory wipe for tests. The suite runs under sanitizers and Valgrind rather
 * than an optimizer that may elide a plain wipe, so memset is enough here;
 * production code must still supply a non-elidable zeroize.
 */
static inline void test_platform_zeroize(void *buffer, size_t length)
{
	memset(buffer, 0, length);
}

static inline const struct edhoc_platform *test_get_platform(void)
{
	static const struct edhoc_platform platform = {
		.zeroize = test_platform_zeroize,
	};

	return &platform;
}

/*
 * Import a 64-byte Ed25519 private key (seed||pub) as an exportable RAW_DATA
 * key: cipher suite 0 exports it and signs with Compact25519.
 */
static int import_sign_priv_key(const uint8_t *priv, size_t priv_len,
				uint8_t *key_id)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
	psa_set_key_type(&attr, PSA_KEY_TYPE_RAW_DATA);

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	const psa_status_t status = psa_import_key(&attr, priv, priv_len, &kid);

	if (PSA_SUCCESS != status) {
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	memcpy(key_id, &kid, sizeof(kid));

	return EDHOC_SUCCESS;
}

static int
auth_cred_select_local_init(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    struct edhoc_credential_selected *selected)
{
	(void)user_ctx;
	(void)call_ctx;

	if (NULL == selected) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	selected->label = EDHOC_COSE_HEADER_X509_CHAIN;
	selected->x509_chain.count = 1;
	selected->x509_chain.certificate[0].value = CRED_I;
	selected->x509_chain.certificate[0].length = ARRAY_SIZE(CRED_I);

	const int res = import_sign_priv_key(SK_I, ARRAY_SIZE(SK_I),
					     selected->private_key_id);

	if (EDHOC_SUCCESS != res) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int
auth_cred_select_local_resp(void *user_ctx,
			    const struct edhoc_call_context *call_ctx,
			    struct edhoc_credential_selected *selected)
{
	(void)user_ctx;
	(void)call_ctx;

	if (NULL == selected) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	selected->label = EDHOC_COSE_HEADER_X509_CHAIN;
	selected->x509_chain.count = 1;
	selected->x509_chain.certificate[0].value = CRED_R;
	selected->x509_chain.certificate[0].length = ARRAY_SIZE(CRED_R);

	const int res = import_sign_priv_key(SK_R, ARRAY_SIZE(SK_R),
					     selected->private_key_id);

	if (EDHOC_SUCCESS != res) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int auth_cred_authenticate_peer_init(
	void *user_ctx, const struct edhoc_call_context *call_ctx,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted)
{
	(void)user_ctx;
	(void)call_ctx;

	if (NULL == received || NULL == trusted) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_COSE_HEADER_X509_CHAIN != received->label) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (1 != received->x509_chain.count) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (received->x509_chain.certificate[0].length != ARRAY_SIZE(CRED_R)) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (0 != memcmp(CRED_R, received->x509_chain.certificate[0].value,
			received->x509_chain.certificate[0].length)) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	trusted->credential = received->x509_chain.certificate[0];
	trusted->format = EDHOC_CREDENTIAL_FORMAT_RAW;
	trusted->public_key.value = PK_R;
	trusted->public_key.length = ARRAY_SIZE(PK_R);

	return EDHOC_SUCCESS;
}

static int auth_cred_authenticate_peer_resp(
	void *user_ctx, const struct edhoc_call_context *call_ctx,
	const struct edhoc_credential_received *received,
	struct edhoc_credential_trusted *trusted)
{
	(void)user_ctx;
	(void)call_ctx;

	if (NULL == received || NULL == trusted) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_COSE_HEADER_X509_CHAIN != received->label) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (1 != received->x509_chain.count) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (received->x509_chain.certificate[0].length != ARRAY_SIZE(CRED_I)) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (0 != memcmp(CRED_I, received->x509_chain.certificate[0].value,
			received->x509_chain.certificate[0].length)) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	trusted->credential = received->x509_chain.certificate[0];
	trusted->format = EDHOC_CREDENTIAL_FORMAT_RAW;
	trusted->public_key.value = PK_I;
	trusted->public_key.length = ARRAY_SIZE(PK_I);

	return EDHOC_SUCCESS;
}

static const struct edhoc_credentials cred_init = {
	.select_local = auth_cred_select_local_init,
	.authenticate_peer = auth_cred_authenticate_peer_init,
};

static const struct edhoc_credentials cred_resp = {
	.select_local = auth_cred_select_local_resp,
	.authenticate_peer = auth_cred_authenticate_peer_resp,
};

/* Module interface function definitions ----------------------------------- */

int test_mem_custom_setup_contexts(struct edhoc_context *initiator,
				   struct edhoc_context *responder)
{
	const enum edhoc_method methods[] = { EDHOC_METHOD_0 };

	const struct edhoc_cipher_suite cipher_suites[] = {
		*edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_0),
	};

	const struct edhoc_connection_id init_cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_I[0],
	};

	const struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = ARRAY_SIZE(C_R),
		.bstr_value = { C_R[0] },
	};

	int rc = 0;

	rc = edhoc_context_init(initiator);

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_set_methods(initiator, methods, ARRAY_SIZE(methods));

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_set_cipher_suites(initiator, cipher_suites,
				     ARRAY_SIZE(cipher_suites));

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_set_connection_id(initiator, &init_cid);

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_bind_crypto(
		initiator, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_0));

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_bind_platform(initiator, test_get_platform());

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_bind_credentials(initiator, &cred_init);

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_context_init(responder);

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_set_methods(responder, methods, ARRAY_SIZE(methods));

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_set_cipher_suites(responder, cipher_suites,
				     ARRAY_SIZE(cipher_suites));

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_set_connection_id(responder, &resp_cid);

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_bind_crypto(
		responder, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_0));

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_bind_platform(responder, test_get_platform());

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_bind_credentials(responder, &cred_resp);

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	return EDHOC_SUCCESS;
}

int test_mem_custom_drive_handshake(struct edhoc_context *initiator,
				    struct edhoc_context *responder)
{
	uint8_t buffer[HANDSHAKE_BUFFER_LENGTH] = { 0 };
	size_t msg_len = 0;
	int rc = 0;

	rc = edhoc_message_1_compose(initiator, buffer, sizeof(buffer),
				     &msg_len);

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_message_1_process(responder, buffer, msg_len);

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_message_2_compose(responder, buffer, sizeof(buffer),
				     &msg_len);

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_message_2_process(initiator, buffer, msg_len);

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_message_3_compose(initiator, buffer, sizeof(buffer),
				     &msg_len);

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_message_3_process(responder, buffer, msg_len);

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_message_4_compose(responder, buffer, sizeof(buffer),
				     &msg_len);

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	rc = edhoc_message_4_process(initiator, buffer, msg_len);

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	uint8_t init_master_secret[OSCORE_MASTER_SECRET_LENGTH] = { 0 };
	uint8_t init_master_salt[OSCORE_MASTER_SALT_LENGTH] = { 0 };
	uint8_t init_sender_id[ARRAY_SIZE(C_R)] = { 0 };
	uint8_t init_recipient_id[ARRAY_SIZE(C_I)] = { 0 };
	size_t init_sender_id_len = 0;
	size_t init_recipient_id_len = 0;

	rc = edhoc_export_oscore_context_raw(
		initiator, init_master_secret, ARRAY_SIZE(init_master_secret),
		init_master_salt, ARRAY_SIZE(init_master_salt), init_sender_id,
		ARRAY_SIZE(init_sender_id), &init_sender_id_len,
		init_recipient_id, ARRAY_SIZE(init_recipient_id),
		&init_recipient_id_len);

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	uint8_t resp_master_secret[OSCORE_MASTER_SECRET_LENGTH] = { 0 };
	uint8_t resp_master_salt[OSCORE_MASTER_SALT_LENGTH] = { 0 };
	uint8_t resp_sender_id[ARRAY_SIZE(C_I)] = { 0 };
	uint8_t resp_recipient_id[ARRAY_SIZE(C_R)] = { 0 };
	size_t resp_sender_id_len = 0;
	size_t resp_recipient_id_len = 0;

	rc = edhoc_export_oscore_context_raw(
		responder, resp_master_secret, ARRAY_SIZE(resp_master_secret),
		resp_master_salt, ARRAY_SIZE(resp_master_salt), resp_sender_id,
		ARRAY_SIZE(resp_sender_id), &resp_sender_id_len,
		resp_recipient_id, ARRAY_SIZE(resp_recipient_id),
		&resp_recipient_id_len);

	if (EDHOC_SUCCESS != rc) {
		return rc;
	}

	if (0 != memcmp(init_master_secret, resp_master_secret,
			ARRAY_SIZE(resp_master_secret))) {
		return EDHOC_ERROR_GENERIC_ERROR;
	}

	if (0 != memcmp(init_master_salt, resp_master_salt,
			ARRAY_SIZE(resp_master_salt))) {
		return EDHOC_ERROR_GENERIC_ERROR;
	}

	if (init_sender_id_len != resp_recipient_id_len) {
		return EDHOC_ERROR_GENERIC_ERROR;
	}

	if (0 !=
	    memcmp(init_sender_id, resp_recipient_id, init_sender_id_len)) {
		return EDHOC_ERROR_GENERIC_ERROR;
	}

	if (init_recipient_id_len != resp_sender_id_len) {
		return EDHOC_ERROR_GENERIC_ERROR;
	}

	if (0 !=
	    memcmp(init_recipient_id, resp_sender_id, resp_sender_id_len)) {
		return EDHOC_ERROR_GENERIC_ERROR;
	}

	return EDHOC_SUCCESS;
}
