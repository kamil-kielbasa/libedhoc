/**
 * \file    test_handshake_x5chain_sig_suite_pqc_1.c
 * \author  Kamil Kielbasa
 * \brief   Integration test for a full EDHOC handshake with:
 *          - post-quantum cipher suite 1 (ML-KEM-512 / ML-DSA-44 /
 *            AES-CCM-16-128-128 / SHAKE256),
 *          - signature authentication (ML-DSA-44),
 *          - X.509 chain credentials (opaque mock certificates).
 *
 *          The suite has no RFC 9529 test vector, so both peers run real
 *          crypto (real ML-KEM key encapsulation, real ML-DSA signatures, real
 *          KMAC256 KDF and AES-CCM) through message_1..4 and must agree on the
 *          derived PRKs and the exported OSCORE session.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Shared test helpers and white-box context: */
#include "test_platform.h"
#include "test_key_agreement.h"
#include "edhoc_context_internal.h"
#include "test_vector_x5chain_sign_keys_suite_pqc_1.h"

/* Cipher suite header: */
#include "edhoc_cipher_suite_pqc_1.h"

/* Standard library headers: */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* edhoc_cipher_suite_pqc_1_import_signing_key() is intentionally not part of
 * the public suite header (the classic suites import the signing key with
 * psa_import_key). The test declares it here to load the oversized ML-DSA-44
 * private key into the suite's software keystore. */
extern int edhoc_cipher_suite_pqc_1_import_signing_key(
	const uint8_t *signing_key, size_t signing_key_length, void *key_id);

/* Module defines ---------------------------------------------------------- */

#define OSCORE_MASTER_SECRET_LENGTH (16)
#define OSCORE_MASTER_SALT_LENGTH (8)

/* Post-quantum message_2 carries the 768-byte KEM ciphertext and a 2420-byte
 * ML-DSA signature, so the message buffer is far larger than for the classic
 * suites. */
#define HANDSHAKE_BUFFER_LENGTH (8192)

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */

/** \brief Authentication credentials fetch callback for the Initiator. */
static int auth_cred_fetch_init(void *user_ctx,
				struct edhoc_auth_credentials *auth_cred);

/** \brief Authentication credentials fetch callback for the Responder. */
static int auth_cred_fetch_resp(void *user_ctx,
				struct edhoc_auth_credentials *auth_cred);

/** \brief Authentication credentials verify callback for the Initiator. */
static int auth_cred_verify_init(void *user_ctx,
				 struct edhoc_auth_credentials *auth_cred,
				 const uint8_t **pub_key, size_t *pub_key_len);

/** \brief Authentication credentials verify callback for the Responder. */
static int auth_cred_verify_resp(void *user_ctx,
				 struct edhoc_auth_credentials *auth_cred,
				 const uint8_t **pub_key, size_t *pub_key_len);

/* Static variables and constants ------------------------------------------ */

static int ret = EDHOC_ERROR_GENERIC_ERROR;
static enum edhoc_error_code error_code_recv =
	EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;

static struct edhoc_context edhoc_initiator_context = { 0 };
static struct edhoc_context *init_ctx = &edhoc_initiator_context;

static struct edhoc_context edhoc_responder_context = { 0 };
static struct edhoc_context *resp_ctx = &edhoc_responder_context;

/* Import a raw ML-DSA-44 signing key into the suite's software keystore and
 * store the returned handle as the credential's private key identifier. */
static int import_sign_priv_key(const uint8_t *priv, size_t priv_len,
				uint8_t *key_id)
{
	if (EDHOC_SUCCESS != edhoc_cipher_suite_pqc_1_import_signing_key(
				     priv, priv_len, key_id)) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	return EDHOC_SUCCESS;
}

/* Bind the post-quantum cipher suite to the shared key-agreement probe. */
static void assert_peers_share_slot_key(const struct edhoc_context *lhs,
					const struct edhoc_context *rhs,
					enum edhoc_key_slot_id slot)
{
	test_assert_peers_share_slot_key(EDHOC_CIPHER_SUITE_PQC_1, lhs, rhs,
					 slot);
}

static const struct edhoc_credentials edhoc_auth_cred_mocked_init = {
	.fetch = auth_cred_fetch_init,
	.verify = auth_cred_verify_init,
};

static const struct edhoc_credentials edhoc_auth_cred_mocked_resp = {
	.fetch = auth_cred_fetch_resp,
	.verify = auth_cred_verify_resp,
};

/* Static function definitions --------------------------------------------- */

static int auth_cred_fetch_init(void *user_ctx,
				struct edhoc_auth_credentials *auth_cred)
{
	(void)user_ctx;

	if (NULL == auth_cred) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.certificate_count = 1;
	auth_cred->x509_chain.certificate[0] = CRED_I;
	auth_cred->x509_chain.certificate_length[0] = ARRAY_SIZE(CRED_I);

	return import_sign_priv_key(SK_I, ARRAY_SIZE(SK_I),
				    auth_cred->private_key_id);
}

static int auth_cred_fetch_resp(void *user_ctx,
				struct edhoc_auth_credentials *auth_cred)
{
	(void)user_ctx;

	if (NULL == auth_cred) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	auth_cred->label = EDHOC_COSE_HEADER_X509_CHAIN;
	auth_cred->x509_chain.certificate_count = 1;
	auth_cred->x509_chain.certificate[0] = CRED_R;
	auth_cred->x509_chain.certificate_length[0] = ARRAY_SIZE(CRED_R);

	return import_sign_priv_key(SK_R, ARRAY_SIZE(SK_R),
				    auth_cred->private_key_id);
}

static int auth_cred_verify_init(void *user_ctx,
				 struct edhoc_auth_credentials *auth_cred,
				 const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == auth_cred || NULL == pub_key || NULL == pub_key_len) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* The Initiator verifies the Responder's credential. */
	if (EDHOC_COSE_HEADER_X509_CHAIN != auth_cred->label) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (1 != auth_cred->x509_chain.certificate_count) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (auth_cred->x509_chain.certificate_length[0] != ARRAY_SIZE(CRED_R)) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (0 != memcmp(CRED_R, auth_cred->x509_chain.certificate[0],
			auth_cred->x509_chain.certificate_length[0])) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	*pub_key = PK_R;
	*pub_key_len = ARRAY_SIZE(PK_R);

	return EDHOC_SUCCESS;
}

static int auth_cred_verify_resp(void *user_ctx,
				 struct edhoc_auth_credentials *auth_cred,
				 const uint8_t **pub_key, size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == auth_cred || NULL == pub_key || NULL == pub_key_len) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* The Responder verifies the Initiator's credential. */
	if (EDHOC_COSE_HEADER_X509_CHAIN != auth_cred->label) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (1 != auth_cred->x509_chain.certificate_count) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (auth_cred->x509_chain.certificate_length[0] != ARRAY_SIZE(CRED_I)) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (0 != memcmp(CRED_I, auth_cred->x509_chain.certificate[0],
			auth_cred->x509_chain.certificate_length[0])) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	*pub_key = PK_I;
	*pub_key_len = ARRAY_SIZE(PK_I);

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(handshake_x5chain_sig_suite_pqc_1);

TEST_SETUP(handshake_x5chain_sig_suite_pqc_1)
{
	ret = psa_crypto_init();
	TEST_ASSERT_EQUAL(PSA_SUCCESS, ret);

	const enum edhoc_method methods[] = { METHOD };
	const struct edhoc_cipher_suite cipher_suites[] = {
		*edhoc_cipher_suite_pqc_1_get_suite(),
	};

	const struct edhoc_connection_id init_cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_I[0],
	};

	struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = ARRAY_SIZE(C_R),
	};
	memcpy(&resp_cid.bstr_value, C_R, ARRAY_SIZE(C_R));

	/* Initiator context. */
	ret = edhoc_context_init(init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(init_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(init_ctx, cipher_suites,
				      ARRAY_SIZE(cipher_suites));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(init_ctx, &init_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(init_ctx,
				edhoc_cipher_suite_pqc_1_get_crypto());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(init_ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Responder context. */
	ret = edhoc_context_init(resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(resp_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(resp_ctx, cipher_suites,
				      ARRAY_SIZE(cipher_suites));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(resp_ctx, &resp_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(resp_ctx,
				edhoc_cipher_suite_pqc_1_get_crypto());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(resp_ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_TEAR_DOWN(handshake_x5chain_sig_suite_pqc_1)
{
	ret = edhoc_context_deinit(init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	mbedtls_psa_crypto_free();
}

TEST(handshake_x5chain_sig_suite_pqc_1, full_handshake)
{
	ret = edhoc_bind_credentials(init_ctx, &edhoc_auth_cred_mocked_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(resp_ctx, &edhoc_auth_cred_mocked_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t buffer[HANDSHAKE_BUFFER_LENGTH];
	memset(buffer, 0, sizeof(buffer));

	/* --- message_1 (Initiator -> Responder): ML-KEM encapsulation key. */
	size_t msg_1_len = 0;
	ret = edhoc_message_1_compose(init_ctx, buffer, sizeof(buffer),
				      &msg_1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M2, init_ctx->state.machine);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_INVALID, init_ctx->state.prk_state);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, init_ctx->state.th.stage);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	ret = edhoc_message_1_process(resp_ctx, buffer, msg_1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_RECEIVED_M1, resp_ctx->state.machine);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, resp_ctx->state.th.stage);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_INVALID, resp_ctx->state.prk_state);

	/* --- message_2 (Responder -> Initiator): KEM ciphertext + signature. */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_2_len = 0;
	ret = edhoc_message_2_compose(resp_ctx, buffer, sizeof(buffer),
				      &msg_2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M3, resp_ctx->state.machine);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, resp_ctx->state.th.stage);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, resp_ctx->state.prk_state);

	ret = edhoc_message_2_process(init_ctx, buffer, msg_2_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_VERIFIED_M2, init_ctx->state.machine);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, init_ctx->state.th.stage);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, init_ctx->state.prk_state);

	/* Both peers derived the same PRK_3e2m from the ML-KEM shared secret. */
	assert_peers_share_slot_key(init_ctx, resp_ctx,
				    EDHOC_KEY_SLOT_PRK_3E2M);

	/* --- message_3 (Initiator -> Responder): signature. */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_3_len = 0;
	ret = edhoc_message_3_compose(init_ctx, buffer, sizeof(buffer),
				      &msg_3_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, init_ctx->state.machine);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx->state.th.stage);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, init_ctx->state.prk_state);

	ret = edhoc_message_3_process(resp_ctx, buffer, msg_3_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, resp_ctx->state.machine);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->state.th.stage);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->state.prk_state);

	/* Both peers derived the same PRK_4e3m. */
	assert_peers_share_slot_key(init_ctx, resp_ctx,
				    EDHOC_KEY_SLOT_PRK_4E3M);

	/* --- message_4 (Responder -> Initiator): key confirmation. */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_4_len = 0;
	ret = edhoc_message_4_compose(resp_ctx, buffer, sizeof(buffer),
				      &msg_4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->state.machine);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->state.th.stage);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->state.prk_state);

	ret = edhoc_message_4_process(init_ctx, buffer, msg_4_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->state.machine);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx->state.th.stage);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, init_ctx->state.prk_state);

	/* --- OSCORE session export: both peers must agree. */
	uint8_t init_master_secret[OSCORE_MASTER_SECRET_LENGTH] = { 0 };
	uint8_t init_master_salt[OSCORE_MASTER_SALT_LENGTH] = { 0 };
	uint8_t init_sender_id[ARRAY_SIZE(C_R)] = { 0 };
	uint8_t init_recipient_id[ARRAY_SIZE(C_I)] = { 0 };
	size_t init_sender_id_len = 0;
	size_t init_recipient_id_len = 0;

	ret = edhoc_export_oscore_session_raw(
		init_ctx, init_master_secret, ARRAY_SIZE(init_master_secret),
		init_master_salt, ARRAY_SIZE(init_master_salt), init_sender_id,
		ARRAY_SIZE(init_sender_id), &init_sender_id_len,
		init_recipient_id, ARRAY_SIZE(init_recipient_id),
		&init_recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->state.machine);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, init_ctx->state.prk_state);

	uint8_t resp_master_secret[OSCORE_MASTER_SECRET_LENGTH] = { 0 };
	uint8_t resp_master_salt[OSCORE_MASTER_SALT_LENGTH] = { 0 };
	uint8_t resp_sender_id[ARRAY_SIZE(C_I)] = { 0 };
	uint8_t resp_recipient_id[ARRAY_SIZE(C_R)] = { 0 };
	size_t resp_sender_id_len = 0;
	size_t resp_recipient_id_len = 0;

	ret = edhoc_export_oscore_session_raw(
		resp_ctx, resp_master_secret, ARRAY_SIZE(resp_master_secret),
		resp_master_salt, ARRAY_SIZE(resp_master_salt), resp_sender_id,
		ARRAY_SIZE(resp_sender_id), &resp_sender_id_len,
		resp_recipient_id, ARRAY_SIZE(resp_recipient_id),
		&resp_recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->state.machine);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, resp_ctx->state.prk_state);

	/* Peer equality: identical OSCORE keying material and mirrored ids. */
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

TEST_GROUP_RUNNER(handshake_x5chain_sig_suite_pqc_1)
{
	RUN_TEST_CASE(handshake_x5chain_sig_suite_pqc_1, full_handshake);
}
