/**
 * \file    test_edhoc_handshake_x5chain.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC handshake unit test for X.509 chain authentication method
 *          with real crypto usage.
 * \version 0.2
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Internal test headers: */
#include "x509_chain/test_edhoc_handshake_x5chain.h"
#include "x509_chain/test_vector_x5chain.h"
#include "x509_chain/authentication_credentials_x5chain.h"
#include "cipher_suites/cipher_suite_0.h"

/* Standard library headers: */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdbool.h>

/* EDHOC header: */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include "edhoc.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Module defines ---------------------------------------------------------- */
#define OSCORE_MASTER_SECRET_LENGTH (16)
#define OSCORE_MASTER_SALT_LENGTH (8)
#define DH_KEY_AGREEMENT_LENGTH (32)
#define ENTROPY_LENGTH (16)

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Helper function for printing arrays.
 */
static inline void print_array(void *user_context, const char *name,
			       const uint8_t *buffer, size_t buffer_length);

/* Static variables and constants ------------------------------------------ */

static const struct edhoc_cipher_suite edhoc_cipher_suite_0 = {
	.value = 0,
	.aead_key_length = 16,
	.aead_tag_length = 8,
	.aead_iv_length = 13,
	.hash_length = 32,
	.mac_length = 32,
	.ecc_key_length = 32,
	.ecc_sign_length = 64,
};

static const struct edhoc_keys edhoc_keys = {
	.generate_key = cipher_suite_0_key_generate,
	.destroy_key = cipher_suite_0_key_destroy,
};

static const struct edhoc_crypto edhoc_crypto = {
	.make_key_pair = cipher_suite_0_make_key_pair,
	.key_agreement = cipher_suite_0_key_agreement,
	.signature = cipher_suite_0_signature,
	.verify = cipher_suite_0_verify,
	.extract = cipher_suite_0_extract,
	.expand = cipher_suite_0_expand,
	.encrypt = cipher_suite_0_encrypt,
	.decrypt = cipher_suite_0_decrypt,
	.hash = cipher_suite_0_hash,
};

static const struct edhoc_credentials edhoc_auth_cred_mocked_resp = {
	.fetch = auth_cred_fetch_resp_x5chain,
	.verify = auth_cred_verify_resp_x5chain,
};

static const struct edhoc_credentials edhoc_auth_cred_mocked_init = {
	.fetch = auth_cred_fetch_init_x5chain,
	.verify = auth_cred_verify_init_x5chain,
};

/* Static function definitions --------------------------------------------- */

static inline void print_array(void *user_context, const char *name,
			       const uint8_t *buffer, size_t buffer_length)
{
	(void)user_context;

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

void test_edhoc_handshake_x5chain_e2e_real_crypto(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/**
         * \brief Setup initiator context.
         */
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_connection_id init_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_I[0],
	};

	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);
	init_ctx.logger = print_array;

	ret = edhoc_set_method(&init_ctx, METHOD);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&init_ctx, &edhoc_cipher_suite_0, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&init_ctx, init_cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, edhoc_crypto);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&init_ctx, edhoc_auth_cred_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Setup responder context.
         */
	struct edhoc_context resp_ctx = { 0 };
	struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = ARRAY_SIZE(C_R),
	};
	memcpy(resp_cid.bstr_value, C_R, ARRAY_SIZE(C_R));

	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
	resp_ctx.logger = print_array;

	ret = edhoc_set_method(&resp_ctx, METHOD);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, &edhoc_cipher_suite_0, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&resp_ctx, resp_cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, edhoc_crypto);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&resp_ctx, edhoc_auth_cred_mocked_resp);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief One buffer for whole EDHOC handshake.
         */
	uint8_t buffer[1000] = { 0 };

	/**
         * \brief EDHOC message 1 compose.
         */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_1_len = 0;
	uint8_t *msg_1 = buffer;

	ret = edhoc_message_1_compose(&init_ctx, msg_1, ARRAY_SIZE(buffer),
				      &msg_1_len);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_WAIT_M2 == init_ctx.status);
	assert(false == init_ctx.is_oscore_export_allowed);
	assert(EDHOC_PRK_STATE_INVALID == init_ctx.prk_state);
	assert(EDHOC_TH_STATE_1 == init_ctx.th_state);

	/**
         * \brief EDHOC message 1 process.
         */
	ret = edhoc_message_1_process(&resp_ctx, msg_1, msg_1_len);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_RECEIVED_M1 == resp_ctx.status);
	assert(false == resp_ctx.is_oscore_export_allowed);
	assert(EDHOC_TH_STATE_1 == resp_ctx.th_state);
	assert(EDHOC_PRK_STATE_INVALID == resp_ctx.prk_state);

	assert(EDHOC_CID_TYPE_ONE_BYTE_INTEGER ==
	       resp_ctx.peer_cid.encode_type);
	assert((int8_t)C_I[0] == resp_ctx.peer_cid.int_value);

	/**
         * \brief EDHOC message 2 compose.
         */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_2_len = 0;
	uint8_t *msg_2 = buffer;

	ret = edhoc_message_2_compose(&resp_ctx, msg_2, ARRAY_SIZE(buffer),
				      &msg_2_len);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_WAIT_M3 == resp_ctx.status);
	assert(false == resp_ctx.is_oscore_export_allowed);
	assert(EDHOC_TH_STATE_3 == resp_ctx.th_state);
	assert(EDHOC_PRK_STATE_3E2M == resp_ctx.prk_state);

	/**
         * \brief EDHOC message 2 process.
         */
	ret = edhoc_message_2_process(&init_ctx, msg_2, msg_2_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_VERIFIED_M2 == init_ctx.status);
	assert(false == init_ctx.is_oscore_export_allowed);
	assert(EDHOC_TH_STATE_3 == init_ctx.th_state);
	assert(EDHOC_PRK_STATE_3E2M == init_ctx.prk_state);

	assert(EDHOC_CID_TYPE_BYTE_STRING == init_ctx.peer_cid.encode_type);
	assert(ARRAY_SIZE(C_R) == init_ctx.peer_cid.bstr_length);
	assert(0 == memcmp(C_R, init_ctx.peer_cid.bstr_value,
			   init_ctx.peer_cid.bstr_length));

	/**
         * \brief Verify ephemeral DH key agreement.
         */
	assert(DH_KEY_AGREEMENT_LENGTH == init_ctx.dh_secret_len);
	assert(DH_KEY_AGREEMENT_LENGTH == resp_ctx.dh_secret_len);
	assert(init_ctx.dh_secret_len == resp_ctx.dh_secret_len);
	assert(0 == memcmp(init_ctx.dh_secret, resp_ctx.dh_secret,
			   DH_KEY_AGREEMENT_LENGTH));

	/**
         * \brief EDHOC message 3 compose.
         */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_3_len = 0;
	uint8_t *msg_3 = buffer;

	ret = edhoc_message_3_compose(&init_ctx, msg_3, ARRAY_SIZE(buffer),
				      &msg_3_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_COMPLETED == init_ctx.status);
	assert(true == init_ctx.is_oscore_export_allowed);
	assert(EDHOC_TH_STATE_4 == init_ctx.th_state);
	assert(EDHOC_PRK_STATE_4E3M == init_ctx.prk_state);

	/**
         * \brief EDHOC message 3 process.
         */
	ret = edhoc_message_3_process(&resp_ctx, msg_3, msg_3_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_COMPLETED == resp_ctx.status);
	assert(true == resp_ctx.is_oscore_export_allowed);
	assert(EDHOC_TH_STATE_4 == resp_ctx.th_state);
	assert(EDHOC_PRK_STATE_4E3M == resp_ctx.prk_state);

	/**
         * \brief EDHOC message 4 compose.
         */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_4_len = 0;
	uint8_t *msg_4 = buffer;

	ret = edhoc_message_4_compose(&resp_ctx, msg_4, ARRAY_SIZE(buffer),
				      &msg_4_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_PERSISTED == resp_ctx.status);
	assert(true == resp_ctx.is_oscore_export_allowed);
	assert(EDHOC_TH_STATE_4 == resp_ctx.th_state);
	assert(EDHOC_PRK_STATE_4E3M == resp_ctx.prk_state);

	/**
         * \brief EDHOC message 3 process.
         */
	ret = edhoc_message_4_process(&init_ctx, msg_4, msg_4_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_PERSISTED == init_ctx.status);
	assert(true == init_ctx.is_oscore_export_allowed);
	assert(EDHOC_TH_STATE_4 == init_ctx.th_state);
	assert(EDHOC_PRK_STATE_4E3M == init_ctx.prk_state);

	/**
         * \brief Initiator - derive OSCORE secret & salt.
         */
	uint8_t init_master_secret[OSCORE_MASTER_SECRET_LENGTH] = { 0 };
	uint8_t init_master_salt[OSCORE_MASTER_SALT_LENGTH] = { 0 };
	size_t init_sender_id_len = 0;
	uint8_t init_sender_id[ARRAY_SIZE(C_R)] = { 0 };
	size_t init_recipient_id_len = 0;
	uint8_t init_recipient_id[ARRAY_SIZE(C_I)] = { 0 };

	ret = edhoc_export_oscore_session(
		&init_ctx, init_master_secret, ARRAY_SIZE(init_master_secret),
		init_master_salt, ARRAY_SIZE(init_master_salt), init_sender_id,
		ARRAY_SIZE(init_sender_id), &init_sender_id_len,
		init_recipient_id, ARRAY_SIZE(init_recipient_id),
		&init_recipient_id_len);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_PERSISTED == init_ctx.status);
	assert(false == init_ctx.is_oscore_export_allowed);
	assert(EDHOC_PRK_STATE_OUT == init_ctx.prk_state);

	/**
         * \brief Responder - derive OSCORE secret & salt.
         */
	uint8_t resp_master_secret[OSCORE_MASTER_SECRET_LENGTH] = { 0 };
	uint8_t resp_master_salt[OSCORE_MASTER_SALT_LENGTH] = { 0 };
	size_t resp_sender_id_len = 0;
	uint8_t resp_sender_id[ARRAY_SIZE(C_I)] = { 0 };
	size_t resp_recipient_id_len = 0;
	uint8_t resp_recipient_id[ARRAY_SIZE(C_R)] = { 0 };

	ret = edhoc_export_oscore_session(
		&resp_ctx, resp_master_secret, ARRAY_SIZE(resp_master_secret),
		resp_master_salt, ARRAY_SIZE(resp_master_salt), resp_sender_id,
		ARRAY_SIZE(resp_sender_id), &resp_sender_id_len,
		resp_recipient_id, ARRAY_SIZE(resp_recipient_id),
		&resp_recipient_id_len);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_PERSISTED == resp_ctx.status);
	assert(false == resp_ctx.is_oscore_export_allowed);
	assert(EDHOC_PRK_STATE_OUT == resp_ctx.prk_state);

	/**
         * \brief Verify OSCORE master secret:
         */
	assert(0 == memcmp(init_master_secret, resp_master_secret,
			   sizeof(resp_master_secret)));

	/**
         * \brief Verify OSCORE master salt:
         */
	assert(0 == memcmp(init_master_salt, resp_master_salt,
			   sizeof(resp_master_salt)));

	/**
         * \brief Verify OSCORE sender and recipient identifiers (cross check).
         */
	assert(init_sender_id_len == resp_recipient_id_len);
	assert(0 ==
	       memcmp(init_sender_id, resp_recipient_id, init_sender_id_len));
	assert(init_recipient_id_len == resp_sender_id_len);
	assert(0 ==
	       memcmp(init_recipient_id, resp_sender_id, resp_sender_id_len));

	uint8_t entropy[ENTROPY_LENGTH] = { 0 };
	ret = psa_generate_random(entropy, sizeof(entropy));
	assert(PSA_SUCCESS == ret);

	/**
	 * \brief Initiator - perform EDHOC key update.
	 */
	ret = edhoc_export_key_update(&init_ctx, entropy, ARRAY_SIZE(entropy));
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_PERSISTED == init_ctx.status);
	assert(true == init_ctx.is_oscore_export_allowed);

	/**
	 * \brief Responder - perform EDHOC key update.
	 */
	ret = edhoc_export_key_update(&resp_ctx, entropy, ARRAY_SIZE(entropy));
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_PERSISTED == resp_ctx.status);
	assert(true == resp_ctx.is_oscore_export_allowed);

	/**
         * \brief Verify new PRK_out.
         */
	assert(init_ctx.prk_state == resp_ctx.prk_state);
	assert(EDHOC_PRK_STATE_OUT == init_ctx.prk_state);
	assert(EDHOC_PRK_STATE_OUT == resp_ctx.prk_state);

	assert(init_ctx.prk_len == resp_ctx.prk_len);
	assert(0 == memcmp(init_ctx.prk, resp_ctx.prk, resp_ctx.prk_len));

	/**
         * \brief Initiator - derive OSCORE secret & salt.
         */
	memset(init_master_secret, 0, sizeof(init_master_secret));
	memset(init_master_salt, 0, sizeof(init_master_salt));
	init_sender_id_len = 0;
	memset(init_sender_id, 0, sizeof(init_sender_id));
	init_recipient_id_len = 0;
	memset(init_recipient_id, 0, sizeof(init_recipient_id));

	ret = edhoc_export_oscore_session(
		&init_ctx, init_master_secret, ARRAY_SIZE(init_master_secret),
		init_master_salt, ARRAY_SIZE(init_master_salt), init_sender_id,
		ARRAY_SIZE(init_sender_id), &init_sender_id_len,
		init_recipient_id, ARRAY_SIZE(init_recipient_id),
		&init_recipient_id_len);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_PERSISTED == init_ctx.status);
	assert(false == init_ctx.is_oscore_export_allowed);
	assert(EDHOC_PRK_STATE_OUT == init_ctx.prk_state);

	/**
         * \brief Responder - derive OSCORE secret & salt.
         */
	memset(resp_master_secret, 0, sizeof(resp_master_secret));
	memset(resp_master_salt, 0, sizeof(resp_master_salt));
	resp_sender_id_len = 0;
	memset(resp_sender_id, 0, sizeof(resp_sender_id));
	resp_recipient_id_len = 0;
	memset(resp_recipient_id, 0, sizeof(resp_recipient_id));

	ret = edhoc_export_oscore_session(
		&resp_ctx, resp_master_secret, ARRAY_SIZE(resp_master_secret),
		resp_master_salt, ARRAY_SIZE(resp_master_salt), resp_sender_id,
		ARRAY_SIZE(resp_sender_id), &resp_sender_id_len,
		resp_recipient_id, ARRAY_SIZE(resp_recipient_id),
		&resp_recipient_id_len);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_PERSISTED == resp_ctx.status);
	assert(false == resp_ctx.is_oscore_export_allowed);
	assert(EDHOC_PRK_STATE_OUT == resp_ctx.prk_state);

	/**
         * \brief Verify OSCORE master secret:
         */
	assert(0 == memcmp(init_master_secret, resp_master_secret,
			   sizeof(resp_master_secret)));

	/**
         * \brief Verify OSCORE master salt:
         */
	assert(0 == memcmp(init_master_salt, resp_master_salt,
			   sizeof(resp_master_salt)));

	/**
         * \brief Verify OSCORE sender and recipient identifiers (cross check).
         */
	assert(init_sender_id_len == resp_recipient_id_len);
	assert(0 ==
	       memcmp(init_sender_id, resp_recipient_id, init_sender_id_len));
	assert(init_recipient_id_len == resp_sender_id_len);
	assert(0 ==
	       memcmp(init_recipient_id, resp_sender_id, resp_sender_id_len));

	/**
         * \brief Clean up of EDHOC context's. 
         */
	ret = edhoc_context_deinit(&init_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_context_deinit(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
}
