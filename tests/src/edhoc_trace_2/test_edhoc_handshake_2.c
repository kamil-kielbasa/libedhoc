/**
 * \file    test_edhoc_handshake_2.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for EDHOC handshake.
 * \version 0.4
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Internal test headers: */
#include "edhoc_trace_2/test_edhoc_handshake_2.h"
#include "edhoc_trace_2/test_vector_2.h"
#include "edhoc_trace_2/authentication_credentials_2.h"
#include "cipher_suites/cipher_suite_2.h"

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

/* Module defines ---------------------------------------------------------- */
#define DH_KEY_AGREEMENT_LENGTH (32)

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Mocked EDHOC crypto function ECDH make key pair for initiator.
 */
static int cipher_suite_2_make_key_pair_init(
	void *user_context, const void *key_id, uint8_t *private_key,
	size_t private_key_size, size_t *private_key_length,
	uint8_t *public_key, size_t public_key_size, size_t *public_key_length);

/**
 * \brief Mocked EDHOC crypto function ECDH make key pair for responder.
 */
static int cipher_suite_2_make_key_pair_resp(
	void *user_context, const void *key_id, uint8_t *private_key,
	size_t private_key_size, size_t *private_key_length,
	uint8_t *public_key, size_t public_key_size, size_t *public_key_length);

/**
 * \brief Helper function for printing arrays.
 */
static inline void print_array(void *user_context, const char *name,
			       const uint8_t *buffer, size_t buffer_length);

/* Static variables and constants ------------------------------------------ */

static const struct edhoc_cipher_suite edhoc_cipher_suites_init[] = {
	{
		.value = 6,
		.aead_key_length = 16,
		.aead_tag_length = 8,
		.aead_iv_length = 13,
		.hash_length = 32,
		.mac_length = 8,
		.ecc_key_length = 32,
		.ecc_sign_length = 64,
	},
	{
		.value = 2,
		.aead_key_length = 16,
		.aead_tag_length = 8,
		.aead_iv_length = 13,
		.hash_length = 32,
		.mac_length = 8,
		.ecc_key_length = 32,
		.ecc_sign_length = 64,
	},
};

static const struct edhoc_cipher_suite edhoc_cipher_suites_resp[] = {
	{
		.value = 2,
		.aead_key_length = 16,
		.aead_tag_length = 8,
		.aead_iv_length = 13,
		.hash_length = 32,
		.mac_length = 8,
		.ecc_key_length = 32,
		.ecc_sign_length = 64,
	},
};

static const struct edhoc_keys edhoc_keys = {
	.generate_key = cipher_suite_2_key_generate,
	.destroy_key = cipher_suite_2_key_destroy,
};

static const struct edhoc_crypto edhoc_crypto_mocked_init = {
	.make_key_pair = cipher_suite_2_make_key_pair_init,
	.key_agreement = cipher_suite_2_key_agreement,
	.signature = cipher_suite_2_signature,
	.verify = cipher_suite_2_verify,
	.extract = cipher_suite_2_extract,
	.expand = cipher_suite_2_expand,
	.encrypt = cipher_suite_2_encrypt,
	.decrypt = cipher_suite_2_decrypt,
	.hash = cipher_suite_2_hash,
};

static const struct edhoc_crypto edhoc_crypto_mocked_resp = {
	.make_key_pair = cipher_suite_2_make_key_pair_resp,
	.key_agreement = cipher_suite_2_key_agreement,
	.signature = cipher_suite_2_signature,
	.verify = cipher_suite_2_verify,
	.extract = cipher_suite_2_extract,
	.expand = cipher_suite_2_expand,
	.encrypt = cipher_suite_2_encrypt,
	.decrypt = cipher_suite_2_decrypt,
	.hash = cipher_suite_2_hash,
};

static const struct edhoc_crypto edhoc_crypto = {
	.make_key_pair = cipher_suite_2_make_key_pair,
	.key_agreement = cipher_suite_2_key_agreement,
	.signature = cipher_suite_2_signature,
	.verify = cipher_suite_2_verify,
	.extract = cipher_suite_2_extract,
	.expand = cipher_suite_2_expand,
	.encrypt = cipher_suite_2_encrypt,
	.decrypt = cipher_suite_2_decrypt,
	.hash = cipher_suite_2_hash,
};

static const struct edhoc_credentials edhoc_auth_cred_mocked_init = {
	.fetch = auth_cred_fetch_init_2,
	.verify = auth_cred_verify_init_2,
};

static const struct edhoc_credentials edhoc_auth_cred_mocked_init_any = {
	.fetch = auth_cred_fetch_init_2_any,
	.verify = auth_cred_verify_init_2,
};

static const struct edhoc_credentials edhoc_auth_cred_mocked_resp = {
	.fetch = auth_cred_fetch_resp_2,
	.verify = auth_cred_verify_resp_2,
};

static const struct edhoc_credentials edhoc_auth_cred_mocked_resp_any = {
	.fetch = auth_cred_fetch_resp_2_any,
	.verify = auth_cred_verify_resp_2,
};

/* Static function definitions --------------------------------------------- */

static int
cipher_suite_2_make_key_pair_init(void *user_ctx, const void *kid,
				  uint8_t *priv_key, size_t priv_key_size,
				  size_t *priv_key_len, uint8_t *pub_key,
				  size_t pub_key_size, size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == kid || NULL == priv_key || 0 == priv_key_size ||
	    NULL == priv_key_len || NULL == pub_key || 0 == pub_key_size ||
	    NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	*priv_key_len = ARRAY_SIZE(X);
	memcpy(priv_key, X, ARRAY_SIZE(X));

	*pub_key_len = ARRAY_SIZE(G_X);
	memcpy(pub_key, G_X, ARRAY_SIZE(G_X));

	return EDHOC_SUCCESS;
}

static int
cipher_suite_2_make_key_pair_resp(void *user_ctx, const void *kid,
				  uint8_t *priv_key, size_t priv_key_size,
				  size_t *priv_key_len, uint8_t *pub_key,
				  size_t pub_key_size, size_t *pub_key_len)
{
	(void)user_ctx;

	if (NULL == kid || NULL == priv_key || 0 == priv_key_size ||
	    NULL == priv_key_len || NULL == pub_key || 0 == pub_key_size ||
	    NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	*priv_key_len = ARRAY_SIZE(Y);
	memcpy(priv_key, Y, ARRAY_SIZE(Y));

	*pub_key_len = ARRAY_SIZE(G_X);
	memcpy(pub_key, G_Y, ARRAY_SIZE(G_Y));

	return EDHOC_SUCCESS;
}

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

void test_edhoc_handshake_2_message_1_compose(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	struct edhoc_context init_ctx = { 0 };
	struct edhoc_connection_id init_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_I[0],
	};

	/**
         * \brief Setup initiator context.
         */
	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);
	init_ctx.logger = print_array;

	ret = edhoc_set_method(&init_ctx, METHOD);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&init_ctx, edhoc_cipher_suites_init,
				      ARRAY_SIZE(edhoc_cipher_suites_init));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&init_ctx, init_cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, edhoc_crypto_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief EDHOC message 1 compose.
         */
	size_t msg_1_len = 0;
	uint8_t msg_1[ARRAY_SIZE(message_1)] = { 0 };

	ret = edhoc_message_1_compose(&init_ctx, msg_1, ARRAY_SIZE(msg_1),
				      &msg_1_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_WAIT_M2 == init_ctx.status);
	assert(false == init_ctx.is_oscore_export_allowed);

	enum edhoc_error_code error_code_recv =
		EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&init_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(ARRAY_SIZE(message_1) == msg_1_len);
	assert(0 == memcmp(message_1, msg_1, msg_1_len));

	assert(EDHOC_TH_STATE_1 == init_ctx.th_state);
	assert(ARRAY_SIZE(H_message_1) == init_ctx.th_len);
	assert(0 == memcmp(H_message_1, init_ctx.th, init_ctx.th_len));

	assert(EDHOC_PRK_STATE_INVALID == init_ctx.prk_state);
	assert(0 == init_ctx.prk_len);

	assert(ARRAY_SIZE(X) == init_ctx.dh_priv_key_len);
	assert(0 == memcmp(X, init_ctx.dh_priv_key, init_ctx.dh_priv_key_len));

	ret = edhoc_context_deinit(&init_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_handshake_2_message_1_process(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	struct edhoc_context resp_ctx = { 0 };
	struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = ARRAY_SIZE(C_R),
	};
	memcpy(resp_cid.bstr_value, C_R, ARRAY_SIZE(C_R));

	/**
         * \brief Setup responder context.
         */
	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
	resp_ctx.logger = print_array;

	ret = edhoc_set_method(&resp_ctx, METHOD);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, edhoc_cipher_suites_resp,
				      ARRAY_SIZE(edhoc_cipher_suites_resp));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&resp_ctx, resp_cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, edhoc_crypto_mocked_resp);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief EDHOC message 1 process.
         */
	ret = edhoc_message_1_process(&resp_ctx, message_1,
				      ARRAY_SIZE(message_1));

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_RECEIVED_M1 == resp_ctx.status);
	assert(false == resp_ctx.is_oscore_export_allowed);

	enum edhoc_error_code error_code_recv =
		EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(EDHOC_TH_STATE_1 == resp_ctx.th_state);
	assert(ARRAY_SIZE(H_message_1) == resp_ctx.th_len);
	assert(0 == memcmp(H_message_1, resp_ctx.th, resp_ctx.th_len));

	assert(EDHOC_PRK_STATE_INVALID == resp_ctx.prk_state);
	assert(0 == resp_ctx.prk_len);

	assert(EDHOC_CID_TYPE_ONE_BYTE_INTEGER ==
	       resp_ctx.peer_cid.encode_type);
	assert((int8_t)C_I[0] == resp_ctx.peer_cid.int_value);

	assert(ARRAY_SIZE(G_X) == resp_ctx.dh_peer_pub_key_len);
	assert(0 == memcmp(G_X, resp_ctx.dh_peer_pub_key,
			   resp_ctx.dh_peer_pub_key_len));

	ret = edhoc_context_deinit(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_handshake_2_message_2_compose(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	struct edhoc_context resp_ctx = { 0 };
	struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_R[0],
	};

	/**
         * \brief Setup responder context.
         */
	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
	resp_ctx.logger = print_array;

	ret = edhoc_set_method(&resp_ctx, METHOD);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, edhoc_cipher_suites_resp,
				      ARRAY_SIZE(edhoc_cipher_suites_resp));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&resp_ctx, resp_cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, edhoc_crypto_mocked_resp);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&resp_ctx, edhoc_auth_cred_mocked_resp);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Required injections.
         */
	resp_ctx.status = EDHOC_SM_RECEIVED_M1;

	resp_ctx.th_state = EDHOC_TH_STATE_1;
	resp_ctx.th_len = ARRAY_SIZE(H_message_1);
	memcpy(resp_ctx.th, H_message_1, sizeof(H_message_1));

	resp_ctx.dh_peer_pub_key_len = ARRAY_SIZE(G_X);
	memcpy(resp_ctx.dh_peer_pub_key, G_X, ARRAY_SIZE(G_X));

	resp_ctx.peer_cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	resp_ctx.peer_cid.int_value = (int8_t)C_I[0];

	/**
         * \brief EDHOC message 2 compose.
         */
	size_t msg_2_len = 0;
	uint8_t msg_2[ARRAY_SIZE(message_2)] = { 0 };

	ret = edhoc_message_2_compose(&resp_ctx, msg_2, ARRAY_SIZE(msg_2),
				      &msg_2_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_WAIT_M3 == resp_ctx.status);
	assert(false == resp_ctx.is_oscore_export_allowed);

	enum edhoc_error_code error_code_recv =
		EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(ARRAY_SIZE(message_2) == msg_2_len);
	assert(0 == memcmp(msg_2, message_2, msg_2_len));

	assert(EDHOC_TH_STATE_3 == resp_ctx.th_state);
	assert(ARRAY_SIZE(TH_3) == resp_ctx.th_len);
	assert(0 == memcmp(resp_ctx.th, TH_3, resp_ctx.th_len));

	assert(EDHOC_PRK_STATE_3E2M == resp_ctx.prk_state);
	assert(ARRAY_SIZE(PRK_3e2m) == resp_ctx.prk_len);
	assert(0 == memcmp(PRK_3e2m, resp_ctx.prk, resp_ctx.prk_len));

	assert(ARRAY_SIZE(G_XY) == resp_ctx.dh_secret_len);
	assert(0 == memcmp(G_XY, resp_ctx.dh_secret, resp_ctx.dh_secret_len));

	ret = edhoc_context_deinit(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_handshake_any_2_message_2_compose(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	struct edhoc_context resp_ctx = { 0 };
	struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_R[0],
	};

	/**
         * \brief Setup responder context.
         */
	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
	resp_ctx.logger = print_array;

	ret = edhoc_set_method(&resp_ctx, METHOD);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, edhoc_cipher_suites_resp,
				      ARRAY_SIZE(edhoc_cipher_suites_resp));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&resp_ctx, resp_cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, edhoc_crypto_mocked_resp);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&resp_ctx,
				     edhoc_auth_cred_mocked_resp_any);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Required injections.
         */
	resp_ctx.status = EDHOC_SM_RECEIVED_M1;

	resp_ctx.th_state = EDHOC_TH_STATE_1;
	resp_ctx.th_len = ARRAY_SIZE(H_message_1);
	memcpy(resp_ctx.th, H_message_1, sizeof(H_message_1));

	resp_ctx.dh_peer_pub_key_len = ARRAY_SIZE(G_X);
	memcpy(resp_ctx.dh_peer_pub_key, G_X, ARRAY_SIZE(G_X));

	resp_ctx.peer_cid.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
	resp_ctx.peer_cid.int_value = (int8_t)C_I[0];

	/**
         * \brief EDHOC message 2 compose.
         */
	size_t msg_2_len = 0;
	uint8_t msg_2[ARRAY_SIZE(message_2)] = { 0 };

	ret = edhoc_message_2_compose(&resp_ctx, msg_2, ARRAY_SIZE(msg_2),
				      &msg_2_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_WAIT_M3 == resp_ctx.status);
	assert(false == resp_ctx.is_oscore_export_allowed);

	enum edhoc_error_code error_code_recv =
		EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(ARRAY_SIZE(message_2) == msg_2_len);
	assert(0 == memcmp(msg_2, message_2, msg_2_len));

	assert(EDHOC_TH_STATE_3 == resp_ctx.th_state);
	assert(ARRAY_SIZE(TH_3) == resp_ctx.th_len);
	assert(0 == memcmp(resp_ctx.th, TH_3, resp_ctx.th_len));

	assert(EDHOC_PRK_STATE_3E2M == resp_ctx.prk_state);
	assert(ARRAY_SIZE(PRK_3e2m) == resp_ctx.prk_len);
	assert(0 == memcmp(PRK_3e2m, resp_ctx.prk, resp_ctx.prk_len));

	assert(ARRAY_SIZE(G_XY) == resp_ctx.dh_secret_len);
	assert(0 == memcmp(G_XY, resp_ctx.dh_secret, resp_ctx.dh_secret_len));

	ret = edhoc_context_deinit(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_handshake_2_message_2_process(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	struct edhoc_context init_ctx = { 0 };
	struct edhoc_connection_id init_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_I[0],
	};

	/**
         * \brief Setup initiator context.
         */
	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);
	init_ctx.logger = print_array;

	ret = edhoc_set_method(&init_ctx, METHOD);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&init_ctx, edhoc_cipher_suites_init,
				      ARRAY_SIZE(edhoc_cipher_suites_init));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&init_ctx, init_cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, edhoc_crypto_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&init_ctx, edhoc_auth_cred_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Required incjections.
         */
	init_ctx.status = EDHOC_SM_WAIT_M2;

	init_ctx.th_state = EDHOC_TH_STATE_1;
	init_ctx.th_len = ARRAY_SIZE(H_message_1);
	memcpy(init_ctx.th, H_message_1, ARRAY_SIZE(H_message_1));

	init_ctx.dh_priv_key_len = ARRAY_SIZE(X);
	memcpy(init_ctx.dh_priv_key, X, ARRAY_SIZE(X));

	/**
         * \brief EDHOC message 2 process.
         */
	ret = edhoc_message_2_process(&init_ctx, message_2,
				      ARRAY_SIZE(message_2));

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_VERIFIED_M2 == init_ctx.status);
	assert(false == init_ctx.is_oscore_export_allowed);

	enum edhoc_error_code error_code_recv =
		EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&init_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(EDHOC_TH_STATE_3 == init_ctx.th_state);
	assert(ARRAY_SIZE(TH_3) == init_ctx.th_len);
	assert(0 == memcmp(init_ctx.th, TH_3, init_ctx.th_len));

	assert(EDHOC_PRK_STATE_3E2M == init_ctx.prk_state);
	assert(ARRAY_SIZE(PRK_3e2m) == init_ctx.prk_len);
	assert(0 == memcmp(PRK_3e2m, init_ctx.prk, init_ctx.prk_len));

	assert(ARRAY_SIZE(G_XY) == init_ctx.dh_secret_len);
	assert(0 ==
	       memcmp(init_ctx.dh_secret, G_XY, sizeof(init_ctx.dh_secret)));

	assert(EDHOC_CID_TYPE_ONE_BYTE_INTEGER ==
	       init_ctx.peer_cid.encode_type);
	assert((int8_t)C_R[0] == init_ctx.peer_cid.int_value);

	ret = edhoc_context_deinit(&init_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_handshake_2_message_3_compose(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	struct edhoc_context init_ctx = { 0 };
	struct edhoc_connection_id init_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_I[0],
	};

	/**
         * \brief Setup initiator context.
         */
	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);
	init_ctx.logger = print_array;

	ret = edhoc_set_method(&init_ctx, METHOD);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&init_ctx, edhoc_cipher_suites_init,
				      ARRAY_SIZE(edhoc_cipher_suites_init));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&init_ctx, init_cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, edhoc_crypto_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&init_ctx, edhoc_auth_cred_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Required incjections.
         */
	init_ctx.status = EDHOC_SM_VERIFIED_M2;

	init_ctx.th_state = EDHOC_TH_STATE_3;
	init_ctx.th_len = ARRAY_SIZE(TH_3);
	memcpy(init_ctx.th, TH_3, ARRAY_SIZE(TH_3));

	init_ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	init_ctx.prk_len = ARRAY_SIZE(PRK_3e2m);
	memcpy(init_ctx.prk, PRK_3e2m, ARRAY_SIZE(PRK_3e2m));

	init_ctx.dh_peer_pub_key_len = ARRAY_SIZE(G_Y);
	memcpy(init_ctx.dh_peer_pub_key, G_Y, ARRAY_SIZE(G_Y));

	init_ctx.dh_secret_len = ARRAY_SIZE(G_XY);
	memcpy(init_ctx.dh_secret, G_XY, ARRAY_SIZE(G_XY));

	/**
         * \brief EDHOC message 3 compose.
         */
	size_t msg_3_len = 0;
	uint8_t msg_3[ARRAY_SIZE(message_3)] = { 0 };

	ret = edhoc_message_3_compose(&init_ctx, msg_3, ARRAY_SIZE(msg_3),
				      &msg_3_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_COMPLETED == init_ctx.status);
	assert(true == init_ctx.is_oscore_export_allowed);

	enum edhoc_error_code error_code_recv =
		EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&init_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(ARRAY_SIZE(message_3) == msg_3_len);
	assert(0 == memcmp(message_3, msg_3, msg_3_len));

	assert(EDHOC_TH_STATE_4 == init_ctx.th_state);
	assert(ARRAY_SIZE(TH_4) == init_ctx.th_len);
	assert(0 == memcmp(TH_4, init_ctx.th, init_ctx.th_len));

	assert(EDHOC_PRK_STATE_4E3M == init_ctx.prk_state);
	assert(ARRAY_SIZE(PRK_4e3m) == init_ctx.prk_len);
	assert(0 == memcmp(PRK_4e3m, init_ctx.prk, init_ctx.prk_len));

	ret = edhoc_context_deinit(&init_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_handshake_any_2_message_3_compose(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	struct edhoc_context init_ctx = { 0 };
	struct edhoc_connection_id init_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_I[0],
	};

	/**
         * \brief Setup initiator context.
         */
	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);
	init_ctx.logger = print_array;

	ret = edhoc_set_method(&init_ctx, METHOD);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&init_ctx, edhoc_cipher_suites_init,
				      ARRAY_SIZE(edhoc_cipher_suites_init));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&init_ctx, init_cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, edhoc_crypto_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&init_ctx,
				     edhoc_auth_cred_mocked_init_any);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Required incjections.
         */
	init_ctx.status = EDHOC_SM_VERIFIED_M2;

	init_ctx.th_state = EDHOC_TH_STATE_3;
	init_ctx.th_len = ARRAY_SIZE(TH_3);
	memcpy(init_ctx.th, TH_3, ARRAY_SIZE(TH_3));

	init_ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	init_ctx.prk_len = ARRAY_SIZE(PRK_3e2m);
	memcpy(init_ctx.prk, PRK_3e2m, ARRAY_SIZE(PRK_3e2m));

	init_ctx.dh_peer_pub_key_len = ARRAY_SIZE(G_Y);
	memcpy(init_ctx.dh_peer_pub_key, G_Y, ARRAY_SIZE(G_Y));

	init_ctx.dh_secret_len = ARRAY_SIZE(G_XY);
	memcpy(init_ctx.dh_secret, G_XY, ARRAY_SIZE(G_XY));

	/**
         * \brief EDHOC message 3 compose.
         */
	size_t msg_3_len = 0;
	uint8_t msg_3[ARRAY_SIZE(message_3)] = { 0 };

	ret = edhoc_message_3_compose(&init_ctx, msg_3, ARRAY_SIZE(msg_3),
				      &msg_3_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_COMPLETED == init_ctx.status);
	assert(true == init_ctx.is_oscore_export_allowed);

	enum edhoc_error_code error_code_recv =
		EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&init_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(ARRAY_SIZE(message_3) == msg_3_len);
	assert(0 == memcmp(message_3, msg_3, msg_3_len));

	assert(EDHOC_TH_STATE_4 == init_ctx.th_state);
	assert(ARRAY_SIZE(TH_4) == init_ctx.th_len);
	assert(0 == memcmp(TH_4, init_ctx.th, init_ctx.th_len));

	assert(EDHOC_PRK_STATE_4E3M == init_ctx.prk_state);
	assert(ARRAY_SIZE(PRK_4e3m) == init_ctx.prk_len);
	assert(0 == memcmp(PRK_4e3m, init_ctx.prk, init_ctx.prk_len));

	ret = edhoc_context_deinit(&init_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_handshake_2_message_3_process(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	struct edhoc_context resp_ctx = { 0 };
	struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_R[0],
	};

	/**
         * \brief Setup responder context.
         */
	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
	resp_ctx.logger = print_array;

	ret = edhoc_set_method(&resp_ctx, METHOD);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, edhoc_cipher_suites_resp,
				      ARRAY_SIZE(edhoc_cipher_suites_resp));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&resp_ctx, resp_cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, edhoc_crypto_mocked_resp);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&resp_ctx, edhoc_auth_cred_mocked_resp);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Required incjections.
         */
	resp_ctx.status = EDHOC_SM_WAIT_M3;

	resp_ctx.th_state = EDHOC_TH_STATE_3;
	resp_ctx.th_len = ARRAY_SIZE(TH_3);
	memcpy(resp_ctx.th, TH_3, ARRAY_SIZE(TH_3));

	resp_ctx.prk_state = EDHOC_PRK_STATE_3E2M;
	resp_ctx.prk_len = ARRAY_SIZE(PRK_3e2m);
	memcpy(resp_ctx.prk, PRK_3e2m, ARRAY_SIZE(PRK_3e2m));

	resp_ctx.dh_priv_key_len = ARRAY_SIZE(Y);
	memcpy(resp_ctx.dh_priv_key, Y, ARRAY_SIZE(Y));

	resp_ctx.dh_secret_len = ARRAY_SIZE(G_XY);
	memcpy(resp_ctx.dh_secret, G_XY, ARRAY_SIZE(G_XY));

	/**
         * \brief EDHOC message 3 process.
         */
	ret = edhoc_message_3_process(&resp_ctx, message_3,
				      ARRAY_SIZE(message_3));

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_COMPLETED == resp_ctx.status);
	assert(true == resp_ctx.is_oscore_export_allowed);

	enum edhoc_error_code error_code_recv =
		EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(EDHOC_TH_STATE_4 == resp_ctx.th_state);
	assert(ARRAY_SIZE(TH_4) == resp_ctx.th_len);
	assert(0 == memcmp(TH_4, resp_ctx.th, resp_ctx.th_len));

	assert(EDHOC_PRK_STATE_4E3M == resp_ctx.prk_state);
	assert(ARRAY_SIZE(PRK_4e3m) == resp_ctx.prk_len);
	assert(0 == memcmp(PRK_4e3m, resp_ctx.prk, resp_ctx.prk_len));

	ret = edhoc_context_deinit(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_handshake_2_message_4_compose(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	struct edhoc_context resp_ctx = { 0 };
	struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_R[0],
	};

	/**
         * \brief Setup responder context.
         */
	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
	resp_ctx.logger = print_array;

	ret = edhoc_set_method(&resp_ctx, METHOD);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, edhoc_cipher_suites_resp,
				      ARRAY_SIZE(edhoc_cipher_suites_resp));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&resp_ctx, resp_cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, edhoc_crypto_mocked_resp);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&resp_ctx, edhoc_auth_cred_mocked_resp);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Required incjections.
         */
	resp_ctx.status = EDHOC_SM_COMPLETED;
	resp_ctx.is_oscore_export_allowed = true;

	resp_ctx.th_state = EDHOC_TH_STATE_4;
	resp_ctx.th_len = ARRAY_SIZE(TH_4);
	memcpy(resp_ctx.th, TH_4, ARRAY_SIZE(TH_4));

	resp_ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	resp_ctx.prk_len = ARRAY_SIZE(PRK_4e3m);
	memcpy(resp_ctx.prk, PRK_4e3m, ARRAY_SIZE(PRK_4e3m));

	/**
         * \brief EDHOC message 4 compose.
         */
	size_t msg_4_len = 0;
	uint8_t msg_4[ARRAY_SIZE(message_4) + 1] = { 0 };

	ret = edhoc_message_4_compose(&resp_ctx, msg_4, ARRAY_SIZE(msg_4),
				      &msg_4_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_PERSISTED == resp_ctx.status);
	assert(true == resp_ctx.is_oscore_export_allowed);

	enum edhoc_error_code error_code_recv =
		EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(ARRAY_SIZE(message_4) == msg_4_len);
	assert(0 == memcmp(message_4, msg_4, msg_4_len));

	assert(EDHOC_TH_STATE_4 == resp_ctx.th_state);
	assert(ARRAY_SIZE(TH_4) == resp_ctx.th_len);
	assert(0 == memcmp(TH_4, resp_ctx.th, resp_ctx.th_len));

	assert(EDHOC_PRK_STATE_4E3M == resp_ctx.prk_state);
	assert(ARRAY_SIZE(PRK_4e3m) == resp_ctx.prk_len);
	assert(0 == memcmp(PRK_4e3m, resp_ctx.prk, resp_ctx.prk_len));

	ret = edhoc_context_deinit(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_handshake_2_message_4_process(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	struct edhoc_context init_ctx = { 0 };
	struct edhoc_connection_id init_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_I[0],
	};

	/**
         * \brief Setup initiator context.
         */
	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);
	init_ctx.logger = print_array;

	ret = edhoc_set_method(&init_ctx, METHOD);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&init_ctx, edhoc_cipher_suites_init,
				      ARRAY_SIZE(edhoc_cipher_suites_init));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&init_ctx, init_cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, edhoc_crypto_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&init_ctx, edhoc_auth_cred_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Required incjections.
         */
	init_ctx.status = EDHOC_SM_COMPLETED;
	init_ctx.is_oscore_export_allowed = true;

	init_ctx.th_state = EDHOC_TH_STATE_4;
	init_ctx.th_len = ARRAY_SIZE(TH_4);
	memcpy(init_ctx.th, TH_4, ARRAY_SIZE(TH_4));

	init_ctx.prk_state = EDHOC_PRK_STATE_4E3M;
	init_ctx.prk_len = ARRAY_SIZE(PRK_4e3m);
	memcpy(init_ctx.prk, PRK_4e3m, ARRAY_SIZE(PRK_4e3m));

	/**
         * \brief EDHOC message 4 process.
         */
	ret = edhoc_message_4_process(&init_ctx, message_4,
				      ARRAY_SIZE(message_4));

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_PERSISTED == init_ctx.status);
	assert(true == init_ctx.is_oscore_export_allowed);

	enum edhoc_error_code error_code_recv =
		EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&init_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(EDHOC_TH_STATE_4 == init_ctx.th_state);
	assert(ARRAY_SIZE(TH_4) == init_ctx.th_len);
	assert(0 == memcmp(TH_4, init_ctx.th, init_ctx.th_len));

	assert(EDHOC_PRK_STATE_4E3M == init_ctx.prk_state);
	assert(ARRAY_SIZE(PRK_4e3m) == init_ctx.prk_len);
	assert(0 == memcmp(PRK_4e3m, init_ctx.prk, init_ctx.prk_len));

	ret = edhoc_context_deinit(&init_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_handshake_2_e2e(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	enum edhoc_error_code error_code_recv =
		EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;

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

	ret = edhoc_set_cipher_suites(&init_ctx, edhoc_cipher_suites_init,
				      ARRAY_SIZE(edhoc_cipher_suites_init));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&init_ctx, init_cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, edhoc_crypto_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&init_ctx, edhoc_auth_cred_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Setup responder context.
         */
	struct edhoc_context resp_ctx = { 0 };
	struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_R[0],
	};

	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
	resp_ctx.logger = print_array;

	ret = edhoc_set_method(&resp_ctx, METHOD);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, edhoc_cipher_suites_resp,
				      ARRAY_SIZE(edhoc_cipher_suites_resp));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&resp_ctx, resp_cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, edhoc_crypto_mocked_resp);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&resp_ctx, edhoc_auth_cred_mocked_resp);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief One buffer for whole EDHOC handshake.
         */
	uint8_t buffer[200] = { 0 };

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

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&init_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(ARRAY_SIZE(message_1) == msg_1_len);
	assert(0 == memcmp(message_1, msg_1, msg_1_len));

	assert(EDHOC_PRK_STATE_INVALID == init_ctx.prk_state);
	assert(0 == init_ctx.prk_len);

	assert(EDHOC_TH_STATE_1 == init_ctx.th_state);
	assert(ARRAY_SIZE(H_message_1) == init_ctx.th_len);
	assert(0 == memcmp(H_message_1, init_ctx.th, init_ctx.th_len));

	assert(ARRAY_SIZE(X) == init_ctx.dh_priv_key_len);
	assert(0 == memcmp(X, init_ctx.dh_priv_key, init_ctx.dh_priv_key_len));

	/**
         * \brief EDHOC message 1 process.
         */
	ret = edhoc_message_1_process(&resp_ctx, msg_1, msg_1_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_RECEIVED_M1 == resp_ctx.status);
	assert(false == resp_ctx.is_oscore_export_allowed);

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(EDHOC_TH_STATE_1 == resp_ctx.th_state);
	assert(ARRAY_SIZE(H_message_1) == resp_ctx.th_len);
	assert(0 == memcmp(H_message_1, resp_ctx.th, resp_ctx.th_len));

	assert(EDHOC_PRK_STATE_INVALID == resp_ctx.prk_state);
	assert(0 == resp_ctx.prk_len);

	assert(EDHOC_CID_TYPE_ONE_BYTE_INTEGER ==
	       resp_ctx.peer_cid.encode_type);
	assert((int8_t)C_I[0] == resp_ctx.peer_cid.int_value);

	assert(ARRAY_SIZE(G_X) == resp_ctx.dh_peer_pub_key_len);
	assert(0 == memcmp(G_X, resp_ctx.dh_peer_pub_key,
			   resp_ctx.dh_peer_pub_key_len));

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

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(ARRAY_SIZE(message_2) == msg_2_len);
	assert(0 == memcmp(message_2, msg_2, msg_2_len));

	assert(EDHOC_TH_STATE_3 == resp_ctx.th_state);
	assert(ARRAY_SIZE(TH_3) == resp_ctx.th_len);
	assert(0 == memcmp(TH_3, resp_ctx.th, resp_ctx.th_len));

	assert(EDHOC_PRK_STATE_3E2M == resp_ctx.prk_state);
	assert(ARRAY_SIZE(PRK_3e2m) == resp_ctx.prk_len);
	assert(0 == memcmp(PRK_3e2m, resp_ctx.prk, resp_ctx.prk_len));

	assert(ARRAY_SIZE(G_XY) == resp_ctx.dh_secret_len);
	assert(0 == memcmp(G_XY, resp_ctx.dh_secret, resp_ctx.dh_secret_len));

	/**
         * \brief EDHOC message 2 process.
         */
	ret = edhoc_message_2_process(&init_ctx, msg_2, msg_2_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_VERIFIED_M2 == init_ctx.status);

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&init_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(EDHOC_TH_STATE_3 == init_ctx.th_state);
	assert(ARRAY_SIZE(TH_3) == init_ctx.th_len);
	assert(0 == memcmp(TH_3, init_ctx.th, init_ctx.th_len));
	assert(false == init_ctx.is_oscore_export_allowed);

	assert(EDHOC_PRK_STATE_3E2M == init_ctx.prk_state);
	assert(ARRAY_SIZE(PRK_3e2m) == init_ctx.prk_len);
	assert(0 == memcmp(PRK_3e2m, init_ctx.prk, init_ctx.prk_len));

	assert(ARRAY_SIZE(G_XY) == init_ctx.dh_secret_len);
	assert(0 == memcmp(G_XY, init_ctx.dh_secret, init_ctx.dh_secret_len));

	assert(EDHOC_CID_TYPE_ONE_BYTE_INTEGER ==
	       init_ctx.peer_cid.encode_type);
	assert((int8_t)C_R[0] == init_ctx.peer_cid.int_value);

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

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&init_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(ARRAY_SIZE(message_3) == msg_3_len);
	assert(0 == memcmp(message_3, msg_3, msg_3_len));

	assert(EDHOC_TH_STATE_4 == init_ctx.th_state);
	assert(ARRAY_SIZE(TH_4) == init_ctx.th_len);
	assert(0 == memcmp(TH_4, init_ctx.th, init_ctx.th_len));

	assert(EDHOC_PRK_STATE_4E3M == init_ctx.prk_state);
	assert(ARRAY_SIZE(PRK_4e3m) == init_ctx.prk_len);
	assert(0 == memcmp(PRK_4e3m, init_ctx.prk, init_ctx.prk_len));

	/**
         * \brief EDHOC message 3 process.
         */
	ret = edhoc_message_3_process(&resp_ctx, msg_3, msg_3_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_COMPLETED == resp_ctx.status);
	assert(true == resp_ctx.is_oscore_export_allowed);

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(EDHOC_TH_STATE_4 == resp_ctx.th_state);
	assert(ARRAY_SIZE(TH_4) == resp_ctx.th_len);
	assert(0 == memcmp(TH_4, resp_ctx.th, resp_ctx.th_len));

	assert(EDHOC_PRK_STATE_4E3M == resp_ctx.prk_state);
	assert(ARRAY_SIZE(PRK_4e3m) == resp_ctx.prk_len);
	assert(0 == memcmp(PRK_4e3m, resp_ctx.prk, resp_ctx.prk_len));

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

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(ARRAY_SIZE(message_4) == msg_4_len);
	assert(0 == memcmp(message_4, msg_4, msg_4_len));

	assert(EDHOC_TH_STATE_4 == resp_ctx.th_state);
	assert(ARRAY_SIZE(TH_4) == resp_ctx.th_len);
	assert(0 == memcmp(TH_4, resp_ctx.th, resp_ctx.th_len));

	assert(EDHOC_PRK_STATE_4E3M == resp_ctx.prk_state);
	assert(ARRAY_SIZE(PRK_4e3m) == resp_ctx.prk_len);
	assert(0 == memcmp(PRK_4e3m, resp_ctx.prk, resp_ctx.prk_len));

	/**
         * \brief EDHOC message 4 process.
         */
	ret = edhoc_message_4_process(&init_ctx, msg_4, msg_4_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_PERSISTED == init_ctx.status);
	assert(true == init_ctx.is_oscore_export_allowed);

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&init_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(EDHOC_TH_STATE_4 == init_ctx.th_state);
	assert(ARRAY_SIZE(TH_4) == init_ctx.th_len);
	assert(0 == memcmp(TH_4, init_ctx.th, init_ctx.th_len));

	assert(EDHOC_PRK_STATE_4E3M == init_ctx.prk_state);
	assert(ARRAY_SIZE(PRK_4e3m) == init_ctx.prk_len);
	assert(0 == memcmp(PRK_4e3m, init_ctx.prk, init_ctx.prk_len));

	/**
         * \brief Initiator - derive OSCORE secret & salt.
         */
	uint8_t init_master_secret[ARRAY_SIZE(OSCORE_Master_Secret)] = { 0 };
	uint8_t init_master_salt[ARRAY_SIZE(OSCORE_Master_Salt)] = { 0 };
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
	assert(ARRAY_SIZE(PRK_out) == init_ctx.prk_len);
	assert(0 == memcmp(PRK_out, init_ctx.prk, init_ctx.prk_len));

	/**
         * \brief Responder - derive OSCORE secret & salt.
         */
	uint8_t resp_master_secret[ARRAY_SIZE(OSCORE_Master_Secret)] = { 0 };
	uint8_t resp_master_salt[ARRAY_SIZE(OSCORE_Master_Salt)] = { 0 };
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
	assert(ARRAY_SIZE(PRK_out) == resp_ctx.prk_len);
	assert(0 == memcmp(PRK_out, resp_ctx.prk, resp_ctx.prk_len));

	/**
         * \brief Verify OSCORE master secret.
         */
	assert(0 == memcmp(init_master_secret, resp_master_secret,
			   sizeof(resp_master_secret)));
	assert(0 == memcmp(OSCORE_Master_Secret, init_master_secret,
			   sizeof(init_master_secret)));
	assert(0 == memcmp(OSCORE_Master_Secret, resp_master_secret,
			   sizeof(resp_master_secret)));

	/**
         * \brief Verify OSCORE master salt.
         */
	assert(0 == memcmp(init_master_salt, resp_master_salt,
			   sizeof(resp_master_salt)));
	assert(0 == memcmp(OSCORE_Master_Salt, init_master_salt,
			   sizeof(init_master_salt)));
	assert(0 == memcmp(OSCORE_Master_Salt, resp_master_salt,
			   sizeof(resp_master_salt)));

	/**
         * \brief Verify OSCORE sender and recipient identifiers shared by initiator.
         */
	assert(ARRAY_SIZE(C_I) == init_recipient_id_len);
	assert(0 == memcmp(C_I, init_recipient_id, init_recipient_id_len));
	assert(ARRAY_SIZE(C_I) == resp_sender_id_len);
	assert(0 == memcmp(C_I, resp_sender_id, resp_sender_id_len));

	/**
         * \brief Verify OSCORE sender and recipient identifiers shared by responder.
         */
	assert(ARRAY_SIZE(C_R) == init_sender_id_len);
	assert(0 == memcmp(C_R, init_sender_id, init_sender_id_len));
	assert(ARRAY_SIZE(C_R) == resp_recipient_id_len);
	assert(0 == memcmp(C_R, resp_recipient_id, resp_recipient_id_len));

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
	 * \brief Initiator - perform EDHOC key update.
	 */
	ret = edhoc_export_key_update(&init_ctx, keyUpdate_context,
				      ARRAY_SIZE(keyUpdate_context));

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_PERSISTED == init_ctx.status);
	assert(true == init_ctx.is_oscore_export_allowed);

	assert(EDHOC_PRK_STATE_OUT == init_ctx.prk_state);
	assert(ARRAY_SIZE(keyUpdate_PRK_out) == init_ctx.prk_len);
	assert(0 == memcmp(keyUpdate_PRK_out, init_ctx.prk, init_ctx.prk_len));

	/**
	 * \brief Responder - perform EDHOC key update.
	 */
	ret = edhoc_export_key_update(&resp_ctx, keyUpdate_context,
				      ARRAY_SIZE(keyUpdate_context));

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_PERSISTED == resp_ctx.status);
	assert(true == resp_ctx.is_oscore_export_allowed);

	assert(EDHOC_PRK_STATE_OUT == resp_ctx.prk_state);
	assert(ARRAY_SIZE(keyUpdate_PRK_out) == resp_ctx.prk_len);
	assert(0 == memcmp(keyUpdate_PRK_out, resp_ctx.prk, resp_ctx.prk_len));

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

	/**
         * \brief Verify OSCORE master secret.
         */
	assert(0 == memcmp(init_master_secret, resp_master_secret,
			   sizeof(resp_master_secret)));
	assert(0 == memcmp(keyUpdate_OSCORE_Master_Secret, init_master_secret,
			   sizeof(init_master_secret)));
	assert(0 == memcmp(keyUpdate_OSCORE_Master_Secret, resp_master_secret,
			   sizeof(resp_master_secret)));

	/**
         * \brief Verify OSCORE master salt.
         */
	assert(0 == memcmp(init_master_salt, resp_master_salt,
			   sizeof(resp_master_salt)));
	assert(0 == memcmp(keyUpdate_OSCORE_Master_Salt, init_master_salt,
			   sizeof(init_master_salt)));
	assert(0 == memcmp(keyUpdate_OSCORE_Master_Salt, resp_master_salt,
			   sizeof(resp_master_salt)));

	/**
         * \brief Verify OSCORE sender and recipient identifiers shared by initiator.
         */
	assert(ARRAY_SIZE(C_I) == init_recipient_id_len);
	assert(0 == memcmp(C_I, init_recipient_id, init_recipient_id_len));
	assert(ARRAY_SIZE(C_I) == resp_sender_id_len);
	assert(0 == memcmp(C_I, resp_sender_id, resp_sender_id_len));

	/**
         * \brief Verify OSCORE sender and recipient identifiers shared by responder.
         */
	assert(ARRAY_SIZE(C_R) == init_sender_id_len);
	assert(0 == memcmp(C_R, init_sender_id, init_sender_id_len));
	assert(ARRAY_SIZE(C_R) == resp_recipient_id_len);
	assert(0 == memcmp(C_R, resp_recipient_id, resp_recipient_id_len));

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

void test_edhoc_handshake_2_e2e_real_crypto(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;
	enum edhoc_error_code error_code_recv =
		EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;

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

	ret = edhoc_set_cipher_suites(&init_ctx, edhoc_cipher_suites_init,
				      ARRAY_SIZE(edhoc_cipher_suites_init));
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
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_R[0],
	};

	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
	resp_ctx.logger = print_array;

	ret = edhoc_set_method(&resp_ctx, METHOD);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, edhoc_cipher_suites_resp,
				      ARRAY_SIZE(edhoc_cipher_suites_resp));
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
	uint8_t buffer[200] = { 0 };

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

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&init_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	/**
         * \brief EDHOC message 1 process.
         */
	ret = edhoc_message_1_process(&resp_ctx, msg_1, msg_1_len);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_RECEIVED_M1 == resp_ctx.status);
	assert(false == resp_ctx.is_oscore_export_allowed);
	assert(EDHOC_TH_STATE_1 == resp_ctx.th_state);
	assert(EDHOC_PRK_STATE_INVALID == resp_ctx.prk_state);

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

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

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	/**
         * \brief EDHOC message 2 process.
         */
	ret = edhoc_message_2_process(&init_ctx, msg_2, msg_2_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_VERIFIED_M2 == init_ctx.status);
	assert(false == init_ctx.is_oscore_export_allowed);
	assert(EDHOC_TH_STATE_3 == init_ctx.th_state);
	assert(EDHOC_PRK_STATE_3E2M == init_ctx.prk_state);

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&init_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	assert(EDHOC_CID_TYPE_ONE_BYTE_INTEGER ==
	       init_ctx.peer_cid.encode_type);
	assert((int8_t)C_R[0] == init_ctx.peer_cid.int_value);

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

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&init_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	/**
         * \brief EDHOC message 3 process.
         */
	ret = edhoc_message_3_process(&resp_ctx, msg_3, msg_3_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_COMPLETED == resp_ctx.status);
	assert(true == resp_ctx.is_oscore_export_allowed);
	assert(EDHOC_TH_STATE_4 == resp_ctx.th_state);
	assert(EDHOC_PRK_STATE_4E3M == resp_ctx.prk_state);

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

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

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	/**
         * \brief EDHOC message 3 process.
         */
	ret = edhoc_message_4_process(&init_ctx, msg_4, msg_4_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_PERSISTED == init_ctx.status);
	assert(true == init_ctx.is_oscore_export_allowed);
	assert(EDHOC_TH_STATE_4 == init_ctx.th_state);
	assert(EDHOC_PRK_STATE_4E3M == init_ctx.prk_state);

	error_code_recv = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	ret = edhoc_error_get_code(&init_ctx, &error_code_recv);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_recv);

	/**
         * \brief Initiator - derive OSCORE secret & salt.
         */
	uint8_t init_master_secret[ARRAY_SIZE(OSCORE_Master_Secret)] = { 0 };
	uint8_t init_master_salt[ARRAY_SIZE(OSCORE_Master_Salt)] = { 0 };
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
	uint8_t resp_master_secret[ARRAY_SIZE(OSCORE_Master_Secret)] = { 0 };
	uint8_t resp_master_salt[ARRAY_SIZE(OSCORE_Master_Salt)] = { 0 };
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

	/**
	 * \brief Initiator - perform EDHOC key update.
	 */
	ret = edhoc_export_key_update(&init_ctx, keyUpdate_context,
				      ARRAY_SIZE(keyUpdate_context));
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_PERSISTED == init_ctx.status);
	assert(true == init_ctx.is_oscore_export_allowed);

	/**
	 * \brief Responder - perform EDHOC key update.
	 */
	ret = edhoc_export_key_update(&resp_ctx, keyUpdate_context,
				      ARRAY_SIZE(keyUpdate_context));
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
