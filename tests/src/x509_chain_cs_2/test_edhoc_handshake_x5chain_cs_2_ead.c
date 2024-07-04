/**
 * \file    test_edhoc_handshake_x5chain_cs_2_ead.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC handshake unit test for X.509 chain authentication method
 *          for cipher suite 2 with multiple EAD tokens.
 * \version 0.3
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Internal test headers: */
#include "x509_chain_cs_2/test_edhoc_handshake_x5chain_cs_2_ead.h"
#include "x509_chain_cs_2/test_vector_x5chain_cs_2.h"
#include "x509_chain_cs_2/authentication_credentials_x5chain_cs_2.h"
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

/* PSA crypto header: */
#include <psa/crypto.h>

/* Module defines ---------------------------------------------------------- */
#define OSCORE_MASTER_SECRET_LENGTH (16)
#define OSCORE_MASTER_SALT_LENGTH (8)
#define DH_KEY_AGREEMENT_LENGTH (32)
#define ENTROPY_LENGTH (16)
#define EAD_TOKEN_BUFFER_LEN (300)
#define MAX_NR_OF_EAD_TOKENS (3)

/* Module types and type definitiones -------------------------------------- */

struct ead_token_buf {
	int32_t label;
	uint8_t value[EAD_TOKEN_BUFFER_LEN];
	size_t value_len;
};

struct ead_context {
	enum edhoc_message msg;
	size_t recv_tokens;
	struct ead_token_buf token[MAX_NR_OF_EAD_TOKENS];
};

/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */

/**
 * \brief Helper function for printing arrays.
 */
static inline void print_array(void *user_context, const char *name,
			       const uint8_t *buffer, size_t buffer_length);

/* Static variables and constants ------------------------------------------ */

static const struct edhoc_cipher_suite edhoc_cipher_suite_2 = {
	.value = 2,
	.aead_key_length = 16,
	.aead_tag_length = 8,
	.aead_iv_length = 13,
	.hash_length = 32,
	.mac_length = 32,
	.ecc_key_length = 32,
	.ecc_sign_length = 64,
};

static const struct edhoc_keys edhoc_keys = {
	.generate_key = cipher_suite_2_key_generate,
	.destroy_key = cipher_suite_2_key_destroy,
};

static int
cipher_suite_2_make_key_pair_init(void *user_ctx, const void *kid,
				  uint8_t *priv_key, size_t priv_key_size,
				  size_t *priv_key_len, uint8_t *pub_key,
				  size_t pub_key_size, size_t *pub_key_len);

static int
cipher_suite_2_make_key_pair_resp(void *user_ctx, const void *kid,
				  uint8_t *priv_key, size_t priv_key_size,
				  size_t *priv_key_len, uint8_t *pub_key,
				  size_t pub_key_size, size_t *pub_key_len);

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

static const struct edhoc_credentials edhoc_auth_cred_single_cert_mocked_init = {
	.fetch = auth_cred_fetch_init_x5chain_cs_2_single_cert,
	.verify = auth_cred_verify_init_x5chain_cs_2_single_cert,
};

static const struct edhoc_credentials edhoc_auth_cred_single_cert_mocked_resp = {
	.fetch = auth_cred_fetch_resp_x5chain_cs_2_single_cert,
	.verify = auth_cred_verify_resp_x5chain_cs_2_single_cert,
};

static const uint8_t ead_val_msg_1[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
static const uint8_t ead_val_msg_2[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
					 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
					 0x0c, 0x0d, 0x0e, 0x0f };
static const uint8_t ead_val_msg_3[] = {
	0x55, 0x9a, 0xea, 0xd0, 0x82, 0x64, 0xd5, 0x79, 0x5d, 0x39, 0x09, 0x71,
	0x8c, 0xdd, 0x05, 0xab, 0xd4, 0x95, 0x72, 0xe8, 0x4f, 0xe5, 0x55, 0x90,
	0xee, 0xf3, 0x1a, 0x88, 0xa0, 0x8f, 0xdf, 0xfd, 0x3c, 0xb2, 0x5f, 0x25,
	0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
	0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
	0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
	0x58, 0x65, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
};

static const uint8_t ead_val_msg_4[] = { 0xff, 0xee, 0xdd, 0xcc,
					 0xbb, 0xaa, 0x00 };

static const struct edhoc_ead_token ead_single_token_msg_1 = {
	.label = 0,
	.value = ead_val_msg_1,
	.value_len = ARRAY_SIZE(ead_val_msg_1),
};

static const struct edhoc_ead_token ead_single_token_msg_2 = {
	.label = 24,
	.value = ead_val_msg_2,
	.value_len = ARRAY_SIZE(ead_val_msg_2),
};

static const struct edhoc_ead_token ead_single_token_msg_3 = {
	.label = 65535,
	.value = ead_val_msg_3,
	.value_len = ARRAY_SIZE(ead_val_msg_3),
};

static const struct edhoc_ead_token ead_single_token_msg_4 = {
	.label = -830,
	.value = ead_val_msg_4,
	.value_len = ARRAY_SIZE(ead_val_msg_4),
};

static const struct edhoc_ead_token ead_multiple_tokens_msg_1[] = {
	ead_single_token_msg_1,
	ead_single_token_msg_2,
	ead_single_token_msg_3,
};

static const struct edhoc_ead_token ead_multiple_tokens_msg_2[] = {
	ead_single_token_msg_3,
	ead_single_token_msg_1,
};

static const struct edhoc_ead_token ead_multiple_tokens_msg_3[] = {
	ead_single_token_msg_3,
	ead_single_token_msg_2,
	ead_single_token_msg_1,
};

static const struct edhoc_ead_token ead_multiple_tokens_msg_4[] = {
	ead_single_token_msg_1,
	ead_single_token_msg_4,
	ead_single_token_msg_3,
};

static int ead_compose_multiple_tokens(void *user_context,
				       enum edhoc_message message,
				       struct edhoc_ead_token *ead_token,
				       size_t ead_token_size,
				       size_t *ead_token_len);

static int ead_process_multiple_tokens(void *user_context,
				       enum edhoc_message message,
				       const struct edhoc_ead_token *ead_token,
				       size_t ead_token_size);

static const struct edhoc_ead edhoc_ead_multiple_tokens = {
	.compose = ead_compose_multiple_tokens,
	.process = ead_process_multiple_tokens,
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

static int ead_compose_multiple_tokens(void *user_ctx, enum edhoc_message msg,
				       struct edhoc_ead_token *ead_token,
				       size_t ead_token_size,
				       size_t *ead_token_len)
{
	if (NULL == user_ctx || NULL == ead_token || 0 == ead_token_size ||
	    NULL == ead_token_len)
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;

	size_t len = 0;
	const struct edhoc_ead_token *token = NULL;

	switch (msg) {
	case EDHOC_MSG_1:
		token = ead_multiple_tokens_msg_1;
		len = ARRAY_SIZE(ead_multiple_tokens_msg_1);
		break;
	case EDHOC_MSG_2:
		token = ead_multiple_tokens_msg_2;
		len = ARRAY_SIZE(ead_multiple_tokens_msg_2);
		break;
	case EDHOC_MSG_3:
		token = ead_multiple_tokens_msg_3;
		len = ARRAY_SIZE(ead_multiple_tokens_msg_3);
		break;
	case EDHOC_MSG_4:
		token = ead_multiple_tokens_msg_4;
		len = ARRAY_SIZE(ead_multiple_tokens_msg_4);
		break;
	default:
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	*ead_token_len = len;

	for (size_t i = 0; i < len; ++i)
		ead_token[i] = token[i];

	struct ead_context *ead_ctx = user_ctx;

	ead_ctx->msg = msg;
	ead_ctx->recv_tokens = len;

	for (size_t i = 0; i < ead_ctx->recv_tokens; ++i) {
		ead_ctx->token[i].label = ead_token[i].label;
		ead_ctx->token[i].value_len = ead_token[i].value_len;
		memcpy(ead_ctx->token[i].value, ead_token[i].value,
		       ead_token[i].value_len);
	}

	return EDHOC_SUCCESS;
}

static int ead_process_multiple_tokens(void *user_ctx, enum edhoc_message msg,
				       const struct edhoc_ead_token *ead_token,
				       size_t ead_token_size)
{
	if (NULL == user_ctx || NULL == ead_token || 0 == ead_token_size)
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;

	struct ead_context *ead_ctx = user_ctx;

	ead_ctx->msg = msg;
	ead_ctx->recv_tokens = ead_token_size;

	for (size_t i = 0; i < ead_token_size; ++i) {
		ead_ctx->token[i].label = ead_token[i].label;
		ead_ctx->token[i].value_len = ead_token[i].value_len;
		memcpy(ead_ctx->token[i].value, ead_token[i].value,
		       ead_token[i].value_len);
	}

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

void test_edhoc_handshake_x5chain_cs_2_single_cert_e2e_multiple_ead_tokens(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/**
         * \brief Setup initiator context.
         */
	struct edhoc_context init_ctx = { 0 };
	struct ead_context init_ead_ctx = { 0 };
	struct edhoc_connection_id init_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_I[0],
	};

	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);
	init_ctx.logger = print_array;

	ret = edhoc_set_method(&init_ctx, METHOD);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&init_ctx, &edhoc_cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&init_ctx, init_cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_user_context(&init_ctx, &init_ead_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_ead(&init_ctx, edhoc_ead_multiple_tokens);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, edhoc_crypto_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&init_ctx,
				     edhoc_auth_cred_single_cert_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Setup responder context.
         */
	struct edhoc_context resp_ctx = { 0 };
	struct ead_context resp_ead_ctx = { 0 };
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

	ret = edhoc_set_cipher_suites(&resp_ctx, &edhoc_cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&resp_ctx, resp_cid);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_user_context(&resp_ctx, &resp_ead_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_ead(&resp_ctx, edhoc_ead_multiple_tokens);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, edhoc_crypto_mocked_resp);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&resp_ctx,
				     edhoc_auth_cred_single_cert_mocked_resp);
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

	/* Verify EAD_1 compose. */
	assert(EDHOC_MSG_1 == init_ead_ctx.msg);
	assert(ARRAY_SIZE(ead_multiple_tokens_msg_1) ==
	       init_ead_ctx.recv_tokens);

	for (size_t i = 0; i < init_ead_ctx.recv_tokens; ++i) {
		assert(ead_multiple_tokens_msg_1[i].label ==
		       init_ead_ctx.token[i].label);
		assert(ead_multiple_tokens_msg_1[i].value_len ==
		       init_ead_ctx.token[i].value_len);
		assert(0 == memcmp(ead_multiple_tokens_msg_1[i].value,
				   init_ead_ctx.token[i].value,
				   init_ead_ctx.token[i].value_len));
	}

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

	/* Verify EAD_1 process. */
	assert(EDHOC_MSG_1 == resp_ead_ctx.msg);
	assert(ARRAY_SIZE(ead_multiple_tokens_msg_1) ==
	       resp_ead_ctx.recv_tokens);

	for (size_t i = 0; i < resp_ead_ctx.recv_tokens; ++i) {
		assert(ead_multiple_tokens_msg_1[i].label ==
		       resp_ead_ctx.token[i].label);
		assert(ead_multiple_tokens_msg_1[i].value_len ==
		       resp_ead_ctx.token[i].value_len);
		assert(0 == memcmp(ead_multiple_tokens_msg_1[i].value,
				   resp_ead_ctx.token[i].value,
				   resp_ead_ctx.token[i].value_len));
	}

	/**
         * \brief Zeros EAD context's.
         */
	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

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

	/* Verify EAD_2 compose. */
	assert(EDHOC_MSG_2 == resp_ead_ctx.msg);
	assert(ARRAY_SIZE(ead_multiple_tokens_msg_2) ==
	       resp_ead_ctx.recv_tokens);

	for (size_t i = 0; i < resp_ead_ctx.recv_tokens; ++i) {
		assert(ead_multiple_tokens_msg_2[i].label ==
		       resp_ead_ctx.token[i].label);
		assert(ead_multiple_tokens_msg_2[i].value_len ==
		       resp_ead_ctx.token[i].value_len);
		assert(0 == memcmp(ead_multiple_tokens_msg_2[i].value,
				   resp_ead_ctx.token[i].value,
				   resp_ead_ctx.token[i].value_len));
	}

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

	/* Verify EAD_2 process. */
	assert(EDHOC_MSG_2 == init_ead_ctx.msg);
	assert(ARRAY_SIZE(ead_multiple_tokens_msg_2) ==
	       init_ead_ctx.recv_tokens);

	for (size_t i = 0; i < init_ead_ctx.recv_tokens; ++i) {
		assert(ead_multiple_tokens_msg_2[i].label ==
		       init_ead_ctx.token[i].label);
		assert(ead_multiple_tokens_msg_2[i].value_len ==
		       init_ead_ctx.token[i].value_len);
		assert(0 == memcmp(ead_multiple_tokens_msg_2[i].value,
				   init_ead_ctx.token[i].value,
				   init_ead_ctx.token[i].value_len));
	}

	/**
         * \brief Verify ephemeral DH key agreement.
         */
	assert(DH_KEY_AGREEMENT_LENGTH == init_ctx.dh_secret_len);
	assert(DH_KEY_AGREEMENT_LENGTH == resp_ctx.dh_secret_len);
	assert(init_ctx.dh_secret_len == resp_ctx.dh_secret_len);
	assert(0 == memcmp(init_ctx.dh_secret, resp_ctx.dh_secret,
			   DH_KEY_AGREEMENT_LENGTH));

	/**
         * \brief Zeros EAD context's.
         */
	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

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

	/* Verify EAD_3 compose. */
	assert(EDHOC_MSG_3 == init_ead_ctx.msg);
	assert(ARRAY_SIZE(ead_multiple_tokens_msg_3) ==
	       init_ead_ctx.recv_tokens);

	for (size_t i = 0; i < init_ead_ctx.recv_tokens; ++i) {
		assert(ead_multiple_tokens_msg_3[i].label ==
		       init_ead_ctx.token[i].label);
		assert(ead_multiple_tokens_msg_3[i].value_len ==
		       init_ead_ctx.token[i].value_len);
		assert(0 == memcmp(ead_multiple_tokens_msg_3[i].value,
				   init_ead_ctx.token[i].value,
				   init_ead_ctx.token[i].value_len));
	}

	/**
         * \brief EDHOC message 3 process.
         */
	ret = edhoc_message_3_process(&resp_ctx, msg_3, msg_3_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_COMPLETED == resp_ctx.status);
	assert(true == resp_ctx.is_oscore_export_allowed);
	assert(EDHOC_TH_STATE_4 == resp_ctx.th_state);
	assert(EDHOC_PRK_STATE_4E3M == resp_ctx.prk_state);

	/* Verify EAD_3 process. */
	assert(EDHOC_MSG_3 == resp_ead_ctx.msg);
	assert(ARRAY_SIZE(ead_multiple_tokens_msg_3) ==
	       resp_ead_ctx.recv_tokens);

	for (size_t i = 0; i < resp_ead_ctx.recv_tokens; ++i) {
		assert(ead_multiple_tokens_msg_3[i].label ==
		       resp_ead_ctx.token[i].label);
		assert(ead_multiple_tokens_msg_3[i].value_len ==
		       resp_ead_ctx.token[i].value_len);
		assert(0 == memcmp(ead_multiple_tokens_msg_3[i].value,
				   resp_ead_ctx.token[i].value,
				   resp_ead_ctx.token[i].value_len));
	}

	/**
         * \brief Zeros EAD context's.
         */
	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

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

	/* Verify EAD_4 compose. */
	assert(EDHOC_MSG_4 == resp_ead_ctx.msg);
	assert(ARRAY_SIZE(ead_multiple_tokens_msg_4) ==
	       resp_ead_ctx.recv_tokens);

	for (size_t i = 0; i < resp_ead_ctx.recv_tokens; ++i) {
		assert(ead_multiple_tokens_msg_4[i].label ==
		       resp_ead_ctx.token[i].label);
		assert(ead_multiple_tokens_msg_4[i].value_len ==
		       resp_ead_ctx.token[i].value_len);
		assert(0 == memcmp(ead_multiple_tokens_msg_4[i].value,
				   resp_ead_ctx.token[i].value,
				   resp_ead_ctx.token[i].value_len));
	}

	/**
         * \brief EDHOC message 4 process.
         */
	ret = edhoc_message_4_process(&init_ctx, msg_4, msg_4_len);

	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_SM_PERSISTED == init_ctx.status);
	assert(true == init_ctx.is_oscore_export_allowed);
	assert(EDHOC_TH_STATE_4 == init_ctx.th_state);
	assert(EDHOC_PRK_STATE_4E3M == init_ctx.prk_state);

	/* Verify EAD_4 process. */
	assert(EDHOC_MSG_4 == init_ead_ctx.msg);
	assert(ARRAY_SIZE(ead_multiple_tokens_msg_4) ==
	       init_ead_ctx.recv_tokens);

	for (size_t i = 0; i < init_ead_ctx.recv_tokens; ++i) {
		assert(ead_multiple_tokens_msg_4[i].label ==
		       init_ead_ctx.token[i].label);
		assert(ead_multiple_tokens_msg_4[i].value_len ==
		       init_ead_ctx.token[i].value_len);
		assert(0 == memcmp(ead_multiple_tokens_msg_4[i].value,
				   init_ead_ctx.token[i].value,
				   init_ead_ctx.token[i].value_len));
	}

	/**
         * \brief Zeros EAD context's.
         */
	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

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
