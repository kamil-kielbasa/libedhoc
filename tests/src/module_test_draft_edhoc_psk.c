/**
 * \file    module_test_draft_edhoc_psk.c
 * \author  Kamil Kielbasa
 * \brief   Module tests according to EDHOC-PSK (draft-ietf-lake-edhoc-psk-03)
 * \version 1.0
 * \date    2025-04-24
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Test vector header: */
#include "test_vector_draft_edhoc_psk.h"

/* Cipher suite 2 header: */
#include "cipher_suite_2.h"

/* Standard library headers: */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

/* EDHOC header: */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include <edhoc.h>

/* PSA crypto header: */
#include <psa/crypto.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */

#define UNUSED(x) ((void)x)

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
 * \brief Authentication credentials fetch callback for initiator.
 */
static int auth_cred_fetch_init(void *user_ctx,
				struct edhoc_auth_creds *auth_cred);

/**
 * \brief Authentication credentials fetch callback for responder.
 */
static int auth_cred_fetch_resp(void *user_ctx,
				struct edhoc_auth_creds *auth_cred);

/**
 * \brief Authentication credentials verify callback for initiator.
 */
static int auth_cred_verify_init(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred,
				 const uint8_t **pub_key, size_t *pub_key_len);

/**
 * \brief Authentication credentials verify callback for responder.
 */
static int auth_cred_verify_resp(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred,
				 const uint8_t **pub_key, size_t *pub_key_len);

/**
 * \brief Example EAD compose for multiple tokens. 
 */
static int ead_compose_multiple_tokens(void *user_context,
				       enum edhoc_message message,
				       struct edhoc_ead_token *ead_token,
				       size_t ead_token_size,
				       size_t *ead_token_len);

/**
 * \brief Example EAD process for multiple tokens. 
 */
static int ead_process_multiple_tokens(void *user_context,
				       enum edhoc_message message,
				       const struct edhoc_ead_token *ead_token,
				       size_t ead_token_size);

/**
 * \brief Helper function for printing arrays.
 */
static void print_array(void *user_context, const char *name,
			const uint8_t *buffer, size_t buffer_length);

/* Static variables and constants ------------------------------------------ */

static int ret = EDHOC_ERROR_GENERIC_ERROR;
static enum edhoc_error_code error_code_recv =
	EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;

static struct edhoc_context edhoc_initiator_context = { 0 };
static struct edhoc_context *init_ctx = &edhoc_initiator_context;

static struct edhoc_context edhoc_responder_context = { 0 };
static struct edhoc_context *resp_ctx = &edhoc_responder_context;

static const struct edhoc_credentials edhoc_auth_cred_mocked_init = {
	.fetch = auth_cred_fetch_init,
	.verify = auth_cred_verify_init,
};

static const struct edhoc_credentials edhoc_auth_cred_mocked_resp = {
	.fetch = auth_cred_fetch_resp,
	.verify = auth_cred_verify_resp,
};

static const struct edhoc_ead edhoc_ead_multiple_tokens = {
	.compose = ead_compose_multiple_tokens,
	.process = ead_process_multiple_tokens,
};

static const uint8_t ead_val_msg_1[] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
};
static const uint8_t ead_val_msg_2[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
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

static const uint8_t ead_val_msg_4[] = {
	0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x00,
};

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

/* Static function definitions --------------------------------------------- */

static int auth_cred_fetch_init(void *user_ctx,
				struct edhoc_auth_creds *auth_cred)
{
	UNUSED(user_ctx);

	if (NULL == auth_cred)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	*auth_cred = (struct edhoc_auth_creds){
		.label = EDHOC_COSE_HEADER_KID,
		.key_id =
			(struct edhoc_auth_cred_key_id){
				.cred = CRED_PSK_cborised,
				.cred_len = ARRAY_SIZE(CRED_PSK_cborised),
				.cred_is_cbor = true,
				.encode_type = EDHOC_ENCODE_TYPE_INTEGER,
				.key_id_int = ID_CRED_PSK_raw,
			},
	};

	return EDHOC_SUCCESS;
}

static int auth_cred_fetch_resp(void *user_ctx,
				struct edhoc_auth_creds *auth_cred)
{
	return EDHOC_ERROR_CREDENTIALS_FAILURE;
}

static int auth_cred_verify_init(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred,
				 const uint8_t **pub_key, size_t *pub_key_len)
{
	return EDHOC_ERROR_CREDENTIALS_FAILURE;
}

static int auth_cred_verify_resp(void *user_ctx,
				 struct edhoc_auth_creds *auth_cred,
				 const uint8_t **pub_key, size_t *pub_key_len)
{
	UNUSED(user_ctx);
	UNUSED(pub_key);
	UNUSED(pub_key_len);

	if (EDHOC_COSE_HEADER_KID != auth_cred->label)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (EDHOC_ENCODE_TYPE_INTEGER != auth_cred->key_id.encode_type)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	if (ID_CRED_PSK_raw != auth_cred->key_id.key_id_int)
		return EDHOC_ERROR_CREDENTIALS_FAILURE;

	auth_cred->key_id.cred_is_cbor = true;
	auth_cred->key_id.cred = CRED_PSK_cborised;
	auth_cred->key_id.cred_len = ARRAY_SIZE(CRED_PSK_cborised);

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

static void print_array(void *user_context, const char *name,
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

TEST_GROUP(draft_edhoc_psk);

TEST_SETUP(draft_edhoc_psk)
{
	ret = psa_crypto_init();
	TEST_ASSERT_EQUAL(PSA_SUCCESS, ret);

	const enum edhoc_mode mode = EDHOC_MODE_PSK_DRAFT;
	const enum edhoc_method methods[] = { METHOD };

	const struct edhoc_connection_id init_cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = (int8_t)C_I[0],
	};

	struct edhoc_connection_id resp_cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = ARRAY_SIZE(C_R),
	};
	memcpy(&resp_cid.bstr_value, C_R, ARRAY_SIZE(C_R));

	ret = edhoc_context_init(init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_mode(init_ctx, mode);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(init_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(init_ctx, cipher_suite_2_get_info(), 1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(init_ctx, &init_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_keys(init_ctx, cipher_suite_2_get_keys_callbacks());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(init_ctx,
				cipher_suite_2_get_cipher_callbacks());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(init_ctx, &edhoc_auth_cred_mocked_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_init(resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_mode(resp_ctx, mode);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(resp_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(resp_ctx, cipher_suite_2_get_info(), 1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(resp_ctx, &resp_cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_keys(resp_ctx, cipher_suite_2_get_keys_callbacks());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(resp_ctx,
				cipher_suite_2_get_cipher_callbacks());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(resp_ctx, &edhoc_auth_cred_mocked_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

#if defined(TEST_TRACES)
	init_ctx->logger = print_array;
	resp_ctx->logger = print_array;
#endif
}

TEST_TEAR_DOWN(draft_edhoc_psk)
{
	mbedtls_psa_crypto_free();

	ret = edhoc_context_deinit(init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(draft_edhoc_psk, handshake_real_crypto_without_ead)
{
	uint8_t buffer[50] = { 0 };

	memset(buffer, 0, sizeof(buffer));
	size_t msg_1_len = 0;
	uint8_t *msg_1 = buffer;

	/* EDHOC message 1 compose. */
	ret = edhoc_message_1_compose(init_ctx, msg_1, ARRAY_SIZE(buffer),
				      &msg_1_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M2, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(false, init_ctx->is_psk_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, init_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_INVALID, init_ctx->prk_state);
	TEST_ASSERT_EQUAL(0, init_ctx->prk_len);

	/* EDHOC message 1 process. */
	ret = edhoc_message_1_process(resp_ctx, msg_1, msg_1_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_RECEIVED_M1, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_psk_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_INVALID, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(0, resp_ctx->prk_len);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
			  resp_ctx->peer_cid.encode_type);
	TEST_ASSERT_EQUAL((int8_t)C_I[0], resp_ctx->peer_cid.int_value);

	TEST_ASSERT_EQUAL(ECC_COMP_KEY_LEN, resp_ctx->dh_peer_pub_key_len);

	/* Verify internal state of initiator and responder. */
	TEST_ASSERT_EQUAL(init_ctx->th_state, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(init_ctx->th_len, resp_ctx->th_len);

	TEST_ASSERT_EQUAL(init_ctx->prk_state, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(init_ctx->prk_len, resp_ctx->prk_len);

	memset(buffer, 0, sizeof(buffer));
	size_t msg_2_len = 0;
	uint8_t *msg_2 = buffer;

	/* EDHOC message 2 compose. */
	ret = edhoc_message_2_compose(resp_ctx, msg_2, ARRAY_SIZE(buffer),
				      &msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M3, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_psk_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(ECC_COMP_KEY_LEN, resp_ctx->dh_secret_len);

	/* EDHOC message 2 process. */
	ret = edhoc_message_2_process(init_ctx, msg_2, msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_VERIFIED_M2, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(false, init_ctx->is_psk_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, init_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, init_ctx->prk_state);

	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_BYTE_STRING,
			  init_ctx->peer_cid.encode_type);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(C_R), init_ctx->peer_cid.bstr_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(C_R, init_ctx->peer_cid.bstr_value,
				      init_ctx->peer_cid.bstr_length);

	/* Verify internal state of initiator and responder. */
	TEST_ASSERT_EQUAL(init_ctx->dh_secret_len, resp_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->dh_secret, resp_ctx->dh_secret,
				      init_ctx->dh_secret_len);

	TEST_ASSERT_EQUAL(init_ctx->th_state, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(init_ctx->th_len, resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->th, resp_ctx->th,
				      init_ctx->th_len);

	TEST_ASSERT_EQUAL(init_ctx->prk_state, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(init_ctx->prk_len, resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->prk, resp_ctx->prk,
				      init_ctx->prk_len);

	memset(buffer, 0, sizeof(buffer));
	size_t msg_3_len = 0;
	uint8_t *msg_3 = buffer;

	/* EDHOC message 3 compose. */
	ret = edhoc_message_3_compose(init_ctx, msg_3, ARRAY_SIZE(buffer),
				      &msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, init_ctx->status);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(true, init_ctx->is_psk_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, init_ctx->prk_state);

	/* EDHOC message 3 process. */
	ret = edhoc_message_3_process(resp_ctx, msg_3, msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, resp_ctx->status);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_psk_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	/* Verify internal state of initiator and responder. */
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(init_ctx->th_state, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(init_ctx->th_len, resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->th, resp_ctx->th,
				      resp_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(init_ctx->prk_state, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(init_ctx->prk_len, resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->prk, resp_ctx->prk,
				      resp_ctx->prk_len);

	memset(buffer, 0, sizeof(buffer));
	size_t msg_4_len = 0;
	uint8_t *msg_4 = buffer;

	/* EDHOC message 4 compose. */
	ret = edhoc_message_4_compose(resp_ctx, msg_4, ARRAY_SIZE(buffer),
				      &msg_4_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->status);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_psk_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->prk_state);

	/* EDHOC message 4 process. */
	ret = edhoc_message_4_process(init_ctx, msg_4, msg_4_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->status);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(true, init_ctx->is_psk_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, init_ctx->prk_state);

	/* Verify internal state of initiator and responder. */
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(init_ctx->th_state, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(init_ctx->th_len, resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->th, resp_ctx->th,
				      resp_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(init_ctx->prk_state, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(init_ctx->prk_len, resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->prk, resp_ctx->prk,
				      resp_ctx->prk_len);

	/* Export ID_CRED_PSK & CRED_PSK. */
	uint8_t init_cred_psk[ARRAY_SIZE(CRED_PSK_raw_key)] = { 0 };
	uint8_t init_id_cred_psk = 0;
	ret = edhoc_export_psk(init_ctx, init_cred_psk,
			       ARRAY_SIZE(init_cred_psk), &init_id_cred_psk,
			       sizeof(init_id_cred_psk));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(false, init_ctx->is_psk_export_allowed);

	uint8_t resp_cred_psk[ARRAY_SIZE(CRED_PSK_raw_key)] = { 0 };
	uint8_t resp_id_cred_psk = 0;
	ret = edhoc_export_psk(resp_ctx, resp_cred_psk,
			       ARRAY_SIZE(resp_cred_psk), &resp_id_cred_psk,
			       sizeof(resp_id_cred_psk));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_psk_export_allowed);

	/* Verify initiator and responder exported ID_CRED_PSK & CRED_PSK. */
	TEST_ASSERT_EQUAL(ARRAY_SIZE(init_cred_psk), ARRAY_SIZE(resp_cred_psk));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_cred_psk, resp_cred_psk,
				      ARRAY_SIZE(resp_cred_psk));
	TEST_ASSERT_EQUAL(sizeof(init_id_cred_psk), sizeof(resp_id_cred_psk));
	TEST_ASSERT_EQUAL(init_id_cred_psk, resp_id_cred_psk);

	uint8_t init_master_secret[oscore_master_secret_length];
	memset(init_master_secret, 0, sizeof(init_master_secret));
	uint8_t init_master_salt[oscore_master_salt_length];
	memset(init_master_salt, 0, sizeof(init_master_salt));
	size_t init_sender_id_len = 0;
	uint8_t init_sender_id[ARRAY_SIZE(C_R)] = { 0 };
	size_t init_recipient_id_len = 0;
	uint8_t init_recipient_id[ARRAY_SIZE(C_I)] = { 0 };

	/* Derive OSCORE master secret and master salt. */
	ret = edhoc_export_oscore_session(
		init_ctx, init_master_secret, ARRAY_SIZE(init_master_secret),
		init_master_salt, ARRAY_SIZE(init_master_salt), init_sender_id,
		ARRAY_SIZE(init_sender_id), &init_sender_id_len,
		init_recipient_id, ARRAY_SIZE(init_recipient_id),
		&init_recipient_id_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, init_ctx->prk_state);

	uint8_t resp_master_secret[oscore_master_secret_length];
	memset(resp_master_secret, 0, sizeof(resp_master_secret));
	uint8_t resp_master_salt[oscore_master_salt_length];
	memset(resp_master_salt, 0, sizeof(resp_master_salt));
	size_t resp_sender_id_len = 0;
	uint8_t resp_sender_id[ARRAY_SIZE(C_I)] = { 0 };
	size_t resp_recipient_id_len = 0;
	uint8_t resp_recipient_id[ARRAY_SIZE(C_R)] = { 0 };

	/* Derive OSCORE master secret and master salt. */
	ret = edhoc_export_oscore_session(
		resp_ctx, resp_master_secret, ARRAY_SIZE(resp_master_secret),
		resp_master_salt, ARRAY_SIZE(resp_master_salt), resp_sender_id,
		ARRAY_SIZE(resp_sender_id), &resp_sender_id_len,
		resp_recipient_id, ARRAY_SIZE(resp_recipient_id),
		&resp_recipient_id_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, resp_ctx->prk_state);

	/* Verify initiator and responder exported OSCORE sessions. */
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

TEST(draft_edhoc_psk, handshake_real_crypto_with_ead)
{
	uint8_t buffer[500] = { 0 };

	/* Required injections. */
	struct ead_context init_ead_ctx = { 0 };
	ret = edhoc_set_user_context(init_ctx, &init_ead_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_ead(init_ctx, &edhoc_ead_multiple_tokens);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct ead_context resp_ead_ctx = { 0 };
	ret = edhoc_set_user_context(resp_ctx, &resp_ead_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_ead(resp_ctx, &edhoc_ead_multiple_tokens);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

	memset(buffer, 0, sizeof(buffer));
	size_t msg_1_len = 0;
	uint8_t *msg_1 = buffer;

	/* EDHOC message 1 compose. */
	ret = edhoc_message_1_compose(init_ctx, msg_1, ARRAY_SIZE(buffer),
				      &msg_1_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M2, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(false, init_ctx->is_psk_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, init_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_INVALID, init_ctx->prk_state);
	TEST_ASSERT_EQUAL(0, init_ctx->prk_len);

	/* Verify EAD_1 compose. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_1, init_ead_ctx.msg);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ead_multiple_tokens_msg_1),
			  init_ead_ctx.recv_tokens);

	for (size_t i = 0; i < init_ead_ctx.recv_tokens; ++i) {
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_1[i].label,
				  init_ead_ctx.token[i].label);
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_1[i].value_len,
				  init_ead_ctx.token[i].value_len);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(
			ead_multiple_tokens_msg_1[i].value,
			init_ead_ctx.token[i].value,
			init_ead_ctx.token[i].value_len);
	}

	/* EDHOC message 1 process. */
	ret = edhoc_message_1_process(resp_ctx, msg_1, msg_1_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_RECEIVED_M1, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_psk_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_INVALID, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(0, resp_ctx->prk_len);
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_1, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
			  resp_ctx->peer_cid.encode_type);
	TEST_ASSERT_EQUAL((int8_t)C_I[0], resp_ctx->peer_cid.int_value);

	TEST_ASSERT_EQUAL(ECC_COMP_KEY_LEN, resp_ctx->dh_peer_pub_key_len);

	/* Verify internal state of initiator and responder. */
	TEST_ASSERT_EQUAL(init_ctx->th_state, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(init_ctx->th_len, resp_ctx->th_len);

	TEST_ASSERT_EQUAL(init_ctx->prk_state, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(init_ctx->prk_len, resp_ctx->prk_len);

	/* Verify EAD_1 process. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_1, resp_ead_ctx.msg);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ead_multiple_tokens_msg_1),
			  resp_ead_ctx.recv_tokens);

	for (size_t i = 0; i < resp_ead_ctx.recv_tokens; ++i) {
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_1[i].label,
				  resp_ead_ctx.token[i].label);
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_1[i].value_len,
				  resp_ead_ctx.token[i].value_len);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(
			ead_multiple_tokens_msg_1[i].value,
			resp_ead_ctx.token[i].value,
			resp_ead_ctx.token[i].value_len);
	}

	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

	memset(buffer, 0, sizeof(buffer));
	size_t msg_2_len = 0;
	uint8_t *msg_2 = buffer;

	/* EDHOC message 2 compose. */
	ret = edhoc_message_2_compose(resp_ctx, msg_2, ARRAY_SIZE(buffer),
				      &msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_WAIT_M3, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_psk_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(ECC_COMP_KEY_LEN, resp_ctx->dh_secret_len);

	/* Verify EAD_2 compose. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_2, resp_ead_ctx.msg);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ead_multiple_tokens_msg_2),
			  resp_ead_ctx.recv_tokens);

	for (size_t i = 0; i < resp_ead_ctx.recv_tokens; ++i) {
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_2[i].label,
				  resp_ead_ctx.token[i].label);
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_2[i].value_len,
				  resp_ead_ctx.token[i].value_len);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(
			ead_multiple_tokens_msg_2[i].value,
			resp_ead_ctx.token[i].value,
			resp_ead_ctx.token[i].value_len);
	}

	/* EDHOC message 2 process. */
	ret = edhoc_message_2_process(init_ctx, msg_2, msg_2_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_VERIFIED_M2, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(false, init_ctx->is_psk_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_3, init_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_3E2M, init_ctx->prk_state);

	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_BYTE_STRING,
			  init_ctx->peer_cid.encode_type);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(C_R), init_ctx->peer_cid.bstr_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(C_R, init_ctx->peer_cid.bstr_value,
				      init_ctx->peer_cid.bstr_length);

	/* Verify internal state of initiator and responder. */
	TEST_ASSERT_EQUAL(init_ctx->dh_secret_len, resp_ctx->dh_secret_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->dh_secret, resp_ctx->dh_secret,
				      init_ctx->dh_secret_len);

	TEST_ASSERT_EQUAL(init_ctx->th_state, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(init_ctx->th_len, resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->th, resp_ctx->th,
				      init_ctx->th_len);

	TEST_ASSERT_EQUAL(init_ctx->prk_state, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(init_ctx->prk_len, resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->prk, resp_ctx->prk,
				      init_ctx->prk_len);

	/* Verify EAD_2 process. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_2, init_ead_ctx.msg);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ead_multiple_tokens_msg_2),
			  init_ead_ctx.recv_tokens);

	for (size_t i = 0; i < init_ead_ctx.recv_tokens; ++i) {
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_2[i].label,
				  init_ead_ctx.token[i].label);
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_2[i].value_len,
				  init_ead_ctx.token[i].value_len);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(
			ead_multiple_tokens_msg_2[i].value,
			init_ead_ctx.token[i].value,
			init_ead_ctx.token[i].value_len);
	}

	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

	memset(buffer, 0, sizeof(buffer));
	size_t msg_3_len = 0;
	uint8_t *msg_3 = buffer;

	/* EDHOC message 3 compose. */
	ret = edhoc_message_3_compose(init_ctx, msg_3, ARRAY_SIZE(buffer),
				      &msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, init_ctx->status);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(true, init_ctx->is_psk_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, init_ctx->prk_state);

	/* Verify EAD_3 compose. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_3, init_ead_ctx.msg);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ead_multiple_tokens_msg_3),
			  init_ead_ctx.recv_tokens);

	for (size_t i = 0; i < init_ead_ctx.recv_tokens; ++i) {
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_3[i].label,
				  init_ead_ctx.token[i].label);
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_3[i].value_len,
				  init_ead_ctx.token[i].value_len);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(
			ead_multiple_tokens_msg_3[i].value,
			init_ead_ctx.token[i].value,
			init_ead_ctx.token[i].value_len);
	}

	/* EDHOC message 3 process. */
	ret = edhoc_message_3_process(resp_ctx, msg_3, msg_3_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_COMPLETED, resp_ctx->status);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_psk_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	/* Verify internal state of initiator and responder. */
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(init_ctx->th_state, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(init_ctx->th_len, resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->th, resp_ctx->th,
				      resp_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(init_ctx->prk_state, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(init_ctx->prk_len, resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->prk, resp_ctx->prk,
				      resp_ctx->prk_len);

	/* Verify EAD_3 process. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_3, resp_ead_ctx.msg);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ead_multiple_tokens_msg_3),
			  resp_ead_ctx.recv_tokens);

	for (size_t i = 0; i < resp_ead_ctx.recv_tokens; ++i) {
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_3[i].label,
				  resp_ead_ctx.token[i].label);
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_3[i].value_len,
				  resp_ead_ctx.token[i].value_len);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(
			ead_multiple_tokens_msg_3[i].value,
			resp_ead_ctx.token[i].value,
			resp_ead_ctx.token[i].value_len);
	}

	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

	memset(buffer, 0, sizeof(buffer));
	size_t msg_4_len = 0;
	uint8_t *msg_4 = buffer;

	/* EDHOC message 4 compose. */
	ret = edhoc_message_4_compose(resp_ctx, msg_4, ARRAY_SIZE(buffer),
				      &msg_4_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->status);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(true, resp_ctx->is_psk_export_allowed);

	ret = edhoc_error_get_code(resp_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->prk_state);

	/* Verify EAD_4 compose. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_4, resp_ead_ctx.msg);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ead_multiple_tokens_msg_4),
			  resp_ead_ctx.recv_tokens);

	for (size_t i = 0; i < resp_ead_ctx.recv_tokens; ++i) {
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_4[i].label,
				  resp_ead_ctx.token[i].label);
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_4[i].value_len,
				  resp_ead_ctx.token[i].value_len);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(
			ead_multiple_tokens_msg_4[i].value,
			resp_ead_ctx.token[i].value,
			resp_ead_ctx.token[i].value_len);
	}

	/* EDHOC message 4 process. */
	ret = edhoc_message_4_process(init_ctx, msg_4, msg_4_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->status);
	TEST_ASSERT_EQUAL(true, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(true, init_ctx->is_psk_export_allowed);

	ret = edhoc_error_get_code(init_ctx, &error_code_recv);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_recv);

	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, init_ctx->th_state);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, init_ctx->prk_state);

	/* Verify internal state of initiator and responder. */
	TEST_ASSERT_EQUAL(EDHOC_TH_STATE_4, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(init_ctx->th_state, resp_ctx->th_state);
	TEST_ASSERT_EQUAL(init_ctx->th_len, resp_ctx->th_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->th, resp_ctx->th,
				      resp_ctx->th_len);

	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_4E3M, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(init_ctx->prk_state, resp_ctx->prk_state);
	TEST_ASSERT_EQUAL(init_ctx->prk_len, resp_ctx->prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_ctx->prk, resp_ctx->prk,
				      resp_ctx->prk_len);

	/* Verify EAD_4 process. */
	TEST_ASSERT_EQUAL(EDHOC_MSG_4, init_ead_ctx.msg);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ead_multiple_tokens_msg_4),
			  init_ead_ctx.recv_tokens);

	for (size_t i = 0; i < init_ead_ctx.recv_tokens; ++i) {
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_4[i].label,
				  init_ead_ctx.token[i].label);
		TEST_ASSERT_EQUAL(ead_multiple_tokens_msg_4[i].value_len,
				  init_ead_ctx.token[i].value_len);
		TEST_ASSERT_EQUAL_UINT8_ARRAY(
			ead_multiple_tokens_msg_4[i].value,
			init_ead_ctx.token[i].value,
			init_ead_ctx.token[i].value_len);
	}

	memset(&init_ead_ctx, 0, sizeof(init_ead_ctx));
	memset(&resp_ead_ctx, 0, sizeof(resp_ead_ctx));

	/* Export ID_CRED_PSK & CRED_PSK. */
	uint8_t init_cred_psk[ARRAY_SIZE(CRED_PSK_raw_key)] = { 0 };
	uint8_t init_id_cred_psk = 0;
	ret = edhoc_export_psk(init_ctx, init_cred_psk,
			       ARRAY_SIZE(init_cred_psk), &init_id_cred_psk,
			       sizeof(init_id_cred_psk));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(false, init_ctx->is_psk_export_allowed);

	uint8_t resp_cred_psk[ARRAY_SIZE(CRED_PSK_raw_key)] = { 0 };
	uint8_t resp_id_cred_psk = 0;
	ret = edhoc_export_psk(resp_ctx, resp_cred_psk,
			       ARRAY_SIZE(resp_cred_psk), &resp_id_cred_psk,
			       sizeof(resp_id_cred_psk));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_psk_export_allowed);

	/* Verify initiator and responder exported ID_CRED_PSK & CRED_PSK. */
	TEST_ASSERT_EQUAL(ARRAY_SIZE(init_cred_psk), ARRAY_SIZE(resp_cred_psk));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_cred_psk, resp_cred_psk,
				      ARRAY_SIZE(resp_cred_psk));
	TEST_ASSERT_EQUAL(sizeof(init_id_cred_psk), sizeof(resp_id_cred_psk));
	TEST_ASSERT_EQUAL(init_id_cred_psk, resp_id_cred_psk);

	uint8_t init_master_secret[oscore_master_secret_length];
	memset(init_master_secret, 0, sizeof(init_master_secret));
	uint8_t init_master_salt[oscore_master_salt_length];
	memset(init_master_salt, 0, sizeof(init_master_salt));
	size_t init_sender_id_len = 0;
	uint8_t init_sender_id[ARRAY_SIZE(C_R)] = { 0 };
	size_t init_recipient_id_len = 0;
	uint8_t init_recipient_id[ARRAY_SIZE(C_I)] = { 0 };

	/* Derive OSCORE master secret and master salt. */
	ret = edhoc_export_oscore_session(
		init_ctx, init_master_secret, ARRAY_SIZE(init_master_secret),
		init_master_salt, ARRAY_SIZE(init_master_salt), init_sender_id,
		ARRAY_SIZE(init_sender_id), &init_sender_id_len,
		init_recipient_id, ARRAY_SIZE(init_recipient_id),
		&init_recipient_id_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, init_ctx->status);
	TEST_ASSERT_EQUAL(false, init_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, init_ctx->prk_state);

	uint8_t resp_master_secret[oscore_master_secret_length];
	memset(resp_master_secret, 0, sizeof(resp_master_secret));
	uint8_t resp_master_salt[oscore_master_salt_length];
	memset(resp_master_salt, 0, sizeof(resp_master_salt));
	size_t resp_sender_id_len = 0;
	uint8_t resp_sender_id[ARRAY_SIZE(C_I)] = { 0 };
	size_t resp_recipient_id_len = 0;
	uint8_t resp_recipient_id[ARRAY_SIZE(C_R)] = { 0 };

	/* Derive OSCORE master secret and master salt. */
	ret = edhoc_export_oscore_session(
		resp_ctx, resp_master_secret, ARRAY_SIZE(resp_master_secret),
		resp_master_salt, ARRAY_SIZE(resp_master_salt), resp_sender_id,
		ARRAY_SIZE(resp_sender_id), &resp_sender_id_len,
		resp_recipient_id, ARRAY_SIZE(resp_recipient_id),
		&resp_recipient_id_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SM_PERSISTED, resp_ctx->status);
	TEST_ASSERT_EQUAL(false, resp_ctx->is_oscore_export_allowed);
	TEST_ASSERT_EQUAL(EDHOC_PRK_STATE_OUT, resp_ctx->prk_state);

	/* Verify initiator and responder exported OSCORE sessions. */
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

TEST_GROUP_RUNNER(draft_edhoc_psk)
{
	RUN_TEST_CASE(draft_edhoc_psk, handshake_real_crypto_without_ead);
	RUN_TEST_CASE(draft_edhoc_psk, handshake_real_crypto_with_ead);
}
