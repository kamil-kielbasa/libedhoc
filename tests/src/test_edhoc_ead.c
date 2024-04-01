/**
 * @file    test_edhoc_ead.c
 * @author  Kamil Kielbasa
 * @brief   Unit test for EDHOC EAD compose & process.
 * @version 0.1
 * @date    2024-01-01
 * 
 * @copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */
#include "test_edhoc_ead.h"
#include "edhoc.h"
#include "test_crypto.h"
#include "test_credentials.h"
#include "test_vectors_p256_v16.h"

/* standard library headers: */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

static const struct edhoc_cipher_suite cipher_suite_2 = {
	.value = 2,
	.aead_key_len = 16,
	.aead_tag_len = 8,
	.aead_iv_len = 13,
	.hash_len = 32,
	.mac_len = 32,
	.ecc_key_len = 32,
	.ecc_sign_len = 64,
};

static const struct edhoc_keys keys = {
	.generate_key = edhoc_keys_generate,
	.destroy_key = edhoc_keys_destroy,
};

static const struct edhoc_crypto crypto = {
	.make_key_pair = test_crypto_make_key_pair,
	.key_agreement = test_crypto_key_agreement,
	.sign = test_crypto_sign,
	.verify = test_crypto_verify,
	.extract = test_crypto_extract,
	.expand = test_crypto_expand,
	.encrypt = test_crypto_encrypt,
	.decrypt = test_crypto_decrypt,
	.hash = test_crypto_hash,
};

static const struct edhoc_credentials cred_init = {
	.fetch = test_cred_fetch_init_x509_chain,
	.verify = test_cred_verify_init_x509_chain,
};

static const struct edhoc_credentials cred_resp = {
	.fetch = test_cred_fetch_resp_x509_chain,
	.verify = test_cred_verify_resp_x509_chain,
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

/* Static function declarations -------------------------------------------- */

static inline void print_array(const char *name, const uint8_t *array,
			       size_t array_length);

static int ead_compose_single_token(void *user_ctx, enum edhoc_message msg,
				    struct edhoc_ead_token *ead_token,
				    size_t nr_of_ead_tokens,
				    size_t *nr_of_written_ead_tokens);

static int ead_process_single_token(void *user_ctx, enum edhoc_message msg,
				    const struct edhoc_ead_token *ead_token,
				    size_t nr_of_ead_tokens);

static int ead_compose_multiple_tokens(void *user_ctx, enum edhoc_message msg,
				       struct edhoc_ead_token *ead_token,
				       size_t nr_of_ead_tokens,
				       size_t *nr_of_written_ead_tokens);

static int ead_process_multiple_tokens(void *user_ctx, enum edhoc_message msg,
				       const struct edhoc_ead_token *ead_token,
				       size_t nr_of_ead_tokens);

/* Static function definitions --------------------------------------------- */

static inline void print_array(const char *name, const uint8_t *array,
			       size_t array_length)
{
	printf("%s:\tLEN( %zu )\n", name, array_length);

	for (size_t i = 0; i < array_length; ++i) {
		if (0 == i % 16 && i > 0) {
			printf("\n");
		}

		printf("%02x ", array[i]);
	}

	printf("\n\n");
}

static int ead_compose_single_token(void *user_ctx, enum edhoc_message msg,
				    struct edhoc_ead_token *ead_token,
				    size_t nr_of_ead_tokens,
				    size_t *nr_of_written_ead_tokens)
{
	(void)user_ctx;

	if (0 == nr_of_ead_tokens)
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;

	const struct edhoc_ead_token *token = NULL;

	switch (msg) {
	case EDHOC_MSG_1:
		token = &ead_single_token_msg_1;
		break;
	case EDHOC_MSG_2:
		token = &ead_single_token_msg_2;
		break;
	case EDHOC_MSG_3:
		token = &ead_single_token_msg_3;
		break;
	default:
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	ead_token[0] = *token;
	*nr_of_written_ead_tokens = 1;

	return EDHOC_SUCCESS;
}

static int ead_process_single_token(void *user_ctx, enum edhoc_message msg,
				    const struct edhoc_ead_token *ead_token,
				    size_t nr_of_ead_tokens)
{
	(void)user_ctx;

	if (0 == nr_of_ead_tokens)
		return EDHOC_ERROR_EAD_PROCESS_FAILURE;

	const struct edhoc_ead_token *token = &ead_token[0];

	switch (msg) {
	case EDHOC_MSG_1:
		assert(ead_single_token_msg_1.label == token->label);
		assert(ead_single_token_msg_1.value_len == token->value_len);
		assert(0 == memcmp(ead_single_token_msg_1.value, token->value,
				   token->value_len));
		break;
	case EDHOC_MSG_2:
		assert(ead_single_token_msg_2.label == token->label);
		assert(ead_single_token_msg_2.value_len == token->value_len);
		assert(0 == memcmp(ead_single_token_msg_2.value, token->value,
				   token->value_len));
		break;
	case EDHOC_MSG_3:
		assert(ead_single_token_msg_3.label == token->label);
		assert(ead_single_token_msg_3.value_len == token->value_len);
		assert(0 == memcmp(ead_single_token_msg_3.value, token->value,
				   token->value_len));
		break;
	default:
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	for (size_t i = 0; i < nr_of_ead_tokens; ++i)
		printf("ead_process single token\n"
		       "  EDHOC message = %d\n"
		       "  EAD token: <label:%d, value_len:%zu, value[0]=%u, value[len-1]=%u>\n",
		       msg, ead_token[i].label, ead_token[i].value_len,
		       ead_token[i].value[0],
		       ead_token[i].value[ead_token[i].value_len - 1]);

	return EDHOC_SUCCESS;
}

static int ead_compose_multiple_tokens(void *user_ctx, enum edhoc_message msg,
				       struct edhoc_ead_token *ead_token,
				       size_t nr_of_ead_tokens,
				       size_t *nr_of_written_ead_tokens)
{
	(void)user_ctx;

	if (0 == nr_of_ead_tokens)
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;

	const struct edhoc_ead_token *token = NULL;
	size_t nr_of_tokens = 0;

	switch (msg) {
	case EDHOC_MSG_1:
		token = ead_multiple_tokens_msg_1;
		nr_of_tokens = ARRAY_SIZE(ead_multiple_tokens_msg_1);
		break;

	case EDHOC_MSG_2:
		token = ead_multiple_tokens_msg_2;
		nr_of_tokens = ARRAY_SIZE(ead_multiple_tokens_msg_2);
		break;

	case EDHOC_MSG_3:
		token = ead_multiple_tokens_msg_3;
		nr_of_tokens = ARRAY_SIZE(ead_multiple_tokens_msg_3);
		break;

	default:
		return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
	}

	*nr_of_written_ead_tokens = nr_of_tokens;

	for (size_t i = 0; i < nr_of_tokens; ++i)
		ead_token[i] = token[i];

	return EDHOC_SUCCESS;
}

static int ead_process_multiple_tokens(void *user_ctx, enum edhoc_message msg,
				       const struct edhoc_ead_token *ead_token,
				       size_t nr_of_ead_tokens)
{
	(void)user_ctx;

	switch (msg) {
	case EDHOC_MSG_1:
		assert(ARRAY_SIZE(ead_multiple_tokens_msg_1) ==
		       nr_of_ead_tokens);

		for (size_t i = 0; i < nr_of_ead_tokens; ++i) {
			assert(ead_multiple_tokens_msg_1[i].label ==
			       ead_token[i].label);
			assert(ead_multiple_tokens_msg_1[i].value_len ==
			       ead_token[i].value_len);
			assert(0 == memcmp(ead_multiple_tokens_msg_1[i].value,
					   ead_token[i].value,
					   ead_token[i].value_len));
		}

		break;

	case EDHOC_MSG_2:
		assert(ARRAY_SIZE(ead_multiple_tokens_msg_2) ==
		       nr_of_ead_tokens);

		for (size_t i = 0; i < nr_of_ead_tokens; ++i) {
			assert(ead_multiple_tokens_msg_2[i].label ==
			       ead_token[i].label);
			assert(ead_multiple_tokens_msg_2[i].value_len ==
			       ead_token[i].value_len);
			assert(0 == memcmp(ead_multiple_tokens_msg_2[i].value,
					   ead_token[i].value,
					   ead_token[i].value_len));
		}

		break;

	case EDHOC_MSG_3:
		assert(ARRAY_SIZE(ead_multiple_tokens_msg_3) ==
		       nr_of_ead_tokens);

		for (size_t i = 0; i < nr_of_ead_tokens; ++i) {
			assert(ead_multiple_tokens_msg_3[i].label ==
			       ead_token[i].label);
			assert(ead_multiple_tokens_msg_3[i].value_len ==
			       ead_token[i].value_len);
			assert(0 == memcmp(ead_multiple_tokens_msg_3[i].value,
					   ead_token[i].value,
					   ead_token[i].value_len));
		}

	default:
		break;
	}

	if (0 < nr_of_ead_tokens) {
		for (size_t i = 0; i < nr_of_ead_tokens; ++i)
			printf("ead_process multiple tokens\n"
			       "EDHOC message = %d\n"
			       "EAD token: <label:%d, value_len:%zu, value[0]=%u, value[len-1]=%u>\n",
			       msg, ead_token[i].label, ead_token[i].value_len,
			       ead_token[i].value[0],
			       ead_token[i].value[ead_token[i].value_len - 1]);
	}

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

void test_edhoc_single_ead_token(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/**
         * \brief Setup initiator context.
         */
	struct edhoc_context init_ctx = { 0 };

	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&init_ctx, test_vector_1_method[0]);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&init_ctx, &cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_conn_id(&init_ctx, &test_vector_1_c_i_raw, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, crypto);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&init_ctx, cred_init);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_ead(&init_ctx, ead_compose_single_token,
			     ead_process_single_token);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Setup responder context.
         */
	struct edhoc_context resp_ctx = { 0 };

	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&resp_ctx, test_vector_1_method[0]);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, &cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_conn_id(&resp_ctx, &test_vector_1_c_r_raw, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, crypto);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&resp_ctx, cred_resp);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_ead(&init_ctx, ead_compose_single_token,
			     ead_process_single_token);
	assert(EDHOC_SUCCESS == ret);

	uint8_t buffer[500] = { 0 };

	/**
         * \brief EDHOC message 1 compose.
         */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_1_len = 0;
	uint8_t *msg_1 = buffer;
	ret = edhoc_message_1_compose(&init_ctx, msg_1, ARRAY_SIZE(buffer),
				      &msg_1_len);

	assert(EDHOC_SUCCESS == ret);
	assert(WAIT_M2 == init_ctx.status);

	/**
         * \brief EDHOC message 1 process.
         */
	ret = edhoc_message_1_process(&resp_ctx, msg_1, msg_1_len);

	assert(EDHOC_SUCCESS == ret);
	assert(VERIFIED_M1 == resp_ctx.status);

	/**
         * \brief EDHOC message 2 compose.
         */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_2_len = 0;
	uint8_t *msg_2 = buffer;
	ret = edhoc_message_2_compose(&resp_ctx, msg_2, ARRAY_SIZE(buffer),
				      &msg_2_len);

	assert(EDHOC_SUCCESS == ret);
	assert(WAIT_M3 == resp_ctx.status);

	/**
         * \brief EDHOC message 2 process.
         */
	ret = edhoc_message_2_process(&init_ctx, msg_2, msg_2_len);

	assert(EDHOC_SUCCESS == ret);
	assert(VERIFIED_M2 == init_ctx.status);

	/**
         * \brief EDHOC message 3 compose.
         */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_3_len = 0;
	uint8_t *msg_3 = buffer;
	ret = edhoc_message_3_compose(&init_ctx, msg_3, ARRAY_SIZE(buffer),
				      &msg_3_len);

	assert(EDHOC_SUCCESS == ret);
	assert(COMPLETED == init_ctx.status);

	/**
         * \brief EDHOC message 3 process.
         */
	ret = edhoc_message_3_process(&resp_ctx, msg_3, msg_3_len);

	assert(EDHOC_SUCCESS == ret);
	assert(COMPLETED == resp_ctx.status);

	/**
         * \brief Initiator - derive OSCORE secret & salt.
         */
	uint8_t init_secret[16] = { 0 };
	uint8_t init_salt[8] = { 0 };

	ret = edhoc_export_secret_and_salt(&init_ctx, init_secret,
					   ARRAY_SIZE(init_secret), init_salt,
					   ARRAY_SIZE(init_salt));

	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Responder - derive OSCORE secret & salt.
         */
	uint8_t resp_secret[16] = { 0 };
	uint8_t resp_salt[8] = { 0 };

	ret = edhoc_export_secret_and_salt(&resp_ctx, resp_secret,
					   ARRAY_SIZE(resp_secret), resp_salt,
					   ARRAY_SIZE(resp_salt));
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Verify both sides OSCORE secret & salt.
         */
	assert(ARRAY_SIZE(init_secret) == ARRAY_SIZE(resp_secret));
	assert(0 == memcmp(init_secret, resp_secret, ARRAY_SIZE(init_secret)));

	assert(ARRAY_SIZE(init_salt) == ARRAY_SIZE(resp_salt));
	assert(0 == memcmp(init_salt, resp_salt, ARRAY_SIZE(init_salt)));

	print_array("Initiator - OSCORE master secret", init_secret,
		    ARRAY_SIZE(init_secret));

	print_array("Initiator - OSCORE master salt", init_salt,
		    ARRAY_SIZE(init_salt));

	print_array("Responder - OSCORE master secret", resp_secret,
		    ARRAY_SIZE(resp_secret));

	print_array("Responder - OSCORE master salt", resp_salt,
		    ARRAY_SIZE(resp_salt));

	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
}

void test_edhoc_multiple_ead_tokens(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/**
         * \brief Setup initiator context.
         */
	struct edhoc_context init_ctx = { 0 };

	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&init_ctx, test_vector_1_method[0]);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&init_ctx, &cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_conn_id(&init_ctx, &test_vector_1_c_i_raw, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, crypto);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&init_ctx, cred_init);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_ead(&init_ctx, ead_compose_multiple_tokens,
			     ead_process_multiple_tokens);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Setup responder context.
         */
	struct edhoc_context resp_ctx = { 0 };

	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&resp_ctx, test_vector_1_method[0]);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, &cipher_suite_2, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_conn_id(&resp_ctx, &test_vector_1_c_r_raw, 1);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, crypto);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_credentials(&resp_ctx, cred_resp);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_ead(&init_ctx, ead_compose_multiple_tokens,
			     ead_process_multiple_tokens);
	assert(EDHOC_SUCCESS == ret);

	uint8_t buffer[2000] = { 0 };

	/**
         * \brief EDHOC message 1 compose.
         */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_1_len = 0;
	uint8_t *msg_1 = buffer;
	ret = edhoc_message_1_compose(&init_ctx, msg_1, ARRAY_SIZE(buffer),
				      &msg_1_len);

	assert(EDHOC_SUCCESS == ret);
	assert(WAIT_M2 == init_ctx.status);

	/**
         * \brief EDHOC message 1 process.
         */
	ret = edhoc_message_1_process(&resp_ctx, msg_1, msg_1_len);

	assert(EDHOC_SUCCESS == ret);
	assert(VERIFIED_M1 == resp_ctx.status);

	/**
         * \brief EDHOC message 2 compose.
         */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_2_len = 0;
	uint8_t *msg_2 = buffer;
	ret = edhoc_message_2_compose(&resp_ctx, msg_2, ARRAY_SIZE(buffer),
				      &msg_2_len);

	assert(EDHOC_SUCCESS == ret);
	assert(WAIT_M3 == resp_ctx.status);

	/**
         * \brief EDHOC message 2 process.
         */
	ret = edhoc_message_2_process(&init_ctx, msg_2, msg_2_len);

	assert(EDHOC_SUCCESS == ret);
	assert(VERIFIED_M2 == init_ctx.status);

	/**
         * \brief EDHOC message 3 compose.
         */
	memset(buffer, 0, sizeof(buffer));
	size_t msg_3_len = 0;
	uint8_t *msg_3 = buffer;
	ret = edhoc_message_3_compose(&init_ctx, msg_3, ARRAY_SIZE(buffer),
				      &msg_3_len);

	assert(EDHOC_SUCCESS == ret);
	assert(COMPLETED == init_ctx.status);

	/**
         * \brief EDHOC message 3 process.
         */
	ret = edhoc_message_3_process(&resp_ctx, msg_3, msg_3_len);

	assert(EDHOC_SUCCESS == ret);
	assert(COMPLETED == resp_ctx.status);

	/**
         * \brief Initiator - derive OSCORE secret & salt.
         */
	uint8_t init_secret[16] = { 0 };
	uint8_t init_salt[8] = { 0 };

	ret = edhoc_export_secret_and_salt(&init_ctx, init_secret,
					   ARRAY_SIZE(init_secret), init_salt,
					   ARRAY_SIZE(init_salt));

	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Responder - derive OSCORE secret & salt.
         */
	uint8_t resp_secret[16] = { 0 };
	uint8_t resp_salt[8] = { 0 };

	ret = edhoc_export_secret_and_salt(&resp_ctx, resp_secret,
					   ARRAY_SIZE(resp_secret), resp_salt,
					   ARRAY_SIZE(resp_salt));
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Verify both sides OSCORE secret & salt.
         */
	assert(ARRAY_SIZE(init_secret) == ARRAY_SIZE(resp_secret));
	assert(0 == memcmp(init_secret, resp_secret, ARRAY_SIZE(init_secret)));

	assert(ARRAY_SIZE(init_salt) == ARRAY_SIZE(resp_salt));
	assert(0 == memcmp(init_salt, resp_salt, ARRAY_SIZE(init_salt)));

	print_array("Initiator - OSCORE master secret", init_secret,
		    ARRAY_SIZE(init_secret));

	print_array("Initiator - OSCORE master salt", init_salt,
		    ARRAY_SIZE(init_salt));

	print_array("Responder - OSCORE master secret", resp_secret,
		    ARRAY_SIZE(resp_secret));

	print_array("Responder - OSCORE master salt", resp_salt,
		    ARRAY_SIZE(resp_salt));

	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);
}