/**
 * \file    test_edhoc_cipher_suite_negotiation.c
 * \author  Kamil Kielbasa
 * \brief   Test scenarios for cipher suite negotiation.
 * \version 0.4
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Internal test headers: */
#include "cipher_suite_negotiation/test_edhoc_cipher_suite_negotiation.h"
#include "cipher_suites/cipher_suite_2.h"

/* Standard library headers: */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>

/* EDHOC header: */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include "edhoc.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

static const uint8_t X[] = {
	0x36, 0x8e, 0xc1, 0xf6, 0x9a, 0xeb, 0x65, 0x9b, 0xa3, 0x7d, 0x5a,
	0x8d, 0x45, 0xb2, 0x1b, 0xdc, 0x02, 0x99, 0xdc, 0xea, 0xa8, 0xef,
	0x23, 0x5f, 0x3c, 0xa4, 0x2c, 0xe3, 0x53, 0x0f, 0x95, 0x25,
};
static const uint8_t G_X[] = {
	0x8a, 0xf6, 0xf4, 0x30, 0xeb, 0xe1, 0x8d, 0x34, 0x18, 0x40, 0x17,
	0xa9, 0xa1, 0x1b, 0xf5, 0x11, 0xc8, 0xdf, 0xf8, 0xf8, 0x34, 0x73,
	0x0b, 0x96, 0xc1, 0xb7, 0xc8, 0xdb, 0xca, 0x2f, 0xc3, 0xb6,
};

static int
cipher_suite_2_make_key_pair_init(void *user_ctx, const void *kid,
				  uint8_t *priv_key, size_t priv_key_size,
				  size_t *priv_key_len, uint8_t *pub_key,
				  size_t pub_key_size, size_t *pub_key_len);

static const struct edhoc_keys edhoc_keys = {
	.import_key = cipher_suite_2_key_import,
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

/* Static function declarations -------------------------------------------- */

/**
 * \brief Helper function for printing arrays.
 */
static inline void print_array(const char *name, const uint8_t *buffer,
			       size_t buffer_length);

/* Static function definitions --------------------------------------------- */

static inline void print_array(const char *name, const uint8_t *buffer,
			       size_t buffer_length)
{
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
	(void)kid;

	if (NULL == priv_key || 0 == priv_key_size || NULL == priv_key_len ||
	    NULL == pub_key || 0 == pub_key_size || NULL == pub_key_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	*priv_key_len = ARRAY_SIZE(X);
	memcpy(priv_key, X, ARRAY_SIZE(X));

	*pub_key_len = ARRAY_SIZE(G_X);
	memcpy(pub_key, G_X, ARRAY_SIZE(G_X));

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

/*
 * Test scenario comes from:
 * - RFC 9528: 6.3.2. Examples
 *   - Figure 8: Cipher Suite Negotiation Example 1.
 *
 * Initiator                                          Responder
 * |          METHOD, SUITES_I = 5, G_X, C_I, EAD_1           |
 * +--------------------------------------------------------->|
 * |                                                          |
 * |            ERR_CODE = 2, SUITES_R = 6                    |
 * |<---------------------------------------------------------+
 * |                                                          |
 * |        METHOD, SUITES_I = [5, 6], G_X, C_I, EAD_1        |
 * +--------------------------------------------------------->|
 * |                                                          |
 */
void test_edhoc_cipher_suites_negotiation_scenario_1(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const enum edhoc_method method = EDHOC_METHOD_1;
	const struct edhoc_cipher_suite csuites_init[] = {
		[0].value = 5,
		[0].ecc_key_length = 32,
		[0].hash_length = 32,
	};
	const struct edhoc_cipher_suite csuites_resp[] = {
		[0].value = 6,
		[0].ecc_key_length = 32,
		[0].hash_length = 32,
	};
	const struct edhoc_connection_id conn_id_init = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 1,
	};

	/**
         * \brief 1. Setup initiator context.
         */
	struct edhoc_context init_ctx = { 0 };

	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&init_ctx, method);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&init_ctx, csuites_init,
				      ARRAY_SIZE(csuites_init));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&init_ctx, &conn_id_init);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, &edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, &edhoc_crypto_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief 2. Setup responder context.
         */
	struct edhoc_context resp_ctx = { 0 };

	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&resp_ctx, method);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, csuites_resp,
				      ARRAY_SIZE(csuites_resp));
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief 3. Initiator compose message 1.
         */
	size_t msg_1_len = 0;
	uint8_t msg_1[100] = { 0 };

	ret = edhoc_message_1_compose(&init_ctx, msg_1, ARRAY_SIZE(msg_1),
				      &msg_1_len);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief 4a. Responder process message 1.
         */
	ret = edhoc_message_1_process(&resp_ctx, msg_1, msg_1_len);
	assert(EDHOC_ERROR_MSG_1_PROCESS_FAILURE == ret);

	/**
         * \brief 4b. Responder checks EDHOC error code.
         */
	enum edhoc_error_code error_code_resp = -1;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_resp);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE == error_code_resp);

	/**
         * \brief 4c. Responder collect his EDHOC cipher suites.
         */
	size_t csuites_len = 0;
	int32_t csuites[1] = { 0 };
	ret = edhoc_error_get_cipher_suites(&resp_ctx, csuites,
					    ARRAY_SIZE(csuites), &csuites_len);
	assert(EDHOC_SUCCESS == ret);
	assert(ARRAY_SIZE(csuites_resp) == csuites_len);
	assert(csuites_resp[0].value == csuites[0]);

	/**
         * \brief 4d. Responder compose error message.
         */
	size_t msg_err_len = 0;
	uint8_t msg_err[100] = { 0 };

	struct edhoc_error_info error_info = {
		.cipher_suites = csuites,
		.total_entries = ARRAY_SIZE(csuites),
		.written_entries = csuites_len,
	};
	ret = edhoc_message_error_compose(msg_err, ARRAY_SIZE(msg_err),
					  &msg_err_len, error_code_resp,
					  &error_info);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief 5a. Initiator process error message.
         */
	enum edhoc_error_code error_code_init = -1;
	int32_t cipher_suites_init[1] = { 0 };
	struct edhoc_error_info error_info_init = {
		.cipher_suites = cipher_suites_init,
		.total_entries = ARRAY_SIZE(cipher_suites_init),
		.written_entries = 0,
	};
	ret = edhoc_message_error_process(msg_err, msg_err_len,
					  &error_code_init, &error_info_init);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE == error_code_init);
	assert(ARRAY_SIZE(csuites_resp) == error_info_init.written_entries);
	assert(csuites_resp[0].value == error_info_init.cipher_suites[0]);

	/**
         * \brief 5b. Initiator reinitialize context with new cipher suites.
         */
	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&init_ctx, method);
	assert(EDHOC_SUCCESS == ret);

	const struct edhoc_cipher_suite fixed_csuites_init[] = {
		[0].value = 5, [0].ecc_key_length = 32, [0].hash_length = 32,
		[1].value = 6, [1].ecc_key_length = 32, [1].hash_length = 32,
	};
	ret = edhoc_set_cipher_suites(&init_ctx, fixed_csuites_init,
				      ARRAY_SIZE(fixed_csuites_init));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&init_ctx, &conn_id_init);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, &edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, &edhoc_crypto_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief 5c. Initiator again compose message 1.
         */
	msg_1_len = 0;
	memset(msg_1, 0, sizeof(msg_1));

	ret = edhoc_message_1_compose(&init_ctx, msg_1, ARRAY_SIZE(msg_1),
				      &msg_1_len);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief 6. Responder reinitialize context.
         */
	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&resp_ctx, method);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, csuites_resp,
				      ARRAY_SIZE(csuites_resp));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, &edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, &edhoc_crypto_mocked_resp);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief 7. Responder successfully process message 1.
         */
	ret = edhoc_message_1_process(&resp_ctx, msg_1, msg_1_len);
	assert(EDHOC_SUCCESS == ret);

	error_code_resp = -1;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_resp);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_resp);
}

/*
 * Test scenario comes from:
 * - RFC 9528: 6.3.2. Examples
 *   - Figure 9: Cipher Suite Negotiation Example 2.
 *
 * Initiator                                          Responder
 * |      METHOD, SUITES_I = [5, 6], G_X, C_I, EAD_1          |
 * +--------------------------------------------------------->|
 * |                                                          |
 * |            ERR_CODE = 2, SUITES_R = [9, 8]               |
 * |<---------------------------------------------------------+
 * |                                                          |
 * |    METHOD, SUITES_I = [5, 6, 7, 8], G_X, C_I, EAD_1      |
 * +--------------------------------------------------------->|
 * |                                                          |
 */
void test_edhoc_cipher_suites_negotiation_scenario_2(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	const enum edhoc_method method = EDHOC_METHOD_1;
	const struct edhoc_cipher_suite csuites_init[] = {
		[0].value = 5, [0].ecc_key_length = 32, [0].hash_length = 32,
		[1].value = 6, [1].ecc_key_length = 32, [1].hash_length = 32,
	};
	const struct edhoc_cipher_suite csuites_resp[] = {
		[0].value = 9, [0].ecc_key_length = 32, [0].hash_length = 32,
		[1].value = 8, [1].ecc_key_length = 32, [1].hash_length = 32,
	};
	const struct edhoc_connection_id conn_id_init = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 1,
	};

	/**
         * \brief 1. Setup initiator context.
         */
	struct edhoc_context init_ctx = { 0 };

	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&init_ctx, method);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&init_ctx, csuites_init,
				      ARRAY_SIZE(csuites_init));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&init_ctx, &conn_id_init);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, &edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, &edhoc_crypto_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief 2. Setup responder context.
         */
	struct edhoc_context resp_ctx = { 0 };

	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&resp_ctx, method);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, csuites_resp,
				      ARRAY_SIZE(csuites_resp));
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief 3. Initiator compose message 1.
         */
	size_t msg_1_len = 0;
	uint8_t msg_1[100] = { 0 };

	ret = edhoc_message_1_compose(&init_ctx, msg_1, ARRAY_SIZE(msg_1),
				      &msg_1_len);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief 4a. Responder process message 1.
         */
	ret = edhoc_message_1_process(&resp_ctx, msg_1, msg_1_len);
	assert(EDHOC_ERROR_MSG_1_PROCESS_FAILURE == ret);

	/**
         * \brief 4b. Responder checks EDHOC error code.
         */
	enum edhoc_error_code error_code_resp = -1;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_resp);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE == error_code_resp);

	/**
         * \brief 4c. Responder collect his EDHOC cipher suites.
         */
	size_t csuites_len = 0;
	int32_t csuites[2] = { 0 };
	ret = edhoc_error_get_cipher_suites(&resp_ctx, csuites,
					    ARRAY_SIZE(csuites), &csuites_len);
	assert(EDHOC_SUCCESS == ret);
	assert(ARRAY_SIZE(csuites_resp) == csuites_len);
	assert(csuites_resp[0].value == csuites[0]);
	assert(csuites_resp[1].value == csuites[1]);

	/**
         * \brief 4d. Responder compose error message.
         */
	size_t msg_err_len = 0;
	uint8_t msg_err[100] = { 0 };

	struct edhoc_error_info error_info = {
		.cipher_suites = csuites,
		.total_entries = ARRAY_SIZE(csuites),
		.written_entries = csuites_len,
	};
	ret = edhoc_message_error_compose(msg_err, ARRAY_SIZE(msg_err),
					  &msg_err_len, error_code_resp,
					  &error_info);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief 5a. Initiator process error message.
         */
	enum edhoc_error_code error_code_init = -1;
	int32_t cipher_suites_init[2] = { 0 };
	struct edhoc_error_info error_info_init = {
		.cipher_suites = cipher_suites_init,
		.total_entries = ARRAY_SIZE(cipher_suites_init),
		.written_entries = 0,
	};
	ret = edhoc_message_error_process(msg_err, msg_err_len,
					  &error_code_init, &error_info_init);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE == error_code_init);
	assert(ARRAY_SIZE(csuites_resp) == error_info_init.written_entries);
	assert(csuites_resp[0].value == error_info_init.cipher_suites[0]);
	assert(csuites_resp[1].value == error_info_init.cipher_suites[1]);

	/**
         * \brief 5b. Initiator reinitialize context with new cipher suites.
         */
	ret = edhoc_context_init(&init_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&init_ctx, method);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \note Because zcbor add arrays sizes statically it means that with
         *       current generated sourcer and header files we support up to 3.
         *
         *       #define DEFAULT_MAX_QTY 3
         *
         *       To avoid regeneration to all files, cipher suite 5 is missed.
         */
	const struct edhoc_cipher_suite fixed_csuites_init[] = {
		/* [0].value = 5, [0].ecc_key_length = 32, [0].hash_length = 32, */
		[0].value = 6, [0].ecc_key_length = 32, [0].hash_length = 32,
		[1].value = 7, [1].ecc_key_length = 32, [1].hash_length = 32,
		[2].value = 8, [2].ecc_key_length = 32, [2].hash_length = 32,

	};
	ret = edhoc_set_cipher_suites(&init_ctx, fixed_csuites_init,
				      ARRAY_SIZE(fixed_csuites_init));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_connection_id(&init_ctx, &conn_id_init);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&init_ctx, &edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&init_ctx, &edhoc_crypto_mocked_init);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief 5c. Initiator again compose message 1.
         */
	msg_1_len = 0;
	memset(msg_1, 0, sizeof(msg_1));

	ret = edhoc_message_1_compose(&init_ctx, msg_1, ARRAY_SIZE(msg_1),
				      &msg_1_len);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief 6. Responder reinitialize context.
         */
	ret = edhoc_context_init(&resp_ctx);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_method(&resp_ctx, method);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, csuites_resp,
				      ARRAY_SIZE(csuites_resp));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_keys(&resp_ctx, &edhoc_keys);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_bind_crypto(&resp_ctx, &edhoc_crypto_mocked_resp);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief 7. Responder successfully process message 1.
         */
	ret = edhoc_message_1_process(&resp_ctx, msg_1, msg_1_len);
	assert(EDHOC_SUCCESS == ret);

	error_code_resp = -1;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_resp);
	assert(EDHOC_SUCCESS == ret);
	assert(EDHOC_ERROR_CODE_SUCCESS == error_code_resp);
}
