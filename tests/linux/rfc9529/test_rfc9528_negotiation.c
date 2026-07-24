/**
 * \file    test_rfc9528_negotiation.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for RFC 9528 suites negotation examples.
 * 
 * \copyright Copyright (c) 2026
 * 
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#include "test_platform.h"
#include "test_credentials.h"
#include "edhoc_context_internal.h"
#include <edhoc/edhoc.h>
#include "edhoc_macros_internal.h"

/* Cipher suite 2: */
#include "edhoc_cipher_suite_2.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* PSA crypto header: */
#include <psa/crypto.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

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

/* Real cipher-suite-2 vtable with only generate_key_pair overridden to inject
 * the RFC's fixed initiator ephemeral; populated in TEST_SETUP. */
static struct edhoc_crypto edhoc_crypto_mocked_init;

static int ret = EDHOC_ERROR_GENERIC_ERROR;

/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */

static int make_key_pair_init(void *user_context, void *decapsulation_key_id,
			      uint8_t *encapsulation_key,
			      size_t encapsulation_key_size,
			      size_t *encapsulation_key_length)
{
	(void)user_context;

	if (NULL == decapsulation_key_id || NULL == encapsulation_key ||
	    0 == encapsulation_key_size || NULL == encapsulation_key_length)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (encapsulation_key_size < ARRAY_SIZE(G_X))
		return EDHOC_ERROR_INVALID_ARGUMENT;

	/* Import the RFC's fixed initiator ephemeral private key X as an ECDH
	 * key so message 1 reproduces the RFC's G_X on the wire. */
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));

	psa_key_id_t *psa_kid = decapsulation_key_id;
	*psa_kid = PSA_KEY_ID_NULL;
	if (PSA_SUCCESS != psa_import_key(&attr, X, ARRAY_SIZE(X), psa_kid))
		return EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE;

	memcpy(encapsulation_key, G_X, ARRAY_SIZE(G_X));
	*encapsulation_key_length = ARRAY_SIZE(G_X);

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(rfc9528_negotiation);

TEST_SETUP(rfc9528_negotiation)
{
	ret = psa_crypto_init();
	TEST_ASSERT_EQUAL(PSA_SUCCESS, ret);

	edhoc_crypto_mocked_init = *edhoc_cipher_suite_2_get_crypto();
	edhoc_crypto_mocked_init.generate_key_pair = make_key_pair_init;
}

TEST_TEAR_DOWN(rfc9528_negotiation)
{
	mbedtls_psa_crypto_free();
}

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
TEST(rfc9528_negotiation, example_1)
{
	const enum edhoc_method methods[] = { EDHOC_METHOD_1 };
	const struct edhoc_cipher_suite csuites_init[] = {
		[0].value = 5,
		[0].kem_encapsulation_key_length = 32,
		[0].hash_length = 32,
	};
	const struct edhoc_cipher_suite csuites_resp[] = {
		[0].value = 6,
		[0].kem_encapsulation_key_length = 32,
		[0].hash_length = 32,
	};
	const struct edhoc_connection_id conn_id_init = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 1,
	};

	/* 1. Setup initiator context. */
	struct edhoc_context init_ctx = { 0 };

	ret = edhoc_context_init(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(&init_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(&init_ctx, csuites_init,
				      ARRAY_SIZE(csuites_init));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(&init_ctx, &conn_id_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(&init_ctx, &edhoc_crypto_mocked_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(&init_ctx, &test_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(&init_ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* 2. Setup responder context. */
	struct edhoc_context resp_ctx = { 0 };

	ret = edhoc_context_init(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(&resp_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, csuites_resp,
				      ARRAY_SIZE(csuites_resp));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(&resp_ctx, &conn_id_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(&resp_ctx, edhoc_cipher_suite_2_get_crypto());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(&resp_ctx, &test_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(&resp_ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* 3. Initiator compose message 1. */
	size_t msg_1_len = 0;
	uint8_t msg_1[100] = { 0 };

	ret = edhoc_message_1_compose(&init_ctx, msg_1, ARRAY_SIZE(msg_1),
				      &msg_1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* 4a. Responder process message 1. */
	ret = edhoc_message_1_process(&resp_ctx, msg_1, msg_1_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_MSG_1_PROCESS_FAILURE, ret);

	/* 4b. Responder checks EDHOC error code. */
	enum edhoc_error_code error_code_resp = -1;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE,
			  error_code_resp);

	/* 4c. Responder collect his own and peer EDHOC cipher suites. */
	size_t csuites_len = 0;
	int32_t csuites[1] = { 0 };
	size_t peer_csuites_len = 0;
	int32_t peer_csuites[1] = { 0 };
	ret = edhoc_error_get_cipher_suites(
		&resp_ctx, csuites, ARRAY_SIZE(csuites), &csuites_len,
		peer_csuites, ARRAY_SIZE(peer_csuites), &peer_csuites_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(csuites_resp), csuites_len);
	TEST_ASSERT_EQUAL(csuites_resp[0].value, csuites[0]);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(csuites_init), peer_csuites_len);
	TEST_ASSERT_EQUAL(csuites_init[0].value, peer_csuites[0]);

	/*
	 * Point where responder can compare his and peer cipher suites.
	 * After comparison responder is able to send error message with his preferences.
	 */

	/* 4d. Responder compose error message. */
	size_t msg_err_len = 0;
	uint8_t msg_err[100] = { 0 };

	struct edhoc_error_info error_info = {
		.cipher_suites = csuites,
		.entries_size = ARRAY_SIZE(csuites),
		.entries_length = csuites_len,
	};
	ret = edhoc_message_error_compose(msg_err, ARRAY_SIZE(msg_err),
					  &msg_err_len, error_code_resp,
					  &error_info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* 5a. Initiator process error message. */
	enum edhoc_error_code error_code_init = -1;
	int32_t cipher_suites_init[1] = { 0 };
	struct edhoc_error_info error_info_init = {
		.cipher_suites = cipher_suites_init,
		.entries_size = ARRAY_SIZE(cipher_suites_init),
		.entries_length = 0,
	};
	ret = edhoc_message_error_process(msg_err, msg_err_len,
					  &error_code_init, &error_info_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE,
			  error_code_init);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(csuites_resp),
			  error_info_init.entries_length);
	TEST_ASSERT_EQUAL(csuites_resp[0].value,
			  error_info_init.cipher_suites[0]);

	/* 5b. Initiator reinitialize context with new cipher suites. */
	ret = edhoc_context_init(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(&init_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_cipher_suite fixed_csuites_init[] = {
		[0].value = 5,
		[0].kem_encapsulation_key_length = 32,
		[0].hash_length = 32,
		[1].value = 6,
		[1].kem_encapsulation_key_length = 32,
		[1].hash_length = 32,
	};
	ret = edhoc_set_cipher_suites(&init_ctx, fixed_csuites_init,
				      ARRAY_SIZE(fixed_csuites_init));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(&init_ctx, &conn_id_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(&init_ctx, &edhoc_crypto_mocked_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(&init_ctx, &test_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(&init_ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* 5c. Initiator again compose message 1. */
	msg_1_len = 0;
	memset(msg_1, 0, sizeof(msg_1));

	ret = edhoc_message_1_compose(&init_ctx, msg_1, ARRAY_SIZE(msg_1),
				      &msg_1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* 6. Responder reinitialize context. */
	ret = edhoc_context_init(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(&resp_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, csuites_resp,
				      ARRAY_SIZE(csuites_resp));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(&resp_ctx, &conn_id_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(&resp_ctx, edhoc_cipher_suite_2_get_crypto());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(&resp_ctx, &test_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(&resp_ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* 7. Responder successfully process message 1. */
	ret = edhoc_message_1_process(&resp_ctx, msg_1, msg_1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	error_code_resp = -1;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_resp);
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
TEST(rfc9528_negotiation, example_2)
{
	const enum edhoc_method methods[] = { EDHOC_METHOD_1 };
	const struct edhoc_cipher_suite csuites_init[] = {
		[0].value = 5,
		[0].kem_encapsulation_key_length = 32,
		[0].hash_length = 32,
		[1].value = 6,
		[1].kem_encapsulation_key_length = 32,
		[1].hash_length = 32,
	};
	const struct edhoc_cipher_suite csuites_resp[] = {
		[0].value = 9,
		[0].kem_encapsulation_key_length = 32,
		[0].hash_length = 32,
		[1].value = 8,
		[1].kem_encapsulation_key_length = 32,
		[1].hash_length = 32,
	};
	const struct edhoc_connection_id conn_id_init = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 1,
	};

	/* 1. Setup initiator context. */
	struct edhoc_context init_ctx = { 0 };

	ret = edhoc_context_init(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(&init_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(&init_ctx, csuites_init,
				      ARRAY_SIZE(csuites_init));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(&init_ctx, &conn_id_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(&init_ctx, &edhoc_crypto_mocked_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(&init_ctx, &test_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(&init_ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* 2. Setup responder context. */
	struct edhoc_context resp_ctx = { 0 };

	ret = edhoc_context_init(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(&resp_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, csuites_resp,
				      ARRAY_SIZE(csuites_resp));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(&resp_ctx, &conn_id_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(&resp_ctx, edhoc_cipher_suite_2_get_crypto());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(&resp_ctx, &test_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(&resp_ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* 3. Initiator compose message 1. */
	size_t msg_1_len = 0;
	uint8_t msg_1[100] = { 0 };

	ret = edhoc_message_1_compose(&init_ctx, msg_1, ARRAY_SIZE(msg_1),
				      &msg_1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* 4a. Responder process message 1. */
	ret = edhoc_message_1_process(&resp_ctx, msg_1, msg_1_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_MSG_1_PROCESS_FAILURE, ret);

	/* 4b. Responder checks EDHOC error code. */
	enum edhoc_error_code error_code_resp = -1;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE,
			  error_code_resp);

	/* 4c. Responder collect his own and peer EDHOC cipher suites. */
	size_t csuites_len = 0;
	int32_t csuites[2] = { 0 };
	size_t peer_csuites_len = 0;
	int32_t peer_csuites[2] = { 0 };
	ret = edhoc_error_get_cipher_suites(
		&resp_ctx, csuites, ARRAY_SIZE(csuites), &csuites_len,
		peer_csuites, ARRAY_SIZE(peer_csuites), &peer_csuites_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(csuites_resp), csuites_len);
	TEST_ASSERT_EQUAL(csuites_resp[0].value, csuites[0]);
	TEST_ASSERT_EQUAL(csuites_resp[1].value, csuites[1]);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(csuites_init), peer_csuites_len);
	TEST_ASSERT_EQUAL(csuites_init[0].value, peer_csuites[0]);
	TEST_ASSERT_EQUAL(csuites_init[1].value, peer_csuites[1]);

	/*
	 * Point where responder can compare his and peer cipher suites.
	 * After comparison responder is able to send error message with his preferences.
	 */

	/* 4d. Responder compose error message. */
	size_t msg_err_len = 0;
	uint8_t msg_err[100] = { 0 };

	struct edhoc_error_info error_info = {
		.cipher_suites = csuites,
		.entries_size = ARRAY_SIZE(csuites),
		.entries_length = csuites_len,
	};

	ret = edhoc_message_error_compose(msg_err, ARRAY_SIZE(msg_err),
					  &msg_err_len, error_code_resp,
					  &error_info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* 5a. Initiator process error message. */
	enum edhoc_error_code error_code_init = -1;
	int32_t cipher_suites_init[2] = { 0 };
	struct edhoc_error_info error_info_init = {
		.cipher_suites = cipher_suites_init,
		.entries_size = ARRAY_SIZE(cipher_suites_init),
		.entries_length = 0,
	};

	ret = edhoc_message_error_process(msg_err, msg_err_len,
					  &error_code_init, &error_info_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE,
			  error_code_init);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(csuites_resp),
			  error_info_init.entries_length);
	TEST_ASSERT_EQUAL(csuites_resp[0].value,
			  error_info_init.cipher_suites[0]);
	TEST_ASSERT_EQUAL(csuites_resp[1].value,
			  error_info_init.cipher_suites[1]);

	/* 5b. Initiator reinitialize context with new cipher suites. */
	ret = edhoc_context_init(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(&init_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/*
         * Because zcbor add arrays sizes statically it means that with
         * current generated sourcer and header files we support up to 3.
         *
         * #define DEFAULT_MAX_QTY 3
         *
         * To avoid regeneration to all files, cipher suite 5 is missed.
         */
	const struct edhoc_cipher_suite fixed_csuites_init[] = {
		/* [0].value = 5, [0].kem_encapsulation_key_length = 32, [0].hash_length = 32, */
		[0].value = 6,
		[0].kem_encapsulation_key_length = 32,
		[0].hash_length = 32,
		[1].value = 7,
		[1].kem_encapsulation_key_length = 32,
		[1].hash_length = 32,
		[2].value = 8,
		[2].kem_encapsulation_key_length = 32,
		[2].hash_length = 32,

	};
	ret = edhoc_set_cipher_suites(&init_ctx, fixed_csuites_init,
				      ARRAY_SIZE(fixed_csuites_init));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(&init_ctx, &conn_id_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(&init_ctx, &edhoc_crypto_mocked_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(&init_ctx, &test_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(&init_ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* 5c. Initiator again compose message 1. */
	msg_1_len = 0;
	memset(msg_1, 0, sizeof(msg_1));

	ret = edhoc_message_1_compose(&init_ctx, msg_1, ARRAY_SIZE(msg_1),
				      &msg_1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* 6. Responder reinitialize context. */
	ret = edhoc_context_init(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(&resp_ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(&resp_ctx, csuites_resp,
				      ARRAY_SIZE(csuites_resp));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(&resp_ctx, &conn_id_init);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(&resp_ctx, edhoc_cipher_suite_2_get_crypto());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(&resp_ctx, &test_cred_stubs);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(&resp_ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* 7. Responder successfully process message 1. */
	ret = edhoc_message_1_process(&resp_ctx, msg_1, msg_1_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	error_code_resp = -1;
	ret = edhoc_error_get_code(&resp_ctx, &error_code_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, error_code_resp);
}

TEST_GROUP_RUNNER(rfc9528_negotiation)
{
	RUN_TEST_CASE(rfc9528_negotiation, example_1);
	RUN_TEST_CASE(rfc9528_negotiation, example_2);
}
