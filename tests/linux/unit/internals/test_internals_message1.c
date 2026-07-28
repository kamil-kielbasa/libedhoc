/**
 * \file    test_internals_message1.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for edhoc_message_1.c internal paths.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Internal headers: */
#include "internals_common.h"
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(internals_message1);

TEST_SETUP(internals_message1)
{
	const psa_status_t status = psa_crypto_init();

	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(internals_message1)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_message1, msg1_compose_invalid_cid_type)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.negotiation.connection_id.encode_type = 99;

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&ctx, msg1, ARRAY_SIZE(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message1, msg1_compose_zero_csuites)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);

	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.machine = EDHOC_SM_START;

	const enum edhoc_method method[] = { EDHOC_METHOD_0 };
	int ret = edhoc_set_methods(&ctx, method, ARRAY_SIZE(method));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 1,
	};
	ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(
		&ctx, edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_2));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(&ctx, internals_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t msg1[256] = { 0 };
	size_t msg1_len = 0;
	ret = edhoc_message_1_compose(&ctx, msg1, ARRAY_SIZE(msg1), &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message1, msg1_compose_tiny_buffer)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.role = EDHOC_ROLE_INITIATOR;
	ctx.state.machine = EDHOC_SM_START;

	uint8_t msg1[2] = { 0 };
	size_t msg1_len = 0;
	int ret = edhoc_message_1_compose(&ctx, msg1, ARRAY_SIZE(msg1),
					  &msg1_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message1, msg1_process_malformed)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);
	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.machine = EDHOC_SM_START;

	const uint8_t garbage[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
	int ret = edhoc_message_1_process(&ctx, garbage, ARRAY_SIZE(garbage));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_MSG_1_PROCESS_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_message1, msg1_process_truncated)
{
	struct edhoc_context ctx = { 0 };
	internals_setup_crypto_context(&ctx);

	ctx.state.role = EDHOC_ROLE_RESPONDER;
	ctx.state.machine = EDHOC_SM_START;

	const uint8_t tiny[1] = { 0x00 };
	int ret = edhoc_message_1_process(&ctx, tiny, ARRAY_SIZE(tiny));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_MSG_1_PROCESS_FAILURE, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(internals_message1)
{
	RUN_TEST_CASE(internals_message1, msg1_compose_invalid_cid_type);
	RUN_TEST_CASE(internals_message1, msg1_compose_zero_csuites);
	RUN_TEST_CASE(internals_message1, msg1_compose_tiny_buffer);
	RUN_TEST_CASE(internals_message1, msg1_process_malformed);
	RUN_TEST_CASE(internals_message1, msg1_process_truncated);
}
