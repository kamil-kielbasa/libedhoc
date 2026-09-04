/**
 * \file    test_error_message.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for EDHOC error message.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include "edhoc_context_internal.h"
#include "edhoc_macros_internal.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

static int ret = EDHOC_ERROR_GENERIC_ERROR;
static enum edhoc_error_code recv_error_code = -1;
static struct edhoc_context ctx = { 0 };

/** ERR_CODE = 1 with SUITES = [-3, 1, 1]: the fingerprint of the out-of-bounds
 *  read that reinterpreted the array as a byte string. */
static const uint8_t err_unspecified_with_suites[] = {
	0x01, 0x83, 0x22, 0x01, 0x01,
};

/** ERR_CODE = 1 with ERR_INFO = true. */
static const uint8_t err_unspecified_with_bool[] = { 0x01, 0xf5 };

/** ERR_CODE = 2 with ERR_INFO = "abc". */
static const uint8_t err_cipher_suite_with_tstr[] = {
	0x02, 0x63, 0x61, 0x62, 0x63,
};

/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(error_message);

TEST_SETUP(error_message)
{
	ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_TEAR_DOWN(error_message)
{
	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(error_message, success)
{
	size_t buffer_len = 0;
	uint8_t buffer[100] = { 0 };

	const enum edhoc_error_code error_code = EDHOC_ERROR_CODE_SUCCESS;
	ret = edhoc_message_error_compose(&ctx, buffer, ARRAY_SIZE(buffer),
					  &buffer_len, error_code, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_error_process(&ctx, buffer, buffer_len,
					  &recv_error_code, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(error_code, recv_error_code);
}

TEST(error_message, unspecified_error)
{
	size_t buffer_len = 0;
	uint8_t buffer[100] = { 0 };

	const char *error_string = "Not supported C509 certificate type.";
	const enum edhoc_error_code error_code =
		EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	const struct edhoc_error_info error_info = {
		.text_string = (char *)error_string,
		.entries_size = strlen(error_string),
		.entries_length = strlen(error_string),
	};

	ret = edhoc_message_error_compose(&ctx, buffer, ARRAY_SIZE(buffer),
					  &buffer_len, error_code, &error_info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	char recv_text_string[100] = { 0 };
	struct edhoc_error_info recv_error_info = {
		.text_string = recv_text_string,
		.entries_size = ARRAY_SIZE(recv_text_string),
		.entries_length = 0,
	};

	ret = edhoc_message_error_process(&ctx, buffer, buffer_len,
					  &recv_error_code, &recv_error_info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(error_code, recv_error_code);
	TEST_ASSERT_EQUAL(error_info.entries_length,
			  recv_error_info.entries_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(error_info.text_string,
				      recv_error_info.text_string,
				      error_info.entries_length);
}

TEST(error_message, wrong_selected_cipher_suite_one)
{
	size_t buffer_len = 0;
	uint8_t buffer[100] = { 0 };

	const int32_t cipher_suites[] = { 1 };
	const enum edhoc_error_code error_code =
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
	const struct edhoc_error_info error_info = {
		.cipher_suites = (int32_t *)cipher_suites,
		.entries_size = ARRAY_SIZE(cipher_suites),
		.entries_length = ARRAY_SIZE(cipher_suites),
	};

	ret = edhoc_message_error_compose(&ctx, buffer, ARRAY_SIZE(buffer),
					  &buffer_len, error_code, &error_info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	int32_t recv_cipher_suites[10] = { 0 };
	struct edhoc_error_info recv_error_info = {
		.cipher_suites = recv_cipher_suites,
		.entries_size = ARRAY_SIZE(recv_cipher_suites),
		.entries_length = 0,
	};

	ret = edhoc_message_error_process(&ctx, buffer, buffer_len,
					  &recv_error_code, &recv_error_info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(error_code, recv_error_code);
	TEST_ASSERT_EQUAL(recv_error_info.entries_length,
			  error_info.entries_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(
		error_info.cipher_suites, recv_error_info.cipher_suites,
		error_info.entries_length * sizeof(*error_info.cipher_suites));
}

TEST(error_message, wrong_selected_cipher_suite_many)
{
	size_t buffer_len = 0;
	uint8_t buffer[100] = { 0 };

	const int32_t cipher_suites[] = { 6, 4, 2 };
	const enum edhoc_error_code error_code =
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
	const struct edhoc_error_info error_info = {
		.cipher_suites = (int32_t *)cipher_suites,
		.entries_size = ARRAY_SIZE(cipher_suites),
		.entries_length = ARRAY_SIZE(cipher_suites),
	};

	ret = edhoc_message_error_compose(&ctx, buffer, ARRAY_SIZE(buffer),
					  &buffer_len, error_code, &error_info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	int32_t recv_cipher_suites[10] = { 0 };
	struct edhoc_error_info recv_error_info = {
		.cipher_suites = recv_cipher_suites,
		.entries_size = ARRAY_SIZE(recv_cipher_suites),
		.entries_length = 0,
	};

	ret = edhoc_message_error_process(&ctx, buffer, buffer_len,
					  &recv_error_code, &recv_error_info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(error_code, recv_error_code);
	TEST_ASSERT_EQUAL(recv_error_info.entries_length,
			  error_info.entries_length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(
		recv_error_info.cipher_suites, error_info.cipher_suites,
		error_info.entries_length * sizeof(*error_info.cipher_suites));
}

TEST(error_message, unknown_credential_referenced)
{
	size_t buffer_len = 0;
	uint8_t buffer[100] = { 0 };

	const enum edhoc_error_code error_code =
		EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;

	ret = edhoc_message_error_compose(&ctx, buffer, ARRAY_SIZE(buffer),
					  &buffer_len, error_code, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_error_process(&ctx, buffer, buffer_len,
					  &recv_error_code, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(error_code, recv_error_code);
}

TEST(error_message, compose_unknown_code)
{
	uint8_t buffer[100] = { 0 };
	size_t buffer_len = 0;
	ret = edhoc_message_error_compose(&ctx, buffer, sizeof(buffer),
					  &buffer_len,
					  (enum edhoc_error_code)99, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST(error_message, compose_cipher_suite_written_gt_total)
{
	uint8_t buffer[100] = { 0 };
	size_t buffer_len = 0;
	int32_t suites[] = { 0, 2 };
	struct edhoc_error_info info = {
		.cipher_suites = suites,
		.entries_size = 2,
		.entries_length = 5,
	};

	ret = edhoc_message_error_compose(
		&ctx, buffer, sizeof(buffer), &buffer_len,
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(error_message, compose_tiny_buffer)
{
	uint8_t buffer[1] = { 0 };
	size_t buffer_len = 0;

	ret = edhoc_message_error_compose(
		&ctx, buffer, sizeof(buffer), &buffer_len,
		EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);
}

TEST(error_message, compose_null_buffer)
{
	size_t buffer_len = 0;

	ret = edhoc_message_error_compose(&ctx, NULL, 100, &buffer_len,
					  EDHOC_ERROR_CODE_SUCCESS, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(error_message, process_null_buffer)
{
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;

	ret = edhoc_message_error_process(&ctx, NULL, 10, &code, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(error_message, process_invalid_cbor)
{
	uint8_t garbage[] = { 0xFF, 0xFF, 0xFF };
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;

	ret = edhoc_message_error_process(&ctx, garbage, sizeof(garbage), &code,
					  NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);
}

TEST(error_message, process_unknown_code)
{
	uint8_t msg[32];
	size_t msg_len = 0;

	ret = edhoc_message_error_compose(&ctx, msg, sizeof(msg), &msg_len,
					  EDHOC_ERROR_CODE_SUCCESS, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(msg_len > 0);

	/*
	 * Manually encode CBOR integer 99 as a replacement for the ERR_CODE.
	 * CBOR uint 99 = 0x18 0x63. Overwrite the first bytes.
	 */
	uint8_t patched[] = { 0x18, 0x63 };
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;

	ret = edhoc_message_error_process(&ctx, patched, sizeof(patched), &code,
					  NULL);
	/* The decoder may accept code 99 (hitting default) or reject it */
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(error_message, process_suites_for_unspecified_rejected)
{
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;
	char text_string[100] = { 0 };
	struct edhoc_error_info info = {
		.text_string = text_string,
		.entries_size = ARRAY_SIZE(text_string),
	};

	ret = edhoc_message_error_process(
		&ctx, err_unspecified_with_suites,
		ARRAY_SIZE(err_unspecified_with_suites), &code, &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
	TEST_ASSERT_EQUAL(0, info.entries_length);
}

TEST(error_message, process_mismatched_info_rejected_without_buffer)
{
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;

	ret = edhoc_message_error_process(
		&ctx, err_unspecified_with_suites,
		ARRAY_SIZE(err_unspecified_with_suites), &code, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(error_message, process_bool_for_unspecified_rejected)
{
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;
	char text_string[100] = { 0 };
	struct edhoc_error_info info = {
		.text_string = text_string,
		.entries_size = ARRAY_SIZE(text_string),
	};

	ret = edhoc_message_error_process(&ctx, err_unspecified_with_bool,
					  ARRAY_SIZE(err_unspecified_with_bool),
					  &code, &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
	TEST_ASSERT_EQUAL(0, info.entries_length);
}

TEST(error_message, process_tstr_for_cipher_suite_rejected)
{
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;
	int32_t cipher_suites[4] = { 0 };
	struct edhoc_error_info info = {
		.cipher_suites = cipher_suites,
		.entries_size = ARRAY_SIZE(cipher_suites),
	};

	ret = edhoc_message_error_process(
		&ctx, err_cipher_suite_with_tstr,
		ARRAY_SIZE(err_cipher_suite_with_tstr), &code, &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
	TEST_ASSERT_EQUAL(0, info.entries_length);
}

TEST(error_message, process_malformed_aborts_context)
{
	const uint8_t garbage[] = { 0xFF, 0xFF, 0xFF };
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;

	ret = edhoc_message_error_process(&ctx, garbage, sizeof(garbage), &code,
					  NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);

	/* Aborted on entry, before the message was decoded. */
	TEST_ASSERT_EQUAL(EDHOC_SM_ABORTED, ctx.state.machine);

	ret = edhoc_error_get_code(&ctx, &code);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_UNSPECIFIED_ERROR, code);
}

TEST(error_message, process_records_peer_cipher_suites)
{
	size_t buffer_len = 0;
	uint8_t buffer[100] = { 0 };

	const int32_t suites_r[] = { 6, 4, 2 };
	const struct edhoc_error_info error_info = {
		.cipher_suites = (int32_t *)suites_r,
		.entries_size = ARRAY_SIZE(suites_r),
		.entries_length = ARRAY_SIZE(suites_r),
	};

	ret = edhoc_message_error_compose(
		&ctx, buffer, ARRAY_SIZE(buffer), &buffer_len,
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, &error_info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	int32_t recv_cipher_suites[3] = { 0 };
	struct edhoc_error_info recv_error_info = {
		.cipher_suites = recv_cipher_suites,
		.entries_size = ARRAY_SIZE(recv_cipher_suites),
		.entries_length = 0,
	};

	ret = edhoc_message_error_process(&ctx, buffer, buffer_len,
					  &recv_error_code, &recv_error_info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(ARRAY_SIZE(suites_r),
			  ctx.negotiation.peer_cipher_suite.count);

	for (size_t i = 0; i < ARRAY_SIZE(suites_r); ++i)
		TEST_ASSERT_EQUAL(
			suites_r[i],
			ctx.negotiation.peer_cipher_suite.entry[i].value);
}

TEST_GROUP_RUNNER(error_message)
{
	RUN_TEST_CASE(error_message, success);
	RUN_TEST_CASE(error_message, unspecified_error);
	RUN_TEST_CASE(error_message, wrong_selected_cipher_suite_one);
	RUN_TEST_CASE(error_message, wrong_selected_cipher_suite_many);
	RUN_TEST_CASE(error_message, unknown_credential_referenced);
	RUN_TEST_CASE(error_message, compose_unknown_code);
	RUN_TEST_CASE(error_message, compose_cipher_suite_written_gt_total);
	RUN_TEST_CASE(error_message, compose_tiny_buffer);
	RUN_TEST_CASE(error_message, compose_null_buffer);
	RUN_TEST_CASE(error_message, process_null_buffer);
	RUN_TEST_CASE(error_message, process_invalid_cbor);
	RUN_TEST_CASE(error_message, process_unknown_code);

	/* ERR_INFO variant must match ERR_CODE (RFC 9528: 6). */
	RUN_TEST_CASE(error_message, process_suites_for_unspecified_rejected);
	RUN_TEST_CASE(error_message,
		      process_mismatched_info_rejected_without_buffer);
	RUN_TEST_CASE(error_message, process_bool_for_unspecified_rejected);
	RUN_TEST_CASE(error_message, process_tstr_for_cipher_suite_rejected);

	/* The context follows the message (RFC 9528: 6). */
	RUN_TEST_CASE(error_message, process_malformed_aborts_context);
	RUN_TEST_CASE(error_message, process_records_peer_cipher_suites);
}
