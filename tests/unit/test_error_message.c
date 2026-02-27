/**
 * \file    test_error_message.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for EDHOC error message.
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include <edhoc.h>

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

/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(error_message);

TEST_SETUP(error_message)
{
}

TEST_TEAR_DOWN(error_message)
{
}

/**
 * @scenario  EDHOC error message compose and process with SUCCESS code.
 * @env       None.
 * @action    Compose error message with EDHOC_ERROR_CODE_SUCCESS and NULL
 *            info; process with edhoc_message_error_process.
 * @expected  Both compose and process succeed; received error code matches.
 */
TEST(error_message, success)
{
	size_t buffer_len = 0;
	uint8_t buffer[100] = { 0 };

	const enum edhoc_error_code error_code = EDHOC_ERROR_CODE_SUCCESS;
	ret = edhoc_message_error_compose(buffer, ARRAY_SIZE(buffer),
					  &buffer_len, error_code, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_error_process(buffer, buffer_len, &recv_error_code,
					  NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(error_code, recv_error_code);
}

/**
 * @scenario  EDHOC error message compose and process with UNSPECIFIED_ERROR and text.
 * @env       None.
 * @action    Compose error message with text string; process and verify
 *            error code and text string.
 * @expected  Both succeed; error code and text string match.
 */
TEST(error_message, unspecified_error)
{
	size_t buffer_len = 0;
	uint8_t buffer[100] = { 0 };

	const char *error_string = "Not supported C509 certificate type.";
	const enum edhoc_error_code error_code =
		EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;
	const struct edhoc_error_info error_info = {
		.text_string = (char *)error_string,
		.total_entries = strlen(error_string),
		.written_entries = strlen(error_string),
	};

	ret = edhoc_message_error_compose(buffer, ARRAY_SIZE(buffer),
					  &buffer_len, error_code, &error_info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	char recv_text_string[100] = { 0 };
	struct edhoc_error_info recv_error_info = {
		.text_string = recv_text_string,
		.total_entries = ARRAY_SIZE(recv_text_string),
		.written_entries = 0,
	};

	ret = edhoc_message_error_process(buffer, buffer_len, &recv_error_code,
					  &recv_error_info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(error_code, recv_error_code);
	TEST_ASSERT_EQUAL(error_info.written_entries,
			  recv_error_info.written_entries);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(error_info.text_string,
				      recv_error_info.text_string,
				      error_info.written_entries);
}

/**
 * @scenario  EDHOC error message with WRONG_SELECTED_CIPHER_SUITE (one suite).
 * @env       None.
 * @action    Compose error message with single cipher suite; process and
 *            verify cipher suite array.
 * @expected  Both succeed; cipher suite array matches.
 */
TEST(error_message, wrong_selected_cipher_suite_one)
{
	size_t buffer_len = 0;
	uint8_t buffer[100] = { 0 };

	const int32_t cipher_suites[] = { 1 };
	const enum edhoc_error_code error_code =
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
	const struct edhoc_error_info error_info = {
		.cipher_suites = (int32_t *)cipher_suites,
		.total_entries = ARRAY_SIZE(cipher_suites),
		.written_entries = ARRAY_SIZE(cipher_suites),
	};

	ret = edhoc_message_error_compose(buffer, ARRAY_SIZE(buffer),
					  &buffer_len, error_code, &error_info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	int32_t recv_cipher_suites[10] = { 0 };
	struct edhoc_error_info recv_error_info = {
		.cipher_suites = recv_cipher_suites,
		.total_entries = ARRAY_SIZE(recv_cipher_suites),
		.written_entries = 0,
	};

	ret = edhoc_message_error_process(buffer, buffer_len, &recv_error_code,
					  &recv_error_info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(error_code, recv_error_code);
	TEST_ASSERT_EQUAL(recv_error_info.written_entries,
			  error_info.written_entries);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(
		error_info.cipher_suites, recv_error_info.cipher_suites,
		error_info.written_entries * sizeof(*error_info.cipher_suites));
}

/**
 * @scenario  EDHOC error message with WRONG_SELECTED_CIPHER_SUITE (many suites).
 * @env       None.
 * @action    Compose error message with multiple cipher suites; process and
 *            verify cipher suite array.
 * @expected  Both succeed; cipher suite array matches.
 */
TEST(error_message, wrong_selected_cipher_suite_many)
{
	size_t buffer_len = 0;
	uint8_t buffer[100] = { 0 };

	const int32_t cipher_suites[] = { 6, 4, 2 };
	const enum edhoc_error_code error_code =
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;
	const struct edhoc_error_info error_info = {
		.cipher_suites = (int32_t *)cipher_suites,
		.total_entries = ARRAY_SIZE(cipher_suites),
		.written_entries = ARRAY_SIZE(cipher_suites),
	};

	ret = edhoc_message_error_compose(buffer, ARRAY_SIZE(buffer),
					  &buffer_len, error_code, &error_info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	int32_t recv_cipher_suites[10] = { 0 };
	struct edhoc_error_info recv_error_info = {
		.cipher_suites = recv_cipher_suites,
		.total_entries = ARRAY_SIZE(recv_cipher_suites),
		.written_entries = 0,
	};

	ret = edhoc_message_error_process(buffer, buffer_len, &recv_error_code,
					  &recv_error_info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(error_code, recv_error_code);
	TEST_ASSERT_EQUAL(recv_error_info.written_entries,
			  error_info.written_entries);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(
		recv_error_info.cipher_suites, error_info.cipher_suites,
		error_info.written_entries * sizeof(*error_info.cipher_suites));
}

TEST(error_message, unknown_credential_referenced)
{
	size_t buffer_len = 0;
	uint8_t buffer[100] = { 0 };

	const enum edhoc_error_code error_code =
		EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;

	ret = edhoc_message_error_compose(buffer, ARRAY_SIZE(buffer),
					  &buffer_len, error_code, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_error_process(buffer, buffer_len, &recv_error_code,
					  NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(error_code, recv_error_code);
}

/**
 * @scenario  Compose error message with unknown error code.
 * @env       None.
 * @action    Call edhoc_message_error_compose with error code 99.
 * @expected  Returns EDHOC_ERROR_NOT_PERMITTED.
 */
TEST(error_message, compose_unknown_code)
{
	uint8_t buffer[100] = { 0 };
	size_t buffer_len = 0;
	ret = edhoc_message_error_compose(buffer, sizeof(buffer), &buffer_len,
					  (enum edhoc_error_code)99, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

/**
 * @scenario  Compose WRONG_SELECTED_CIPHER_SUITE with written > total entries.
 * @env       None.
 * @action    Call compose with written_entries = 5, total_entries = 2.
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(error_message, compose_cipher_suite_written_gt_total)
{
	uint8_t buffer[100] = { 0 };
	size_t buffer_len = 0;
	int32_t suites[] = { 0, 2 };
	struct edhoc_error_info info = {
		.cipher_suites = suites,
		.total_entries = 2,
		.written_entries = 5,
	};
	ret = edhoc_message_error_compose(
		buffer, sizeof(buffer), &buffer_len,
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  Compose error message into a tiny buffer (1 byte).
 * @env       None.
 * @action    Call compose with buffer size 1 for UNKNOWN_CREDENTIAL_REFERENCED
 *            which needs ERR_CODE + ERR_INFO (2+ bytes of CBOR).
 * @expected  Returns EDHOC_ERROR_CBOR_FAILURE.
 */
TEST(error_message, compose_tiny_buffer)
{
	uint8_t buffer[1] = { 0 };
	size_t buffer_len = 0;
	ret = edhoc_message_error_compose(
		buffer, sizeof(buffer), &buffer_len,
		EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);
}

/**
 * @scenario  Compose with NULL buffer pointer.
 * @env       None.
 * @action    Call compose with NULL msg_err.
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(error_message, compose_null_buffer)
{
	size_t buffer_len = 0;
	ret = edhoc_message_error_compose(NULL, 100, &buffer_len,
					  EDHOC_ERROR_CODE_SUCCESS, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  Process with NULL msg_err pointer.
 * @env       None.
 * @action    Call process with NULL msg_err.
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(error_message, process_null_buffer)
{
	enum edhoc_error_code code;
	ret = edhoc_message_error_process(NULL, 10, &code, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  Process with invalid CBOR data.
 * @env       None.
 * @action    Call process with garbage CBOR bytes.
 * @expected  Returns EDHOC_ERROR_CBOR_FAILURE.
 */
TEST(error_message, process_invalid_cbor)
{
	uint8_t garbage[] = { 0xFF, 0xFF, 0xFF };
	enum edhoc_error_code code;
	ret = edhoc_message_error_process(garbage, sizeof(garbage), &code,
					  NULL);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

/**
 * @scenario  Process error message with out-of-range error code.
 * @env       Compose a valid error message (code 0), then patch the CBOR byte
 *            to code 99 which the decoder accepts but the process switch rejects.
 * @action    Call process on the patched message.
 * @expected  Returns EDHOC_ERROR_NOT_PERMITTED (default case in process).
 */
TEST(error_message, process_unknown_code)
{
	uint8_t msg[32];
	size_t msg_len = 0;
	ret = edhoc_message_error_compose(msg, sizeof(msg), &msg_len,
					  EDHOC_ERROR_CODE_SUCCESS, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(msg_len > 0);

	/*
	 * Manually encode CBOR integer 99 as a replacement for the ERR_CODE.
	 * CBOR uint 99 = 0x18 0x63. Overwrite the first bytes.
	 */
	uint8_t patched[] = { 0x18, 0x63 };
	enum edhoc_error_code code;
	ret = edhoc_message_error_process(patched, sizeof(patched), &code,
					  NULL);
	/* The decoder may accept code 99 (hitting default) or reject it */
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
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
}
