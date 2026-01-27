/**
 * \file    module_test_error_message.c
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

TEST_GROUP_RUNNER(error_message)
{
	RUN_TEST_CASE(error_message, success);
	RUN_TEST_CASE(error_message, unspecified_error);
	RUN_TEST_CASE(error_message, wrong_selected_cipher_suite_one);
	RUN_TEST_CASE(error_message, wrong_selected_cipher_suite_many);
	RUN_TEST_CASE(error_message, unknown_credential_referenced);
}
