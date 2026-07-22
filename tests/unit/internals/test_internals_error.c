/**
 * \file    test_internals_error.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for edhoc_message_error.c internal paths.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#include "internals_common.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(internals_error);

TEST_SETUP(internals_error)
{
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, psa_crypto_init());
	internals_crypto = edhoc_cipher_suite_0_get_crypto();
}

TEST_TEAR_DOWN(internals_error)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_error, error_message_compose_null)
{
	uint8_t buf[64];
	size_t len;
	int ret = edhoc_message_error_compose(NULL, sizeof(buf), &len,
					      EDHOC_ERROR_CODE_SUCCESS, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	ret = edhoc_message_error_compose(buf, 0, &len,
					  EDHOC_ERROR_CODE_SUCCESS, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	ret = edhoc_message_error_compose(buf, sizeof(buf), NULL,
					  EDHOC_ERROR_CODE_SUCCESS, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_error, error_message_process_null)
{
	uint8_t buf[64] = { 0 };
	enum edhoc_error_code code;
	int ret = edhoc_message_error_process(NULL, sizeof(buf), &code, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	ret = edhoc_message_error_process(buf, 0, &code, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	ret = edhoc_message_error_process(buf, sizeof(buf), NULL, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_error, error_compose_tiny_buffer)
{
	uint8_t buf[1];
	size_t len;
	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len, EDHOC_ERROR_CODE_UNSPECIFIED_ERROR,
		NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_error, error_compose_unspecified_null_info)
{
	uint8_t buf[64];
	size_t len;
	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len, EDHOC_ERROR_CODE_UNSPECIFIED_ERROR,
		NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_error, error_compose_success_code)
{
	uint8_t buf[64];
	size_t len;
	int ret = edhoc_message_error_compose(buf, sizeof(buf), &len,
					      EDHOC_ERROR_CODE_SUCCESS, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_error, error_compose_unknown_cred)
{
	uint8_t buf[64];
	size_t len;
	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len,
		EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_error, error_compose_invalid_code)
{
	uint8_t buf[64];
	size_t len;
	int ret = edhoc_message_error_compose(buf, sizeof(buf), &len, 99, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST(internals_error, error_compose_unspecified_with_info)
{
	uint8_t buf[64];
	size_t len;
	char text[] = "test error";
	struct edhoc_error_info info = {
		.text_string = text,
		.entries_size = 10,
		.entries_length = 10,
	};
	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len, EDHOC_ERROR_CODE_UNSPECIFIED_ERROR,
		&info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_error, error_compose_wrong_csuite_single)
{
	uint8_t buf[64];
	size_t len;
	int32_t suites[] = { 0 };
	struct edhoc_error_info info = {
		.cipher_suites = suites,
		.entries_size = 1,
		.entries_length = 1,
	};
	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len,
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, &info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_error, error_compose_wrong_csuite_multi)
{
	uint8_t buf[64];
	size_t len;
	int32_t suites[] = { 0, 2 };
	struct edhoc_error_info info = {
		.cipher_suites = suites,
		.entries_size = 2,
		.entries_length = 2,
	};
	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len,
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, &info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_error, error_process_roundtrip)
{
	uint8_t buf[64];
	size_t len;
	int ret = edhoc_message_error_compose(buf, sizeof(buf), &len,
					      EDHOC_ERROR_CODE_SUCCESS, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	enum edhoc_error_code code;
	ret = edhoc_message_error_process(buf, len, &code, NULL);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_SUCCESS, code);
}

TEST(internals_error, error_process_unspecified_roundtrip)
{
	uint8_t buf[64];
	size_t len;
	char text[] = "err";
	struct edhoc_error_info info = {
		.text_string = text,
		.entries_size = 3,
		.entries_length = 3,
	};
	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len, EDHOC_ERROR_CODE_UNSPECIFIED_ERROR,
		&info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	enum edhoc_error_code code;
	struct edhoc_error_info info_out = { 0 };
	ret = edhoc_message_error_process(buf, len, &code, &info_out);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_UNSPECIFIED_ERROR, code);
}

TEST(internals_error, error_process_wrong_csuite_roundtrip)
{
	uint8_t buf[64];
	size_t len;
	int32_t suites[] = { 0, 2 };
	struct edhoc_error_info info = {
		.cipher_suites = suites,
		.entries_size = 2,
		.entries_length = 2,
	};
	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len,
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, &info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	enum edhoc_error_code code;
	struct edhoc_error_info info_out = { 0 };
	ret = edhoc_message_error_process(buf, len, &code, &info_out);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, code);
}

TEST(internals_error, error_process_malformed)
{
	uint8_t garbage[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
	enum edhoc_error_code code;
	int ret = edhoc_message_error_process(garbage, sizeof(garbage), &code,
					      NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);
}

TEST(internals_error, error_compose_out_of_range_code)
{
	uint8_t buf[64];
	size_t len = 0;

	int ret = edhoc_message_error_compose(buf, sizeof(buf), &len, 99, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);
}

TEST_GROUP_RUNNER(internals_error)
{
	RUN_TEST_CASE(internals_error, error_message_compose_null);
	RUN_TEST_CASE(internals_error, error_message_process_null);
	RUN_TEST_CASE(internals_error, error_compose_tiny_buffer);
	RUN_TEST_CASE(internals_error, error_compose_unspecified_null_info);
	RUN_TEST_CASE(internals_error, error_compose_success_code);
	RUN_TEST_CASE(internals_error, error_compose_unknown_cred);
	RUN_TEST_CASE(internals_error, error_compose_invalid_code);
	RUN_TEST_CASE(internals_error, error_compose_unspecified_with_info);
	RUN_TEST_CASE(internals_error, error_compose_wrong_csuite_single);
	RUN_TEST_CASE(internals_error, error_compose_wrong_csuite_multi);
	RUN_TEST_CASE(internals_error, error_process_roundtrip);
	RUN_TEST_CASE(internals_error, error_process_unspecified_roundtrip);
	RUN_TEST_CASE(internals_error, error_process_wrong_csuite_roundtrip);
	RUN_TEST_CASE(internals_error, error_process_malformed);
	RUN_TEST_CASE(internals_error, error_compose_out_of_range_code);
}
