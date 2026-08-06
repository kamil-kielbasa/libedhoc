/**
 * \file    test_coverage_error.c
 * \author  Kamil Kielbasa
 * \brief   Coverage tests for EDHOC error message paths.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Internal headers: */
#include "coverage_common.h"
#include "edhoc_macros_internal.h"

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

TEST_GROUP(coverage_error);

TEST_SETUP(coverage_error)
{
}

TEST_TEAR_DOWN(coverage_error)
{
}

TEST(coverage_error, error_msg_compose_bad_info)
{
	uint8_t buf[64] = { 0 };
	size_t len = 0;

	const char text[] = "error";

	struct edhoc_error_info info = {
		.text_string = (char *)text,
		.entries_size = 2,
		.entries_length = 5,
	};

	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len, EDHOC_ERROR_CODE_UNSPECIFIED_ERROR,
		&info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coverage_error, error_msg_compose_suites_overflow)
{
	uint8_t buf[256] = { 0 };
	size_t len = 0;

	int32_t suites[100] = { 0 };

	for (size_t i = 0; i < ARRAY_SIZE(suites); i++) {
		suites[i] = (int32_t)i;
	}

	struct edhoc_error_info info = {
		.cipher_suites = suites,
		.entries_size = 100,
		.entries_length = 100,
	};

	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len,
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, &info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(coverage_error, error_msg_process_text_too_small)
{
	uint8_t buf[128] = { 0 };
	size_t len = 0;

	const char text[] = "a long error description";
	struct edhoc_error_info info = {
		.text_string = (char *)text,
		.entries_size = sizeof(text) - 1,
		.entries_length = sizeof(text) - 1,
	};

	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len, EDHOC_ERROR_CODE_UNSPECIFIED_ERROR,
		&info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	char recv_text[2] = { 0 };
	struct edhoc_error_info recv_info = {
		.text_string = recv_text,
		.entries_size = 1,
	};
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;

	ret = edhoc_message_error_process(buf, len, &code, &recv_info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	struct edhoc_context ctx = { 0 };
	ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_error_process_with_context(&ctx, buf, len,
						       &recv_info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_error, error_msg_process_suites_too_small)
{
	uint8_t buf[128] = { 0 };
	size_t len = 0;

	int32_t suites[] = { 0, 2, 3 };
	struct edhoc_error_info info = {
		.cipher_suites = suites,
		.entries_size = 3,
		.entries_length = 3,
	};

	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len,
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, &info);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	int32_t recv_suites[1] = { 0 };
	struct edhoc_error_info recv_info = {
		.cipher_suites = recv_suites,
		.entries_size = 1,
	};
	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;

	ret = edhoc_message_error_process(buf, len, &code, &recv_info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	struct edhoc_context ctx = { 0 };
	ret = edhoc_context_init(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_error_process_with_context(&ctx, buf, len,
						       &recv_info);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	ret = edhoc_context_deinit(&ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(coverage_error, error_msg_compose_suites_null_info)
{
	uint8_t buf[64] = { 0 };
	size_t len = 0;

	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len,
		EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coverage_error, error_msg_compose_unspecified_null_info)
{
	uint8_t buf[64] = { 0 };
	size_t len = 0;

	int ret = edhoc_message_error_compose(
		buf, sizeof(buf), &len, EDHOC_ERROR_CODE_UNSPECIFIED_ERROR,
		NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST_GROUP_RUNNER(coverage_error)
{
	RUN_TEST_CASE(coverage_error, error_msg_compose_bad_info);
	RUN_TEST_CASE(coverage_error, error_msg_compose_suites_overflow);
	RUN_TEST_CASE(coverage_error, error_msg_process_text_too_small);
	RUN_TEST_CASE(coverage_error, error_msg_process_suites_too_small);
	RUN_TEST_CASE(coverage_error, error_msg_compose_suites_null_info);
	RUN_TEST_CASE(coverage_error, error_msg_compose_unspecified_null_info);
}
