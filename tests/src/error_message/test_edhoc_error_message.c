/**
 * \file    test_edhoc_error_message.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC error message unit tests.
 * \version 0.4
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Internal test headers: */
#include "error_message/test_edhoc_error_message.h"

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

/* Module interface function definitions ----------------------------------- */

void test_edhoc_error_message_success(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t buffer_len = 0;
	uint8_t buffer[100] = { 0 };

	const enum edhoc_error_code error_code = EDHOC_ERROR_CODE_SUCCESS;

	ret = edhoc_message_error_compose(buffer, ARRAY_SIZE(buffer),
					  &buffer_len, error_code, NULL);
	assert(EDHOC_SUCCESS == ret);

	print_array("error msg - success", buffer, buffer_len);

	enum edhoc_error_code recv_error_code = -1;
	ret = edhoc_message_error_process(buffer, buffer_len, &recv_error_code,
					  NULL);
	assert(EDHOC_SUCCESS == ret);
	assert(error_code == recv_error_code);
}

void test_edhoc_error_message_unspecified_error(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

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
	assert(EDHOC_SUCCESS == ret);

	print_array("error msg - unspecified error", buffer, buffer_len);

	enum edhoc_error_code recv_error_code = -1;
	char recv_text_string[100] = { 0 };
	struct edhoc_error_info recv_error_info = {
		.text_string = recv_text_string,
		.total_entries = ARRAY_SIZE(recv_text_string),
		.written_entries = 0,
	};
	ret = edhoc_message_error_process(buffer, buffer_len, &recv_error_code,
					  &recv_error_info);
	assert(EDHOC_SUCCESS == ret);
	assert(error_code == recv_error_code);
	assert(error_info.written_entries == recv_error_info.written_entries);
	assert(0 == memcmp(error_info.text_string, recv_error_info.text_string,
			   error_info.written_entries));

	printf("Received message: %s\n\n", error_info.text_string);
}

void test_edhoc_error_message_wrong_selected_cipher_suite_one(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

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
	assert(EDHOC_SUCCESS == ret);

	print_array("error msg - wrong selected cipher suite", buffer,
		    buffer_len);

	enum edhoc_error_code recv_error_code = -1;
	int32_t recv_cipher_suites[10] = { 0 };
	struct edhoc_error_info recv_error_info = {
		.cipher_suites = recv_cipher_suites,
		.total_entries = ARRAY_SIZE(recv_cipher_suites),
		.written_entries = 0,
	};
	ret = edhoc_message_error_process(buffer, buffer_len, &recv_error_code,
					  &recv_error_info);
	assert(EDHOC_SUCCESS == ret);
	assert(error_code == recv_error_code);
	assert(recv_error_info.written_entries == error_info.written_entries);
	assert(0 == memcmp(error_info.cipher_suites,
			   recv_error_info.cipher_suites,
			   error_info.written_entries *
				   sizeof(*error_info.cipher_suites)));
}

void test_edhoc_error_message_wrong_selected_cipher_suite_many(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

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
	assert(EDHOC_SUCCESS == ret);

	print_array("error msg - wrong selected cipher suite", buffer,
		    buffer_len);

	enum edhoc_error_code recv_error_code = -1;
	int32_t recv_cipher_suites[10] = { 0 };
	struct edhoc_error_info recv_error_info = {
		.cipher_suites = recv_cipher_suites,
		.total_entries = ARRAY_SIZE(recv_cipher_suites),
		.written_entries = 0,
	};
	ret = edhoc_message_error_process(buffer, buffer_len, &recv_error_code,
					  &recv_error_info);
	assert(EDHOC_SUCCESS == ret);
	assert(error_code == recv_error_code);
	assert(recv_error_info.written_entries == error_info.written_entries);
	assert(0 == memcmp(recv_error_info.cipher_suites,
			   error_info.cipher_suites,
			   error_info.written_entries *
				   sizeof(*error_info.cipher_suites)));
}

void test_edhoc_error_message_unknown_credential_referenced(void)
{
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	size_t buffer_len = 0;
	uint8_t buffer[100] = { 0 };

	const enum edhoc_error_code error_code =
		EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;

	ret = edhoc_message_error_compose(buffer, ARRAY_SIZE(buffer),
					  &buffer_len, error_code, NULL);
	assert(EDHOC_SUCCESS == ret);

	print_array("error msg - wrong selected cipher suite", buffer,
		    buffer_len);

	enum edhoc_error_code recv_error_code = -1;
	ret = edhoc_message_error_process(buffer, buffer_len, &recv_error_code,
					  NULL);
	assert(EDHOC_SUCCESS == ret);
	assert(error_code == recv_error_code);
}
