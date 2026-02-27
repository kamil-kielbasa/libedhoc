/**
 * \file    fuzz_message_error_process.c
 * \brief   libFuzzer harness for edhoc_message_error_process().
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <edhoc.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	enum edhoc_error_code error_code = EDHOC_ERROR_CODE_SUCCESS;
	int32_t cipher_suites[8] = { 0 };
	char text_buf[256] = { 0 };

	struct edhoc_error_info error_info = {
		.text_string = text_buf,
		.total_entries = sizeof(text_buf),
		.written_entries = 0,
	};

	edhoc_message_error_process(data, size, &error_code, &error_info);

	if (EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE == error_code) {
		error_info.cipher_suites = cipher_suites;
		error_info.total_entries = 8;
		error_info.written_entries = 0;
		edhoc_message_error_process(data, size, &error_code,
					    &error_info);
	}

	return 0;
}
