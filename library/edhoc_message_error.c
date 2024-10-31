/**
 * \file    edhoc_message_error.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message error.
 * \version 0.6
 * \date    2024-08-05
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include "edhoc.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
#pragma clang diagnostic ignored "-Wreserved-identifier"
#pragma clang diagnostic ignored "-Wpadded"
#pragma clang diagnostic ignored "-Wdocumentation"
#endif

/* CBOR headers: */
#include <backend_cbor_message_error_encode.h>
#include <backend_cbor_message_error_decode.h>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

int edhoc_message_error_compose(uint8_t *msg_err, size_t msg_err_size,
				size_t *msg_err_len, enum edhoc_error_code code,
				const struct edhoc_error_info *info)
{
	if (NULL == msg_err || 0 == msg_err_size || NULL == msg_err_len)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	if (EDHOC_ERROR_CODE_SUCCESS > code ||
	    EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED < code)
		return EDHOC_ERROR_BAD_STATE;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	struct message_error input = { .message_error_ERR_CODE =
					       (int32_t)code };

	switch (code) {
	case EDHOC_ERROR_CODE_SUCCESS: {
		input.message_error_ERR_INFO_present = false;
		break;
	}

	case EDHOC_ERROR_CODE_UNSPECIFIED_ERROR: {
		if (NULL == info || NULL == info->text_string ||
		    0 == info->total_entries || 0 == info->written_entries)
			return EDHOC_ERROR_INVALID_ARGUMENT;

		if (info->written_entries > info->total_entries)
			return EDHOC_ERROR_INVALID_ARGUMENT;

		input.message_error_ERR_INFO_present = true;
		input.message_error_ERR_INFO.message_error_ERR_INFO_choice =
			message_error_ERR_INFO_tstr_c;
		input.message_error_ERR_INFO.message_error_ERR_INFO_tstr
			.value = (const uint8_t *)info->text_string;
		input.message_error_ERR_INFO.message_error_ERR_INFO_tstr.len =
			info->written_entries;
		break;
	}

	case EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE: {
		input.message_error_ERR_INFO_present = true;
		input.message_error_ERR_INFO.message_error_ERR_INFO_choice =
			message_error_ERR_INFO_suites_m_c;

		if (NULL == info || NULL == info->cipher_suites ||
		    0 == info->total_entries || 0 == info->written_entries)
			return EDHOC_ERROR_INVALID_ARGUMENT;

		if (info->written_entries > info->total_entries)
			return EDHOC_ERROR_INVALID_ARGUMENT;

		struct suites_r *suites =
			&input.message_error_ERR_INFO
				 .message_error_ERR_INFO_suites_m;

		if (1 == info->written_entries) {
			suites->suites_choice = suites_int_c;
			suites->suites_int = *info->cipher_suites;
		} else {
			if (ARRAY_SIZE(suites->suites_int_l_int) <
			    info->written_entries)
				return EDHOC_ERROR_BUFFER_TOO_SMALL;

			suites->suites_choice = suites_int_l_c;
			suites->suites_int_l_int_count = info->written_entries;
			memcpy(suites->suites_int_l_int, info->cipher_suites,
			       sizeof(*info->cipher_suites) *
				       info->written_entries);
		}

		break;
	}

	case EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED: {
		input.message_error_ERR_INFO_present = true;
		input.message_error_ERR_INFO.message_error_ERR_INFO_choice =
			message_error_ERR_INFO_bool_c;
		break;
	}

	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	ret = cbor_encode_message_error(msg_err, msg_err_size, &input,
					msg_err_len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	return EDHOC_SUCCESS;
}

int edhoc_message_error_process(const uint8_t *msg_err, size_t msg_err_len,
				enum edhoc_error_code *code,
				struct edhoc_error_info *info)
{
	if (NULL == msg_err || 0 == msg_err_len || NULL == code)
		return EDHOC_ERROR_INVALID_ARGUMENT;

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	struct message_error result = { 0 };

	size_t len = 0;
	ret = cbor_decode_message_error(msg_err, msg_err_len, &result, &len);

	if (ZCBOR_SUCCESS != ret)
		return EDHOC_ERROR_CBOR_FAILURE;

	switch (result.message_error_ERR_CODE) {
	case EDHOC_ERROR_CODE_SUCCESS: {
		*code = EDHOC_ERROR_CODE_SUCCESS;
		break;
	}

	case EDHOC_ERROR_CODE_UNSPECIFIED_ERROR: {
		*code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;

		if (NULL == info || NULL == info->text_string ||
		    0 == info->total_entries)
			break;

		if (true == result.message_error_ERR_INFO_present) {
			const struct zcbor_string *tstr =
				&result.message_error_ERR_INFO
					 .message_error_ERR_INFO_tstr;

			if (tstr->len > info->total_entries)
				return EDHOC_ERROR_BUFFER_TOO_SMALL;

			info->written_entries = tstr->len;
			memcpy(info->text_string, tstr->value,
			       sizeof(*info->text_string) * tstr->len);
		}

		break;
	}

	case EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE: {
		*code = EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;

		if (NULL == info || NULL == info->cipher_suites ||
		    0 == info->total_entries)
			break;

		if (true == result.message_error_ERR_INFO_present) {
			const struct suites_r *suites =
				&result.message_error_ERR_INFO
					 .message_error_ERR_INFO_suites_m;

			switch (suites->suites_choice) {
			case suites_int_c: {
				info->written_entries = 1;
				*info->cipher_suites = suites->suites_int;
				break;
			}

			case suites_int_l_c: {
				if (suites->suites_int_l_int_count >
				    info->total_entries)
					return EDHOC_ERROR_BUFFER_TOO_SMALL;

				info->written_entries =
					suites->suites_int_l_int_count;
				memcpy(info->cipher_suites,
				       suites->suites_int_l_int,
				       sizeof(*info->cipher_suites) *
					       suites->suites_int_l_int_count);
				break;
			}

			default:
				return EDHOC_ERROR_NOT_PERMITTED;
			}
		}

		break;
	}

	case EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED: {
		*code = EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;

		break;
	}

	default:
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	return EDHOC_SUCCESS;
}
