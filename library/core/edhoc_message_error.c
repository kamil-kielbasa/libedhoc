/**
 * \file    edhoc_message_error.c
 * \author  Kamil Kielbasa
 * \brief   EDHOC message error compose & process.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include <edhoc_config.h>
#endif

/* EDHOC public headers: */
#include <edhoc/edhoc.h>
#include <edhoc/types.h>
#include <edhoc/values.h>

/* EDHOC internal headers: */
#include "edhoc_context_internal.h"
#include "edhoc_macros_internal.h"
#include "edhoc_backend_log.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_edhoc_types.h>
#include <backend_cbor_message_error_encode.h>
#include <backend_cbor_message_error_decode.h>

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
	if (NULL == msg_err || 0 == msg_err_size || NULL == msg_err_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_ERROR_CODE_SUCCESS > code ||
	    EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED < code) {
		EDHOC_LOG_ERR("Unknown error code: %d", code);
		return EDHOC_ERROR_BAD_STATE;
	}

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
		    0 == info->entries_size || 0 == info->entries_length) {
			EDHOC_LOG_ERR(
				"Invalid arguments for unspecified error: info missing or empty");
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		if (info->entries_length > info->entries_size) {
			EDHOC_LOG_ERR("Invalid arguments");
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		input.message_error_ERR_INFO_present = true;
		input.message_error_ERR_INFO.message_error_ERR_INFO_choice =
			message_error_ERR_INFO_tstr_c;
		input.message_error_ERR_INFO.message_error_ERR_INFO_tstr.value =
			(const uint8_t *)info->text_string;
		input.message_error_ERR_INFO.message_error_ERR_INFO_tstr.len =
			info->entries_length;
		break;
	}

	case EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE: {
		input.message_error_ERR_INFO_present = true;
		input.message_error_ERR_INFO.message_error_ERR_INFO_choice =
			message_error_ERR_INFO_suites_m_c;

		if (NULL == info || NULL == info->cipher_suites ||
		    0 == info->entries_size || 0 == info->entries_length) {
			EDHOC_LOG_ERR(
				"Invalid arguments for wrong cipher suite: info missing or empty");
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		if (info->entries_length > info->entries_size) {
			EDHOC_LOG_ERR("Invalid arguments");
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		struct suites_r *suites =
			&input.message_error_ERR_INFO
				 .message_error_ERR_INFO_suites_m;

		if (1 == info->entries_length) {
			suites->suites_choice = suites_int_c;
			suites->suites_int = *info->cipher_suites;
		} else {
			if (ARRAY_SIZE(suites->suites_int_l_int) <
			    info->entries_length) {
				EDHOC_LOG_ERR("Buffer too small: %zu",
					      info->entries_length);
				return EDHOC_ERROR_BUFFER_TOO_SMALL;
			}

			suites->suites_choice = suites_int_l_c;
			suites->suites_int_l_int_count = info->entries_length;
			memcpy(suites->suites_int_l_int, info->cipher_suites,
			       sizeof(*info->cipher_suites) *
				       info->entries_length);
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
		EDHOC_LOG_ERR("Unknown error code: %d", code);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	ret = cbor_encode_message_error(msg_err, msg_err_size, &input,
					msg_err_len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc error msg: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int decode_message_error(const uint8_t *msg_err, size_t msg_err_len,
				struct message_error *result)
{
	size_t len = 0;
	int ret = cbor_decode_message_error(msg_err, msg_err_len, result, &len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR dec error msg: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int process_decoded_message_error(const struct message_error *result,
					 enum edhoc_error_code *code,
					 struct edhoc_error_info *info)
{
	switch (result->message_error_ERR_CODE) {
	case EDHOC_ERROR_CODE_SUCCESS: {
		*code = EDHOC_ERROR_CODE_SUCCESS;
		break;
	}

	case EDHOC_ERROR_CODE_UNSPECIFIED_ERROR: {
		*code = EDHOC_ERROR_CODE_UNSPECIFIED_ERROR;

		if (false == result->message_error_ERR_INFO_present) {
			break;
		}

		if (message_error_ERR_INFO_tstr_c !=
		    result->message_error_ERR_INFO
			    .message_error_ERR_INFO_choice) {
			EDHOC_LOG_ERR("ERR_INFO does not match ERR_CODE: %d",
				      result->message_error_ERR_INFO
					      .message_error_ERR_INFO_choice);
			return EDHOC_ERROR_NOT_PERMITTED;
		}

		if (NULL == info || NULL == info->text_string ||
		    0 == info->entries_size)
			break;

		const struct zcbor_string *tstr =
			&result->message_error_ERR_INFO
				 .message_error_ERR_INFO_tstr;

		if (tstr->len > info->entries_size) {
			EDHOC_LOG_ERR("Buffer too small: %zu, %zu", tstr->len,
				      info->entries_size);
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		info->entries_length = tstr->len;
		memcpy(info->text_string, tstr->value,
		       sizeof(*info->text_string) * tstr->len);

		break;
	}

	case EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE: {
		*code = EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE;

		if (false == result->message_error_ERR_INFO_present) {
			break;
		}

		if (message_error_ERR_INFO_suites_m_c !=
		    result->message_error_ERR_INFO
			    .message_error_ERR_INFO_choice) {
			EDHOC_LOG_ERR("ERR_INFO does not match ERR_CODE: %d",
				      result->message_error_ERR_INFO
					      .message_error_ERR_INFO_choice);
			return EDHOC_ERROR_NOT_PERMITTED;
		}

		if (NULL == info || NULL == info->cipher_suites ||
		    0 == info->entries_size)
			break;

		const struct suites_r *suites =
			&result->message_error_ERR_INFO
				 .message_error_ERR_INFO_suites_m;

		switch (suites->suites_choice) {
		case suites_int_c: {
			info->entries_length = 1;
			*info->cipher_suites = suites->suites_int;
			break;
		}

		case suites_int_l_c: {
			if (suites->suites_int_l_int_count >
			    info->entries_size) {
				EDHOC_LOG_ERR("Buffer too small: %zu, %zu",
					      suites->suites_int_l_int_count,
					      info->entries_size);
				return EDHOC_ERROR_BUFFER_TOO_SMALL;
			}

			info->entries_length = suites->suites_int_l_int_count;
			memcpy(info->cipher_suites, suites->suites_int_l_int,
			       sizeof(*info->cipher_suites) *
				       suites->suites_int_l_int_count);
			break;
		}

		default:
			EDHOC_LOG_ERR("Invalid suites choice: %d",
				      suites->suites_choice);
			return EDHOC_ERROR_NOT_PERMITTED;
		}

		break;
	}

	case EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED: {
		*code = EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED;

		break;
	}

	default:
		EDHOC_LOG_ERR("Unknown error code in message: %d",
			      result->message_error_ERR_CODE);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	return EDHOC_SUCCESS;
}

int edhoc_message_error_process(const uint8_t *msg_err, size_t msg_err_len,
				enum edhoc_error_code *code,
				struct edhoc_error_info *info)
{
	if (NULL == msg_err || 0 == msg_err_len || NULL == code) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	struct message_error result = { 0 };
	int ret = decode_message_error(msg_err, msg_err_len, &result);

	if (EDHOC_SUCCESS != ret)
		return ret;

	return process_decoded_message_error(&result, code, info);
}

int edhoc_message_error_process_with_context(struct edhoc_context *ctx,
					     const uint8_t *msg_err,
					     size_t msg_err_len,
					     struct edhoc_error_info *info)
{
	if (NULL == ctx || NULL == msg_err || 0 == msg_err_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (!ctx->is_init) {
		EDHOC_LOG_ERR("Bad state");
		return EDHOC_ERROR_BAD_STATE;
	}

	struct message_error result = { 0 };
	int ret = decode_message_error(msg_err, msg_err_len, &result);

	if (EDHOC_SUCCESS != ret)
		return ret;

	enum edhoc_error_code code = EDHOC_ERROR_CODE_SUCCESS;
	int32_t peer_csuites[CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES] = { 0 };
	struct edhoc_error_info peer_info = {
		.cipher_suites = peer_csuites,
		.entries_size = ARRAY_SIZE(peer_csuites),
	};
	struct edhoc_error_info *decoded_info = info;

	if (EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE ==
	    result.message_error_ERR_CODE)
		decoded_info = &peer_info;

	ret = process_decoded_message_error(&result, &code, decoded_info);

	if (EDHOC_SUCCESS != ret)
		return ret;

	if (EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE == code) {
		if (NULL != info && NULL != info->cipher_suites &&
		    0 != info->entries_size) {
			if (info->entries_size < peer_info.entries_length) {
				EDHOC_LOG_ERR("Buffer too small: %zu, %zu",
					      peer_info.entries_length,
					      info->entries_size);
				return EDHOC_ERROR_BUFFER_TOO_SMALL;
			}

			info->entries_length = peer_info.entries_length;
			memcpy(info->cipher_suites, peer_info.cipher_suites,
			       sizeof(*info->cipher_suites) *
				       peer_info.entries_length);
		}
	}

	memset(&ctx->negotiation.peer_cipher_suite, 0,
	       sizeof(ctx->negotiation.peer_cipher_suite));

	if (EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE == code) {
		ctx->negotiation.peer_cipher_suite.count =
			peer_info.entries_length;

		for (size_t i = 0; i < peer_info.entries_length; ++i)
			ctx->negotiation.peer_cipher_suite.entry[i].value =
				peer_info.cipher_suites[i];
	}

	ctx->error_code = code;
	ctx->state.machine = EDHOC_SM_ABORTED;
	return EDHOC_SUCCESS;
}
