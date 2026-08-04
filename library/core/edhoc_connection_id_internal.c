/**
 * \file    edhoc_connection_id_internal.c
 * \author  Kamil Kielbasa
 * \brief   Implementation of the EDHOC connection identifier module.
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
#include <edhoc/values.h>

/* EDHOC internal headers: */
#include "edhoc_macros_internal.h"
#include "edhoc_common_internal.h"
#include "edhoc_connection_id_internal.h"
#include "edhoc_backend_log.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_int_type_encode.h>
#include <backend_cbor_int_type_decode.h>
#include <backend_cbor_bstr_type_encode.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitions --------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

bool edhoc_connection_id_compact(const struct connection_id *connection_id,
				 int32_t *value)
{
	if (NULL == connection_id || NULL == value) {
		EDHOC_LOG_ERR("Invalid arguments");
		return false;
	}

	/* RFC 9528: 3.3.2 - the identifier travels as an integer exactly when
	 * its whole byte string is one complete CBOR integer, which is what
	 * decoding it as such answers. */
	size_t decoded_length = 0;
	const int ret = cbor_decode_integer_type_int_type(connection_id->value,
							  connection_id->length,
							  value,
							  &decoded_length);

	return ZCBOR_SUCCESS == ret && connection_id->length == decoded_length;
}

size_t
edhoc_connection_id_encoded_length(const struct connection_id *connection_id)
{
	if (NULL == connection_id) {
		EDHOC_LOG_ERR("Invalid argument");
		return 0;
	}

	int32_t value = 0;

	if (edhoc_connection_id_compact(connection_id, &value)) {
		return edhoc_cbor_int_length(value);
	}

	return connection_id->length +
	       edhoc_cbor_bstr_header_length(connection_id->length);
}

int edhoc_connection_id_encode(const struct connection_id *connection_id,
			       uint8_t *buffer, size_t buffer_length,
			       size_t *length)
{
	if (NULL == connection_id || NULL == buffer || 0 == buffer_length ||
	    NULL == length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	int ret = ZCBOR_SUCCESS;
	int32_t value = 0;

	if (edhoc_connection_id_compact(connection_id, &value)) {
		ret = cbor_encode_integer_type_int_type(buffer, buffer_length,
							&value, length);
	} else {
		const struct zcbor_string input = {
			.value = connection_id->value,
			.len = connection_id->length,
		};

		ret = cbor_encode_byte_string_type_bstr_type(
			buffer, buffer_length, &input, length);
	}

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR enc connection identifier: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	return EDHOC_SUCCESS;
}

int edhoc_connection_id_from_int(int32_t value,
				 struct connection_id *connection_id)
{
	if (NULL == connection_id) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* RFC 9528: 3.3.2 - the integer is the transport encoding of the byte
	 * string that its own CBOR encoding consists of, which only holds when
	 * that encoding is a single byte. Re-encoding recovers the byte and
	 * rejects any wider integer in one step. */
	uint8_t byte = 0;
	size_t encoded_length = 0;
	const int ret = cbor_encode_integer_type_int_type(
		&byte, sizeof(byte), &value, &encoded_length);

	if (ZCBOR_SUCCESS != ret || sizeof(byte) != encoded_length) {
		EDHOC_LOG_ERR("Connection identifier int is not one byte: %d",
			      (int)value);
		return EDHOC_ERROR_NOT_PERMITTED;
	}

	connection_id->value[0] = byte;
	connection_id->length = sizeof(byte);

	return EDHOC_SUCCESS;
}

int edhoc_connection_id_from_bstr(const uint8_t *value, size_t length,
				  struct connection_id *connection_id)
{
	if (NULL == connection_id || (NULL == value && 0 != length)) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (ARRAY_SIZE(connection_id->value) < length) {
		EDHOC_LOG_ERR("Connection identifier too large: %zu (max %d)",
			      length, CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	if (0 != length) {
		memcpy(connection_id->value, value, length);
	}

	connection_id->length = length;

	return EDHOC_SUCCESS;
}
