/**
 * \file    edhoc_helpers.c
 * \author  Assa Abloy
 * \brief   EDHOC Utilities implementations:
 *          - Connection ID utilities.
 *          - Buffer utilities (prepend/extract).
 * \version 1.0
 * \date    2026-01-27
 * 
 * \copyright Copyright (c) 2026
 * 
 */

/* Include files ----------------------------------------------------------- */

#include <string.h>

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* EDHOC headers: */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include "edhoc.h"
#include "edhoc_helpers.h"
#include "edhoc_common.h"
#include "edhoc_log.h"

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
#pragma clang diagnostic ignored "-Wreserved-identifier"
#pragma clang diagnostic ignored "-Wpadded"
#pragma clang diagnostic ignored "-Wdocumentation"
#endif

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_connection_identifier_encode.h>
#include <backend_cbor_connection_identifier_decode.h>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/* Module interface function definitions ----------------------------------- */

/* Connection ID Utilities -------------------------------------------------- */

bool edhoc_connection_id_equal(const struct edhoc_connection_id *conn_id_1,
			       const struct edhoc_connection_id *conn_id_2)
{
	if (NULL == conn_id_1 || NULL == conn_id_2)
		return false;

	if (conn_id_1->encode_type != conn_id_2->encode_type)
		return false;

	switch (conn_id_1->encode_type) {
	case EDHOC_CID_TYPE_ONE_BYTE_INTEGER:
		return (conn_id_1->int_value == conn_id_2->int_value);

	case EDHOC_CID_TYPE_BYTE_STRING:
		return (conn_id_1->bstr_length == conn_id_2->bstr_length) &&
		       (0 == memcmp(conn_id_1->bstr_value,
				    conn_id_2->bstr_value,
				    conn_id_1->bstr_length));

	default:
		return false;
	}
}

/* Buffer Utilities --------------------------------------------------------- */

int edhoc_prepend_flow(struct edhoc_prepended_fields *prepended_fields)
{
	if (NULL == prepended_fields || NULL == prepended_fields->buffer) {
		EDHOC_LOG_ERR(
			"Invalid argument: prepended_fields or buffer is NULL\n");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* Check if we have enough space for CBOR true (1 byte) */
	if (prepended_fields->buffer_size < 1) {
		EDHOC_LOG_ERR("Buffer too small for CBOR true\n");
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	/* Initialize edhoc_message_ptr to point after prepended CBOR true */
	prepended_fields->edhoc_message_ptr = prepended_fields->buffer + 1;
	prepended_fields->edhoc_message_size =
		prepended_fields->buffer_size - 1;

	/* Prepend CBOR true at the start of buffer */
	prepended_fields->buffer[0] = EDHOC_CBOR_TRUE;

	return EDHOC_SUCCESS;
}

int edhoc_prepend_connection_id(struct edhoc_prepended_fields *prepended_fields,
				const struct edhoc_connection_id *conn_id)
{
	if (NULL == prepended_fields || NULL == conn_id ||
	    NULL == prepended_fields->buffer) {
		EDHOC_LOG_ERR(
			"Invalid argument: prepended_fields, conn_id or buffer is NULL\n");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (0 == prepended_fields->buffer_size) {
		EDHOC_LOG_ERR("Buffer size is zero\n");
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	if (conn_id->encode_type == EDHOC_CID_TYPE_ONE_BYTE_INTEGER) {
		if (prepended_fields->buffer_size < 1) {
			EDHOC_LOG_ERR(
				"Buffer too small for one-byte integer connection ID\n");
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		prepended_fields->buffer[0] = (uint8_t)conn_id->int_value;
		prepended_fields->edhoc_message_ptr =
			prepended_fields->buffer + 1;
		prepended_fields->edhoc_message_size =
			prepended_fields->buffer_size - 1;
	} else if (conn_id->encode_type == EDHOC_CID_TYPE_BYTE_STRING) {
		if (conn_id->bstr_length == 0 ||
		    conn_id->bstr_length > CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID) {
			EDHOC_LOG_ERR(
				"Invalid byte string connection ID length: %zu\n",
				conn_id->bstr_length);
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		struct connection_identifier_r
			cid_r = { .connection_identifier_choice =
					  connection_identifier_bstr_c,
				  .connection_identifier_bstr = {
					  .value = (uint8_t *)
							   conn_id->bstr_value,
					  .len = conn_id->bstr_length } };

		size_t cid_encoded_len = 0;
		int ret = cbor_encode_connection_identifier(
			prepended_fields->buffer, prepended_fields->buffer_size,
			&cid_r, &cid_encoded_len);

		if (ZCBOR_SUCCESS != ret) {
			EDHOC_LOG_ERR(
				"CBOR encoding of connection ID failed\n");
			return EDHOC_ERROR_CBOR_FAILURE;
		}

		if (cid_encoded_len == 0) {
			EDHOC_LOG_ERR(
				"CBOR encoded connection ID length is zero\n");
			return EDHOC_ERROR_INVALID_ARGUMENT;
		}

		prepended_fields->edhoc_message_ptr =
			prepended_fields->buffer + cid_encoded_len;
		prepended_fields->edhoc_message_size =
			prepended_fields->buffer_size - cid_encoded_len;
	} else {
		EDHOC_LOG_ERR("Invalid connection ID encode type: %d\n",
			      conn_id->encode_type);
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	return EDHOC_SUCCESS;
}

int edhoc_prepend_recalculate_size(
	struct edhoc_prepended_fields *prepended_fields)
{
	if (NULL == prepended_fields) {
		EDHOC_LOG_ERR("Invalid argument: prepended_fields is NULL\n");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (NULL == prepended_fields->buffer ||
	    0 == prepended_fields->buffer_size) {
		EDHOC_LOG_ERR(
			"Invalid argument: buffer is NULL or buffer_size is zero\n");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (NULL == prepended_fields->edhoc_message_ptr ||
	    0 == prepended_fields->edhoc_message_size) {
		EDHOC_LOG_ERR(
			"Invalid argument: edhoc_message_ptr is NULL or edhoc_message_size is zero\n");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* Check that edhoc_message_ptr is within buffer bounds */
	if (prepended_fields->edhoc_message_ptr < prepended_fields->buffer) {
		EDHOC_LOG_ERR(
			"Invalid argument: edhoc_message_ptr is before buffer start\n");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* Calculate size of the prepended field based on difference between buffer start and edhoc message start pointers.
	 * Both edhoc_message_ptr and buffer are part of the same struct and edhoc_message_ptr is always set
	 * by edhoc_prepend_* functions to point within buffer after the prepended fields. */
	const size_t prepended_size =
		prepended_fields->edhoc_message_ptr - prepended_fields->buffer;

	/* Check that prepended size doesn't exceed buffer size */
	if (prepended_size > prepended_fields->buffer_size) {
		EDHOC_LOG_ERR(
			"Invalid argument: prepended_size exceeds buffer_size\n");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const size_t total_size =
		prepended_size + prepended_fields->edhoc_message_size;

	/* Sanity check: total size shouldn't exceed buffer size */
	if (total_size > prepended_fields->buffer_size) {
		EDHOC_LOG_ERR(
			"Buffer too small: total_size exceeds buffer_size\n");
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	prepended_fields->buffer_size = total_size;

	return EDHOC_SUCCESS;
}

int edhoc_extract_flow_info(struct edhoc_extracted_fields *extracted_fields)
{
	if (NULL == extracted_fields) {
		EDHOC_LOG_ERR("Invalid argument: extracted_fields is NULL\n");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	extracted_fields->is_forward_flow = false;
	extracted_fields->is_reverse_flow = false;

	extracted_fields->edhoc_message_ptr = NULL;
	extracted_fields->edhoc_message_size = 0;

	if ((NULL == extracted_fields->buffer) &&
	    (0 == extracted_fields->buffer_size)) {
		extracted_fields->is_reverse_flow = true;
		return EDHOC_SUCCESS;
	}

	/* Check for forward flow: buffer is not NULL AND size > 1 AND first byte is CBOR_TRUE */
	if ((NULL != extracted_fields->buffer) &&
	    (extracted_fields->buffer_size > 1) &&
	    (EDHOC_CBOR_TRUE == extracted_fields->buffer[0])) {
		extracted_fields->is_forward_flow = true;
		extracted_fields->edhoc_message_ptr =
			extracted_fields->buffer + 1;
		extracted_fields->edhoc_message_size =
			extracted_fields->buffer_size - 1;
	}

	return EDHOC_SUCCESS;
}

int edhoc_extract_connection_id(struct edhoc_extracted_fields *extracted_fields)
{
	if ((NULL == extracted_fields) || (NULL == extracted_fields->buffer) ||
	    (0 == extracted_fields->buffer_size)) {
		EDHOC_LOG_ERR(
			"Invalid argument: extracted_fields, buffer is NULL or buffer_size is zero\n");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	memset(&extracted_fields->extracted_conn_id, 0,
	       sizeof(extracted_fields->extracted_conn_id));

	/* Decode connection ID from the raw buffer start (connection ID is always prepended at buffer start) */
	struct connection_identifier_r cid_r = { 0 };
	size_t decoded_len = 0;
	int ret = cbor_decode_connection_identifier(
		extracted_fields->buffer, extracted_fields->buffer_size, &cid_r,
		&decoded_len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR decoding of connection ID failed\n");
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* Convert connection_identifier_r to edhoc_connection_id */
	switch (cid_r.connection_identifier_choice) {
	case connection_identifier_int_c:
		extracted_fields->extracted_conn_id.encode_type =
			EDHOC_CID_TYPE_ONE_BYTE_INTEGER;
		extracted_fields->extracted_conn_id.int_value =
			extracted_fields->buffer[0];
		break;
	case connection_identifier_bstr_c:
		if (cid_r.connection_identifier_bstr.len >
		    CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID) {
			EDHOC_LOG_ERR(
				"Byte string connection ID length exceeds maximum: %zu\n",
				cid_r.connection_identifier_bstr.len);
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}
		extracted_fields->extracted_conn_id.encode_type =
			EDHOC_CID_TYPE_BYTE_STRING;
		extracted_fields->extracted_conn_id.bstr_length =
			cid_r.connection_identifier_bstr.len;
		memcpy(extracted_fields->extracted_conn_id.bstr_value,
		       cid_r.connection_identifier_bstr.value,
		       cid_r.connection_identifier_bstr.len);
		break;
	default:
		EDHOC_LOG_ERR("Invalid connection identifier choice: %d\n",
			      cid_r.connection_identifier_choice);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	extracted_fields->edhoc_message_ptr =
		extracted_fields->buffer + decoded_len;
	extracted_fields->edhoc_message_size =
		extracted_fields->buffer_size - decoded_len;

	return EDHOC_SUCCESS;
}
