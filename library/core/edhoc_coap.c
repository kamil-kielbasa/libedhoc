/**
 * \file    edhoc_coap.c
 * \author  Assa Abloy
 * \brief   EDHOC Utilities implementations:
 *          - Connection ID utilities.
 *          - Buffer utilities (prepend/extract).
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
#include <edhoc/edhoc.h>
#include "edhoc_context_internal.h"
#include "edhoc_values_internal.h"
#include <edhoc/coap.h>
#include "edhoc_common_internal.h"
#include "edhoc_connection_id_internal.h"
#include "edhoc_backend_log.h"

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_connection_identifier_encode.h>
#include <backend_cbor_connection_identifier_decode.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/* Module interface function definitions ----------------------------------- */

bool edhoc_coap_connection_id_equal(const struct edhoc_buffer *conn_id_1,
				    const struct edhoc_buffer *conn_id_2)
{
	if (NULL == conn_id_1 || NULL == conn_id_2)
		return false;

	if (conn_id_1->length != conn_id_2->length)
		return false;

	if (0 == conn_id_1->length)
		return true;

	if (NULL == conn_id_1->value || NULL == conn_id_2->value)
		return false;

	return 0 ==
	       memcmp(conn_id_1->value, conn_id_2->value, conn_id_1->length);
}

int edhoc_coap_prepend_flow(struct edhoc_coap_prepended_fields *prepended_fields)
{
	if (NULL == prepended_fields || NULL == prepended_fields->buffer) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* Check if we have enough space for CBOR true (1 byte) */
	if (prepended_fields->buffer_size < 1) {
		EDHOC_LOG_ERR("Buffer too small: %zu",
			      prepended_fields->buffer_size);
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

int edhoc_coap_prepend_connection_id(
	struct edhoc_coap_prepended_fields *prepended_fields,
	const struct edhoc_buffer *conn_id)
{
	if (NULL == prepended_fields || NULL == conn_id ||
	    NULL == prepended_fields->buffer ||
	    (NULL == conn_id->value && 0 != conn_id->length)) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (0 == prepended_fields->buffer_size) {
		EDHOC_LOG_ERR("Buffer too small");
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	struct connection_id cid = { 0 };
	int ret = edhoc_connection_id_from_bstr(conn_id->value, conn_id->length,
						&cid);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Connection ID conversion: %d", ret);
		return ret;
	}

	size_t encoded_length = 0;
	ret = edhoc_connection_id_encode(&cid, prepended_fields->buffer,
					 prepended_fields->buffer_size,
					 &encoded_length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Connection ID encoding: %d", ret);
		return ret;
	}

	prepended_fields->edhoc_message_ptr =
		prepended_fields->buffer + encoded_length;
	prepended_fields->edhoc_message_size =
		prepended_fields->buffer_size - encoded_length;

	return EDHOC_SUCCESS;
}

int edhoc_coap_prepend_recalculate_size(
	struct edhoc_coap_prepended_fields *prepended_fields)
{
	if (NULL == prepended_fields) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (NULL == prepended_fields->buffer ||
	    0 == prepended_fields->buffer_size) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (NULL == prepended_fields->edhoc_message_ptr ||
	    0 == prepended_fields->edhoc_message_size) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* Check that edhoc_message_ptr is within buffer bounds */
	if (prepended_fields->edhoc_message_ptr < prepended_fields->buffer) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* Calculate size of the prepended field based on difference between buffer start and edhoc message start pointers.
	 * Both edhoc_message_ptr and buffer are part of the same struct and edhoc_message_ptr is always set
	 * by edhoc_prepend_* functions to point within buffer after the prepended fields. */
	const size_t prepended_size =
		(size_t)(prepended_fields->edhoc_message_ptr -
			 prepended_fields->buffer);

	/* Check that prepended size doesn't exceed buffer size */
	if (prepended_size > prepended_fields->buffer_size) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const size_t total_size =
		prepended_size + prepended_fields->edhoc_message_size;

	/* Sanity check: total size shouldn't exceed buffer size */
	if (total_size > prepended_fields->buffer_size) {
		EDHOC_LOG_ERR("Buffer too small: %zu, %zu", total_size,
			      prepended_fields->buffer_size);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	prepended_fields->buffer_size = total_size;

	return EDHOC_SUCCESS;
}

int edhoc_coap_extract_flow_info(
	struct edhoc_coap_extracted_fields *extracted_fields)
{
	if (NULL == extracted_fields) {
		EDHOC_LOG_ERR("Invalid argument");
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

int edhoc_coap_extract_connection_id(
	struct edhoc_coap_extracted_fields *extracted_fields)
{
	if ((NULL == extracted_fields) || (NULL == extracted_fields->buffer) ||
	    (0 == extracted_fields->buffer_size)) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	struct connection_identifier_r cid_r = { 0 };
	size_t decoded_len = 0;
	const int ret = cbor_decode_connection_identifier(
		extracted_fields->buffer, extracted_fields->buffer_size, &cid_r,
		&decoded_len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR decoding: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* The identifier is a slice of the payload: the compact form is the
	 * leading byte itself, the byte string form follows its header. */
	switch (cid_r.connection_identifier_choice) {
	case connection_identifier_int_c:
		extracted_fields->extracted_conn_id.value =
			extracted_fields->buffer;
		extracted_fields->extracted_conn_id.length = decoded_len;
		break;

	case connection_identifier_bstr_c:
		if (CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID <
		    cid_r.connection_identifier_bstr.len) {
			EDHOC_LOG_ERR("Connection ID too large: %zu",
				      cid_r.connection_identifier_bstr.len);
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		extracted_fields->extracted_conn_id.value =
			cid_r.connection_identifier_bstr.value;
		extracted_fields->extracted_conn_id.length =
			cid_r.connection_identifier_bstr.len;
		break;

	default:
		EDHOC_LOG_ERR("Invalid connection identifier choice: %d",
			      cid_r.connection_identifier_choice);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	extracted_fields->edhoc_message_ptr =
		extracted_fields->buffer + decoded_len;
	extracted_fields->edhoc_message_size =
		extracted_fields->buffer_size - decoded_len;

	return EDHOC_SUCCESS;
}
