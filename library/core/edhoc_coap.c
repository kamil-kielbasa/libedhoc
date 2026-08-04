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

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include <edhoc_config.h>
#endif

/* EDHOC public headers: */
#include <edhoc/coap.h>
#include <edhoc/types.h>
#include <edhoc/values.h>

/* EDHOC internal headers: */
#include "edhoc_connection_id_internal.h"
#include "edhoc_values_internal.h"
#include "edhoc_backend_log.h"

/* CBOR headers: */
#include <zcbor_common.h>
#include <backend_cbor_connection_identifier_types.h>
#include <backend_cbor_connection_identifier_decode.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

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
	if (NULL == prepended_fields || NULL == prepended_fields->buffer ||
	    prepended_fields->capacity < prepended_fields->length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const uint8_t indicator = EDHOC_CBOR_TRUE;

	if (sizeof(indicator) >
	    prepended_fields->capacity - prepended_fields->length) {
		EDHOC_LOG_ERR("Buffer too small: %zu",
			      prepended_fields->capacity);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	prepended_fields->buffer[prepended_fields->length] = indicator;
	prepended_fields->length += sizeof(indicator);

	return EDHOC_SUCCESS;
}

int edhoc_coap_prepend_connection_id(
	struct edhoc_coap_prepended_fields *prepended_fields,
	const struct edhoc_buffer *conn_id)
{
	if (NULL == prepended_fields || NULL == conn_id ||
	    NULL == prepended_fields->buffer ||
	    prepended_fields->capacity < prepended_fields->length ||
	    (NULL == conn_id->value && 0 != conn_id->length)) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (prepended_fields->capacity == prepended_fields->length) {
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
	ret = edhoc_connection_id_encode(
		&cid, &prepended_fields->buffer[prepended_fields->length],
		prepended_fields->capacity - prepended_fields->length,
		&encoded_length);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Connection ID encoding: %d", ret);
		return ret;
	}

	prepended_fields->length += encoded_length;

	return EDHOC_SUCCESS;
}

int edhoc_coap_extract_flow_info(
	struct edhoc_coap_extracted_fields *extracted_fields)
{
	if (NULL == extracted_fields ||
	    extracted_fields->length < extracted_fields->consumed) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	extracted_fields->is_forward_flow = false;
	extracted_fields->is_reverse_flow = false;

	/* An empty payload is the reverse flow whether or not it carries a
	 * pointer (RFC 9528: A.2). */
	if (extracted_fields->length == extracted_fields->consumed) {
		extracted_fields->is_reverse_flow = true;
		return EDHOC_SUCCESS;
	}

	if (NULL == extracted_fields->buffer) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_CBOR_TRUE ==
	    extracted_fields->buffer[extracted_fields->consumed]) {
		extracted_fields->is_forward_flow = true;
		extracted_fields->consumed += 1;
	}

	return EDHOC_SUCCESS;
}

int edhoc_coap_extract_connection_id(
	struct edhoc_coap_extracted_fields *extracted_fields)
{
	if (NULL == extracted_fields || NULL == extracted_fields->buffer ||
	    extracted_fields->length <= extracted_fields->consumed) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const uint8_t *const position =
		&extracted_fields->buffer[extracted_fields->consumed];
	const size_t remaining =
		extracted_fields->length - extracted_fields->consumed;

	struct connection_identifier_r cid_r = { 0 };
	size_t decoded_len = 0;
	const int ret = cbor_decode_connection_identifier(position, remaining,
							  &cid_r, &decoded_len);

	if (ZCBOR_SUCCESS != ret) {
		EDHOC_LOG_ERR("CBOR decoding: %d", ret);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	/* The identifier is a slice of the payload: the compact form is the
	 * leading byte itself, the byte string form follows its header. */
	switch (cid_r.connection_identifier_choice) {
	case connection_identifier_int_c:
		extracted_fields->connection_id.value = position;
		extracted_fields->connection_id.length = decoded_len;
		break;

	case connection_identifier_bstr_c:
		if (CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID <
		    cid_r.connection_identifier_bstr.len) {
			EDHOC_LOG_ERR("Connection ID too large: %zu",
				      cid_r.connection_identifier_bstr.len);
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		extracted_fields->connection_id.value =
			cid_r.connection_identifier_bstr.value;
		extracted_fields->connection_id.length =
			cid_r.connection_identifier_bstr.len;
		break;

	default:
		EDHOC_LOG_ERR("Invalid connection identifier choice: %d",
			      cid_r.connection_identifier_choice);
		return EDHOC_ERROR_CBOR_FAILURE;
	}

	extracted_fields->consumed += decoded_len;

	return EDHOC_SUCCESS;
}
