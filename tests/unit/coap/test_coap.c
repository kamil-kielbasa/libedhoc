/**
 * \file    test_coap.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for EDHOC CoAP API.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include <edhoc/coap.h>
#include "edhoc_values_internal.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(coap);

TEST_SETUP(coap)
{
}

TEST_TEAR_DOWN(coap)
{
}

/* Connection ID Utilities Tests ------------------------------------------- */

TEST(coap, connection_id_equal_same_int)
{
	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5
	};
	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5
	};

	TEST_ASSERT_TRUE(
		edhoc_coap_connection_id_equal(&conn_id_1, &conn_id_2));
}

TEST(coap, connection_id_equal_different_int)
{
	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5
	};
	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 10
	};

	TEST_ASSERT_FALSE(
		edhoc_coap_connection_id_equal(&conn_id_1, &conn_id_2));
}

TEST(coap, connection_id_equal_same_bstr)
{
	uint8_t bstr1[] = { 0x01, 0x02, 0x03 };
	uint8_t bstr2[] = { 0x01, 0x02, 0x03 };

	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = 3
	};
	memcpy(conn_id_1.bstr_value, bstr1, 3);

	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = 3
	};
	memcpy(conn_id_2.bstr_value, bstr2, 3);

	TEST_ASSERT_TRUE(
		edhoc_coap_connection_id_equal(&conn_id_1, &conn_id_2));
}

TEST(coap, connection_id_equal_different_bstr)
{
	uint8_t bstr1[] = { 0x01, 0x02, 0x03 };
	uint8_t bstr2[] = { 0x01, 0x02, 0x04 };

	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = 3
	};
	memcpy(conn_id_1.bstr_value, bstr1, 3);

	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = 3
	};
	memcpy(conn_id_2.bstr_value, bstr2, 3);

	TEST_ASSERT_FALSE(
		edhoc_coap_connection_id_equal(&conn_id_1, &conn_id_2));
}

TEST(coap, connection_id_equal_different_bstr_length)
{
	uint8_t bstr1[] = { 0x01, 0x02, 0x03 };
	uint8_t bstr2[] = { 0x01, 0x02 };

	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = 3
	};
	memcpy(conn_id_1.bstr_value, bstr1, 3);

	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = 2
	};
	memcpy(conn_id_2.bstr_value, bstr2, 2);

	TEST_ASSERT_FALSE(
		edhoc_coap_connection_id_equal(&conn_id_1, &conn_id_2));
}

TEST(coap, connection_id_equal_different_type)
{
	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5
	};
	uint8_t bstr[] = { 0x05 };
	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = 1
	};
	memcpy(conn_id_2.bstr_value, bstr, 1);

	TEST_ASSERT_FALSE(
		edhoc_coap_connection_id_equal(&conn_id_1, &conn_id_2));
}

TEST(coap, connection_id_equal_null_first)
{
	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5
	};

	TEST_ASSERT_FALSE(edhoc_coap_connection_id_equal(NULL, &conn_id_2));
}

TEST(coap, connection_id_equal_null_second)
{
	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5
	};

	TEST_ASSERT_FALSE(edhoc_coap_connection_id_equal(&conn_id_1, NULL));
}

TEST(coap, connection_id_equal_both_null)
{
	TEST_ASSERT_FALSE(edhoc_coap_connection_id_equal(NULL, NULL));
}

/* Buffer Prepend Tests ---------------------------------------------------- */

TEST(coap, prepend_flow_success)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	int ret = edhoc_coap_prepend_flow(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_CBOR_TRUE, buffer[0]);
	TEST_ASSERT_EQUAL_PTR(buffer + 1, prepended_fields.edhoc_message_ptr);
	TEST_ASSERT_EQUAL(sizeof(buffer) - 1,
			  prepended_fields.edhoc_message_size);
}

TEST(coap, prepend_flow_null_fields)
{
	int ret = edhoc_coap_prepend_flow(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_flow_null_buffer)
{
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = NULL, .buffer_size = 100
	};

	int ret = edhoc_coap_prepend_flow(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_flow_buffer_too_small)
{
	uint8_t buffer[1] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer, .buffer_size = 0
	};

	int ret = edhoc_coap_prepend_flow(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(coap, prepend_connection_id_int_success)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value =
			5 /* Use value in valid CBOR one-byte integer range (-24 to 23) */
	};
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	int ret = edhoc_coap_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(5, buffer[0]);
	TEST_ASSERT_EQUAL_PTR(buffer + 1, prepended_fields.edhoc_message_ptr);
	TEST_ASSERT_EQUAL(sizeof(buffer) - 1,
			  prepended_fields.edhoc_message_size);
}

TEST(coap, prepend_connection_id_bstr_success)
{
	uint8_t buffer[100] = { 0 };
	uint8_t cid_bstr[] = { 0x01, 0x02, 0x03 };
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = 3
	};
	memcpy(conn_id.bstr_value, cid_bstr, 3);
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	int ret = edhoc_coap_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	/* CBOR byte string encoding: 0x43 (major type 2, length 3) followed by data */
	TEST_ASSERT_EQUAL(0x43, buffer[0]);
	TEST_ASSERT_EQUAL(0x01, buffer[1]);
	TEST_ASSERT_EQUAL(0x02, buffer[2]);
	TEST_ASSERT_EQUAL(0x03, buffer[3]);
	TEST_ASSERT_EQUAL_PTR(buffer + 4, prepended_fields.edhoc_message_ptr);
}

TEST(coap, prepend_connection_id_null_fields)
{
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5
	};

	int ret = edhoc_coap_prepend_connection_id(NULL, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_connection_id_null_conn_id)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer, .buffer_size = sizeof(buffer)
	};

	int ret = edhoc_coap_prepend_connection_id(&prepended_fields, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_connection_id_null_buffer)
{
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5
	};
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = NULL, .buffer_size = 100
	};

	int ret = edhoc_coap_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_connection_id_bstr_zero_length)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = 0
	};
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer, .buffer_size = sizeof(buffer)
	};

	int ret = edhoc_coap_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_recalculate_size_success)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer + 5,
		.edhoc_message_size = 10
	};

	int ret = edhoc_coap_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(15, prepended_fields.buffer_size);
}

TEST(coap, prepend_recalculate_size_null_fields)
{
	int ret = edhoc_coap_prepend_recalculate_size(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_recalculate_size_null_buffer)
{
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = NULL,
		.buffer_size = 100,
		.edhoc_message_ptr = (uint8_t *)0x1000,
		.edhoc_message_size = 10
	};

	int ret = edhoc_coap_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_recalculate_size_zero_buffer_size)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = 0,
		.edhoc_message_ptr = buffer + 5,
		.edhoc_message_size = 10
	};

	int ret = edhoc_coap_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_recalculate_size_null_message_ptr)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = NULL,
		.edhoc_message_size = 10
	};

	int ret = edhoc_coap_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_recalculate_size_zero_message_size)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer + 5,
		.edhoc_message_size = 0
	};

	int ret = edhoc_coap_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_recalculate_size_total_exceeds_buffer)
{
	uint8_t buffer[10] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer + 5,
		.edhoc_message_size = 10 /* 5 + 10 = 15 > 10 */
	};

	int ret = edhoc_coap_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

/* Buffer Extract Tests ---------------------------------------------------- */

TEST(coap, extract_flow_info_forward_flow)
{
	uint8_t buffer[] = { EDHOC_CBOR_TRUE, 0x01, 0x02, 0x03 };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	int ret = edhoc_coap_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(extracted_fields.is_forward_flow);
	TEST_ASSERT_FALSE(extracted_fields.is_reverse_flow);
	TEST_ASSERT_EQUAL_PTR(buffer + 1, extracted_fields.edhoc_message_ptr);
	TEST_ASSERT_EQUAL(sizeof(buffer) - 1,
			  extracted_fields.edhoc_message_size);
}

TEST(coap, extract_flow_info_reverse_flow)
{
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = NULL,
		.buffer_size = 0,
		.edhoc_message_ptr = NULL,
		.edhoc_message_size = 0
	};

	int ret = edhoc_coap_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_FALSE(extracted_fields.is_forward_flow);
	TEST_ASSERT_TRUE(extracted_fields.is_reverse_flow);
}

TEST(coap, extract_flow_info_no_flow_indicator)
{
	uint8_t buffer[] = { 0x01, 0x02, 0x03 };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	int ret = edhoc_coap_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_FALSE(extracted_fields.is_forward_flow);
	TEST_ASSERT_FALSE(extracted_fields.is_reverse_flow);
}

TEST(coap, extract_flow_info_null_fields)
{
	int ret = edhoc_coap_extract_flow_info(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, extract_flow_info_single_byte_buffer)
{
	uint8_t buffer[] = { EDHOC_CBOR_TRUE };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = 1,
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = 1
	};

	int ret = edhoc_coap_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	/* Single byte buffer with CBOR_TRUE is not considered forward flow (needs size > 1) */
	TEST_ASSERT_FALSE(extracted_fields.is_forward_flow);
	TEST_ASSERT_FALSE(extracted_fields.is_reverse_flow);
}

TEST(coap, extract_connection_id_int_success)
{
	/* Use value 5 which is in valid CBOR one-byte integer range (-24 to 23) where raw byte is valid CBOR */
	uint8_t buffer[] = {
		0x05
	}; /* Integer 5 (valid CBOR one-byte integer) */
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_CONNECTION_ID_TYPE_ONE_BYTE_INTEGER,
			  extracted_fields.extracted_conn_id.encode_type);
	TEST_ASSERT_EQUAL(5, extracted_fields.extracted_conn_id.int_value);
}

TEST(coap, extract_connection_id_bstr_success)
{
	uint8_t buffer[] = {
		0x43, 0x01, 0x02, 0x03
	}; /* CBOR byte string: 0x43 (major 2, length 3) + data */
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
			  extracted_fields.extracted_conn_id.encode_type);
	TEST_ASSERT_EQUAL(3, extracted_fields.extracted_conn_id.bstr_length);
	TEST_ASSERT_EQUAL(0x01,
			  extracted_fields.extracted_conn_id.bstr_value[0]);
	TEST_ASSERT_EQUAL(0x02,
			  extracted_fields.extracted_conn_id.bstr_value[1]);
	TEST_ASSERT_EQUAL(0x03,
			  extracted_fields.extracted_conn_id.bstr_value[2]);
}

TEST(coap, extract_connection_id_null_fields)
{
	int ret = edhoc_coap_extract_connection_id(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, extract_connection_id_null_buffer)
{
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = NULL, .buffer_size = 0
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, extract_connection_id_zero_buffer_size)
{
	uint8_t buffer[] = { 0x2A };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer, .buffer_size = 0
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/* Integration Tests ------------------------------------------------------- */

TEST(coap, prepend_and_extract_flow_roundtrip)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	/* Prepend flow */
	int ret = edhoc_coap_prepend_flow(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Extract flow */
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = prepended_fields.buffer_size,
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = prepended_fields.buffer_size
	};
	ret = edhoc_coap_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(extracted_fields.is_forward_flow);
}

TEST(coap, prepend_and_extract_connection_id_roundtrip)
{
	uint8_t buffer[100] = { 0 };
	uint8_t cid_bstr[] = { 0x01, 0x02, 0x03 };
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CONNECTION_ID_TYPE_BYTE_STRING,
		.bstr_length = 3
	};
	memcpy(conn_id.bstr_value, cid_bstr, 3);
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	/* Prepend connection ID */
	int ret = edhoc_coap_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Extract connection ID */
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = prepended_fields.buffer_size,
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = prepended_fields.buffer_size
	};
	ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(edhoc_coap_connection_id_equal(
		&conn_id, &extracted_fields.extracted_conn_id));
}

TEST(coap, prepend_recalculate_size_ptr_before_buffer)
{
	uint8_t buf[64] = { 0 };
	struct edhoc_coap_prepended_fields pf = {
		.buffer = &buf[32],
		.buffer_size = 32,
		.edhoc_message_ptr = &buf[0],
		.edhoc_message_size = 16,
	};
	int ret = edhoc_coap_prepend_recalculate_size(&pf);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_recalculate_size_ptr_past_buffer)
{
	uint8_t buf[64] = { 0 };
	struct edhoc_coap_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = 32,
		.edhoc_message_ptr = &buf[48],
		.edhoc_message_size = 16,
	};
	int ret = edhoc_coap_prepend_recalculate_size(&pf);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_connection_id_invalid_type)
{
	uint8_t buf[64] = { 0 };
	struct edhoc_coap_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = sizeof(buf),
	};
	struct edhoc_connection_id cid = { 0 };
	cid.encode_type = (enum edhoc_connection_id_type)99;
	int ret = edhoc_coap_prepend_connection_id(&pf, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, extract_connection_id_invalid_cbor)
{
	uint8_t garbage[] = { 0xFF, 0xFF, 0xFF, 0xFF };
	struct edhoc_coap_extracted_fields ef = {
		.buffer = garbage,
		.buffer_size = sizeof(garbage),
	};
	int ret = edhoc_coap_extract_connection_id(&ef);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);
}

TEST(coap, extract_connection_id_bstr_too_long)
{
	/*
	 * CBOR byte string of length 8 (CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID=7):
	 * 0x48 = major type 2 (bstr), additional info 8
	 * followed by 8 bytes of data.
	 */
	uint8_t cbor_bstr[] = { 0x48, 0x01, 0x02, 0x03, 0x04,
				0x05, 0x06, 0x07, 0x08 };
	struct edhoc_coap_extracted_fields ef = {
		.buffer = cbor_bstr,
		.buffer_size = sizeof(cbor_bstr),
	};
	int ret = edhoc_coap_extract_connection_id(&ef);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST_GROUP_RUNNER(coap)
{
	RUN_TEST_CASE(coap, connection_id_equal_same_int);
	RUN_TEST_CASE(coap, connection_id_equal_different_int);
	RUN_TEST_CASE(coap, connection_id_equal_same_bstr);
	RUN_TEST_CASE(coap, connection_id_equal_different_bstr);
	RUN_TEST_CASE(coap, connection_id_equal_different_bstr_length);
	RUN_TEST_CASE(coap, connection_id_equal_different_type);
	RUN_TEST_CASE(coap, connection_id_equal_null_first);
	RUN_TEST_CASE(coap, connection_id_equal_null_second);
	RUN_TEST_CASE(coap, connection_id_equal_both_null);
	RUN_TEST_CASE(coap, prepend_flow_success);
	RUN_TEST_CASE(coap, prepend_flow_null_fields);
	RUN_TEST_CASE(coap, prepend_flow_null_buffer);
	RUN_TEST_CASE(coap, prepend_flow_buffer_too_small);
	RUN_TEST_CASE(coap, prepend_connection_id_int_success);
	RUN_TEST_CASE(coap, prepend_connection_id_bstr_success);
	RUN_TEST_CASE(coap, prepend_connection_id_null_fields);
	RUN_TEST_CASE(coap, prepend_connection_id_null_conn_id);
	RUN_TEST_CASE(coap, prepend_connection_id_null_buffer);
	RUN_TEST_CASE(coap, prepend_connection_id_bstr_zero_length);
	RUN_TEST_CASE(coap, prepend_recalculate_size_success);
	RUN_TEST_CASE(coap, prepend_recalculate_size_null_fields);
	RUN_TEST_CASE(coap, prepend_recalculate_size_null_buffer);
	RUN_TEST_CASE(coap, prepend_recalculate_size_zero_buffer_size);
	RUN_TEST_CASE(coap, prepend_recalculate_size_null_message_ptr);
	RUN_TEST_CASE(coap, prepend_recalculate_size_zero_message_size);
	RUN_TEST_CASE(coap, prepend_recalculate_size_total_exceeds_buffer);
	RUN_TEST_CASE(coap, extract_flow_info_forward_flow);
	RUN_TEST_CASE(coap, extract_flow_info_reverse_flow);
	RUN_TEST_CASE(coap, extract_flow_info_no_flow_indicator);
	RUN_TEST_CASE(coap, extract_flow_info_null_fields);
	RUN_TEST_CASE(coap, extract_flow_info_single_byte_buffer);
	RUN_TEST_CASE(coap, extract_connection_id_int_success);
	RUN_TEST_CASE(coap, extract_connection_id_bstr_success);
	RUN_TEST_CASE(coap, extract_connection_id_null_fields);
	RUN_TEST_CASE(coap, extract_connection_id_null_buffer);
	RUN_TEST_CASE(coap, extract_connection_id_zero_buffer_size);
	RUN_TEST_CASE(coap, prepend_and_extract_flow_roundtrip);
	RUN_TEST_CASE(coap, prepend_and_extract_connection_id_roundtrip);
	RUN_TEST_CASE(coap, prepend_recalculate_size_ptr_before_buffer);
	RUN_TEST_CASE(coap, prepend_recalculate_size_ptr_past_buffer);
	RUN_TEST_CASE(coap, prepend_connection_id_invalid_type);
	RUN_TEST_CASE(coap, extract_connection_id_invalid_cbor);
	RUN_TEST_CASE(coap, extract_connection_id_bstr_too_long);
}
