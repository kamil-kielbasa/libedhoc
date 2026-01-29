/**
 * \file    module_test_edhoc_helpers.c
 * \author  Assa Abloy
 * \brief   Module tests for EDHOC helpers API.
 * \version 1.0
 * \date    2026-01-28
 * 
 * \copyright Copyright (c) 2026
 * 
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC headers: */
#define EDHOC_ALLOW_PRIVATE_ACCESS
#include <edhoc.h>
#include "edhoc_helpers.h"

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

TEST_GROUP(edhoc_helpers);

TEST_SETUP(edhoc_helpers)
{
}

TEST_TEAR_DOWN(edhoc_helpers)
{
}

/* Connection ID Utilities Tests ------------------------------------------- */

TEST(edhoc_helpers, connection_id_equal_same_int)
{
	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5
	};
	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5
	};

	TEST_ASSERT_TRUE(edhoc_connection_id_equal(&conn_id_1, &conn_id_2));
}

TEST(edhoc_helpers, connection_id_equal_different_int)
{
	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5
	};
	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 10
	};

	TEST_ASSERT_FALSE(edhoc_connection_id_equal(&conn_id_1, &conn_id_2));
}

TEST(edhoc_helpers, connection_id_equal_same_bstr)
{
	uint8_t bstr1[] = {0x01, 0x02, 0x03};
	uint8_t bstr2[] = {0x01, 0x02, 0x03};
	
	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3
	};
	memcpy(conn_id_1.bstr_value, bstr1, 3);
	
	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3
	};
	memcpy(conn_id_2.bstr_value, bstr2, 3);

	TEST_ASSERT_TRUE(edhoc_connection_id_equal(&conn_id_1, &conn_id_2));
}

TEST(edhoc_helpers, connection_id_equal_different_bstr)
{
	uint8_t bstr1[] = {0x01, 0x02, 0x03};
	uint8_t bstr2[] = {0x01, 0x02, 0x04};
	
	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3
	};
	memcpy(conn_id_1.bstr_value, bstr1, 3);
	
	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3
	};
	memcpy(conn_id_2.bstr_value, bstr2, 3);

	TEST_ASSERT_FALSE(edhoc_connection_id_equal(&conn_id_1, &conn_id_2));
}

TEST(edhoc_helpers, connection_id_equal_different_bstr_length)
{
	uint8_t bstr1[] = {0x01, 0x02, 0x03};
	uint8_t bstr2[] = {0x01, 0x02};
	
	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3
	};
	memcpy(conn_id_1.bstr_value, bstr1, 3);
	
	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 2
	};
	memcpy(conn_id_2.bstr_value, bstr2, 2);

	TEST_ASSERT_FALSE(edhoc_connection_id_equal(&conn_id_1, &conn_id_2));
}

TEST(edhoc_helpers, connection_id_equal_different_type)
{
	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5
	};
	uint8_t bstr[] = {0x05};
	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 1
	};
	memcpy(conn_id_2.bstr_value, bstr, 1);

	TEST_ASSERT_FALSE(edhoc_connection_id_equal(&conn_id_1, &conn_id_2));
}

TEST(edhoc_helpers, connection_id_equal_null_first)
{
	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5
	};

	TEST_ASSERT_FALSE(edhoc_connection_id_equal(NULL, &conn_id_2));
}

TEST(edhoc_helpers, connection_id_equal_null_second)
{
	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5
	};

	TEST_ASSERT_FALSE(edhoc_connection_id_equal(&conn_id_1, NULL));
}

TEST(edhoc_helpers, connection_id_equal_both_null)
{
	TEST_ASSERT_FALSE(edhoc_connection_id_equal(NULL, NULL));
}

/* Buffer Prepend Tests ---------------------------------------------------- */

TEST(edhoc_helpers, prepend_flow_success)
{
	uint8_t buffer[100] = {0};
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	int ret = edhoc_prepend_flow(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_CBOR_TRUE, buffer[0]);
	TEST_ASSERT_EQUAL_PTR(buffer + 1, prepended_fields.edhoc_message_ptr);
	TEST_ASSERT_EQUAL(sizeof(buffer) - 1, prepended_fields.edhoc_message_size);
}

TEST(edhoc_helpers, prepend_flow_null_fields)
{
	int ret = edhoc_prepend_flow(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(edhoc_helpers, prepend_flow_null_buffer)
{
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = NULL,
		.buffer_size = 100
	};

	int ret = edhoc_prepend_flow(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(edhoc_helpers, prepend_flow_buffer_too_small)
{
	uint8_t buffer[0] = {};
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = 0
	};

	int ret = edhoc_prepend_flow(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(edhoc_helpers, prepend_connection_id_int_success)
{
	uint8_t buffer[100] = {0};
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5  /* Use value in valid CBOR one-byte integer range (-24 to 23) */
	};
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	int ret = edhoc_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(5, buffer[0]);
	TEST_ASSERT_EQUAL_PTR(buffer + 1, prepended_fields.edhoc_message_ptr);
	TEST_ASSERT_EQUAL(sizeof(buffer) - 1, prepended_fields.edhoc_message_size);
}

TEST(edhoc_helpers, prepend_connection_id_bstr_success)
{
	uint8_t buffer[100] = {0};
	uint8_t cid_bstr[] = {0x01, 0x02, 0x03};
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3
	};
	memcpy(conn_id.bstr_value, cid_bstr, 3);
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	int ret = edhoc_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	/* CBOR byte string encoding: 0x43 (major type 2, length 3) followed by data */
	TEST_ASSERT_EQUAL(0x43, buffer[0]);
	TEST_ASSERT_EQUAL(0x01, buffer[1]);
	TEST_ASSERT_EQUAL(0x02, buffer[2]);
	TEST_ASSERT_EQUAL(0x03, buffer[3]);
	TEST_ASSERT_EQUAL_PTR(buffer + 4, prepended_fields.edhoc_message_ptr);
}

TEST(edhoc_helpers, prepend_connection_id_null_fields)
{
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5
	};

	int ret = edhoc_prepend_connection_id(NULL, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(edhoc_helpers, prepend_connection_id_null_conn_id)
{
	uint8_t buffer[100] = {0};
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer)
	};

	int ret = edhoc_prepend_connection_id(&prepended_fields, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(edhoc_helpers, prepend_connection_id_null_buffer)
{
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5
	};
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = NULL,
		.buffer_size = 100
	};

	int ret = edhoc_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(edhoc_helpers, prepend_connection_id_bstr_zero_length)
{
	uint8_t buffer[100] = {0};
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 0
	};
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer)
	};

	int ret = edhoc_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(edhoc_helpers, prepend_recalculate_size_success)
{
	uint8_t buffer[100] = {0};
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer + 5,
		.edhoc_message_size = 10
	};

	int ret = edhoc_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(15, prepended_fields.buffer_size);
}

TEST(edhoc_helpers, prepend_recalculate_size_null_fields)
{
	int ret = edhoc_prepend_recalculate_size(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(edhoc_helpers, prepend_recalculate_size_null_buffer)
{
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = NULL,
		.buffer_size = 100,
		.edhoc_message_ptr = (uint8_t *)0x1000,
		.edhoc_message_size = 10
	};

	int ret = edhoc_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(edhoc_helpers, prepend_recalculate_size_zero_buffer_size)
{
	uint8_t buffer[100] = {0};
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = 0,
		.edhoc_message_ptr = buffer + 5,
		.edhoc_message_size = 10
	};

	int ret = edhoc_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(edhoc_helpers, prepend_recalculate_size_null_message_ptr)
{
	uint8_t buffer[100] = {0};
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = NULL,
		.edhoc_message_size = 10
	};

	int ret = edhoc_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(edhoc_helpers, prepend_recalculate_size_zero_message_size)
{
	uint8_t buffer[100] = {0};
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer + 5,
		.edhoc_message_size = 0
	};

	int ret = edhoc_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(edhoc_helpers, prepend_recalculate_size_total_exceeds_buffer)
{
	uint8_t buffer[10] = {0};
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer + 5,
		.edhoc_message_size = 10  /* 5 + 10 = 15 > 10 */
	};

	int ret = edhoc_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

/* Buffer Extract Tests ---------------------------------------------------- */

TEST(edhoc_helpers, extract_flow_info_forward_flow)
{
	uint8_t buffer[] = {EDHOC_CBOR_TRUE, 0x01, 0x02, 0x03};
	struct edhoc_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	int ret = edhoc_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(extracted_fields.is_forward_flow);
	TEST_ASSERT_FALSE(extracted_fields.is_reverse_flow);
	TEST_ASSERT_EQUAL_PTR(buffer + 1, extracted_fields.edhoc_message_ptr);
	TEST_ASSERT_EQUAL(sizeof(buffer) - 1, extracted_fields.edhoc_message_size);
}

TEST(edhoc_helpers, extract_flow_info_reverse_flow)
{
	struct edhoc_extracted_fields extracted_fields = {
		.buffer = NULL,
		.buffer_size = 0,
		.edhoc_message_ptr = NULL,
		.edhoc_message_size = 0
	};

	int ret = edhoc_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_FALSE(extracted_fields.is_forward_flow);
	TEST_ASSERT_TRUE(extracted_fields.is_reverse_flow);
}

TEST(edhoc_helpers, extract_flow_info_no_flow_indicator)
{
	uint8_t buffer[] = {0x01, 0x02, 0x03};
	struct edhoc_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	int ret = edhoc_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_FALSE(extracted_fields.is_forward_flow);
	TEST_ASSERT_FALSE(extracted_fields.is_reverse_flow);
}

TEST(edhoc_helpers, extract_flow_info_null_fields)
{
	int ret = edhoc_extract_flow_info(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(edhoc_helpers, extract_flow_info_single_byte_buffer)
{
	uint8_t buffer[] = {EDHOC_CBOR_TRUE};
	struct edhoc_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = 1,
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = 1
	};

	int ret = edhoc_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	/* Single byte buffer with CBOR_TRUE is not considered forward flow (needs size > 1) */
	TEST_ASSERT_FALSE(extracted_fields.is_forward_flow);
	TEST_ASSERT_FALSE(extracted_fields.is_reverse_flow);
}

TEST(edhoc_helpers, extract_connection_id_int_success)
{
	/* Use value 5 which is in valid CBOR one-byte integer range (-24 to 23) where raw byte is valid CBOR */
	uint8_t buffer[] = {0x05};  /* Integer 5 (valid CBOR one-byte integer) */
	struct edhoc_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	int ret = edhoc_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_ONE_BYTE_INTEGER, extracted_fields.extracted_conn_id.encode_type);
	TEST_ASSERT_EQUAL(5, extracted_fields.extracted_conn_id.int_value);
}

TEST(edhoc_helpers, extract_connection_id_bstr_success)
{
	uint8_t buffer[] = {0x43, 0x01, 0x02, 0x03};  /* CBOR byte string: 0x43 (major 2, length 3) + data */
	struct edhoc_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	int ret = edhoc_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_BYTE_STRING, extracted_fields.extracted_conn_id.encode_type);
	TEST_ASSERT_EQUAL(3, extracted_fields.extracted_conn_id.bstr_length);
	TEST_ASSERT_EQUAL(0x01, extracted_fields.extracted_conn_id.bstr_value[0]);
	TEST_ASSERT_EQUAL(0x02, extracted_fields.extracted_conn_id.bstr_value[1]);
	TEST_ASSERT_EQUAL(0x03, extracted_fields.extracted_conn_id.bstr_value[2]);
}

TEST(edhoc_helpers, extract_connection_id_null_fields)
{
	int ret = edhoc_extract_connection_id(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(edhoc_helpers, extract_connection_id_null_buffer)
{
	struct edhoc_extracted_fields extracted_fields = {
		.buffer = NULL,
		.buffer_size = 0
	};

	int ret = edhoc_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(edhoc_helpers, extract_connection_id_zero_buffer_size)
{
	uint8_t buffer[] = {0x2A};
	struct edhoc_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = 0
	};

	int ret = edhoc_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/* Integration Tests ------------------------------------------------------- */

TEST(edhoc_helpers, prepend_and_extract_flow_roundtrip)
{
	uint8_t buffer[100] = {0};
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	/* Prepend flow */
	int ret = edhoc_prepend_flow(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Extract flow */
	struct edhoc_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = prepended_fields.buffer_size,
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = prepended_fields.buffer_size
	};
	ret = edhoc_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(extracted_fields.is_forward_flow);
}

TEST(edhoc_helpers, prepend_and_extract_connection_id_roundtrip)
{
	uint8_t buffer[100] = {0};
	uint8_t cid_bstr[] = {0x01, 0x02, 0x03};
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 3
	};
	memcpy(conn_id.bstr_value, cid_bstr, 3);
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	/* Prepend connection ID */
	int ret = edhoc_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Extract connection ID */
	struct edhoc_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = prepended_fields.buffer_size,
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = prepended_fields.buffer_size
	};
	ret = edhoc_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(edhoc_connection_id_equal(&conn_id, &extracted_fields.extracted_conn_id));
}

TEST_GROUP_RUNNER(edhoc_helpers)
{
	RUN_TEST_CASE(edhoc_helpers, connection_id_equal_same_int);
	RUN_TEST_CASE(edhoc_helpers, connection_id_equal_different_int);
	RUN_TEST_CASE(edhoc_helpers, connection_id_equal_same_bstr);
	RUN_TEST_CASE(edhoc_helpers, connection_id_equal_different_bstr);
	RUN_TEST_CASE(edhoc_helpers, connection_id_equal_different_bstr_length);
	RUN_TEST_CASE(edhoc_helpers, connection_id_equal_different_type);
	RUN_TEST_CASE(edhoc_helpers, connection_id_equal_null_first);
	RUN_TEST_CASE(edhoc_helpers, connection_id_equal_null_second);
	RUN_TEST_CASE(edhoc_helpers, connection_id_equal_both_null);
	RUN_TEST_CASE(edhoc_helpers, prepend_flow_success);
	RUN_TEST_CASE(edhoc_helpers, prepend_flow_null_fields);
	RUN_TEST_CASE(edhoc_helpers, prepend_flow_null_buffer);
	RUN_TEST_CASE(edhoc_helpers, prepend_flow_buffer_too_small);
	RUN_TEST_CASE(edhoc_helpers, prepend_connection_id_int_success);
	RUN_TEST_CASE(edhoc_helpers, prepend_connection_id_bstr_success);
	RUN_TEST_CASE(edhoc_helpers, prepend_connection_id_null_fields);
	RUN_TEST_CASE(edhoc_helpers, prepend_connection_id_null_conn_id);
	RUN_TEST_CASE(edhoc_helpers, prepend_connection_id_null_buffer);
	RUN_TEST_CASE(edhoc_helpers, prepend_connection_id_bstr_zero_length);
	RUN_TEST_CASE(edhoc_helpers, prepend_recalculate_size_success);
	RUN_TEST_CASE(edhoc_helpers, prepend_recalculate_size_null_fields);
	RUN_TEST_CASE(edhoc_helpers, prepend_recalculate_size_null_buffer);
	RUN_TEST_CASE(edhoc_helpers, prepend_recalculate_size_zero_buffer_size);
	RUN_TEST_CASE(edhoc_helpers, prepend_recalculate_size_null_message_ptr);
	RUN_TEST_CASE(edhoc_helpers, prepend_recalculate_size_zero_message_size);
	RUN_TEST_CASE(edhoc_helpers, prepend_recalculate_size_total_exceeds_buffer);
	RUN_TEST_CASE(edhoc_helpers, extract_flow_info_forward_flow);
	RUN_TEST_CASE(edhoc_helpers, extract_flow_info_reverse_flow);
	RUN_TEST_CASE(edhoc_helpers, extract_flow_info_no_flow_indicator);
	RUN_TEST_CASE(edhoc_helpers, extract_flow_info_null_fields);
	RUN_TEST_CASE(edhoc_helpers, extract_flow_info_single_byte_buffer);
	RUN_TEST_CASE(edhoc_helpers, extract_connection_id_int_success);
	RUN_TEST_CASE(edhoc_helpers, extract_connection_id_bstr_success);
	RUN_TEST_CASE(edhoc_helpers, extract_connection_id_null_fields);
	RUN_TEST_CASE(edhoc_helpers, extract_connection_id_null_buffer);
	RUN_TEST_CASE(edhoc_helpers, extract_connection_id_zero_buffer_size);
	RUN_TEST_CASE(edhoc_helpers, prepend_and_extract_flow_roundtrip);
	RUN_TEST_CASE(edhoc_helpers, prepend_and_extract_connection_id_roundtrip);
}

