/**
 * \file    test_helpers.c
 * \author  Kamil Kielbasa
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

TEST_GROUP(helpers);

TEST_SETUP(helpers)
{
}

TEST_TEAR_DOWN(helpers)
{
}

/* Connection ID Utilities Tests ------------------------------------------- */

/**
 * @scenario  edhoc_connection_id_equal with same one-byte integer CIDs.
 * @env       None.
 * @action    Compare two connection IDs with same int_value (5).
 * @expected  Returns true (IDs are equal).
 */
TEST(helpers, connection_id_equal_same_int)
{
	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER, .int_value = 5
	};
	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER, .int_value = 5
	};

	TEST_ASSERT_TRUE(edhoc_connection_id_equal(&conn_id_1, &conn_id_2));
}

/**
 * @scenario  edhoc_connection_id_equal with different one-byte integer CIDs.
 * @env       None.
 * @action    Compare two connection IDs with different int_values (5 vs 10).
 * @expected  Returns false (IDs are not equal).
 */
TEST(helpers, connection_id_equal_different_int)
{
	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER, .int_value = 5
	};
	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER, .int_value = 10
	};

	TEST_ASSERT_FALSE(edhoc_connection_id_equal(&conn_id_1, &conn_id_2));
}

/**
 * @scenario  edhoc_connection_id_equal with same byte string CIDs.
 * @env       None.
 * @action    Compare two connection IDs with same bstr_value and length.
 * @expected  Returns true (IDs are equal).
 */
TEST(helpers, connection_id_equal_same_bstr)
{
	uint8_t bstr1[] = { 0x01, 0x02, 0x03 };
	uint8_t bstr2[] = { 0x01, 0x02, 0x03 };

	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING, .bstr_length = 3
	};
	memcpy(conn_id_1.bstr_value, bstr1, 3);

	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING, .bstr_length = 3
	};
	memcpy(conn_id_2.bstr_value, bstr2, 3);

	TEST_ASSERT_TRUE(edhoc_connection_id_equal(&conn_id_1, &conn_id_2));
}

/**
 * @scenario  edhoc_connection_id_equal with different byte string CIDs.
 * @env       None.
 * @action    Compare two connection IDs with same length but different bstr_value.
 * @expected  Returns false (IDs are not equal).
 */
TEST(helpers, connection_id_equal_different_bstr)
{
	uint8_t bstr1[] = { 0x01, 0x02, 0x03 };
	uint8_t bstr2[] = { 0x01, 0x02, 0x04 };

	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING, .bstr_length = 3
	};
	memcpy(conn_id_1.bstr_value, bstr1, 3);

	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING, .bstr_length = 3
	};
	memcpy(conn_id_2.bstr_value, bstr2, 3);

	TEST_ASSERT_FALSE(edhoc_connection_id_equal(&conn_id_1, &conn_id_2));
}

/**
 * @scenario  edhoc_connection_id_equal with different byte string lengths.
 * @env       None.
 * @action    Compare two connection IDs with different bstr_length (3 vs 2).
 * @expected  Returns false (IDs are not equal).
 */
TEST(helpers, connection_id_equal_different_bstr_length)
{
	uint8_t bstr1[] = { 0x01, 0x02, 0x03 };
	uint8_t bstr2[] = { 0x01, 0x02 };

	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING, .bstr_length = 3
	};
	memcpy(conn_id_1.bstr_value, bstr1, 3);

	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING, .bstr_length = 2
	};
	memcpy(conn_id_2.bstr_value, bstr2, 2);

	TEST_ASSERT_FALSE(edhoc_connection_id_equal(&conn_id_1, &conn_id_2));
}

/**
 * @scenario  edhoc_connection_id_equal with different encode types.
 * @env       None.
 * @action    Compare one-byte integer CID with byte string CID (same value 5).
 * @expected  Returns false (IDs are not equal).
 */
TEST(helpers, connection_id_equal_different_type)
{
	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER, .int_value = 5
	};
	uint8_t bstr[] = { 0x05 };
	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING, .bstr_length = 1
	};
	memcpy(conn_id_2.bstr_value, bstr, 1);

	TEST_ASSERT_FALSE(edhoc_connection_id_equal(&conn_id_1, &conn_id_2));
}

/**
 * @scenario  edhoc_connection_id_equal with NULL first argument.
 * @env       None.
 * @action    Call edhoc_connection_id_equal(NULL, &conn_id_2).
 * @expected  Returns false.
 */
TEST(helpers, connection_id_equal_null_first)
{
	struct edhoc_connection_id conn_id_2 = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER, .int_value = 5
	};

	TEST_ASSERT_FALSE(edhoc_connection_id_equal(NULL, &conn_id_2));
}

/**
 * @scenario  edhoc_connection_id_equal with NULL second argument.
 * @env       None.
 * @action    Call edhoc_connection_id_equal(&conn_id_1, NULL).
 * @expected  Returns false.
 */
TEST(helpers, connection_id_equal_null_second)
{
	struct edhoc_connection_id conn_id_1 = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER, .int_value = 5
	};

	TEST_ASSERT_FALSE(edhoc_connection_id_equal(&conn_id_1, NULL));
}

/**
 * @scenario  edhoc_connection_id_equal with both arguments NULL.
 * @env       None.
 * @action    Call edhoc_connection_id_equal(NULL, NULL).
 * @expected  Returns false.
 */
TEST(helpers, connection_id_equal_both_null)
{
	TEST_ASSERT_FALSE(edhoc_connection_id_equal(NULL, NULL));
}

/* Buffer Prepend Tests ---------------------------------------------------- */

/**
 * @scenario  edhoc_prepend_flow prepends flow indicator (CBOR true) to buffer.
 * @env       Buffer with edhoc_message_ptr at start.
 * @action    Call edhoc_prepend_flow(&prepended_fields).
 * @expected  Returns EDHOC_SUCCESS; buffer[0] is EDHOC_CBOR_TRUE; ptr updated.
 */
TEST(helpers, prepend_flow_success)
{
	uint8_t buffer[100] = { 0 };
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
	TEST_ASSERT_EQUAL(sizeof(buffer) - 1,
			  prepended_fields.edhoc_message_size);
}

/**
 * @scenario  edhoc_prepend_flow with NULL prepended_fields.
 * @env       None.
 * @action    Call edhoc_prepend_flow(NULL).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, prepend_flow_null_fields)
{
	int ret = edhoc_prepend_flow(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_prepend_flow with NULL buffer.
 * @env       prepended_fields with buffer = NULL.
 * @action    Call edhoc_prepend_flow(&prepended_fields).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, prepend_flow_null_buffer)
{
	struct edhoc_prepended_fields prepended_fields = { .buffer = NULL,
							   .buffer_size = 100 };

	int ret = edhoc_prepend_flow(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_prepend_flow with zero-size buffer.
 * @env       prepended_fields with buffer_size = 0.
 * @action    Call edhoc_prepend_flow(&prepended_fields).
 * @expected  Returns EDHOC_ERROR_BUFFER_TOO_SMALL.
 */
TEST(helpers, prepend_flow_buffer_too_small)
{
	uint8_t buffer[1] = { 0 };
	struct edhoc_prepended_fields prepended_fields = { .buffer = buffer,
							   .buffer_size = 0 };

	int ret = edhoc_prepend_flow(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

/**
 * @scenario  edhoc_prepend_connection_id with one-byte integer CID.
 * @env       Buffer and prepended_fields; CID with int_value = 5.
 * @action    Call edhoc_prepend_connection_id(&prepended_fields, &conn_id).
 * @expected  Returns EDHOC_SUCCESS; buffer[0] is 5; ptr and size updated.
 */
TEST(helpers, prepend_connection_id_int_success)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value =
			5 /* Use value in valid CBOR one-byte integer range (-24 to 23) */
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
	TEST_ASSERT_EQUAL(sizeof(buffer) - 1,
			  prepended_fields.edhoc_message_size);
}

/**
 * @scenario  edhoc_prepend_connection_id with byte string CID.
 * @env       Buffer and prepended_fields; CID with 3-byte bstr.
 * @action    Call edhoc_prepend_connection_id(&prepended_fields, &conn_id).
 * @expected  Returns EDHOC_SUCCESS; CBOR byte string 0x43 + data; ptr updated.
 */
TEST(helpers, prepend_connection_id_bstr_success)
{
	uint8_t buffer[100] = { 0 };
	uint8_t cid_bstr[] = { 0x01, 0x02, 0x03 };
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING, .bstr_length = 3
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

/**
 * @scenario  edhoc_prepend_connection_id with NULL prepended_fields.
 * @env       None.
 * @action    Call edhoc_prepend_connection_id(NULL, &conn_id).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, prepend_connection_id_null_fields)
{
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER, .int_value = 5
	};

	int ret = edhoc_prepend_connection_id(NULL, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_prepend_connection_id with NULL connection ID.
 * @env       Valid prepended_fields.
 * @action    Call edhoc_prepend_connection_id(&prepended_fields, NULL).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, prepend_connection_id_null_conn_id)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer, .buffer_size = sizeof(buffer)
	};

	int ret = edhoc_prepend_connection_id(&prepended_fields, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_prepend_connection_id with NULL buffer.
 * @env       prepended_fields with buffer = NULL.
 * @action    Call edhoc_prepend_connection_id(&prepended_fields, &conn_id).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, prepend_connection_id_null_buffer)
{
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER, .int_value = 5
	};
	struct edhoc_prepended_fields prepended_fields = { .buffer = NULL,
							   .buffer_size = 100 };

	int ret = edhoc_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_prepend_connection_id with zero-length byte string CID.
 * @env       prepended_fields with buffer; CID with bstr_length = 0.
 * @action    Call edhoc_prepend_connection_id(&prepended_fields, &conn_id).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, prepend_connection_id_bstr_zero_length)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING, .bstr_length = 0
	};
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer, .buffer_size = sizeof(buffer)
	};

	int ret = edhoc_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_prepend_recalculate_size computes total buffer size.
 * @env       prepended_fields with message_ptr at buffer+5, message_size 10.
 * @action    Call edhoc_prepend_recalculate_size(&prepended_fields).
 * @expected  Returns EDHOC_SUCCESS; buffer_size becomes 15.
 */
TEST(helpers, prepend_recalculate_size_success)
{
	uint8_t buffer[100] = { 0 };
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

/**
 * @scenario  edhoc_prepend_recalculate_size with NULL prepended_fields.
 * @env       None.
 * @action    Call edhoc_prepend_recalculate_size(NULL).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, prepend_recalculate_size_null_fields)
{
	int ret = edhoc_prepend_recalculate_size(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_prepend_recalculate_size with NULL buffer.
 * @env       prepended_fields with buffer = NULL.
 * @action    Call edhoc_prepend_recalculate_size(&prepended_fields).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, prepend_recalculate_size_null_buffer)
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

/**
 * @scenario  edhoc_prepend_recalculate_size with zero buffer_size.
 * @env       prepended_fields with buffer_size = 0.
 * @action    Call edhoc_prepend_recalculate_size(&prepended_fields).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, prepend_recalculate_size_zero_buffer_size)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = 0,
		.edhoc_message_ptr = buffer + 5,
		.edhoc_message_size = 10
	};

	int ret = edhoc_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_prepend_recalculate_size with NULL edhoc_message_ptr.
 * @env       prepended_fields with edhoc_message_ptr = NULL.
 * @action    Call edhoc_prepend_recalculate_size(&prepended_fields).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, prepend_recalculate_size_null_message_ptr)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = NULL,
		.edhoc_message_size = 10
	};

	int ret = edhoc_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_prepend_recalculate_size with zero edhoc_message_size.
 * @env       prepended_fields with edhoc_message_size = 0.
 * @action    Call edhoc_prepend_recalculate_size(&prepended_fields).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, prepend_recalculate_size_zero_message_size)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer + 5,
		.edhoc_message_size = 0
	};

	int ret = edhoc_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_prepend_recalculate_size when total exceeds buffer.
 * @env       prepended_fields with buffer_size 10, message_ptr at +5, size 10.
 * @action    Call edhoc_prepend_recalculate_size(&prepended_fields).
 * @expected  Returns EDHOC_ERROR_BUFFER_TOO_SMALL.
 */
TEST(helpers, prepend_recalculate_size_total_exceeds_buffer)
{
	uint8_t buffer[10] = { 0 };
	struct edhoc_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer + 5,
		.edhoc_message_size = 10 /* 5 + 10 = 15 > 10 */
	};

	int ret = edhoc_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

/* Buffer Extract Tests ---------------------------------------------------- */

/**
 * @scenario  edhoc_extract_flow_info detects forward flow (CBOR true).
 * @env       Buffer starting with EDHOC_CBOR_TRUE.
 * @action    Call edhoc_extract_flow_info(&extracted_fields).
 * @expected  Returns EDHOC_SUCCESS; is_forward_flow true; ptr and size updated.
 */
TEST(helpers, extract_flow_info_forward_flow)
{
	uint8_t buffer[] = { EDHOC_CBOR_TRUE, 0x01, 0x02, 0x03 };
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
	TEST_ASSERT_EQUAL(sizeof(buffer) - 1,
			  extracted_fields.edhoc_message_size);
}

/**
 * @scenario  edhoc_extract_flow_info detects reverse flow (no CBOR true).
 * @env       extracted_fields with NULL buffer (no flow indicator).
 * @action    Call edhoc_extract_flow_info(&extracted_fields).
 * @expected  Returns EDHOC_SUCCESS; is_reverse_flow true.
 */
TEST(helpers, extract_flow_info_reverse_flow)
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

/**
 * @scenario  edhoc_extract_flow_info with no flow indicator (first byte not CBOR true).
 * @env       Buffer starting with 0x01 (no flow indicator).
 * @action    Call edhoc_extract_flow_info(&extracted_fields).
 * @expected  Returns EDHOC_SUCCESS; both flow flags false.
 */
TEST(helpers, extract_flow_info_no_flow_indicator)
{
	uint8_t buffer[] = { 0x01, 0x02, 0x03 };
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

/**
 * @scenario  edhoc_extract_flow_info with NULL extracted_fields.
 * @env       None.
 * @action    Call edhoc_extract_flow_info(NULL).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, extract_flow_info_null_fields)
{
	int ret = edhoc_extract_flow_info(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_extract_flow_info with single-byte buffer (CBOR true).
 * @env       Buffer of size 1 containing EDHOC_CBOR_TRUE.
 * @action    Call edhoc_extract_flow_info(&extracted_fields).
 * @expected  Returns EDHOC_SUCCESS; flow flags false (no message after).
 */
TEST(helpers, extract_flow_info_single_byte_buffer)
{
	uint8_t buffer[] = { EDHOC_CBOR_TRUE };
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

/**
 * @scenario  edhoc_extract_connection_id extracts one-byte integer CID.
 * @env       Buffer with single byte 0x05 (CBOR one-byte integer 5).
 * @action    Call edhoc_extract_connection_id(&extracted_fields).
 * @expected  Returns EDHOC_SUCCESS; encode_type ONE_BYTE_INTEGER, int_value 5.
 */
TEST(helpers, extract_connection_id_int_success)
{
	/* Use value 5 which is in valid CBOR one-byte integer range (-24 to 23) where raw byte is valid CBOR */
	uint8_t buffer[] = {
		0x05
	}; /* Integer 5 (valid CBOR one-byte integer) */
	struct edhoc_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	int ret = edhoc_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
			  extracted_fields.extracted_conn_id.encode_type);
	TEST_ASSERT_EQUAL(5, extracted_fields.extracted_conn_id.int_value);
}

/**
 * @scenario  edhoc_extract_connection_id extracts byte string CID.
 * @env       Buffer with CBOR byte string 0x43 0x01 0x02 0x03.
 * @action    Call edhoc_extract_connection_id(&extracted_fields).
 * @expected  Returns EDHOC_SUCCESS; encode_type BYTE_STRING; bstr_length 3.
 */
TEST(helpers, extract_connection_id_bstr_success)
{
	uint8_t buffer[] = {
		0x43, 0x01, 0x02, 0x03
	}; /* CBOR byte string: 0x43 (major 2, length 3) + data */
	struct edhoc_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer)
	};

	int ret = edhoc_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_BYTE_STRING,
			  extracted_fields.extracted_conn_id.encode_type);
	TEST_ASSERT_EQUAL(3, extracted_fields.extracted_conn_id.bstr_length);
	TEST_ASSERT_EQUAL(0x01,
			  extracted_fields.extracted_conn_id.bstr_value[0]);
	TEST_ASSERT_EQUAL(0x02,
			  extracted_fields.extracted_conn_id.bstr_value[1]);
	TEST_ASSERT_EQUAL(0x03,
			  extracted_fields.extracted_conn_id.bstr_value[2]);
}

/**
 * @scenario  edhoc_extract_connection_id with NULL extracted_fields.
 * @env       None.
 * @action    Call edhoc_extract_connection_id(NULL).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, extract_connection_id_null_fields)
{
	int ret = edhoc_extract_connection_id(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_extract_connection_id with NULL buffer.
 * @env       extracted_fields with buffer = NULL.
 * @action    Call edhoc_extract_connection_id(&extracted_fields).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, extract_connection_id_null_buffer)
{
	struct edhoc_extracted_fields extracted_fields = { .buffer = NULL,
							   .buffer_size = 0 };

	int ret = edhoc_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  edhoc_extract_connection_id with zero buffer_size.
 * @env       extracted_fields with buffer_size = 0.
 * @action    Call edhoc_extract_connection_id(&extracted_fields).
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, extract_connection_id_zero_buffer_size)
{
	uint8_t buffer[] = { 0x2A };
	struct edhoc_extracted_fields extracted_fields = { .buffer = buffer,
							   .buffer_size = 0 };

	int ret = edhoc_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/* Integration Tests ------------------------------------------------------- */

/**
 * @scenario  Roundtrip: prepend flow then extract flow info.
 * @env       Empty buffer.
 * @action    Call edhoc_prepend_flow, then edhoc_extract_flow_info.
 * @expected  Both succeed; is_forward_flow true after extract.
 */
TEST(helpers, prepend_and_extract_flow_roundtrip)
{
	uint8_t buffer[100] = { 0 };
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

/**
 * @scenario  Roundtrip: prepend connection ID then extract.
 * @env       Empty buffer; byte string CID {0x01, 0x02, 0x03}.
 * @action    Call edhoc_prepend_connection_id, then edhoc_extract_connection_id.
 * @expected  Both succeed; extracted CID equals original.
 */
TEST(helpers, prepend_and_extract_connection_id_roundtrip)
{
	uint8_t buffer[100] = { 0 };
	uint8_t cid_bstr[] = { 0x01, 0x02, 0x03 };
	struct edhoc_connection_id conn_id = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING, .bstr_length = 3
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
	TEST_ASSERT_TRUE(edhoc_connection_id_equal(
		&conn_id, &extracted_fields.extracted_conn_id));
}

/**
 * @scenario  recalculate_size with edhoc_message_ptr before buffer start.
 * @env       Manually crafted prepended_fields with ptr before buffer.
 * @action    Call edhoc_prepend_recalculate_size.
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, prepend_recalculate_size_ptr_before_buffer)
{
	uint8_t buf[64] = { 0 };
	struct edhoc_prepended_fields pf = {
		.buffer = &buf[32],
		.buffer_size = 32,
		.edhoc_message_ptr = &buf[0],
		.edhoc_message_size = 16,
	};
	int ret = edhoc_prepend_recalculate_size(&pf);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  recalculate_size with edhoc_message_ptr far past buffer end.
 * @env       Manually crafted prepended_fields with ptr beyond buffer_size.
 * @action    Call edhoc_prepend_recalculate_size.
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, prepend_recalculate_size_ptr_past_buffer)
{
	uint8_t buf[64] = { 0 };
	struct edhoc_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = 32,
		.edhoc_message_ptr = &buf[48],
		.edhoc_message_size = 16,
	};
	int ret = edhoc_prepend_recalculate_size(&pf);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  prepend_connection_id with invalid encode_type.
 * @env       prepended_fields with valid buffer; conn_id with corrupted type.
 * @action    Call edhoc_prepend_connection_id.
 * @expected  Returns EDHOC_ERROR_INVALID_ARGUMENT.
 */
TEST(helpers, prepend_connection_id_invalid_type)
{
	uint8_t buf[64] = { 0 };
	struct edhoc_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = sizeof(buf),
	};
	struct edhoc_connection_id cid = { 0 };
	cid.encode_type = (enum edhoc_connection_id_type)99;
	int ret = edhoc_prepend_connection_id(&pf, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  extract_connection_id with invalid CBOR data.
 * @env       extracted_fields with garbage CBOR bytes.
 * @action    Call edhoc_extract_connection_id.
 * @expected  Returns EDHOC_ERROR_CBOR_FAILURE.
 */
TEST(helpers, extract_connection_id_invalid_cbor)
{
	uint8_t garbage[] = { 0xFF, 0xFF, 0xFF, 0xFF };
	struct edhoc_extracted_fields ef = {
		.buffer = garbage,
		.buffer_size = sizeof(garbage),
	};
	int ret = edhoc_extract_connection_id(&ef);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

/**
 * @scenario  extract_connection_id with byte string CID exceeding max length.
 * @env       Craft CBOR bstr of length > CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID.
 * @action    Call edhoc_extract_connection_id on the crafted buffer.
 * @expected  Returns EDHOC_ERROR_BUFFER_TOO_SMALL.
 */
TEST(helpers, extract_connection_id_bstr_too_long)
{
	/*
	 * CBOR byte string of length 8 (CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID=7):
	 * 0x48 = major type 2 (bstr), additional info 8
	 * followed by 8 bytes of data.
	 */
	uint8_t cbor_bstr[] = { 0x48, 0x01, 0x02, 0x03, 0x04,
				0x05, 0x06, 0x07, 0x08 };
	struct edhoc_extracted_fields ef = {
		.buffer = cbor_bstr,
		.buffer_size = sizeof(cbor_bstr),
	};
	int ret = edhoc_extract_connection_id(&ef);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(helpers)
{
	RUN_TEST_CASE(helpers, connection_id_equal_same_int);
	RUN_TEST_CASE(helpers, connection_id_equal_different_int);
	RUN_TEST_CASE(helpers, connection_id_equal_same_bstr);
	RUN_TEST_CASE(helpers, connection_id_equal_different_bstr);
	RUN_TEST_CASE(helpers, connection_id_equal_different_bstr_length);
	RUN_TEST_CASE(helpers, connection_id_equal_different_type);
	RUN_TEST_CASE(helpers, connection_id_equal_null_first);
	RUN_TEST_CASE(helpers, connection_id_equal_null_second);
	RUN_TEST_CASE(helpers, connection_id_equal_both_null);
	RUN_TEST_CASE(helpers, prepend_flow_success);
	RUN_TEST_CASE(helpers, prepend_flow_null_fields);
	RUN_TEST_CASE(helpers, prepend_flow_null_buffer);
	RUN_TEST_CASE(helpers, prepend_flow_buffer_too_small);
	RUN_TEST_CASE(helpers, prepend_connection_id_int_success);
	RUN_TEST_CASE(helpers, prepend_connection_id_bstr_success);
	RUN_TEST_CASE(helpers, prepend_connection_id_null_fields);
	RUN_TEST_CASE(helpers, prepend_connection_id_null_conn_id);
	RUN_TEST_CASE(helpers, prepend_connection_id_null_buffer);
	RUN_TEST_CASE(helpers, prepend_connection_id_bstr_zero_length);
	RUN_TEST_CASE(helpers, prepend_recalculate_size_success);
	RUN_TEST_CASE(helpers, prepend_recalculate_size_null_fields);
	RUN_TEST_CASE(helpers, prepend_recalculate_size_null_buffer);
	RUN_TEST_CASE(helpers, prepend_recalculate_size_zero_buffer_size);
	RUN_TEST_CASE(helpers, prepend_recalculate_size_null_message_ptr);
	RUN_TEST_CASE(helpers, prepend_recalculate_size_zero_message_size);
	RUN_TEST_CASE(helpers, prepend_recalculate_size_total_exceeds_buffer);
	RUN_TEST_CASE(helpers, extract_flow_info_forward_flow);
	RUN_TEST_CASE(helpers, extract_flow_info_reverse_flow);
	RUN_TEST_CASE(helpers, extract_flow_info_no_flow_indicator);
	RUN_TEST_CASE(helpers, extract_flow_info_null_fields);
	RUN_TEST_CASE(helpers, extract_flow_info_single_byte_buffer);
	RUN_TEST_CASE(helpers, extract_connection_id_int_success);
	RUN_TEST_CASE(helpers, extract_connection_id_bstr_success);
	RUN_TEST_CASE(helpers, extract_connection_id_null_fields);
	RUN_TEST_CASE(helpers, extract_connection_id_null_buffer);
	RUN_TEST_CASE(helpers, extract_connection_id_zero_buffer_size);
	RUN_TEST_CASE(helpers, prepend_and_extract_flow_roundtrip);
	RUN_TEST_CASE(helpers, prepend_and_extract_connection_id_roundtrip);
	RUN_TEST_CASE(helpers, prepend_recalculate_size_ptr_before_buffer);
	RUN_TEST_CASE(helpers, prepend_recalculate_size_ptr_past_buffer);
	RUN_TEST_CASE(helpers, prepend_connection_id_invalid_type);
	RUN_TEST_CASE(helpers, extract_connection_id_invalid_cbor);
	RUN_TEST_CASE(helpers, extract_connection_id_bstr_too_long);
}
