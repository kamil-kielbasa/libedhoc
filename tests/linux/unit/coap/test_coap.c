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
#include <edhoc/coap.h>
#include "edhoc_values_internal.h"
#include "edhoc_macros_internal.h"

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
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(coap);

TEST_SETUP(coap)
{
}

TEST_TEAR_DOWN(coap)
{
}

TEST(coap, connection_id_equal_same)
{
	const uint8_t value[] = { 0x01, 0x02, 0x03 };
	const struct edhoc_buffer conn_id_1 = { .value = value,
						.length = ARRAY_SIZE(value) };
	const struct edhoc_buffer conn_id_2 = { .value = value,
						.length = ARRAY_SIZE(value) };

	TEST_ASSERT_TRUE(
		edhoc_coap_connection_id_equal(&conn_id_1, &conn_id_2));
}

TEST(coap, connection_id_equal_different_value)
{
	const uint8_t value_1[] = { 0x01, 0x02, 0x03 };
	const uint8_t value_2[] = { 0x01, 0x02, 0x04 };
	const struct edhoc_buffer conn_id_1 = { .value = value_1,
						.length = ARRAY_SIZE(value_1) };
	const struct edhoc_buffer conn_id_2 = { .value = value_2,
						.length = ARRAY_SIZE(value_2) };

	TEST_ASSERT_FALSE(
		edhoc_coap_connection_id_equal(&conn_id_1, &conn_id_2));
}

TEST(coap, connection_id_equal_different_length)
{
	const uint8_t value[] = { 0x01, 0x02, 0x03 };
	const struct edhoc_buffer conn_id_1 = { .value = value,
						.length = ARRAY_SIZE(value) };
	const struct edhoc_buffer conn_id_2 = {
		.value = value, .length = ARRAY_SIZE(value) - 1
	};

	TEST_ASSERT_FALSE(
		edhoc_coap_connection_id_equal(&conn_id_1, &conn_id_2));
}

TEST(coap, connection_id_equal_empty)
{
	const struct edhoc_buffer conn_id_1 = { 0 };
	const struct edhoc_buffer conn_id_2 = { 0 };

	TEST_ASSERT_TRUE(
		edhoc_coap_connection_id_equal(&conn_id_1, &conn_id_2));
}

TEST(coap, connection_id_equal_null_first)
{
	const uint8_t value[] = { 0x05 };
	const struct edhoc_buffer conn_id_2 = { .value = value,
						.length = ARRAY_SIZE(value) };

	TEST_ASSERT_FALSE(edhoc_coap_connection_id_equal(NULL, &conn_id_2));
}

TEST(coap, connection_id_equal_null_second)
{
	const uint8_t value[] = { 0x05 };
	const struct edhoc_buffer conn_id_1 = { .value = value,
						.length = ARRAY_SIZE(value) };

	TEST_ASSERT_FALSE(edhoc_coap_connection_id_equal(&conn_id_1, NULL));
}

TEST(coap, connection_id_equal_both_null)
{
	TEST_ASSERT_FALSE(edhoc_coap_connection_id_equal(NULL, NULL));
}

TEST(coap, prepend_flow_success)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer),
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
		.buffer = NULL,
		.buffer_size = 100,
	};

	int ret = edhoc_coap_prepend_flow(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_flow_buffer_too_small)
{
	uint8_t buffer[1] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = 0,
	};

	int ret = edhoc_coap_prepend_flow(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(coap, prepend_connection_id_compact)
{
	/* RFC 9528: 3.3.2 - h'2b' is the one byte encoding of -12. */
	uint8_t buffer[100] = { 0 };
	const uint8_t value[] = { 0x2b };
	const struct edhoc_buffer conn_id = { .value = value,
					      .length = ARRAY_SIZE(value) };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer),
	};

	int ret = edhoc_coap_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_HEX8(0x2b, buffer[0]);
	TEST_ASSERT_EQUAL_PTR(buffer + 1, prepended_fields.edhoc_message_ptr);
	TEST_ASSERT_EQUAL(sizeof(buffer) - 1,
			  prepended_fields.edhoc_message_size);
}

TEST(coap, prepend_connection_id_byte_string)
{
	uint8_t buffer[100] = { 0 };
	const uint8_t value[] = { 0xff };
	const struct edhoc_buffer conn_id = { .value = value,
					      .length = ARRAY_SIZE(value) };

	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer),
	};

	int ret = edhoc_coap_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_HEX8(0x41, buffer[0]);
	TEST_ASSERT_EQUAL_HEX8(0xff, buffer[1]);
	TEST_ASSERT_EQUAL_PTR(buffer + 2, prepended_fields.edhoc_message_ptr);
}

TEST(coap, prepend_connection_id_empty)
{
	uint8_t buffer[100] = { 0 };
	const struct edhoc_buffer conn_id = { 0 };

	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer),
	};

	int ret = edhoc_coap_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_HEX8(0x40, buffer[0]);
	TEST_ASSERT_EQUAL_PTR(buffer + 1, prepended_fields.edhoc_message_ptr);
}

TEST(coap, prepend_connection_id_too_large)
{
	uint8_t buffer[100] = { 0 };
	const uint8_t value[CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID + 1] = { 0 };
	const struct edhoc_buffer conn_id = { .value = value,
					      .length = ARRAY_SIZE(value) };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
	};

	int ret = edhoc_coap_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(coap, prepend_connection_id_null_fields)
{
	const uint8_t value[] = { 0x05 };
	const struct edhoc_buffer conn_id = { .value = value,
					      .length = ARRAY_SIZE(value) };

	int ret = edhoc_coap_prepend_connection_id(NULL, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_connection_id_null_conn_id)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
	};

	int ret = edhoc_coap_prepend_connection_id(&prepended_fields, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_connection_id_null_buffer)
{
	const uint8_t value[] = { 0x05 };
	const struct edhoc_buffer conn_id = { .value = value,
					      .length = ARRAY_SIZE(value) };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = NULL,
		.buffer_size = 100,
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
		.edhoc_message_size = 10,
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
		.edhoc_message_size = 10,
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
		.edhoc_message_size = 10,
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
		.edhoc_message_size = 10,
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
		.edhoc_message_size = 0,
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
		.edhoc_message_size = 10, /* 5 + 10 = 15 > 10 */
	};

	int ret = edhoc_coap_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(coap, prepend_recalculate_size_ptr_before_buffer)
{
	uint8_t buffer[64] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = &buffer[32],
		.buffer_size = 32,
		.edhoc_message_ptr = &buffer[0],
		.edhoc_message_size = 16,
	};

	int ret = edhoc_coap_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_recalculate_size_ptr_past_buffer)
{
	uint8_t buffer[64] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = 32,
		.edhoc_message_ptr = &buffer[48],
		.edhoc_message_size = 16,
	};

	int ret = edhoc_coap_prepend_recalculate_size(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, extract_flow_info_forward_flow)
{
	const uint8_t buffer[] = { EDHOC_CBOR_TRUE, 0x01, 0x02, 0x03 };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer),
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
		.edhoc_message_size = 0,
	};

	int ret = edhoc_coap_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_FALSE(extracted_fields.is_forward_flow);
	TEST_ASSERT_TRUE(extracted_fields.is_reverse_flow);
}

TEST(coap, extract_flow_info_no_flow_indicator)
{
	const uint8_t buffer[] = { 0x01, 0x02, 0x03 };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer),
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
	const uint8_t buffer[] = { EDHOC_CBOR_TRUE };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer),
	};

	int ret = edhoc_coap_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* A one-byte CBOR_TRUE payload is not a forward flow (needs size > 1). */
	TEST_ASSERT_FALSE(extracted_fields.is_forward_flow);
	TEST_ASSERT_FALSE(extracted_fields.is_reverse_flow);
}

TEST(coap, extract_connection_id_compact)
{
	/* RFC 9528: 3.3.2 - the CBOR integer -12 stands for the byte string
	 * h'2b', so the identifier is the payload byte itself. */
	const uint8_t buffer[] = { 0x2b };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer),
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_size_t(1, extracted_fields.extracted_conn_id.length);
	TEST_ASSERT_EQUAL_HEX8(0x2b,
			       extracted_fields.extracted_conn_id.value[0]);
}

TEST(coap, extract_connection_id_byte_string)
{
	const uint8_t buffer[] = { 0x43, 0x01, 0x02, 0x03 };
	const uint8_t expected[] = { 0x01, 0x02, 0x03 };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer),
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_size_t(ARRAY_SIZE(expected),
				 extracted_fields.extracted_conn_id.length);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(expected,
				      extracted_fields.extracted_conn_id.value,
				      ARRAY_SIZE(expected));
}

TEST(coap, extract_connection_id_empty)
{
	const uint8_t buffer[] = { 0x40 };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer),
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_size_t(0, extracted_fields.extracted_conn_id.length);
}

TEST(coap, connection_id_survives_prepend_and_extract)
{
	/* Both ends of the compact range plus a value outside it. */
	const uint8_t identifiers[][1] = {
		{ 0x37 }, { 0x17 }, { 0x00 }, { 0xff }
	};

	for (size_t i = 0; i < ARRAY_SIZE(identifiers); ++i) {
		uint8_t buffer[8] = { 0 };
		const struct edhoc_buffer conn_id = {
			.value = identifiers[i],
			.length = ARRAY_SIZE(identifiers[i]),
		};
		struct edhoc_coap_prepended_fields prepended_fields = {
			.buffer = buffer,
			.buffer_size = sizeof(buffer),
			.edhoc_message_ptr = buffer,
			.edhoc_message_size = sizeof(buffer),
		};

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_coap_prepend_connection_id(
					  &prepended_fields, &conn_id));

		struct edhoc_coap_extracted_fields extracted_fields = {
			.buffer = buffer,
			.buffer_size = sizeof(buffer),
			.edhoc_message_ptr = buffer,
			.edhoc_message_size = sizeof(buffer),
		};

		TEST_ASSERT_EQUAL(
			EDHOC_SUCCESS,
			edhoc_coap_extract_connection_id(&extracted_fields));
		TEST_ASSERT_TRUE(edhoc_coap_connection_id_equal(
			&conn_id, &extracted_fields.extracted_conn_id));
	}
}

TEST(coap, extract_connection_id_null_fields)
{
	int ret = edhoc_coap_extract_connection_id(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, extract_connection_id_null_buffer)
{
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = NULL,
		.buffer_size = 0,
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, extract_connection_id_zero_buffer_size)
{
	const uint8_t buffer[] = { 0x2A };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = 0,
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, extract_connection_id_invalid_cbor)
{
	const uint8_t buffer[] = { 0xFF, 0xFF, 0xFF, 0xFF };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);
}

TEST(coap, extract_connection_id_bstr_too_long)
{
	/*
	 * CBOR byte string of length 8 (CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID=7):
	 * 0x48 = major type 2 (bstr), additional info 8, followed by 8 bytes.
	 */
	const uint8_t buffer[] = { 0x48, 0x01, 0x02, 0x03, 0x04,
				   0x05, 0x06, 0x07, 0x08 };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(coap, prepend_and_extract_flow_roundtrip)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.buffer_size = sizeof(buffer),
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = sizeof(buffer),
	};

	int ret = edhoc_coap_prepend_flow(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.buffer_size = prepended_fields.buffer_size,
		.edhoc_message_ptr = buffer,
		.edhoc_message_size = prepended_fields.buffer_size,
	};

	ret = edhoc_coap_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(extracted_fields.is_forward_flow);
}

TEST_GROUP_RUNNER(coap)
{
	RUN_TEST_CASE(coap, connection_id_equal_same);
	RUN_TEST_CASE(coap, connection_id_equal_different_value);
	RUN_TEST_CASE(coap, connection_id_equal_different_length);
	RUN_TEST_CASE(coap, connection_id_equal_empty);
	RUN_TEST_CASE(coap, connection_id_equal_null_first);
	RUN_TEST_CASE(coap, connection_id_equal_null_second);
	RUN_TEST_CASE(coap, connection_id_equal_both_null);

	RUN_TEST_CASE(coap, prepend_flow_success);
	RUN_TEST_CASE(coap, prepend_flow_null_fields);
	RUN_TEST_CASE(coap, prepend_flow_null_buffer);
	RUN_TEST_CASE(coap, prepend_flow_buffer_too_small);

	RUN_TEST_CASE(coap, prepend_connection_id_compact);
	RUN_TEST_CASE(coap, prepend_connection_id_byte_string);
	RUN_TEST_CASE(coap, prepend_connection_id_empty);
	RUN_TEST_CASE(coap, prepend_connection_id_too_large);
	RUN_TEST_CASE(coap, prepend_connection_id_null_fields);
	RUN_TEST_CASE(coap, prepend_connection_id_null_conn_id);
	RUN_TEST_CASE(coap, prepend_connection_id_null_buffer);

	RUN_TEST_CASE(coap, prepend_recalculate_size_success);
	RUN_TEST_CASE(coap, prepend_recalculate_size_null_fields);
	RUN_TEST_CASE(coap, prepend_recalculate_size_null_buffer);
	RUN_TEST_CASE(coap, prepend_recalculate_size_zero_buffer_size);
	RUN_TEST_CASE(coap, prepend_recalculate_size_null_message_ptr);
	RUN_TEST_CASE(coap, prepend_recalculate_size_zero_message_size);
	RUN_TEST_CASE(coap, prepend_recalculate_size_total_exceeds_buffer);
	RUN_TEST_CASE(coap, prepend_recalculate_size_ptr_before_buffer);
	RUN_TEST_CASE(coap, prepend_recalculate_size_ptr_past_buffer);

	RUN_TEST_CASE(coap, extract_flow_info_forward_flow);
	RUN_TEST_CASE(coap, extract_flow_info_reverse_flow);
	RUN_TEST_CASE(coap, extract_flow_info_no_flow_indicator);
	RUN_TEST_CASE(coap, extract_flow_info_null_fields);
	RUN_TEST_CASE(coap, extract_flow_info_single_byte_buffer);

	RUN_TEST_CASE(coap, extract_connection_id_compact);
	RUN_TEST_CASE(coap, extract_connection_id_byte_string);
	RUN_TEST_CASE(coap, extract_connection_id_empty);
	RUN_TEST_CASE(coap, connection_id_survives_prepend_and_extract);
	RUN_TEST_CASE(coap, extract_connection_id_null_fields);
	RUN_TEST_CASE(coap, extract_connection_id_null_buffer);
	RUN_TEST_CASE(coap, extract_connection_id_zero_buffer_size);
	RUN_TEST_CASE(coap, extract_connection_id_invalid_cbor);
	RUN_TEST_CASE(coap, extract_connection_id_bstr_too_long);

	RUN_TEST_CASE(coap, prepend_and_extract_flow_roundtrip);
}
