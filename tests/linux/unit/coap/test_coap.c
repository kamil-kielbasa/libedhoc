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
#include "edhoc_macros_internal.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */

/* RFC 9528: A.2.1 - the EDHOC indicator is CBOR true. */
#define EDHOC_INDICATOR_BYTE ((uint8_t)0xf5)

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
		.capacity = sizeof(buffer),
	};

	int ret = edhoc_coap_prepend_flow(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_HEX8(EDHOC_INDICATOR_BYTE, buffer[0]);
	TEST_ASSERT_EQUAL_size_t(1, prepended_fields.length);
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
		.capacity = 100,
	};

	int ret = edhoc_coap_prepend_flow(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_flow_buffer_too_small)
{
	uint8_t buffer[1] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.capacity = 0,
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
		.capacity = sizeof(buffer),
	};

	int ret = edhoc_coap_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_HEX8(0x2b, buffer[0]);
	TEST_ASSERT_EQUAL_size_t(1, prepended_fields.length);
}

TEST(coap, prepend_connection_id_byte_string)
{
	uint8_t buffer[100] = { 0 };
	const uint8_t value[] = { 0xff };
	const struct edhoc_buffer conn_id = { .value = value,
					      .length = ARRAY_SIZE(value) };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.capacity = sizeof(buffer),
	};

	int ret = edhoc_coap_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_HEX8(0x41, buffer[0]);
	TEST_ASSERT_EQUAL_HEX8(0xff, buffer[1]);
	TEST_ASSERT_EQUAL_size_t(2, prepended_fields.length);
}

TEST(coap, prepend_connection_id_empty)
{
	uint8_t buffer[100] = { 0 };
	const struct edhoc_buffer conn_id = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.capacity = sizeof(buffer),
	};

	int ret = edhoc_coap_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_HEX8(0x40, buffer[0]);
	TEST_ASSERT_EQUAL_size_t(1, prepended_fields.length);
}

TEST(coap, prepend_connection_id_too_large)
{
	uint8_t buffer[100] = { 0 };
	const uint8_t value[CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID + 1] = { 0 };
	const struct edhoc_buffer conn_id = { .value = value,
					      .length = ARRAY_SIZE(value) };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.capacity = sizeof(buffer),
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
		.capacity = sizeof(buffer),
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
		.capacity = 100,
	};

	int ret = edhoc_coap_prepend_connection_id(&prepended_fields, &conn_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, prepend_calls_follow_each_other)
{
	uint8_t buffer[100] = { 0 };
	const uint8_t value[] = { 0x2b };
	const struct edhoc_buffer conn_id = { .value = value,
					      .length = ARRAY_SIZE(value) };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.capacity = sizeof(buffer),
	};

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_coap_prepend_flow(&prepended_fields));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_coap_prepend_connection_id(
						 &prepended_fields, &conn_id));

	TEST_ASSERT_EQUAL_HEX8(EDHOC_INDICATOR_BYTE, buffer[0]);
	TEST_ASSERT_EQUAL_HEX8(0x2b, buffer[1]);
	TEST_ASSERT_EQUAL_size_t(2, prepended_fields.length);
}

TEST(coap, prepend_second_call_reports_a_full_buffer)
{
	uint8_t buffer[1] = { 0 };
	const uint8_t value[] = { 0x2b };
	const struct edhoc_buffer conn_id = { .value = value,
					      .length = ARRAY_SIZE(value) };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.capacity = sizeof(buffer),
	};

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_coap_prepend_flow(&prepended_fields));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL,
			  edhoc_coap_prepend_connection_id(&prepended_fields,
							   &conn_id));
	TEST_ASSERT_EQUAL_size_t(1, prepended_fields.length);
}

TEST(coap, prepend_rejects_length_past_capacity)
{
	uint8_t buffer[4] = { 0 };
	const uint8_t value[] = { 0x2b };
	const struct edhoc_buffer conn_id = { .value = value,
					      .length = ARRAY_SIZE(value) };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.capacity = sizeof(buffer),
		.length = sizeof(buffer) + 1,
	};

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_coap_prepend_flow(&prepended_fields));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_coap_prepend_connection_id(&prepended_fields,
							   &conn_id));
}

TEST(coap, extract_rejects_consumed_past_length)
{
	const uint8_t buffer[] = { EDHOC_INDICATOR_BYTE, 0x2b };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.length = sizeof(buffer),
		.consumed = sizeof(buffer) + 1,
	};

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_coap_extract_flow_info(&extracted_fields));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_coap_extract_connection_id(&extracted_fields));
}

TEST(coap, extract_flow_info_forward_flow)
{
	const uint8_t buffer[] = { EDHOC_INDICATOR_BYTE, 0x01, 0x02, 0x03 };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.length = sizeof(buffer),
	};

	int ret = edhoc_coap_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(extracted_fields.is_forward_flow);
	TEST_ASSERT_FALSE(extracted_fields.is_reverse_flow);
	TEST_ASSERT_EQUAL_size_t(1, extracted_fields.consumed);
}

TEST(coap, extract_flow_info_reverse_flow_without_payload)
{
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = NULL,
		.length = 0,
	};

	int ret = edhoc_coap_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_FALSE(extracted_fields.is_forward_flow);
	TEST_ASSERT_TRUE(extracted_fields.is_reverse_flow);
}

TEST(coap, extract_flow_info_reverse_flow_with_empty_payload)
{
	const uint8_t buffer[1] = { 0 };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.length = 0,
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
		.length = sizeof(buffer),
	};

	int ret = edhoc_coap_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_FALSE(extracted_fields.is_forward_flow);
	TEST_ASSERT_FALSE(extracted_fields.is_reverse_flow);
	TEST_ASSERT_EQUAL_size_t(0, extracted_fields.consumed);
}

TEST(coap, extract_flow_info_null_fields)
{
	int ret = edhoc_coap_extract_flow_info(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, extract_flow_info_indicator_without_message)
{
	const uint8_t buffer[] = { EDHOC_INDICATOR_BYTE };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.length = sizeof(buffer),
	};

	int ret = edhoc_coap_extract_flow_info(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* The indicator is consumed even with nothing behind it, so it cannot
	 * be mistaken for the first byte of an EDHOC message. */
	TEST_ASSERT_TRUE(extracted_fields.is_forward_flow);
	TEST_ASSERT_EQUAL_size_t(1, extracted_fields.consumed);
}

TEST(coap, extract_connection_id_compact)
{
	/* RFC 9528: 3.3.2 - the CBOR integer -12 stands for the byte string
	 * h'2b', so the identifier is the payload byte itself. */
	const uint8_t buffer[] = { 0x2b };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.length = sizeof(buffer),
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_size_t(1, extracted_fields.connection_id.length);
	TEST_ASSERT_EQUAL_HEX8(0x2b, extracted_fields.connection_id.value[0]);
	TEST_ASSERT_EQUAL_size_t(1, extracted_fields.consumed);
}

TEST(coap, extract_connection_id_byte_string)
{
	const uint8_t buffer[] = { 0x41, 0xff };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.length = sizeof(buffer),
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_size_t(1, extracted_fields.connection_id.length);
	TEST_ASSERT_EQUAL_HEX8(0xff, extracted_fields.connection_id.value[0]);
	TEST_ASSERT_EQUAL_size_t(2, extracted_fields.consumed);
}

TEST(coap, extract_connection_id_empty)
{
	const uint8_t buffer[] = { 0x40 };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.length = sizeof(buffer),
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_size_t(0, extracted_fields.connection_id.length);
	TEST_ASSERT_EQUAL_size_t(1, extracted_fields.consumed);
}

TEST(coap, extract_calls_advance_each_other)
{
	const uint8_t buffer[] = { EDHOC_INDICATOR_BYTE, 0x2b, 0x01, 0x02 };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.length = sizeof(buffer),
	};

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_coap_extract_flow_info(&extracted_fields));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_coap_extract_connection_id(&extracted_fields));

	TEST_ASSERT_TRUE(extracted_fields.is_forward_flow);
	TEST_ASSERT_EQUAL_size_t(1, extracted_fields.connection_id.length);
	TEST_ASSERT_EQUAL_HEX8(0x2b, extracted_fields.connection_id.value[0]);
	TEST_ASSERT_EQUAL_size_t(2, extracted_fields.consumed);
}

TEST(coap, connection_id_survives_prepend_and_extract)
{
	static const uint8_t compact_lowest[] = { 0x37 };
	static const uint8_t compact_highest[] = { 0x17 };
	static const uint8_t compact_zero[] = { 0x00 };
	static const uint8_t byte_string[] = { 0xff };
	static const uint8_t multi_byte[] = { 0x01, 0x02, 0x03 };

	/* Both ends of the compact range, values outside it and the empty
	 * identifier of RFC 9528: 3.3. */
	const struct edhoc_buffer identifiers[] = {
		{ .value = compact_lowest,
		  .length = ARRAY_SIZE(compact_lowest) },
		{ .value = compact_highest,
		  .length = ARRAY_SIZE(compact_highest) },
		{ .value = compact_zero, .length = ARRAY_SIZE(compact_zero) },
		{ .value = byte_string, .length = ARRAY_SIZE(byte_string) },
		{ .value = multi_byte, .length = ARRAY_SIZE(multi_byte) },
		{ .value = NULL, .length = 0 },
	};

	for (size_t i = 0; i < ARRAY_SIZE(identifiers); ++i) {
		uint8_t buffer[8] = { 0 };
		struct edhoc_coap_prepended_fields prepended_fields = {
			.buffer = buffer,
			.capacity = sizeof(buffer),
		};

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_coap_prepend_connection_id(
					  &prepended_fields, &identifiers[i]));

		struct edhoc_coap_extracted_fields extracted_fields = {
			.buffer = buffer,
			.length = prepended_fields.length,
		};

		TEST_ASSERT_EQUAL(
			EDHOC_SUCCESS,
			edhoc_coap_extract_connection_id(&extracted_fields));
		TEST_ASSERT_TRUE(edhoc_coap_connection_id_equal(
			&identifiers[i], &extracted_fields.connection_id));
		TEST_ASSERT_EQUAL_size_t(prepended_fields.length,
					 extracted_fields.consumed);
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
		.length = 10,
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, extract_connection_id_nothing_left)
{
	const uint8_t buffer[] = { 0x2b };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.length = sizeof(buffer),
		.consumed = sizeof(buffer),
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(coap, extract_connection_id_invalid_cbor)
{
	/* A CBOR map is neither an integer nor a byte string. */
	const uint8_t buffer[] = { 0xa1, 0x01, 0x02 };
	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.length = sizeof(buffer),
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);
}

TEST(coap, extract_connection_id_bstr_too_long)
{
	uint8_t buffer[CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID + 2] = { 0 };

	buffer[0] = (uint8_t)(0x40 + CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID + 1);

	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.length = sizeof(buffer),
	};

	int ret = edhoc_coap_extract_connection_id(&extracted_fields);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(coap, prepend_and_extract_flow_roundtrip)
{
	uint8_t buffer[100] = { 0 };
	struct edhoc_coap_prepended_fields prepended_fields = {
		.buffer = buffer,
		.capacity = sizeof(buffer),
	};

	int ret = edhoc_coap_prepend_flow(&prepended_fields);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	struct edhoc_coap_extracted_fields extracted_fields = {
		.buffer = buffer,
		.length = prepended_fields.length,
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

	RUN_TEST_CASE(coap, prepend_calls_follow_each_other);
	RUN_TEST_CASE(coap, prepend_second_call_reports_a_full_buffer);
	RUN_TEST_CASE(coap, prepend_rejects_length_past_capacity);
	RUN_TEST_CASE(coap, extract_rejects_consumed_past_length);

	RUN_TEST_CASE(coap, extract_flow_info_forward_flow);
	RUN_TEST_CASE(coap, extract_flow_info_reverse_flow_without_payload);
	RUN_TEST_CASE(coap, extract_flow_info_reverse_flow_with_empty_payload);
	RUN_TEST_CASE(coap, extract_flow_info_no_flow_indicator);
	RUN_TEST_CASE(coap, extract_flow_info_null_fields);
	RUN_TEST_CASE(coap, extract_flow_info_indicator_without_message);

	RUN_TEST_CASE(coap, extract_connection_id_compact);
	RUN_TEST_CASE(coap, extract_connection_id_byte_string);
	RUN_TEST_CASE(coap, extract_connection_id_empty);
	RUN_TEST_CASE(coap, extract_calls_advance_each_other);
	RUN_TEST_CASE(coap, connection_id_survives_prepend_and_extract);
	RUN_TEST_CASE(coap, extract_connection_id_null_fields);
	RUN_TEST_CASE(coap, extract_connection_id_null_buffer);
	RUN_TEST_CASE(coap, extract_connection_id_nothing_left);
	RUN_TEST_CASE(coap, extract_connection_id_invalid_cbor);
	RUN_TEST_CASE(coap, extract_connection_id_bstr_too_long);

	RUN_TEST_CASE(coap, prepend_and_extract_flow_roundtrip);
}
