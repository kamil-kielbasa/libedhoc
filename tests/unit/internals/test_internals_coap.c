/**
 * \file    test_internals_coap.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for edhoc_coap.c buffer and CID utilities.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#include "internals_common.h"

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(internals_coap);

TEST_SETUP(internals_coap)
{
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, psa_crypto_init());
	internals_crypto = edhoc_cipher_suite_0_get_crypto();
}

TEST_TEAR_DOWN(internals_coap)
{
	mbedtls_psa_crypto_free();
}

TEST(internals_coap, set_connection_id_invalid_type)
{
	struct edhoc_context ctx = { 0 };
	edhoc_context_init(&ctx);

	struct edhoc_connection_id cid = { .encode_type = 99 };
	int ret = edhoc_set_connection_id(&ctx, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BAD_STATE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&ctx));
}

TEST(internals_coap, conn_id_equal_invalid_type)
{
	struct edhoc_connection_id a = { .encode_type = 99, .int_value = 1 };
	struct edhoc_connection_id b = { .encode_type = 99, .int_value = 1 };
	TEST_ASSERT_FALSE(edhoc_coap_connection_id_equal(&a, &b));
}

TEST(internals_coap, conn_id_equal_null)
{
	struct edhoc_connection_id a = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 1,
	};
	TEST_ASSERT_FALSE(edhoc_coap_connection_id_equal(NULL, &a));
	TEST_ASSERT_FALSE(edhoc_coap_connection_id_equal(&a, NULL));
}

TEST(internals_coap, conn_id_equal_type_mismatch)
{
	struct edhoc_connection_id a = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 1,
	};
	struct edhoc_connection_id b = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 1,
	};
	TEST_ASSERT_FALSE(edhoc_coap_connection_id_equal(&a, &b));
}

TEST(internals_coap, conn_id_equal_bstr_success)
{
	struct edhoc_connection_id a = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 2,
	};
	a.bstr_value[0] = 0xAA;
	a.bstr_value[1] = 0xBB;

	struct edhoc_connection_id b = a;
	TEST_ASSERT_TRUE(edhoc_coap_connection_id_equal(&a, &b));
}

TEST(internals_coap, prepend_conn_id_null)
{
	int ret = edhoc_coap_prepend_connection_id(NULL, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_coap, prepend_conn_id_zero_buf)
{
	uint8_t buf[32];
	struct edhoc_coap_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = 0,
	};
	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
		.int_value = 5,
	};
	int ret = edhoc_coap_prepend_connection_id(&pf, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(internals_coap, prepend_conn_id_invalid_type)
{
	uint8_t buf[32];
	struct edhoc_coap_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = sizeof(buf),
	};
	struct edhoc_connection_id cid = { .encode_type = 99 };
	int ret = edhoc_coap_prepend_connection_id(&pf, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_coap, prepend_conn_id_bstr_zero_len)
{
	uint8_t buf[32];
	struct edhoc_coap_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = sizeof(buf),
	};
	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 0,
	};
	int ret = edhoc_coap_prepend_connection_id(&pf, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_coap, prepend_conn_id_bstr_success)
{
	uint8_t buf[32];
	struct edhoc_coap_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = sizeof(buf),
	};
	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 2,
	};
	cid.bstr_value[0] = 0xAA;
	cid.bstr_value[1] = 0xBB;
	int ret = edhoc_coap_prepend_connection_id(&pf, &cid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_NOT_NULL(pf.edhoc_message_ptr);
}

TEST(internals_coap, prepend_flow_null)
{
	int ret = edhoc_coap_prepend_flow(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_coap, prepend_flow_success)
{
	uint8_t buf[32];
	struct edhoc_coap_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = sizeof(buf),
	};
	int ret = edhoc_coap_prepend_flow(&pf);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(0xF5, buf[0]);
}

TEST(internals_coap, prepend_flow_tiny_buf)
{
	struct edhoc_coap_prepended_fields pf = {
		.buffer = NULL,
		.buffer_size = 0,
	};
	int ret = edhoc_coap_prepend_flow(&pf);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_coap, prepend_recalculate_null)
{
	int ret = edhoc_coap_prepend_recalculate_size(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_coap, prepend_recalculate_null_buf)
{
	struct edhoc_coap_prepended_fields pf = {
		.buffer = NULL,
		.buffer_size = 0,
	};
	int ret = edhoc_coap_prepend_recalculate_size(&pf);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_coap, prepend_recalculate_null_msg_ptr)
{
	uint8_t buf[32];
	struct edhoc_coap_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = sizeof(buf),
		.edhoc_message_ptr = NULL,
		.edhoc_message_size = 0,
	};
	int ret = edhoc_coap_prepend_recalculate_size(&pf);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_coap, extract_flow_info_null)
{
	int ret = edhoc_coap_extract_flow_info(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_coap, extract_flow_info_null_buf)
{
	struct edhoc_coap_extracted_fields ef = {
		.buffer = NULL,
		.buffer_size = 0,
	};
	int ret = edhoc_coap_extract_flow_info(&ef);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(ef.is_reverse_flow);
}

TEST(internals_coap, extract_flow_info_forward)
{
	uint8_t buf[32] = { 0xF5, 0x01, 0x02 };
	struct edhoc_coap_extracted_fields ef = {
		.buffer = buf,
		.buffer_size = 3,
	};
	int ret = edhoc_coap_extract_flow_info(&ef);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_TRUE(ef.is_forward_flow);
	TEST_ASSERT_EQUAL(2, ef.edhoc_message_size);
}

TEST(internals_coap, extract_conn_id_null)
{
	int ret = edhoc_coap_extract_connection_id(NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_coap, extract_conn_id_int)
{
	uint8_t buf[32] = { 0x05, 0x01, 0x02 };
	struct edhoc_coap_extracted_fields ef = {
		.buffer = buf,
		.buffer_size = 3,
	};
	int ret = edhoc_coap_extract_connection_id(&ef);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
			  ef.extracted_conn_id.encode_type);
}

TEST(internals_coap, extract_conn_id_bstr)
{
	uint8_t buf[32] = { 0x42, 0xAA, 0xBB, 0x01 };
	struct edhoc_coap_extracted_fields ef = {
		.buffer = buf,
		.buffer_size = 4,
	};
	int ret = edhoc_coap_extract_connection_id(&ef);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_CID_TYPE_BYTE_STRING,
			  ef.extracted_conn_id.encode_type);
	TEST_ASSERT_EQUAL(2, ef.extracted_conn_id.bstr_length);
}

TEST(internals_coap, prepend_conn_id_bstr_tiny_buf)
{
	uint8_t buf[1];
	struct edhoc_coap_prepended_fields pf = {
		.buffer = buf,
		.buffer_size = 1,
	};
	struct edhoc_connection_id cid = {
		.encode_type = EDHOC_CID_TYPE_BYTE_STRING,
		.bstr_length = 2,
	};
	cid.bstr_value[0] = 0xAA;
	cid.bstr_value[1] = 0xBB;
	int ret = edhoc_coap_prepend_connection_id(&pf, &cid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);
}

TEST(internals_coap, extract_conn_id_invalid_cbor)
{
	uint8_t garbage[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
	struct edhoc_coap_extracted_fields ef = {
		.buffer = garbage,
		.buffer_size = sizeof(garbage),
	};
	int ret = edhoc_coap_extract_connection_id(&ef);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE, ret);
}

TEST(internals_coap, extract_conn_id_null_buf)
{
	struct edhoc_coap_extracted_fields ef = {
		.buffer = NULL,
		.buffer_size = 0,
	};
	int ret = edhoc_coap_extract_connection_id(&ef);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST_GROUP_RUNNER(internals_coap)
{
	RUN_TEST_CASE(internals_coap, set_connection_id_invalid_type);
	RUN_TEST_CASE(internals_coap, conn_id_equal_invalid_type);
	RUN_TEST_CASE(internals_coap, conn_id_equal_null);
	RUN_TEST_CASE(internals_coap, conn_id_equal_type_mismatch);
	RUN_TEST_CASE(internals_coap, conn_id_equal_bstr_success);
	RUN_TEST_CASE(internals_coap, prepend_conn_id_null);
	RUN_TEST_CASE(internals_coap, prepend_conn_id_zero_buf);
	RUN_TEST_CASE(internals_coap, prepend_conn_id_invalid_type);
	RUN_TEST_CASE(internals_coap, prepend_conn_id_bstr_zero_len);
	RUN_TEST_CASE(internals_coap, prepend_conn_id_bstr_success);
	RUN_TEST_CASE(internals_coap, prepend_flow_null);
	RUN_TEST_CASE(internals_coap, prepend_flow_success);
	RUN_TEST_CASE(internals_coap, prepend_flow_tiny_buf);
	RUN_TEST_CASE(internals_coap, prepend_recalculate_null);
	RUN_TEST_CASE(internals_coap, prepend_recalculate_null_buf);
	RUN_TEST_CASE(internals_coap, prepend_recalculate_null_msg_ptr);
	RUN_TEST_CASE(internals_coap, extract_flow_info_null);
	RUN_TEST_CASE(internals_coap, extract_flow_info_null_buf);
	RUN_TEST_CASE(internals_coap, extract_flow_info_forward);
	RUN_TEST_CASE(internals_coap, extract_conn_id_null);
	RUN_TEST_CASE(internals_coap, extract_conn_id_int);
	RUN_TEST_CASE(internals_coap, extract_conn_id_bstr);
	RUN_TEST_CASE(internals_coap, prepend_conn_id_bstr_tiny_buf);
	RUN_TEST_CASE(internals_coap, extract_conn_id_invalid_cbor);
	RUN_TEST_CASE(internals_coap, extract_conn_id_null_buf);
}
