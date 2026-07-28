/**
 * \file    test_coverage_cbor.c
 * \author  Kamil Kielbasa
 * \brief   Coverage tests for EDHOC CBOR helper edge cases.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Internal headers: */
#include "coverage_common.h"

/* Standard library headers: */
#include <stdint.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(coverage_cbor);

TEST_SETUP(coverage_cbor)
{
}

TEST_TEAR_DOWN(coverage_cbor)
{
}

TEST(coverage_cbor, cbor_int_mem_req_ranges)
{
	TEST_ASSERT_EQUAL(1, edhoc_cbor_int_mem_req(0));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_int_mem_req(23));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_int_mem_req(24));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_int_mem_req(255));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_int_mem_req(256));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_int_mem_req(65535));
	TEST_ASSERT_EQUAL(4, edhoc_cbor_int_mem_req(65536));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_int_mem_req(-1));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_int_mem_req(-24));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_int_mem_req(-25));
}

TEST(coverage_cbor, cbor_bstr_oh_ranges)
{
	TEST_ASSERT_EQUAL(1, edhoc_cbor_bstr_oh(0));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_bstr_oh(23));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_bstr_oh(24));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_bstr_oh(255));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_bstr_oh(256));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_bstr_oh(65535));
	TEST_ASSERT_EQUAL(4, edhoc_cbor_bstr_oh(65536));
}

TEST(coverage_cbor, cbor_bstr_header_ranges)
{
	uint8_t header[EDHOC_CBOR_BSTR_HEADER_MAX_LEN] = { 0 };

	TEST_ASSERT_EQUAL(1, edhoc_cbor_bstr_header(header, 0));
	TEST_ASSERT_EQUAL(0x40, header[0]);

	TEST_ASSERT_EQUAL(1, edhoc_cbor_bstr_header(header, 23));
	TEST_ASSERT_EQUAL(0x57, header[0]);

	TEST_ASSERT_EQUAL(2, edhoc_cbor_bstr_header(header, 24));
	TEST_ASSERT_EQUAL(0x58, header[0]);
	TEST_ASSERT_EQUAL(24, header[1]);

	TEST_ASSERT_EQUAL(2, edhoc_cbor_bstr_header(header, 255));
	TEST_ASSERT_EQUAL(0x58, header[0]);
	TEST_ASSERT_EQUAL(255, header[1]);

	TEST_ASSERT_EQUAL(3, edhoc_cbor_bstr_header(header, 256));
	TEST_ASSERT_EQUAL(0x59, header[0]);
	TEST_ASSERT_EQUAL(0x01, header[1]);
	TEST_ASSERT_EQUAL(0x00, header[2]);

	TEST_ASSERT_EQUAL(3, edhoc_cbor_bstr_header(header, 65535));
	TEST_ASSERT_EQUAL(0x59, header[0]);
	TEST_ASSERT_EQUAL(0xFF, header[1]);
	TEST_ASSERT_EQUAL(0xFF, header[2]);

	TEST_ASSERT_EQUAL(5, edhoc_cbor_bstr_header(header, 65536));
	TEST_ASSERT_EQUAL(0x5A, header[0]);
	TEST_ASSERT_EQUAL(0x00, header[1]);
	TEST_ASSERT_EQUAL(0x01, header[2]);
	TEST_ASSERT_EQUAL(0x00, header[3]);
	TEST_ASSERT_EQUAL(0x00, header[4]);
}

TEST(coverage_cbor, cbor_tstr_oh_ranges)
{
	TEST_ASSERT_EQUAL(1, edhoc_cbor_tstr_oh(0));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_tstr_oh(23));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_tstr_oh(24));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_tstr_oh(255));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_tstr_oh(256));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_tstr_oh(65535));
	TEST_ASSERT_EQUAL(4, edhoc_cbor_tstr_oh(65536));
}

TEST(coverage_cbor, cbor_map_oh)
{
	TEST_ASSERT_EQUAL(3, edhoc_cbor_map_oh(1));
}

TEST(coverage_cbor, cbor_array_oh_ranges)
{
	TEST_ASSERT_EQUAL(1, edhoc_cbor_array_oh(0));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_array_oh(23));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_array_oh(24));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_array_oh(255));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_array_oh(256));
}

TEST_GROUP_RUNNER(coverage_cbor)
{
	RUN_TEST_CASE(coverage_cbor, cbor_int_mem_req_ranges);
	RUN_TEST_CASE(coverage_cbor, cbor_bstr_oh_ranges);
	RUN_TEST_CASE(coverage_cbor, cbor_bstr_header_ranges);
	RUN_TEST_CASE(coverage_cbor, cbor_tstr_oh_ranges);
	RUN_TEST_CASE(coverage_cbor, cbor_map_oh);
	RUN_TEST_CASE(coverage_cbor, cbor_array_oh_ranges);
}
