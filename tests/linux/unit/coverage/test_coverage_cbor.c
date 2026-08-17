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

TEST(coverage_cbor, cbor_int_head_length_ranges)
{
	TEST_ASSERT_EQUAL(1, edhoc_cbor_int_head_length(0));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_int_head_length(23));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_int_head_length(24));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_int_head_length(255));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_int_head_length(256));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_int_head_length(65535));
	TEST_ASSERT_EQUAL(5, edhoc_cbor_int_head_length(65536));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_int_head_length(-1));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_int_head_length(-24));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_int_head_length(-25));
	TEST_ASSERT_EQUAL(5, edhoc_cbor_int_head_length(-65537));
}

TEST(coverage_cbor, cbor_bstr_head_length_ranges)
{
	TEST_ASSERT_EQUAL(1, edhoc_cbor_bstr_head_length(0));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_bstr_head_length(23));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_bstr_head_length(24));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_bstr_head_length(255));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_bstr_head_length(256));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_bstr_head_length(65535));
	TEST_ASSERT_EQUAL(5, edhoc_cbor_bstr_head_length(65536));
	TEST_ASSERT_EQUAL(9,
			  edhoc_cbor_bstr_head_length((size_t)UINT32_MAX + 1));
}

TEST(coverage_cbor, cbor_bstr_head_write_ranges)
{
	uint8_t head[EDHOC_CBOR_BSTR_HEAD_MAX_LEN] = { 0 };

	TEST_ASSERT_EQUAL(1, edhoc_cbor_bstr_head_write(head, 0));
	TEST_ASSERT_EQUAL(0x40, head[0]);

	TEST_ASSERT_EQUAL(1, edhoc_cbor_bstr_head_write(head, 23));
	TEST_ASSERT_EQUAL(0x57, head[0]);

	TEST_ASSERT_EQUAL(2, edhoc_cbor_bstr_head_write(head, 24));
	TEST_ASSERT_EQUAL(0x58, head[0]);
	TEST_ASSERT_EQUAL(24, head[1]);

	TEST_ASSERT_EQUAL(2, edhoc_cbor_bstr_head_write(head, 255));
	TEST_ASSERT_EQUAL(0x58, head[0]);
	TEST_ASSERT_EQUAL(255, head[1]);

	TEST_ASSERT_EQUAL(3, edhoc_cbor_bstr_head_write(head, 256));
	TEST_ASSERT_EQUAL(0x59, head[0]);
	TEST_ASSERT_EQUAL(0x01, head[1]);
	TEST_ASSERT_EQUAL(0x00, head[2]);

	TEST_ASSERT_EQUAL(3, edhoc_cbor_bstr_head_write(head, 65535));
	TEST_ASSERT_EQUAL(0x59, head[0]);
	TEST_ASSERT_EQUAL(0xFF, head[1]);
	TEST_ASSERT_EQUAL(0xFF, head[2]);

	TEST_ASSERT_EQUAL(5, edhoc_cbor_bstr_head_write(head, 65536));
	TEST_ASSERT_EQUAL(0x5A, head[0]);
	TEST_ASSERT_EQUAL(0x00, head[1]);
	TEST_ASSERT_EQUAL(0x01, head[2]);
	TEST_ASSERT_EQUAL(0x00, head[3]);
	TEST_ASSERT_EQUAL(0x00, head[4]);

	TEST_ASSERT_EQUAL(0, edhoc_cbor_bstr_head_write(NULL, 0));

	const size_t too_long = (size_t)UINT32_MAX + 1;

	TEST_ASSERT_EQUAL(0, edhoc_cbor_bstr_head_write(head, too_long));
}

TEST(coverage_cbor, cbor_tstr_head_length_ranges)
{
	TEST_ASSERT_EQUAL(1, edhoc_cbor_tstr_head_length(0));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_tstr_head_length(23));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_tstr_head_length(24));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_tstr_head_length(255));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_tstr_head_length(256));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_tstr_head_length(65535));
	TEST_ASSERT_EQUAL(5, edhoc_cbor_tstr_head_length(65536));
}

TEST(coverage_cbor, cbor_map_head_length_ranges)
{
	TEST_ASSERT_EQUAL(1, edhoc_cbor_map_head_length(1));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_map_head_length(23));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_map_head_length(24));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_map_head_length(256));
}

TEST(coverage_cbor, cbor_array_head_length_ranges)
{
	TEST_ASSERT_EQUAL(1, edhoc_cbor_array_head_length(0));
	TEST_ASSERT_EQUAL(1, edhoc_cbor_array_head_length(23));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_array_head_length(24));
	TEST_ASSERT_EQUAL(2, edhoc_cbor_array_head_length(255));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_array_head_length(256));
	TEST_ASSERT_EQUAL(3, edhoc_cbor_array_head_length(65535));
	TEST_ASSERT_EQUAL(5, edhoc_cbor_array_head_length(65536));
}

TEST_GROUP_RUNNER(coverage_cbor)
{
	RUN_TEST_CASE(coverage_cbor, cbor_int_head_length_ranges);
	RUN_TEST_CASE(coverage_cbor, cbor_bstr_head_length_ranges);
	RUN_TEST_CASE(coverage_cbor, cbor_bstr_head_write_ranges);
	RUN_TEST_CASE(coverage_cbor, cbor_tstr_head_length_ranges);
	RUN_TEST_CASE(coverage_cbor, cbor_map_head_length_ranges);
	RUN_TEST_CASE(coverage_cbor, cbor_array_head_length_ranges);
}
