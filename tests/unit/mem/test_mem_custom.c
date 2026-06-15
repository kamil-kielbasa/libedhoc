/**
 * \file    test_mem_custom.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for the instrumented custom EDHOC memory backend
 *          allocator: allocation accounting, zero-initialisation and
 *          single-shot out-of-memory fault injection.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Internal test header: */
#include "test_mem_custom.h"

/* Memory backend facade: */
#include "edhoc_backend_memory.h"

/* Standard library headers: */
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

#if CONFIG_LIBEDHOC_MEM_BACKEND == EDHOC_MEM_BACKEND_CUSTOM

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitions --------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(mem_custom);

TEST_SETUP(mem_custom)
{
	edhoc_mem_reset();
}

TEST_TEAR_DOWN(mem_custom)
{
	edhoc_mem_reset();
}

TEST(mem_custom, allocator_tracks_alloc_and_free)
{
	struct edhoc_mem_stats stats = { 0 };

	edhoc_mem_reset();

	edhoc_mem_stats(&stats);
	TEST_ASSERT_EQUAL(0, stats.outstanding_blocks);
	TEST_ASSERT_EQUAL(0, stats.outstanding_bytes);
	TEST_ASSERT_EQUAL(0, stats.total_allocs);

	void *first = edhoc_mem_alloc(32);
	TEST_ASSERT_NOT_NULL(first);
	edhoc_mem_stats(&stats);
	TEST_ASSERT_EQUAL(1, stats.outstanding_blocks);
	TEST_ASSERT_EQUAL(32, stats.outstanding_bytes);
	TEST_ASSERT_EQUAL(1, stats.total_allocs);

	void *second = edhoc_mem_alloc(16);
	TEST_ASSERT_NOT_NULL(second);
	edhoc_mem_stats(&stats);
	TEST_ASSERT_EQUAL(2, stats.outstanding_blocks);
	TEST_ASSERT_EQUAL(48, stats.outstanding_bytes);

	memset(first, 0xAB, 32);
	memset(second, 0xCD, 16);

	edhoc_mem_free(first);
	edhoc_mem_stats(&stats);
	TEST_ASSERT_EQUAL(1, stats.outstanding_blocks);
	TEST_ASSERT_EQUAL(16, stats.outstanding_bytes);

	edhoc_mem_free(second);
	edhoc_mem_stats(&stats);
	TEST_ASSERT_EQUAL(0, stats.outstanding_blocks);
	TEST_ASSERT_EQUAL(0, stats.outstanding_bytes);
	TEST_ASSERT_EQUAL(2, stats.total_allocs);
	TEST_ASSERT_EQUAL(2, stats.total_frees);
}

TEST(mem_custom, free_null_is_noop)
{
	struct edhoc_mem_stats stats = { 0 };

	edhoc_mem_reset();

	edhoc_mem_free(NULL);

	edhoc_mem_stats(&stats);
	TEST_ASSERT_EQUAL(0, stats.outstanding_blocks);
	TEST_ASSERT_EQUAL(0, stats.total_frees);
}

TEST(mem_custom, fault_injection_fails_selected_allocation)
{
	struct edhoc_mem_stats stats = { 0 };

	edhoc_mem_reset();
	edhoc_mem_fail_on_alloc(2);

	void *first = edhoc_mem_alloc(8);
	TEST_ASSERT_NOT_NULL(first);
	edhoc_mem_stats(&stats);
	TEST_ASSERT_FALSE(stats.fault_triggered);

	void *second = edhoc_mem_alloc(8);
	TEST_ASSERT_NULL(second);
	edhoc_mem_stats(&stats);
	TEST_ASSERT_TRUE(stats.fault_triggered);

	void *third = edhoc_mem_alloc(8);
	TEST_ASSERT_NOT_NULL(third);

	edhoc_mem_free(first);
	edhoc_mem_free(third);
	edhoc_mem_stats(&stats);
	TEST_ASSERT_EQUAL(0, stats.outstanding_blocks);
	TEST_ASSERT_EQUAL(2, stats.total_allocs);
	TEST_ASSERT_EQUAL(2, stats.total_frees);
}

TEST(mem_custom, alloc_returns_zeroed_memory)
{
	const size_t size = 64;

	edhoc_mem_reset();

	/*
	 * Dirty a block, release it and request the same size again: the
	 * allocator must hand back fully zeroed memory even when the underlying
	 * block is recycled.
	 */
	uint8_t *first = edhoc_mem_alloc(size);
	TEST_ASSERT_NOT_NULL(first);
	memset(first, 0xFF, size);
	edhoc_mem_free(first);

	uint8_t *second = edhoc_mem_alloc(size);
	TEST_ASSERT_NOT_NULL(second);
	for (size_t i = 0; i < size; ++i)
		TEST_ASSERT_EQUAL_UINT8(0, second[i]);

	edhoc_mem_free(second);
}

TEST_GROUP_RUNNER(mem_custom)
{
	RUN_TEST_CASE(mem_custom, allocator_tracks_alloc_and_free);
	RUN_TEST_CASE(mem_custom, free_null_is_noop);
	RUN_TEST_CASE(mem_custom, fault_injection_fails_selected_allocation);
	RUN_TEST_CASE(mem_custom, alloc_returns_zeroed_memory);
}

#endif /* EDHOC_MEM_BACKEND_CUSTOM */
