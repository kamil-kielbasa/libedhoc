/**
 * \file    test_mem_custom.c
 * \author  Kamil Kielbasa
 * \brief   Integration tests for the custom EDHOC memory backend: a baseline
 *          allocation-balanced suite-0 handshake and an exhaustive
 *          out-of-memory sweep proving that every allocation failure path
 *          releases all previously allocated buffers.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Internal test headers: */
#include "test_mem_custom.h"
#include "test_mem_custom_handshake.h"

/* EDHOC header: */
#include <edhoc/edhoc.h>

/* Memory backend facade: */
#include "edhoc_backend_memory.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Standard library headers: */
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

TEST_GROUP(mem_custom_handshake);

TEST_SETUP(mem_custom_handshake)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
	edhoc_mem_reset();
}

TEST_TEAR_DOWN(mem_custom_handshake)
{
	mbedtls_psa_crypto_free();
	edhoc_mem_reset();
}

TEST(mem_custom_handshake, full_handshake_is_allocation_balanced)
{
	struct edhoc_context initiator = { 0 };
	struct edhoc_context responder = { 0 };
	struct edhoc_mem_stats stats = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, test_mem_custom_setup_contexts(
						 &initiator, &responder));

	edhoc_mem_reset();
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, test_mem_custom_drive_handshake(
						 &initiator, &responder));

	edhoc_mem_stats(&stats);
	TEST_ASSERT_TRUE(stats.total_allocs > 0);
	TEST_ASSERT_EQUAL(stats.total_allocs, stats.total_frees);
	TEST_ASSERT_EQUAL(0, stats.outstanding_blocks);
	TEST_ASSERT_EQUAL(0, stats.outstanding_bytes);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&initiator));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&responder));
}

TEST(mem_custom_handshake, every_allocation_failure_frees_all_priors)
{
	struct edhoc_context initiator = { 0 };
	struct edhoc_context responder = { 0 };
	struct edhoc_mem_stats stats = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, test_mem_custom_setup_contexts(
						 &initiator, &responder));
	edhoc_mem_reset();
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, test_mem_custom_drive_handshake(
						 &initiator, &responder));
	edhoc_mem_stats(&stats);
	const size_t alloc_count = stats.total_allocs;
	TEST_ASSERT_TRUE(alloc_count > 0);
	TEST_ASSERT_EQUAL(stats.total_allocs, stats.total_frees);
	TEST_ASSERT_EQUAL(0, stats.outstanding_blocks);
	TEST_ASSERT_EQUAL(0, stats.outstanding_bytes);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&initiator));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_context_deinit(&responder));

	size_t not_enough_memory_codes = 0;

	for (size_t nth = 1; nth <= alloc_count; ++nth) {
		mbedtls_psa_crypto_free();
		TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());

		struct edhoc_context init_oom = { 0 };
		struct edhoc_context resp_oom = { 0 };
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, test_mem_custom_setup_contexts(
							 &init_oom, &resp_oom));

		edhoc_mem_reset();
		edhoc_mem_fail_on_alloc(nth);

		const int ret =
			test_mem_custom_drive_handshake(&init_oom, &resp_oom);

		TEST_ASSERT_TRUE(EDHOC_SUCCESS != ret);

		edhoc_mem_stats(&stats);
		TEST_ASSERT_TRUE(stats.fault_triggered);
		TEST_ASSERT_EQUAL(0, stats.outstanding_blocks);
		TEST_ASSERT_EQUAL(0, stats.outstanding_bytes);
		TEST_ASSERT_EQUAL(stats.total_allocs, stats.total_frees);

		if (EDHOC_ERROR_NOT_ENOUGH_MEMORY == ret)
			not_enough_memory_codes += 1;

		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&init_oom));
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_context_deinit(&resp_oom));
	}

	edhoc_mem_stats(&stats);
	TEST_ASSERT_EQUAL(0, stats.outstanding_blocks);
	TEST_ASSERT_EQUAL(0, stats.outstanding_bytes);
	TEST_ASSERT_TRUE(not_enough_memory_codes > 0);
}

TEST_GROUP_RUNNER(mem_custom_handshake)
{
	RUN_TEST_CASE(mem_custom_handshake,
		      full_handshake_is_allocation_balanced);
	RUN_TEST_CASE(mem_custom_handshake,
		      every_allocation_failure_frees_all_priors);
}

#endif /* EDHOC_MEM_BACKEND_CUSTOM */
