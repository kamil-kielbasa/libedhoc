/**
 * \file    test_mem_custom.h
 * \author  Kamil Kielbasa
 * \brief   Instrumented allocator for the custom EDHOC memory backend.
 *
 *          When the library is built with the custom backend
 *          (\c CONFIG_LIBEDHOC_MEM_BACKEND set to \c EDHOC_MEM_BACKEND_CUSTOM)
 *          it expects the application to provide \c edhoc_mem_alloc() and
 *          \c edhoc_mem_free() at link time.
 *          For tests these hooks wrap \c calloc() / \c free() with per-block
 *          bookkeeping, letting the suite read allocation statistics and inject
 *          a single out-of-memory fault at a chosen allocation.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef TEST_MEM_CUSTOM_H
#define TEST_MEM_CUSTOM_H

/* Include files ----------------------------------------------------------- */

/* Standard library headers: */
#include <stddef.h>
#include <stdbool.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitions --------------------------------------- */

/**
 * \brief Snapshot of the instrumented allocator counters.
 */
struct edhoc_mem_stats {
	size_t outstanding_blocks; /**< Live blocks not yet freed. */
	size_t outstanding_bytes; /**< Live payload bytes not yet freed. */
	size_t total_allocs; /**< Successful allocations since reset. */
	size_t total_frees; /**< Frees since reset. */
	bool fault_triggered; /**< Whether an armed fault has fired. */
};

/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

/**
 * \brief Reset all counters and clear any pending fault injection.
 */
void edhoc_mem_reset(void);

/**
 * \brief Arm a single out-of-memory fault.
 *
 * \param nth  1-based index of the allocation that shall fail (return NULL).
 *             Pass 0 to disable fault injection.
 */
void edhoc_mem_fail_on_alloc(size_t nth);

/**
 * \brief Read the current allocator statistics.
 *
 * \param[out] stats  Destination filled with the current counters.
 */
void edhoc_mem_stats(struct edhoc_mem_stats *stats);

#endif /* TEST_MEM_CUSTOM_H */
