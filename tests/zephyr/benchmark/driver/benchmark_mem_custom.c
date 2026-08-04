/**
 * \file    benchmark_mem_custom.c
 * \author  Kamil Kielbasa
 * \brief   Zephyr k_heap-backed allocator for the libedhoc custom memory
 *          backend.
 *
 *          The custom backend requests variable-size, zero-initialised blocks,
 *          which rules out a fixed-block k_mem_slab; a k_heap is the
 *          Zephyr-native variable-size allocator. Compiled only under the
 *          custom backend (see CMakeLists.txt), so it needs no #if guard.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* EDHOC memory backend header: */
#include "edhoc_backend_memory.h"

/* Zephyr headers: */
#include <zephyr/kernel.h>

/* Standard library headers: */
#include <stddef.h>
#include <string.h>

/* Static variables and constants ------------------------------------------ */

/* Sized for a full handshake working set across every suite (the post-quantum
 * message 3 dominates); serial handshakes free everything between iterations. */
K_HEAP_DEFINE(benchmark_edhoc_heap, KB(32));

/* Module interface function definitions ----------------------------------- */

void *edhoc_mem_alloc(size_t size)
{
	void *ptr = k_heap_alloc(&benchmark_edhoc_heap, size, K_NO_WAIT);

	if (NULL != ptr) {
		/* The custom backend requires cleared storage (calloc). */
		(void)memset(ptr, 0, size);
	}

	return ptr;
}

void edhoc_mem_free(void *ptr)
{
	if (NULL == ptr) {
		return;
	}

	k_heap_free(&benchmark_edhoc_heap, ptr);
}
