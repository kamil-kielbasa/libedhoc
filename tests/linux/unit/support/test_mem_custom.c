/**
 * \file    test_mem_custom.c
 * \author  Kamil Kielbasa
 * \brief   Instrumented edhoc_mem_alloc() / edhoc_mem_free() implementation for
 *          the custom EDHOC memory backend tests.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Internal test header: */
#include "test_mem_custom.h"

/* EDHOC header: */
#include "edhoc_backend_memory.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#if CONFIG_LIBEDHOC_MEM_BACKEND == EDHOC_MEM_BACKEND_CUSTOM

/* Module defines ---------------------------------------------------------- */
#define TEST_MEM_CUSTOM_MAGIC ((size_t)0xED11C0DEU)

/* Module types and type definitions --------------------------------------- */

/**
 * \brief Per-allocation bookkeeping header placed in front of the payload.
 */
struct block_header {
	size_t magic;
	size_t size;
	uint8_t payload[];
};

/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

static struct {
	struct edhoc_mem_stats stats;
	size_t fail_target;
} g_mem;

/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

void edhoc_mem_reset(void)
{
	memset(&g_mem, 0, sizeof(g_mem));
}

void edhoc_mem_fail_on_alloc(size_t nth)
{
	g_mem.fail_target = nth;
	g_mem.stats.fault_triggered = false;
}

void edhoc_mem_stats(struct edhoc_mem_stats *stats)
{
	*stats = g_mem.stats;
}

void *edhoc_mem_alloc(size_t size)
{
	if (0 != g_mem.fail_target &&
	    g_mem.stats.total_allocs + 1 == g_mem.fail_target) {
		g_mem.fail_target = 0;
		g_mem.stats.fault_triggered = true;
		return NULL;
	}

	/*
	 * calloc() zero-initialises the whole block; the header fields are then
	 * overwritten while the payload handed back to the caller stays cleared,
	 * as required by the edhoc_mem_alloc() contract.
	 */
	struct block_header *hdr = calloc(1, sizeof(*hdr) + size);

	if (NULL == hdr)
		return NULL;

	hdr->magic = TEST_MEM_CUSTOM_MAGIC;
	hdr->size = size;

	g_mem.stats.total_allocs += 1;
	g_mem.stats.outstanding_blocks += 1;
	g_mem.stats.outstanding_bytes += size;

	return hdr->payload;
}

void edhoc_mem_free(void *ptr)
{
	if (NULL == ptr)
		return;

	struct block_header *hdr =
		(struct block_header *)((uint8_t *)ptr -
					offsetof(struct block_header, payload));

	if (TEST_MEM_CUSTOM_MAGIC != hdr->magic)
		abort();

	hdr->magic = 0;

	g_mem.stats.total_frees += 1;
	g_mem.stats.outstanding_blocks -= 1;
	g_mem.stats.outstanding_bytes -= hdr->size;

	free(hdr);
}

#endif /* EDHOC_MEM_BACKEND_CUSTOM */
