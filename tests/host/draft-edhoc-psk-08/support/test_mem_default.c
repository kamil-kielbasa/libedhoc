/**
 * \file    test_mem_default.c
 * \author  libedhoc tests
 * \brief   Plain malloc()/free() implementation of the custom EDHOC memory
 *          backend hooks.
 *
 *          The custom backend (CONFIG_LIBEDHOC_MEM_BACKEND == 2) leaves
 *          edhoc_mem_alloc() / edhoc_mem_free() as link-time user hooks. The
 *          dedicated mem_custom test supplies an instrumented version to drive
 *          out-of-memory paths; every OTHER test binary just needs a working
 *          allocator so the handshake runs under the custom backend too. This
 *          provides exactly that. It is compiled only for the custom backend
 *          (empty translation unit otherwise) and is never linked into the
 *          mem_custom binary, which brings its own hooks.
 *
 * \copyright Copyright (c) 2026
 */

#include "edhoc_backend_memory.h"

#if CONFIG_LIBEDHOC_MEM_BACKEND == EDHOC_MEM_BACKEND_CUSTOM

#include <stdlib.h>

void *edhoc_mem_alloc(size_t size)
{
	/* The custom backend requires cleared storage (calloc semantics). */
	return calloc(1, size);
}

void edhoc_mem_free(void *ptr)
{
	free(ptr);
}

#endif /* CONFIG_LIBEDHOC_MEM_BACKEND == EDHOC_MEM_BACKEND_CUSTOM */
