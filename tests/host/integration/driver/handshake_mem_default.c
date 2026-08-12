/**
 * \file    handshake_mem_default.c
 * \author  Kamil Kielbasa
 * \brief   Default calloc()-based edhoc_mem_alloc() / edhoc_mem_free() hooks for
 *          the custom memory backend.
 *
 *          Linked into every handshake binary built with the custom backend so
 *          the handshake has a working allocator; the robustness mem_custom test
 *          is the exception, bringing its own instrumented hooks. CMake compiles
 *          this only under the custom backend, so it needs no #if guard.
 *
 * \copyright Copyright (c) 2026
 */

#include "edhoc_backend_memory.h"

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
