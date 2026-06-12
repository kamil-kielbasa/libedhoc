/**
 * \file    edhoc_backend_memory.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC pluggable memory backend facade.
 *
 *          Working buffers inside the library are allocated through a small
 *          set of macros (\ref EDHOC_MEM_ALLOC, \ref EDHOC_MEM_FREE, ...)
 *          whose implementation is selected at build time, so the same
 *          sources can target stack-only, heap or custom-allocator builds
 *          without touching the call sites.
 *
 *          The backend is chosen at build time by the integer
 *          \c CONFIG_LIBEDHOC_MEM_BACKEND:
 *            - \c EDHOC_MEM_BACKEND_STACK  (0, default) -- C99 VLA / \c _alloca,
 *            - \c EDHOC_MEM_BACKEND_HEAP   (1)          -- heap allocator,
 *            - \c EDHOC_MEM_BACKEND_CUSTOM (2)          -- link-time user hooks.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_BACKEND_MEMORY_H
#define EDHOC_BACKEND_MEMORY_H

/* Include files ----------------------------------------------------------- */
#include <stddef.h>
#include <string.h>

/* Defines ----------------------------------------------------------------- */

/** \defgroup edhoc-backend-memory EDHOC memory backend
 * @{
 */

/*
 * The backend is selected by the integer CONFIG_LIBEDHOC_MEM_BACKEND. On
 * Zephyr its value is derived from the LIBEDHOC_MEM_BACKEND_CHOICE Kconfig
 * choice; on every other build it is passed directly, e.g.
 * -DCONFIG_LIBEDHOC_MEM_BACKEND=1. When it is not defined the stack backend is
 * used by default.
 */
#define EDHOC_MEM_BACKEND_STACK 0
#define EDHOC_MEM_BACKEND_HEAP 1
#define EDHOC_MEM_BACKEND_CUSTOM 2

#ifndef CONFIG_LIBEDHOC_MEM_BACKEND
#define CONFIG_LIBEDHOC_MEM_BACKEND EDHOC_MEM_BACKEND_STACK
#endif /* default backend */

/* Types and type definitions ---------------------------------------------- */

#ifdef __DOXYGEN__

/**
 * \brief Assert that the current thread has at least the requested amount of
 *        free stack space.
 *
 * On Zephyr expands to a runtime check using ``k_thread_stack_space_get`` and
 * ``__ASSERT`` (only when both ``CONFIG_THREAD_STACK_INFO`` and
 * ``CONFIG_ASSERT`` are enabled). On every other platform it compiles to a
 * no-op. Only the stack backend evaluates this macro.
 *
 * \param required_bytes  Minimum number of free stack bytes required.
 */
#define EDHOC_ASSERT_FREE_STACK_SIZE(required_bytes)

/**
 * \brief Allocate a working buffer of \p size elements of \p type named \p name.
 *
 * Depending on the selected backend this expands to a C99 VLA (stack),
 * a ``calloc``/``k_calloc`` call (heap) or a call to the user supplied
 * allocator (custom). The returned buffer is always zero-initialised. For
 * every backend \p name is usable as a pointer and may be compared against
 * ``NULL``:
 *   - on the stack backend the allocation cannot fail, so the ``NULL`` check is
 *     a compile-time-false branch that the optimiser removes,
 *   - on the heap and custom backends ``NULL`` signals an out-of-memory
 *     condition and the caller must bail out.
 *
 * Every successful allocation must be released with \ref EDHOC_MEM_FREE (a
 * no-op on the stack backend).
 *
 * \param type  Element type.
 * \param name  Variable name bound to the allocated buffer.
 * \param size  Number of elements to allocate.
 */
#define EDHOC_MEM_ALLOC(type, name, size)

/**
 * \brief Total size in bytes of a buffer allocated with \ref EDHOC_MEM_ALLOC.
 *
 * \param name  Variable name used in \ref EDHOC_MEM_ALLOC.
 */
#define EDHOC_MEM_ALLOC_SIZEOF(name)

/**
 * \brief Number of elements in a buffer allocated with \ref EDHOC_MEM_ALLOC.
 *
 * \param x  Variable name used in \ref EDHOC_MEM_ALLOC.
 */
#define EDHOC_MEM_ALLOC_SIZE(x)

/**
 * \brief Release a buffer allocated with \ref EDHOC_MEM_ALLOC.
 *
 * No-op on the stack backend. On the heap and custom backends frees the buffer
 * and sets \p name to ``NULL`` so a double free is harmless.
 *
 * \param name  Variable name used in \ref EDHOC_MEM_ALLOC.
 */
#define EDHOC_MEM_FREE(name)

#else /* !__DOXYGEN__ */

#if defined(__ZEPHYR__) && defined(CONFIG_THREAD_STACK_INFO) && \
	defined(CONFIG_ASSERT)

#include <zephyr/kernel.h>
#include <zephyr/sys/__assert.h>

#define EDHOC_ASSERT_FREE_STACK_SIZE(required_bytes)                         \
	do {                                                                 \
		size_t _unused = 0;                                          \
		int _err =                                                   \
			k_thread_stack_space_get(k_current_get(), &_unused); \
		__ASSERT_NO_MSG(_err == 0);                                  \
		__ASSERT(_unused >= (size_t)(required_bytes),                \
			 "Insufficient stack: %zu bytes free, %zu required", \
			 _unused, (size_t)(required_bytes));                 \
	} while (0)
#else /* assert / stack-info support unavailable */
#define EDHOC_ASSERT_FREE_STACK_SIZE(required_bytes) \
	do {                                         \
	} while (0)
#endif /* __ZEPHYR__ && CONFIG_THREAD_STACK_INFO && CONFIG_ASSERT */

#if CONFIG_LIBEDHOC_MEM_BACKEND == EDHOC_MEM_BACKEND_STACK

#if defined(_WIN32) || defined(_MSC_VER)

#include <malloc.h>

/*
 * MSVC has no VLAs; _alloca already yields a pointer, so no aliasing is needed.
 * The buffer is zero-initialised to match the heap and custom backends.
 */
#define EDHOC_MEM_ALLOC(type, name, size)                    \
	type *name = (type *)_alloca((size) * sizeof(type)); \
	const size_t name##_size = (size) * sizeof(type);    \
	memset(name, 0, name##_size)

#define EDHOC_MEM_ALLOC_SIZEOF(name) name##_size

#else /* !(_WIN32 || _MSC_VER) -- Linux & Zephyr */

/*
 * A real VLA buffer (name##_vla_buf) plus a pointer alias (name). Exposing the
 * buffer through a pointer keeps "if (NULL == name)" warning-clean on every
 * backend: comparing an array to NULL trips -Waddress / -Wtautological-compare
 * (=-Werror here), comparing a runtime pointer variable does not. The buffer is
 * zero-initialised to match the heap and custom backends.
 */
#define EDHOC_MEM_ALLOC(type, name, size)                    \
	EDHOC_ASSERT_FREE_STACK_SIZE((size) * sizeof(type)); \
	type name##_vla_buf[size];                           \
	type *name = name##_vla_buf;                         \
	memset(name, 0, sizeof(name##_vla_buf))

#define EDHOC_MEM_ALLOC_SIZEOF(name) sizeof(name##_vla_buf)

#endif /* _WIN32 || _MSC_VER */

#define EDHOC_MEM_FREE(name) \
	do {                 \
	} while (0)

#elif CONFIG_LIBEDHOC_MEM_BACKEND == EDHOC_MEM_BACKEND_HEAP || \
	CONFIG_LIBEDHOC_MEM_BACKEND == EDHOC_MEM_BACKEND_CUSTOM

#if CONFIG_LIBEDHOC_MEM_BACKEND == EDHOC_MEM_BACKEND_HEAP

#if defined(__ZEPHYR__)

#include <zephyr/kernel.h>

#define EDHOC_MEM_RAW_ALLOC(num_bytes) k_calloc(1, num_bytes)
#define EDHOC_MEM_RAW_FREE(ptr) k_free(ptr)

#else /* !__ZEPHYR__ */

#include <stdlib.h>

#define EDHOC_MEM_RAW_ALLOC(num_bytes) calloc(1, num_bytes)
#define EDHOC_MEM_RAW_FREE(ptr) free(ptr)

#endif /* __ZEPHYR__ */

#else /* EDHOC_MEM_BACKEND_CUSTOM */

/**
 * \brief User-provided allocation hook (custom backend).
 *
 * Must behave like ``calloc(1, size)``: return a pointer to \p size bytes of
 * suitably aligned, zero-initialised storage, or ``NULL`` on failure. The
 * library relies on the returned memory being cleared, so the hook is required
 * to zero the whole block before returning it.
 */
extern void *edhoc_mem_alloc(size_t size);

/**
 * \brief User-provided release hook (custom backend).
 *
 * Must behave like ``free``: release a block previously returned by
 * \ref edhoc_mem_alloc. Passing ``NULL`` must be a no-op.
 */
extern void edhoc_mem_free(void *ptr);

#define EDHOC_MEM_RAW_ALLOC(num_bytes) edhoc_mem_alloc(num_bytes)
#define EDHOC_MEM_RAW_FREE(ptr) edhoc_mem_free(ptr)

#endif /* heap vs custom raw allocator */

#define EDHOC_MEM_ALLOC(type, name, size)                                \
	type *name = (type *)EDHOC_MEM_RAW_ALLOC((size) * sizeof(type)); \
	const size_t name##_size = (size) * sizeof(type);                \
	(void)(name##_size)

#define EDHOC_MEM_ALLOC_SIZEOF(name) name##_size

#define EDHOC_MEM_FREE(name)              \
	do {                              \
		EDHOC_MEM_RAW_FREE(name); \
		(name) = NULL;            \
	} while (0)

#else /* invalid CONFIG_LIBEDHOC_MEM_BACKEND */

#error "Invalid CONFIG_LIBEDHOC_MEM_BACKEND value (expected 0, 1 or 2)."

#endif /* backend selection */

#define EDHOC_MEM_ALLOC_SIZE(x) (EDHOC_MEM_ALLOC_SIZEOF(x) / sizeof((x)[0]))

#endif /* __DOXYGEN__ */

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_BACKEND_MEMORY_H */
