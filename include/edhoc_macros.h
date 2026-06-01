/**
 * \file    edhoc_macros.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC utility macros.
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_MACROS_H
#define EDHOC_MACROS_H

/* Include files ----------------------------------------------------------- */
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-macros EDHOC utility macros
 * @{
 */

#ifdef __DOXYGEN__

/**
 * \brief Assert that the current thread has at least the requested amount of
 *        free stack space.
 *
 * On Zephyr expands to a runtime check using ``k_thread_stack_space_get`` and
 * ``__ASSERT`` (only when both ``CONFIG_THREAD_STACK_INFO`` and
 * ``CONFIG_ASSERT`` are enabled). On every other platform it compiles to a
 * no-op.
 *
 * \param required_bytes  Minimum number of free stack bytes required.
 */
#define EDHOC_ASSERT_FREE_STACK_SIZE(required_bytes)

/**
 * \brief Allocate a variable-length array on the stack.
 *
 * On GCC and Clang (Linux, Zephyr) uses a C99 VLA and asserts available stack
 * via \ref EDHOC_ASSERT_FREE_STACK_SIZE. On MSVC falls back to ``_alloca``.
 *
 * \param type  Element type.
 * \param name  Variable name for the allocated array.
 * \param size  Number of elements to allocate.
 */
#define VLA_ALLOC(type, name, size)

/**
 * \brief Return the total size in bytes of a VLA allocated with \ref VLA_ALLOC.
 *
 * \param name  Variable name used in \ref VLA_ALLOC.
 */
#define VLA_SIZEOF(name)

#else /* !__DOXYGEN__ */

#if defined(__ZEPHYR__) && defined(CONFIG_THREAD_STACK_INFO) && defined(CONFIG_ASSERT)

#include <zephyr/kernel.h>
#include <zephyr/sys/__assert.h>

#define EDHOC_ASSERT_FREE_STACK_SIZE(required_bytes)                            \
	do {                                                                    \
		size_t _unused = 0;                                             \
		int _err = k_thread_stack_space_get(k_current_get(), &_unused); \
		__ASSERT_NO_MSG(_err == 0);                                     \
		__ASSERT(_unused >= (size_t)(required_bytes),                   \
			 "Insufficient stack: %zu bytes free, %zu required",    \
			 _unused, (size_t)(required_bytes));                    \
	} while (0)
#else
#define EDHOC_ASSERT_FREE_STACK_SIZE(required_bytes) \
	do {                                         \
	} while (0)
#endif

#if defined(_WIN32) || defined(_MSC_VER)

#include <malloc.h>

#define VLA_ALLOC(type, name, size)                \
	type *name = _alloca(size * sizeof(type)); \
	const size_t name##_size = size * sizeof(type)

#define VLA_SIZEOF(name) name##_size

#else /* Linux & Zephyr */

#define VLA_ALLOC(type, name, size)                          \
	EDHOC_ASSERT_FREE_STACK_SIZE((size) * sizeof(type)); \
	type name[size]

#define VLA_SIZEOF(name) sizeof(name)

#endif

#endif /* __DOXYGEN__ */

/**
 * \brief Return the number of elements in a VLA allocated with \ref VLA_ALLOC.
 *
 * \param x  Variable name used in \ref VLA_ALLOC.
 */
#define VLA_SIZE(x) (VLA_SIZEOF(x) / sizeof((x)[0]))

/**
 * \brief Compute the number of elements in a statically allocated array.
 *
 * \param x  Array variable (must not be a pointer).
 */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif /* ARRAY_SIZE */

/**
 * \brief Access control macro for context structure members.
 *
 * When ``EDHOC_ALLOW_PRIVATE_ACCESS`` is **not** defined, each member is
 * prefixed with ``private_`` to discourage direct access. Defining
 * ``EDHOC_ALLOW_PRIVATE_ACCESS`` removes the prefix, granting direct access.
 *
 * \param member  Structure member name.
 */
#ifndef EDHOC_ALLOW_PRIVATE_ACCESS
#define EDHOC_PRIVATE(member) private_##member
#else
#define EDHOC_PRIVATE(member) member
#endif

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_MACROS_H */
