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

/**
 * \brief Allocate a variable-length array on the stack.
 *
 * On GCC and Clang this uses C99 VLA. On MSVC it falls back to ``_alloca``.
 *
 * \param type  Element type.
 * \param name  Variable name for the allocated array.
 * \param size  Number of elements to allocate.
 */
#if defined(_WIN32) || defined(_MSC_VER)
#include <malloc.h>
#define VLA_ALLOC(type, name, size)                \
	type *name = _alloca(size * sizeof(type)); \
	const size_t name##_size = size * sizeof(type)

/**
 * \brief Return the total size in bytes of a VLA allocated with \ref VLA_ALLOC.
 *
 * \param name  Variable name used in \ref VLA_ALLOC.
 */
#define VLA_SIZEOF(name) name##_size
#else
#define VLA_ALLOC(type, name, size) type name[size]
#define VLA_SIZEOF(name) sizeof(name)
#endif

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
