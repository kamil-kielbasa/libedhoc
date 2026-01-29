/**
 * \file    edhoc_macros.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC macros and functionlike macros.
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

/**
 * \brief Macros for hiding dynamic stack allocations:
 *        - GCC and Clang support C99 feature VLA. (Variable Length Array)
 *        - MSVC supports only alloca. Lack of VLA.
 */
#if defined(_WIN32) || defined(_MSC_VER)
#include <malloc.h>
#define VLA_ALLOC(type, name, size)                \
	type *name = _alloca(size * sizeof(type)); \
	const size_t name##_size = size * sizeof(type)
#define VLA_SIZEOF(name) name##_size
#else
#define VLA_ALLOC(type, name, size) type name[size]
#define VLA_SIZEOF(name) sizeof(name)
#endif

#define VLA_SIZE(x) (VLA_SIZEOF(x) / sizeof(x[0]))

/**
 * \brief Macro for calculating arrays length.
 */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif /* ARRAY_SIZE */

/**
 * \brief Macro which allows for private access into structure members.
 */
#ifndef EDHOC_ALLOW_PRIVATE_ACCESS
#define EDHOC_PRIVATE(member) private_##member
#else
#define EDHOC_PRIVATE(member) member
#endif

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_MACROS_H */
