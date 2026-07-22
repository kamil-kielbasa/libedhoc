/**
 * \file    edhoc_macros_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC utility macros.
 * 
 * \copyright Copyright (c) 2026
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_MACROS_INTERNAL_H
#define EDHOC_MACROS_INTERNAL_H

/* Include files ----------------------------------------------------------- */
#include <stddef.h>

#if defined(__ZEPHYR__)
#include <zephyr/sys/__assert.h>
#else
#include <assert.h>
#endif

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-macros EDHOC utility macros
 * @{
 */

/**
 * \brief Compute the number of elements in a statically allocated array.
 *
 * \param x  Array variable (must not be a pointer).
 */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif /* ARRAY_SIZE */

/**
 * \brief Assert a precondition inside the library and reference backends.
 *
 * Maps to Zephyr's \c __ASSERT_NO_MSG on Zephyr targets and to the C standard
 * \c assert elsewhere, so the same precondition checks build on both. Like any
 * assertion it is compiled out in release builds (\c CONFIG_ASSERT disabled on
 * Zephyr, \c NDEBUG defined otherwise), so it must guard programmer errors,
 * never untrusted input.
 *
 * \param cond  Condition that must hold.
 */
#if defined(__ZEPHYR__)
#define EDHOC_ASSERT(cond) __ASSERT_NO_MSG(cond)
#else
#define EDHOC_ASSERT(cond) assert(cond)
#endif

/**
 * \brief Internal linkage control for module-test builds.
 *
 * When ``LIBEDHOC_MODULE_TESTS`` is defined at library compile time, internal
 * functions become externally visible so the test binary can link against them
 * via ``extern`` declarations.  Production builds keep ``static`` linkage.
 *
 * All internal functions in the library use ``STATIC`` instead of ``static``.
 */
#if defined(LIBEDHOC_MODULE_TESTS)
#define STATIC
#else
#define STATIC static
#endif

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_MACROS_INTERNAL_H */
