/**
 * \file    edhoc_macros.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC utility macros.
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
 * \brief Compute the number of elements in a statically allocated array.
 *
 * \param x  Array variable (must not be a pointer).
 */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif /* ARRAY_SIZE */

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

#endif /* EDHOC_MACROS_H */
