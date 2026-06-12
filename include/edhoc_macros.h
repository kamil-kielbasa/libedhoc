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
