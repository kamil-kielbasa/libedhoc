/**
 * \file    edhoc_macros.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC macros and functionlike macros.
 * \version 0.3
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_MACROS_H
#define EDHOC_MACROS_H

/* Include files ----------------------------------------------------------- */
/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/**
 * \brief Macro for calculating arrays length.
 */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

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
