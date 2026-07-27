/**
 * \file    cipher_suite_test_getters.h
 * \author  Kamil Kielbasa
 * \brief   Enum-keyed getter test for the cipher-suite driver.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef CIPHER_SUITE_TEST_GETTERS_H
#define CIPHER_SUITE_TEST_GETTERS_H

/* Include files ----------------------------------------------------------- */

/* Cipher-suite driver header: */
#include "cipher_suite_driver.h"

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Assert the enum-keyed getters resolve this suite: every parameter is
 *        canonical and every crypto operation is wired.
 */
void cipher_suite_test_enum_getters(const struct cipher_suite_descriptor *suite);

#endif /* CIPHER_SUITE_TEST_GETTERS_H */
