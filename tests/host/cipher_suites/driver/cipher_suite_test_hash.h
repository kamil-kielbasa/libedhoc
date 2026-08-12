/**
 * \file    cipher_suite_test_hash.h
 * \author  Kamil Kielbasa
 * \brief   Hash tests for the cipher-suite driver
 *          (\c hash_init, \c hash_update, \c hash_finish, \c hash_abort).
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef CIPHER_SUITE_TEST_HASH_H
#define CIPHER_SUITE_TEST_HASH_H

/* Include files ----------------------------------------------------------- */

/* Cipher-suite driver header: */
#include "cipher_suite_driver.h"

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Hash a known-answer input across a multipart operation and match it.
 */
void cipher_suite_test_hash(const struct cipher_suite_descriptor *suite);

/**
 * \brief NULL arguments are rejected by every hash entry point.
 */
void cipher_suite_test_hash_null_args(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A hash buffer smaller than the digest is rejected by \c hash_finish.
 */
void cipher_suite_test_hash_small_buffer(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Aborting a hash returns its slot to the operation pool.
 */
void cipher_suite_test_hash_abort_frees_pool_slot(
	const struct cipher_suite_descriptor *suite);

#endif /* CIPHER_SUITE_TEST_HASH_H */
