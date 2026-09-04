/**
 * \file    cipher_suite_test_kdf.h
 * \author  Kamil Kielbasa
 * \brief   Key-derivation tests for the cipher-suite driver
 *          (\c extract, \c expand, \c expand_raw).
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef CIPHER_SUITE_TEST_KDF_H
#define CIPHER_SUITE_TEST_KDF_H

/* Include files ----------------------------------------------------------- */

/* Cipher-suite driver header: */
#include "cipher_suite_driver.h"

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Extract then expand a known-answer test vector (HKDF or KMAC256).
 *
 *        The intermediate pseudorandom key is not exportable, so the KAT is
 *        asserted on the expanded output, which transitively validates extract.
 */
void cipher_suite_test_kdf(const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: KMAC256 extract and expand match the same KAT vector.
 */
void cipher_suite_test_kmac256_kat(const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: \c expand yields KDF and AEAD key handles that work.
 */
void cipher_suite_test_expand_handles(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A NULL input keying material handle is rejected by \c extract.
 */
void cipher_suite_test_extract_null_args(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A key of the wrong type must not seed \c extract.
 */
void cipher_suite_test_extract_wrong_key_type(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief \c extract with a destroyed key handle is rejected.
 */
void cipher_suite_test_extract_destroyed_key(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: NULL arguments are rejected by \c expand.
 */
void cipher_suite_test_expand_derive_null_args(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: an unknown key-usage value is rejected by \c expand.
 */
void cipher_suite_test_expand_invalid_usage(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: \c expand with a destroyed pseudorandom key is rejected.
 */
void cipher_suite_test_expand_derive_stale_prk(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A NULL pseudorandom key handle is rejected by \c expand_raw.
 */
void cipher_suite_test_expand_null_args(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: NULL arguments are rejected by \c expand_raw.
 */
void cipher_suite_test_expand_raw_null_args(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A key of the wrong type must not seed \c expand_raw.
 */
void cipher_suite_test_expand_wrong_key_type(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief \c expand_raw with a destroyed key handle is rejected.
 */
void cipher_suite_test_expand_destroyed_key(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief An output longer than the KDF maximum is rejected by \c expand_raw.
 */
void cipher_suite_test_expand_output_too_large(
	const struct cipher_suite_descriptor *suite);

#endif /* CIPHER_SUITE_TEST_KDF_H */
