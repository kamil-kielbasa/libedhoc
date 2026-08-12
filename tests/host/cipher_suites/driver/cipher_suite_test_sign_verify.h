/**
 * \file    cipher_suite_test_sign_verify.h
 * \author  Kamil Kielbasa
 * \brief   Signature (\c sign / \c verify) tests for the cipher-suite driver.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef CIPHER_SUITE_TEST_SIGN_VERIFY_H
#define CIPHER_SUITE_TEST_SIGN_VERIFY_H

/* Include files ----------------------------------------------------------- */

/* Cipher-suite driver header: */
#include "cipher_suite_driver.h"

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Sign a random message and verify it against the raw public key.
 */
void cipher_suite_test_sign_verify(const struct cipher_suite_descriptor *suite);

/**
 * \brief Signing and verifying a zero-length input is rejected.
 */
void cipher_suite_test_sign_verify_zero_input(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A NULL key handle is rejected by \c sign.
 */
void cipher_suite_test_sign_null_args(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A signature buffer smaller than the fixed length is rejected.
 */
void cipher_suite_test_sign_small_buffer(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Signing with a destroyed key handle is rejected.
 */
void cipher_suite_test_sign_destroyed_key(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief EdDSA only: a key without EXPORT permission cannot sign.
 */
void cipher_suite_test_sign_non_exportable_key(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief EdDSA only: a key that exports fewer bytes than expected is rejected.
 */
void cipher_suite_test_sign_short_key(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief ECDSA only: a public key cannot be used as a signing key.
 */
void cipher_suite_test_sign_public_key(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: signing with a key handle of the wrong kind is rejected.
 */
void cipher_suite_test_sign_wrong_key_type_handle(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A NULL public key is rejected by \c verify.
 */
void cipher_suite_test_verify_null_args(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A single flipped signature byte must fail verification.
 */
void cipher_suite_test_verify_corrupted_signature(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Corrupting either signature half fails; the pristine one still passes.
 */
void cipher_suite_test_verify_bitflip_halves(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Tampering with the signed input must fail verification.
 */
void cipher_suite_test_verify_tampered_input(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A signature length other than the fixed length is rejected.
 */
void cipher_suite_test_verify_bad_signature_length(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A public key of the wrong length is rejected by \c verify.
 */
void cipher_suite_test_verify_bad_public_key_length(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: the ML-DSA-44 keystore import rejects NULL arguments.
 */
void cipher_suite_test_import_signing_key_null_args(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: the ML-DSA-44 keystore import rejects a wrong length.
 */
void cipher_suite_test_import_signing_key_bad_length(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: importing signing keys until the keystore is full.
 */
void cipher_suite_test_import_signing_key_keystore_full(
	const struct cipher_suite_descriptor *suite);

#endif /* CIPHER_SUITE_TEST_SIGN_VERIFY_H */
