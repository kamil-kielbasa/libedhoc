/**
 * \file    cipher_suite_test_key_exchange.h
 * \author  Kamil Kielbasa
 * \brief   Key-exchange and key-lifecycle tests for the cipher-suite driver
 *          (\c generate_key_pair, \c encapsulate, \c decapsulate,
 *          \c key_agreement, \c destroy_key).
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef CIPHER_SUITE_TEST_KEY_EXCHANGE_H
#define CIPHER_SUITE_TEST_KEY_EXCHANGE_H

/* Include files ----------------------------------------------------------- */

/* Cipher-suite driver header: */
#include "cipher_suite_driver.h"

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Two ephemeral static-DH pairs agree on one shared secret (NIKE).
 */
void cipher_suite_test_key_agreement_roundtrip(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Encapsulate to a fresh public key and decapsulate it back (KEM).
 */
void cipher_suite_test_kem_roundtrip(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A NULL key handle or public-key buffer is rejected by
 *        \c generate_key_pair.
 */
void cipher_suite_test_generate_key_pair_null_args(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A public-key buffer smaller than the encapsulation key is rejected.
 */
void cipher_suite_test_generate_key_pair_small_buffer(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A NULL private key handle is rejected by \c key_agreement.
 */
void cipher_suite_test_key_agreement_null_args(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief EC curves only: a peer key of the right length but not on the curve
 *        is rejected by \c key_agreement.
 */
void cipher_suite_test_key_agreement_bad_point(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A peer key shorter than the curve length is rejected.
 */
void cipher_suite_test_key_agreement_peer_key_too_short(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A peer key longer than the curve length is rejected.
 */
void cipher_suite_test_key_agreement_peer_key_too_long(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A key of the wrong type must not perform key agreement.
 */
void cipher_suite_test_key_agreement_wrong_key_type(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Key agreement with a destroyed key handle is rejected.
 */
void cipher_suite_test_key_agreement_destroyed_key(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: a KEM suite must reject static Diffie-Hellman.
 */
void cipher_suite_test_key_agreement_not_supported(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A NULL handle is rejected by \c destroy_key.
 */
void cipher_suite_test_destroy_key_null_args(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Destroying an unknown key handle is rejected.
 */
void cipher_suite_test_destroy_key_invalid_handle(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: NULL arguments are rejected by \c encapsulate.
 */
void cipher_suite_test_encapsulate_null_args(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: a wrong encapsulation-key length is rejected.
 */
void cipher_suite_test_encapsulate_bad_encapsulation_key_length(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: a ciphertext buffer that is too small is rejected.
 */
void cipher_suite_test_encapsulate_ciphertext_too_small(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: NULL arguments are rejected by \c decapsulate.
 */
void cipher_suite_test_decapsulate_null_args(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: a wrong ciphertext length is rejected by \c decapsulate.
 */
void cipher_suite_test_decapsulate_bad_ciphertext_length(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: decapsulating with a destroyed handle is rejected.
 */
void cipher_suite_test_decapsulate_stale_handle(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: decapsulating with a wrong-kind handle is rejected.
 */
void cipher_suite_test_decapsulate_wrong_key_type_handle(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Post-quantum: generating key pairs until the keystore is full.
 */
void cipher_suite_test_keystore_exhaustion(
	const struct cipher_suite_descriptor *suite);

#endif /* CIPHER_SUITE_TEST_KEY_EXCHANGE_H */
