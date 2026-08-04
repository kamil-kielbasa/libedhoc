/**
 * \file    cipher_suite_test_aead.h
 * \author  Kamil Kielbasa
 * \brief   AEAD tests for the cipher-suite driver
 *          (\c aead_encrypt, \c aead_decrypt).
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef CIPHER_SUITE_TEST_AEAD_H
#define CIPHER_SUITE_TEST_AEAD_H

/* Include files ----------------------------------------------------------- */

/* Cipher-suite driver header: */
#include "cipher_suite_driver.h"

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Encrypt then decrypt a plaintext and recover it unchanged.
 */
void cipher_suite_test_aead(const struct cipher_suite_descriptor *suite);

/**
 * \brief Encrypt and decrypt an empty plaintext (a bare authentication tag).
 */
void cipher_suite_test_aead_empty_plaintext(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A flipped authentication-tag bit is detected on decryption.
 */
void cipher_suite_test_aead_tag_tamper(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Associated data that differs on decryption is detected.
 */
void cipher_suite_test_aead_aad_tamper(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A NULL key handle is rejected by \c aead_encrypt.
 */
void cipher_suite_test_encrypt_null_args(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A key of the wrong type must not encrypt.
 */
void cipher_suite_test_encrypt_wrong_key_type(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Encrypting with a destroyed key handle is rejected.
 */
void cipher_suite_test_encrypt_destroyed_key(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A NULL key handle is rejected by \c aead_decrypt.
 */
void cipher_suite_test_decrypt_null_args(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief A key of the wrong type must not decrypt.
 */
void cipher_suite_test_decrypt_wrong_key_type(
	const struct cipher_suite_descriptor *suite);

/**
 * \brief Decrypting with a destroyed key handle is rejected.
 */
void cipher_suite_test_decrypt_destroyed_key(
	const struct cipher_suite_descriptor *suite);

#endif /* CIPHER_SUITE_TEST_AEAD_H */
