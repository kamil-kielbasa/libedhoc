/**
 * \file    cipher_suite_test_getters.c
 * \author  Kamil Kielbasa
 * \brief   Implementation of the cipher-suite enum-keyed getter test.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Cipher-suite driver headers: */
#include "cipher_suite_test_getters.h"
#include "cipher_suite_driver.h"

/* EDHOC headers: */
#include <edhoc/crypto.h>
#include <edhoc/cipher_suite.h>

/* Unity headers: */
#include <unity.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

void cipher_suite_test_enum_getters(const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	const struct edhoc_cipher_suite *expected = &suite->expected;

	/* The enum-keyed dispatchers resolve to a wired reference suite. */
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	/* Every descriptor parameter has its canonical value. */
	TEST_ASSERT_EQUAL_INT32(expected->value, params->value);
	TEST_ASSERT_EQUAL(expected->supports_dh_nike, params->supports_dh_nike);
	TEST_ASSERT_EQUAL(expected->kem_encapsulation_key_length,
			  params->kem_encapsulation_key_length);
	TEST_ASSERT_EQUAL(expected->kem_ciphertext_length,
			  params->kem_ciphertext_length);
	TEST_ASSERT_EQUAL(expected->nike_key_length, params->nike_key_length);
	TEST_ASSERT_EQUAL(expected->sign_length, params->sign_length);
	TEST_ASSERT_EQUAL(expected->aead_key_length, params->aead_key_length);
	TEST_ASSERT_EQUAL(expected->aead_tag_length, params->aead_tag_length);
	TEST_ASSERT_EQUAL(expected->aead_iv_length, params->aead_iv_length);
	TEST_ASSERT_EQUAL(expected->hash_length, params->hash_length);
	TEST_ASSERT_EQUAL(expected->mac_length, params->mac_length);

	/* Every crypto operation is wired. */
	TEST_ASSERT_NOT_NULL(crypto->destroy_key);
	TEST_ASSERT_NOT_NULL(crypto->generate_key_pair);
	TEST_ASSERT_NOT_NULL(crypto->encapsulate);
	TEST_ASSERT_NOT_NULL(crypto->decapsulate);
	TEST_ASSERT_NOT_NULL(crypto->key_agreement);
	TEST_ASSERT_NOT_NULL(crypto->sign);
	TEST_ASSERT_NOT_NULL(crypto->verify);
	TEST_ASSERT_NOT_NULL(crypto->extract);
	TEST_ASSERT_NOT_NULL(crypto->expand);
	TEST_ASSERT_NOT_NULL(crypto->expand_raw);
	TEST_ASSERT_NOT_NULL(crypto->aead_encrypt);
	TEST_ASSERT_NOT_NULL(crypto->aead_decrypt);
	TEST_ASSERT_NOT_NULL(crypto->hash_init);
	TEST_ASSERT_NOT_NULL(crypto->hash_update);
	TEST_ASSERT_NOT_NULL(crypto->hash_finish);
	TEST_ASSERT_NOT_NULL(crypto->hash_abort);
}
