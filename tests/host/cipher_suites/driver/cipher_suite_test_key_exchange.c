/**
 * \file    cipher_suite_test_key_exchange.c
 * \author  Kamil Kielbasa
 * \brief   Implementation of the cipher-suite key-exchange tests.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Cipher-suite driver headers: */
#include "cipher_suite_test_key_exchange.h"
#include "cipher_suite_driver.h"

/* EDHOC headers: */
#include <edhoc/crypto.h>
#include <edhoc/cipher_suite.h>
#include <edhoc/values.h>
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Unity headers: */
#include <unity.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Module defines ---------------------------------------------------------- */

/** \brief Length derived from a shared secret to prove two handles match. */
#define CIPHER_SUITE_KEY_CHECK_LENGTH ((size_t)32)

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

void cipher_suite_test_key_agreement_roundtrip(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* Two ephemeral key pairs; a correct agreement yields one shared secret
	 * from either side. The secret is non-exportable, so equality is proven
	 * by deriving through expand_raw and comparing the outputs. */
	psa_key_id_t key_id_a = PSA_KEY_ID_NULL;
	psa_key_id_t key_id_b = PSA_KEY_ID_NULL;

	size_t public_key_a_length = 0;
	uint8_t public_key_a[params->kem_encapsulation_key_length];
	memset(public_key_a, 0, sizeof(public_key_a));

	size_t public_key_b_length = 0;
	uint8_t public_key_b[params->kem_encapsulation_key_length];
	memset(public_key_b, 0, sizeof(public_key_b));

	ret = crypto->generate_key_pair(NULL, &key_id_a, public_key_a,
					ARRAY_SIZE(public_key_a),
					&public_key_a_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(params->nike_key_length, public_key_a_length);

	ret = crypto->generate_key_pair(NULL, &key_id_b, public_key_b,
					ARRAY_SIZE(public_key_b),
					&public_key_b_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(params->nike_key_length, public_key_b_length);

	psa_key_id_t shared_secret_a = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret_b = PSA_KEY_ID_NULL;

	ret = crypto->key_agreement(NULL, &key_id_a, public_key_b,
				    public_key_b_length, &shared_secret_a);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = crypto->key_agreement(NULL, &key_id_b, public_key_a,
				    public_key_a_length, &shared_secret_b);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t info[] = { 'e', 'd', 'h', 'o', 'c', 'k', 'a', 't' };
	uint8_t output_a[CIPHER_SUITE_KEY_CHECK_LENGTH] = { 0 };
	uint8_t output_b[CIPHER_SUITE_KEY_CHECK_LENGTH] = { 0 };

	ret = crypto->expand_raw(NULL, &shared_secret_a, info, ARRAY_SIZE(info),
				 output_a, ARRAY_SIZE(output_a));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = crypto->expand_raw(NULL, &shared_secret_b, info, ARRAY_SIZE(info),
				 output_b, ARRAY_SIZE(output_b));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(output_a, output_b, ARRAY_SIZE(output_a));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  crypto->destroy_key(NULL, &shared_secret_a));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  crypto->destroy_key(NULL, &shared_secret_b));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, crypto->destroy_key(NULL, &key_id_a));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, crypto->destroy_key(NULL, &key_id_b));
}

void cipher_suite_test_kem_roundtrip(const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* Encapsulate to a responder's public key, then have the responder
	 * decapsulate the ciphertext; both shared secrets must match. */
	psa_key_id_t responder_decapsulation = PSA_KEY_ID_NULL;

	size_t responder_encapsulation_key_length = 0;
	uint8_t responder_encapsulation_key[params->kem_encapsulation_key_length];
	memset(responder_encapsulation_key, 0,
	       sizeof(responder_encapsulation_key));

	ret = crypto->generate_key_pair(NULL, &responder_decapsulation,
					responder_encapsulation_key,
					ARRAY_SIZE(responder_encapsulation_key),
					&responder_encapsulation_key_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	psa_key_id_t initiator_decapsulation = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret_initiator = PSA_KEY_ID_NULL;

	uint8_t ciphertext[params->kem_ciphertext_length];
	memset(ciphertext, 0, sizeof(ciphertext));
	size_t ciphertext_length = 0;

	ret = crypto->encapsulate(NULL, responder_encapsulation_key,
				  responder_encapsulation_key_length,
				  &initiator_decapsulation,
				  &shared_secret_initiator, ciphertext,
				  ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(params->kem_ciphertext_length, ciphertext_length);

	psa_key_id_t shared_secret_responder = PSA_KEY_ID_NULL;

	ret = crypto->decapsulate(NULL, &responder_decapsulation, ciphertext,
				  ciphertext_length, &shared_secret_responder);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t info[] = { 'k', 'e', 'm' };
	uint8_t output_initiator[CIPHER_SUITE_KEY_CHECK_LENGTH] = { 0 };
	uint8_t output_responder[CIPHER_SUITE_KEY_CHECK_LENGTH] = { 0 };

	ret = crypto->expand_raw(NULL, &shared_secret_initiator, info,
				 ARRAY_SIZE(info), output_initiator,
				 ARRAY_SIZE(output_initiator));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = crypto->expand_raw(NULL, &shared_secret_responder, info,
				 ARRAY_SIZE(info), output_responder,
				 ARRAY_SIZE(output_responder));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(output_initiator, output_responder,
				      ARRAY_SIZE(output_initiator));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  crypto->destroy_key(NULL, &shared_secret_initiator));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  crypto->destroy_key(NULL, &shared_secret_responder));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  crypto->destroy_key(NULL, &initiator_decapsulation));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  crypto->destroy_key(NULL, &responder_decapsulation));
}

void cipher_suite_test_generate_key_pair_null_args(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t key_id = PSA_KEY_ID_NULL;

	size_t public_key_length = 0;
	uint8_t public_key[params->kem_encapsulation_key_length];
	memset(public_key, 0, sizeof(public_key));

	ret = crypto->generate_key_pair(NULL, NULL, public_key,
					ARRAY_SIZE(public_key),
					&public_key_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->generate_key_pair(NULL, &key_id, NULL,
					ARRAY_SIZE(public_key),
					&public_key_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->generate_key_pair(NULL, &key_id, public_key, 0,
					&public_key_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->generate_key_pair(NULL, &key_id, public_key,
					ARRAY_SIZE(public_key), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_generate_key_pair_small_buffer(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t key_id = PSA_KEY_ID_NULL;

	uint8_t public_key[params->kem_encapsulation_key_length / 2U];
	memset(public_key, 0, sizeof(public_key));
	size_t public_key_length = 0;

	ret = crypto->generate_key_pair(NULL, &key_id, public_key,
					ARRAY_SIZE(public_key),
					&public_key_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

void cipher_suite_test_key_agreement_null_args(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t shared_secret = PSA_KEY_ID_NULL;

	ret = crypto->key_agreement(NULL, NULL, NULL, 0, &shared_secret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_key_agreement_bad_point(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t key_id = cipher_suite_import_nike_key(
		suite, suite->nike.private_key.pointer,
		suite->nike.private_key.length);

	/* Correct length, but not a valid coordinate on the curve. */
	uint8_t bad_peer[params->nike_key_length];
	memset(bad_peer, 0xFF, sizeof(bad_peer));

	psa_key_id_t shared_secret = PSA_KEY_ID_NULL;

	ret = crypto->key_agreement(NULL, &key_id, bad_peer,
				    ARRAY_SIZE(bad_peer), &shared_secret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_key_agreement_peer_key_too_short(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t key_id = cipher_suite_import_nike_key(
		suite, suite->nike.private_key.pointer,
		suite->nike.private_key.length);

	/* A peer key shorter than the curve length is rejected, not asserted. */
	uint8_t short_peer[params->nike_key_length / 2U];
	memset(short_peer, 0x41, sizeof(short_peer));

	psa_key_id_t shared_secret = PSA_KEY_ID_NULL;

	ret = crypto->key_agreement(NULL, &key_id, short_peer,
				    ARRAY_SIZE(short_peer), &shared_secret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_key_agreement_peer_key_too_long(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t key_id = cipher_suite_import_nike_key(
		suite, suite->nike.private_key.pointer,
		suite->nike.private_key.length);

	/* A peer key longer than the curve length is rejected, not asserted. */
	uint8_t long_peer[params->nike_key_length + 1U];
	memset(long_peer, 0x41, sizeof(long_peer));

	psa_key_id_t shared_secret = PSA_KEY_ID_NULL;

	ret = crypto->key_agreement(NULL, &key_id, long_peer,
				    ARRAY_SIZE(long_peer), &shared_secret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_key_agreement_wrong_key_type(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* A signing key is not a key-agreement key and must not agree. */
	psa_key_id_t key_id = cipher_suite_import_sign_key(
		suite, suite->sign.private_key.pointer,
		suite->sign.private_key.length);

	uint8_t peer[params->nike_key_length];
	memset(peer, 0x42, sizeof(peer));

	psa_key_id_t shared_secret = PSA_KEY_ID_NULL;

	ret = crypto->key_agreement(NULL, &key_id, peer, ARRAY_SIZE(peer),
				    &shared_secret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_key_agreement_destroyed_key(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t key_id = cipher_suite_import_nike_key(
		suite, suite->nike.private_key.pointer,
		suite->nike.private_key.length);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t peer[params->nike_key_length];
	memset(peer, 0x42, sizeof(peer));

	psa_key_id_t shared_secret = PSA_KEY_ID_NULL;

	ret = crypto->key_agreement(NULL, &key_id, peer, ARRAY_SIZE(peer),
				    &shared_secret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

void cipher_suite_test_key_agreement_not_supported(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* A KEM suite is not a NIKE: static Diffie-Hellman is unsupported.  */
	psa_key_id_t private_key_id = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret = PSA_KEY_ID_NULL;
	const uint8_t peer_public_key[32] = { 0 };

	ret = crypto->key_agreement(NULL, &private_key_id, peer_public_key,
				    ARRAY_SIZE(peer_public_key),
				    &shared_secret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);
}

void cipher_suite_test_destroy_key_null_args(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	ret = crypto->destroy_key(NULL, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_destroy_key_invalid_handle(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t key_id = 0xDEADBEEF;

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

void cipher_suite_test_encapsulate_null_args(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t decapsulation = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret = PSA_KEY_ID_NULL;

	uint8_t encapsulation_key[params->kem_encapsulation_key_length];
	memset(encapsulation_key, 0, sizeof(encapsulation_key));
	uint8_t ciphertext[params->kem_ciphertext_length];
	memset(ciphertext, 0, sizeof(ciphertext));
	size_t ciphertext_length = 0;

	ret = crypto->encapsulate(NULL, NULL, ARRAY_SIZE(encapsulation_key),
				  &decapsulation, &shared_secret, ciphertext,
				  ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->encapsulate(NULL, encapsulation_key, 0, &decapsulation,
				  &shared_secret, ciphertext,
				  ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->encapsulate(NULL, encapsulation_key,
				  ARRAY_SIZE(encapsulation_key), NULL,
				  &shared_secret, ciphertext,
				  ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->encapsulate(NULL, encapsulation_key,
				  ARRAY_SIZE(encapsulation_key), &decapsulation,
				  NULL, ciphertext, ARRAY_SIZE(ciphertext),
				  &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->encapsulate(NULL, encapsulation_key,
				  ARRAY_SIZE(encapsulation_key), &decapsulation,
				  &shared_secret, NULL, ARRAY_SIZE(ciphertext),
				  &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->encapsulate(NULL, encapsulation_key,
				  ARRAY_SIZE(encapsulation_key), &decapsulation,
				  &shared_secret, ciphertext,
				  ARRAY_SIZE(ciphertext), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_encapsulate_bad_encapsulation_key_length(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t decapsulation = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret = PSA_KEY_ID_NULL;

	uint8_t encapsulation_key[params->kem_encapsulation_key_length];
	memset(encapsulation_key, 0, sizeof(encapsulation_key));

	size_t ciphertext_length = 0;
	uint8_t ciphertext[params->kem_ciphertext_length];
	memset(ciphertext, 0, sizeof(ciphertext));

	ret = crypto->encapsulate(NULL, encapsulation_key,
				  ARRAY_SIZE(encapsulation_key) - 1U,
				  &decapsulation, &shared_secret, ciphertext,
				  ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_encapsulate_ciphertext_too_small(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t decapsulation = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret = PSA_KEY_ID_NULL;

	uint8_t encapsulation_key[params->kem_encapsulation_key_length];
	memset(encapsulation_key, 0, sizeof(encapsulation_key));
	uint8_t ciphertext[params->kem_ciphertext_length - 1U];
	memset(ciphertext, 0, sizeof(ciphertext));
	size_t ciphertext_length = 0;

	ret = crypto->encapsulate(NULL, encapsulation_key,
				  ARRAY_SIZE(encapsulation_key), &decapsulation,
				  &shared_secret, ciphertext,
				  ARRAY_SIZE(ciphertext), &ciphertext_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

void cipher_suite_test_decapsulate_null_args(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t decapsulation = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret = PSA_KEY_ID_NULL;

	uint8_t ciphertext[params->kem_ciphertext_length];
	memset(ciphertext, 0, sizeof(ciphertext));

	ret = crypto->decapsulate(NULL, NULL, ciphertext,
				  ARRAY_SIZE(ciphertext), &shared_secret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->decapsulate(NULL, &decapsulation, NULL,
				  ARRAY_SIZE(ciphertext), &shared_secret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->decapsulate(NULL, &decapsulation, ciphertext, 0,
				  &shared_secret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->decapsulate(NULL, &decapsulation, ciphertext,
				  ARRAY_SIZE(ciphertext), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_decapsulate_bad_ciphertext_length(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t decapsulation = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret = PSA_KEY_ID_NULL;

	uint8_t ciphertext[params->kem_ciphertext_length];
	memset(ciphertext, 0, sizeof(ciphertext));

	ret = crypto->decapsulate(NULL, &decapsulation, ciphertext,
				  ARRAY_SIZE(ciphertext) - 1U, &shared_secret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_decapsulate_stale_handle(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	psa_key_id_t decapsulation = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret = PSA_KEY_ID_NULL;

	size_t encapsulation_key_length = 0;
	uint8_t encapsulation_key[params->kem_encapsulation_key_length];
	memset(encapsulation_key, 0, sizeof(encapsulation_key));

	uint8_t ciphertext[params->kem_ciphertext_length];
	memset(ciphertext, 0, sizeof(ciphertext));

	ret = crypto->generate_key_pair(NULL, &decapsulation, encapsulation_key,
					ARRAY_SIZE(encapsulation_key),
					&encapsulation_key_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Free the decapsulation slot, then use its stale handle. */
	ret = crypto->destroy_key(NULL, &decapsulation);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = crypto->decapsulate(NULL, &decapsulation, ciphertext,
				  ARRAY_SIZE(ciphertext), &shared_secret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

void cipher_suite_test_decapsulate_wrong_key_type_handle(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* A signing-key slot holds an ML-DSA-44 secret whose length differs
	 * from an ML-KEM-512 decapsulation key, so borrowing it as one is a
	 * valid keystore handle but must still be rejected on the length
	 * check. */
	psa_key_id_t key_id = cipher_suite_import_sign_key(
		suite, suite->sign.private_key.pointer,
		suite->sign.private_key.length);
	psa_key_id_t shared_secret = PSA_KEY_ID_NULL;

	uint8_t ciphertext[params->kem_ciphertext_length];
	memset(ciphertext, 0, sizeof(ciphertext));

	ret = crypto->decapsulate(NULL, &key_id, ciphertext,
				  ARRAY_SIZE(ciphertext), &shared_secret);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_keystore_exhaustion(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* Fill the software keystore until it rejects a new key, then release
	 * every slot that was taken (the keystore is static across tests). */
	size_t filled = 0;
	int last = EDHOC_SUCCESS;

	psa_key_id_t decapsulation_ids[16] = { 0 };

	size_t encapsulation_key_length = 0;
	uint8_t encapsulation_key[params->kem_encapsulation_key_length];
	memset(encapsulation_key, 0, sizeof(encapsulation_key));

	for (size_t i = 0; i < ARRAY_SIZE(decapsulation_ids); ++i) {
		last = crypto->generate_key_pair(NULL, &decapsulation_ids[i],
						 encapsulation_key,
						 ARRAY_SIZE(encapsulation_key),
						 &encapsulation_key_length);

		if (EDHOC_SUCCESS != last) {
			break;
		}

		filled += 1;
	}

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, last);
	TEST_ASSERT_GREATER_THAN(0, filled);

	for (size_t i = 0; i < filled; ++i) {
		ret = crypto->destroy_key(NULL, &decapsulation_ids[i]);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}
