/**
 * \file    cipher_suite_test_sign_verify.c
 * \author  Kamil Kielbasa
 * \brief   Implementation of the cipher-suite signature tests.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Cipher-suite driver headers: */
#include "cipher_suite_test_sign_verify.h"
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
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

void cipher_suite_test_sign_verify(const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(params);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	uint8_t input[128] = { 0 };
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_generate_random(input, ARRAY_SIZE(input)));

	psa_key_id_t key_id = cipher_suite_import_sign_key(
		suite, suite->sign.private_key.pointer,
		suite->sign.private_key.length);

	size_t signature_length = 0;
	uint8_t signature[params->sign_length];
	memset(signature, 0, sizeof(signature));

	ret = crypto->sign(NULL, &key_id, input, ARRAY_SIZE(input), signature,
			   ARRAY_SIZE(signature), &signature_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(params->sign_length, signature_length);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* verify() takes the peer's raw public key; no key handle involved. */
	ret = crypto->verify(NULL, suite->sign.public_key.pointer,
			     suite->sign.public_key.length, input,
			     ARRAY_SIZE(input), signature, signature_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_sign_verify_zero_input(
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

	psa_key_id_t key_id = cipher_suite_import_sign_key(
		suite, suite->sign.private_key.pointer,
		suite->sign.private_key.length);

	uint8_t dummy = 0;

	size_t signature_length = 0;
	uint8_t signature[params->sign_length];
	memset(signature, 0, sizeof(signature));

	ret = crypto->sign(NULL, &key_id, &dummy, 0, signature,
			   ARRAY_SIZE(signature), &signature_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t fake_signature[params->sign_length];
	memset(fake_signature, 0, sizeof(fake_signature));

	ret = crypto->verify(NULL, suite->sign.public_key.pointer,
			     suite->sign.public_key.length, &dummy, 0,
			     fake_signature, ARRAY_SIZE(fake_signature));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_sign_null_args(
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

	const uint8_t input[16] = { 0 };

	size_t signature_length = 0;
	uint8_t signature[params->sign_length];
	memset(signature, 0, sizeof(signature));

	ret = crypto->sign(NULL, NULL, input, ARRAY_SIZE(input), signature,
			   ARRAY_SIZE(signature), &signature_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->sign(NULL, &key_id, NULL, ARRAY_SIZE(input), signature,
			   ARRAY_SIZE(signature), &signature_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->sign(NULL, &key_id, input, 0, signature,
			   ARRAY_SIZE(signature), &signature_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->sign(NULL, &key_id, input, ARRAY_SIZE(input), NULL,
			   ARRAY_SIZE(signature), &signature_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->sign(NULL, &key_id, input, ARRAY_SIZE(input), signature,
			   0, &signature_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->sign(NULL, &key_id, input, ARRAY_SIZE(input), signature,
			   ARRAY_SIZE(signature), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_sign_small_buffer(
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

	psa_key_id_t key_id = cipher_suite_import_sign_key(
		suite, suite->sign.private_key.pointer,
		suite->sign.private_key.length);

	const uint8_t input[16] = { 0x42 };
	uint8_t signature[params->sign_length];
	memset(signature, 0, sizeof(signature));
	size_t signature_length = 0;

	/* A signature buffer below the fixed signature length is rejected. */
	ret = crypto->sign(NULL, &key_id, input, ARRAY_SIZE(input), signature,
			   params->sign_length / 2U, &signature_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_sign_destroyed_key(
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

	psa_key_id_t key_id = cipher_suite_import_sign_key(
		suite, suite->sign.private_key.pointer,
		suite->sign.private_key.length);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t input[32] = { 0 };

	size_t signature_length = 0;
	uint8_t signature[params->sign_length];
	memset(signature, 0, sizeof(signature));

	ret = crypto->sign(NULL, &key_id, input, ARRAY_SIZE(input), signature,
			   ARRAY_SIZE(signature), &signature_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

void cipher_suite_test_sign_non_exportable_key(
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

	/* The suite must export the Ed25519 key to sign; a key without EXPORT
	 * permission is rejected. */
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_COPY);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);

	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	TEST_ASSERT_EQUAL(
		PSA_SUCCESS,
		psa_import_key(&attributes, suite->sign.private_key.pointer,
			       suite->sign.private_key.length, &key_id));

	const uint8_t input[32] = { 0 };

	uint8_t signature[params->sign_length];
	memset(signature, 0, sizeof(signature));
	size_t signature_length = 0;

	ret = crypto->sign(NULL, &key_id, input, ARRAY_SIZE(input), signature,
			   ARRAY_SIZE(signature), &signature_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_sign_short_key(
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

	/* Importing the shorter public key as the signing key exports fewer
	 * than the expected bytes, so signing is rejected. */
	psa_key_id_t key_id = cipher_suite_import_sign_key(
		suite, suite->sign.public_key.pointer,
		suite->sign.public_key.length);

	const uint8_t input[32] = { 0 };

	size_t signature_length = 0;
	uint8_t signature[params->sign_length];
	memset(signature, 0, sizeof(signature));

	ret = crypto->sign(NULL, &key_id, input, ARRAY_SIZE(input), signature,
			   ARRAY_SIZE(signature), &signature_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_sign_public_key(
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

	/* A public key cannot sign: importing it as an ECDSA public key and
	 * asking the suite to sign with that handle must fail. */
	psa_algorithm_t algorithm = PSA_ALG_NONE;

	switch (suite->sign.import) {
	case CIPHER_SUITE_SIGN_ECDSA_SHA256:
		algorithm = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
		break;
	case CIPHER_SUITE_SIGN_ECDSA_SHA384:
		algorithm = PSA_ALG_ECDSA(PSA_ALG_SHA_384);
		break;
	default:
		TEST_FAIL_MESSAGE(
			"cipher_suite_test_sign_public_key is ECDSA only");
		break;
	}

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&attributes, algorithm);
	psa_set_key_type(&attributes,
			 PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	TEST_ASSERT_EQUAL(
		PSA_SUCCESS,
		psa_import_key(&attributes, suite->sign.public_key.pointer,
			       suite->sign.public_key.length, &key_id));

	const uint8_t input[16] = { 0x01 };

	size_t signature_length = 0;
	uint8_t signature[params->sign_length];
	memset(signature, 0, sizeof(signature));

	ret = crypto->sign(NULL, &key_id, input, ARRAY_SIZE(input), signature,
			   ARRAY_SIZE(signature), &signature_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_sign_wrong_key_type_handle(
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

	/* A decapsulation-key slot holds an ML-KEM-512 secret whose length
	 * differs from an ML-DSA-44 signing key, so signing with it must be
	 * rejected on the length check. */
	psa_key_id_t key_id = PSA_KEY_ID_NULL;

	size_t encapsulation_key_length = 0;
	uint8_t encapsulation_key[params->kem_encapsulation_key_length];
	memset(encapsulation_key, 0, sizeof(encapsulation_key));

	ret = crypto->generate_key_pair(NULL, &key_id, encapsulation_key,
					ARRAY_SIZE(encapsulation_key),
					&encapsulation_key_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t input[16] = { 0 };

	size_t signature_length = 0;
	uint8_t signature[params->sign_length];
	memset(signature, 0, sizeof(signature));

	ret = crypto->sign(NULL, &key_id, input, ARRAY_SIZE(input), signature,
			   ARRAY_SIZE(signature), &signature_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_verify_null_args(
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

	const uint8_t input[16] = { 0 };
	uint8_t signature[params->sign_length];
	memset(signature, 0, sizeof(signature));

	ret = crypto->verify(NULL, NULL, suite->sign.public_key.length, input,
			     ARRAY_SIZE(input), signature,
			     ARRAY_SIZE(signature));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->verify(NULL, suite->sign.public_key.pointer, 0, input,
			     ARRAY_SIZE(input), signature,
			     ARRAY_SIZE(signature));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->verify(NULL, suite->sign.public_key.pointer,
			     suite->sign.public_key.length, NULL,
			     ARRAY_SIZE(input), signature,
			     ARRAY_SIZE(signature));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->verify(NULL, suite->sign.public_key.pointer,
			     suite->sign.public_key.length, input, 0, signature,
			     ARRAY_SIZE(signature));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->verify(NULL, suite->sign.public_key.pointer,
			     suite->sign.public_key.length, input,
			     ARRAY_SIZE(input), NULL, ARRAY_SIZE(signature));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = crypto->verify(NULL, suite->sign.public_key.pointer,
			     suite->sign.public_key.length, input,
			     ARRAY_SIZE(input), signature, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_verify_corrupted_signature(
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

	uint8_t input[32] = { 0 };
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_generate_random(input, sizeof(input)));

	psa_key_id_t key_id = cipher_suite_import_sign_key(
		suite, suite->sign.private_key.pointer,
		suite->sign.private_key.length);

	uint8_t signature[params->sign_length];
	memset(signature, 0, sizeof(signature));
	size_t signature_length = 0;

	ret = crypto->sign(NULL, &key_id, input, ARRAY_SIZE(input), signature,
			   ARRAY_SIZE(signature), &signature_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	signature[0] ^= (uint8_t)0xFF;

	ret = crypto->verify(NULL, suite->sign.public_key.pointer,
			     suite->sign.public_key.length, input,
			     ARRAY_SIZE(input), signature, signature_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

void cipher_suite_test_verify_bitflip_halves(
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

	uint8_t input[32] = { 0 };
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_generate_random(input, sizeof(input)));

	psa_key_id_t key_id = cipher_suite_import_sign_key(
		suite, suite->sign.private_key.pointer,
		suite->sign.private_key.length);

	size_t signature_length = 0;
	uint8_t signature[params->sign_length];
	memset(signature, 0, sizeof(signature));

	ret = crypto->sign(NULL, &key_id, input, ARRAY_SIZE(input), signature,
			   ARRAY_SIZE(signature), &signature_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t tampered[params->sign_length];

	/* Corrupt one bit in the first signature half (R). */
	memcpy(tampered, signature, sizeof(tampered));
	tampered[0] ^= (uint8_t)0x01;

	ret = crypto->verify(NULL, suite->sign.public_key.pointer,
			     suite->sign.public_key.length, input,
			     ARRAY_SIZE(input), tampered, signature_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	/* Corrupt one bit in the second signature half (S). */
	memcpy(tampered, signature, sizeof(tampered));
	tampered[params->sign_length / 2U] ^= (uint8_t)0x01;

	ret = crypto->verify(NULL, suite->sign.public_key.pointer,
			     suite->sign.public_key.length, input,
			     ARRAY_SIZE(input), tampered, signature_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	/* The pristine signature must still verify. */
	ret = crypto->verify(NULL, suite->sign.public_key.pointer,
			     suite->sign.public_key.length, input,
			     ARRAY_SIZE(input), signature, signature_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

void cipher_suite_test_verify_tampered_input(
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

	uint8_t input[32] = { 0 };
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_generate_random(input, sizeof(input)));

	psa_key_id_t key_id = cipher_suite_import_sign_key(
		suite, suite->sign.private_key.pointer,
		suite->sign.private_key.length);

	size_t signature_length = 0;
	uint8_t signature[params->sign_length];
	memset(signature, 0, sizeof(signature));

	ret = crypto->sign(NULL, &key_id, input, ARRAY_SIZE(input), signature,
			   ARRAY_SIZE(signature), &signature_length);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Flipping a message bit must fail verification of the old signature. */
	input[0] ^= (uint8_t)0x01;

	ret = crypto->verify(NULL, suite->sign.public_key.pointer,
			     suite->sign.public_key.length, input,
			     ARRAY_SIZE(input), signature, signature_length);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

void cipher_suite_test_verify_bad_signature_length(
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

	const uint8_t input[16] = { 0x42 };
	uint8_t signature[params->sign_length];
	memset(signature, 0, sizeof(signature));

	/* A signature length other than the fixed length is rejected. */
	ret = crypto->verify(NULL, suite->sign.public_key.pointer,
			     suite->sign.public_key.length, input,
			     ARRAY_SIZE(input), signature,
			     params->sign_length / 2U);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_verify_bad_public_key_length(
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

	const uint8_t input[16] = { 0x42 };
	uint8_t signature[params->sign_length];
	memset(signature, 0, sizeof(signature));

	/* A public key of a length other than the expected one is rejected. */
	ret = crypto->verify(NULL, suite->sign.public_key.pointer,
			     suite->sign.public_key.length / 2U, input,
			     ARRAY_SIZE(input), signature,
			     ARRAY_SIZE(signature));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_import_signing_key_null_args(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);
	TEST_ASSERT_NOT_NULL(suite->import_signing_key);

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;

	ret = suite->import_signing_key(NULL, suite->sign.private_key.length,
					&key_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = suite->import_signing_key(suite->sign.private_key.pointer,
					suite->sign.private_key.length, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_import_signing_key_bad_length(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);
	TEST_ASSERT_NOT_NULL(suite->import_signing_key);

	int ret = EDHOC_ERROR_GENERIC_ERROR;
	psa_key_id_t key_id = PSA_KEY_ID_NULL;

	ret = suite->import_signing_key(suite->sign.private_key.pointer,
					suite->sign.private_key.length - 1U,
					&key_id);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

void cipher_suite_test_import_signing_key_keystore_full(
	const struct cipher_suite_descriptor *suite)
{
	TEST_ASSERT_NOT_NULL(suite);
	TEST_ASSERT_NOT_NULL(suite->import_signing_key);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite->id);
	TEST_ASSERT_NOT_NULL(crypto);

	int ret = EDHOC_ERROR_GENERIC_ERROR;

	/* Filling the keystore with signing keys must make the next import fail
	 * on the store path; release every reserved slot afterwards. */
	psa_key_id_t key_ids[16] = { 0 };
	size_t filled = 0;
	int last = EDHOC_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(key_ids); ++i) {
		last = suite->import_signing_key(
			suite->sign.private_key.pointer,
			suite->sign.private_key.length, &key_ids[i]);
		if (EDHOC_SUCCESS != last) {
			break;
		}
		++filled;
	}

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, last);
	TEST_ASSERT_GREATER_THAN(0, filled);

	for (size_t i = 0; i < filled; ++i) {
		ret = crypto->destroy_key(NULL, &key_ids[i]);
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	}
}
