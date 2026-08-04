/**
 * \file    test_cipher_suite_2.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for cipher suite 2
 *          (P-256 / ES256 / AES-CCM-16-64-128 / SHA-256).
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Cipher-suite driver headers: */
#include "cipher_suite_driver.h"
#include "cipher_suite_test_getters.h"
#include "cipher_suite_test_key_exchange.h"
#include "cipher_suite_test_sign_verify.h"
#include "cipher_suite_test_kdf.h"
#include "cipher_suite_test_aead.h"
#include "cipher_suite_test_hash.h"

/* EDHOC headers: */
#include <edhoc/cipher_suite.h>
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Standard library headers: */
#include <stdint.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

/* A fixed, valid P-256 test scalar reused by the sign / ECDH cases. */
static const uint8_t p256_private_key[] = {
	0xfb, 0x13, 0xad, 0xeb, 0x65, 0x18, 0xce, 0xe5, 0xf8, 0x84, 0x17,
	0x66, 0x08, 0x41, 0x14, 0x2e, 0x83, 0x0a, 0x81, 0xfe, 0x33, 0x43,
	0x80, 0xa9, 0x53, 0x40, 0x6a, 0x13, 0x05, 0xe8, 0x70, 0x6b,
};

/* The matching uncompressed P-256 public key (0x04 | X | Y). */
static const uint8_t p256_public_key[] = {
	0x04, 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e, 0xd6,
	0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf, 0x16, 0xdf,
	0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30, 0x7f, 0x7e, 0xb6,
	0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b, 0x8a, 0x82, 0x11, 0x33,
	0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52, 0xa3, 0x87, 0xd2, 0x57, 0xe6,
	0xdb, 0x3c, 0x2a, 0x93, 0xdf, 0x21, 0xff, 0x3a, 0xff, 0xc8,
};

/* HKDF-SHA-256 known-answer test (RFC 5869 Appendix A.1, Test Case 1). */
static const uint8_t hkdf_ikm[] = {
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
};
static const uint8_t hkdf_salt[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
};
static const uint8_t hkdf_info[] = {
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
};
static const uint8_t hkdf_okm[] = {
	0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
	0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
	0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
	0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
};

/* SHA-256 known-answer test: the digest of the single ASCII byte 'A' (0x41),
 * i.e. the value of `printf 'A' | sha256sum`. */
static const uint8_t hash_input[] = { 'A' };
static const uint8_t hash_expected[] = {
	0x55, 0x9a, 0xea, 0xd0, 0x82, 0x64, 0xd5, 0x79, 0x5d, 0x39, 0x09,
	0x71, 0x8c, 0xdd, 0x05, 0xab, 0xd4, 0x95, 0x72, 0xe8, 0x4f, 0xe5,
	0x55, 0x90, 0xee, 0xf3, 0x1a, 0x88, 0xa0, 0x8f, 0xdf, 0xfd,
};

static const struct cipher_suite_descriptor suite = {
	.id = EDHOC_CIPHER_SUITE_2,
	.name = "cipher suite 2 (P-256 / ES256 / AES-CCM-16-64-128 / SHA-256)",
	.expected = {
		.value = 2,
		.supports_dh_nike = true,
		.kem_encapsulation_key_length = 32,
		.kem_ciphertext_length = 32,
		.nike_key_length = 32,
		.sign_length = 64,
		.aead_key_length = 16,
		.aead_tag_length = 8,
		.aead_iv_length = 13,
		.hash_length = 32,
		.mac_length = 8,
	},
	.sign = {
		.import = CIPHER_SUITE_SIGN_ECDSA_SHA256,
		.private_key = { p256_private_key,
				 ARRAY_SIZE(p256_private_key) },
		.public_key = { p256_public_key,
				ARRAY_SIZE(p256_public_key) },
	},
	.nike = {
		.curve = CIPHER_SUITE_NIKE_P256,
		.private_key = { p256_private_key,
				 ARRAY_SIZE(p256_private_key) },
	},
	.aead = CIPHER_SUITE_AEAD_AES_CCM,
	.kdf = {
		.algorithm = CIPHER_SUITE_KDF_HKDF_SHA256,
		.ikm = { hkdf_ikm, ARRAY_SIZE(hkdf_ikm) },
		.salt = { hkdf_salt, ARRAY_SIZE(hkdf_salt) },
		.info = { hkdf_info, ARRAY_SIZE(hkdf_info) },
		.okm = { hkdf_okm, ARRAY_SIZE(hkdf_okm) },
	},
	.hash = {
		.input = { hash_input, ARRAY_SIZE(hash_input) },
		.expected = { hash_expected, ARRAY_SIZE(hash_expected) },
	},
};

/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(cipher_suite_2_positive);

TEST_SETUP(cipher_suite_2_positive)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
}

TEST_TEAR_DOWN(cipher_suite_2_positive)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_2_positive, enum_getters)
{
	cipher_suite_test_enum_getters(&suite);
}

TEST(cipher_suite_2_positive, sign_verify)
{
	cipher_suite_test_sign_verify(&suite);
}

TEST(cipher_suite_2_positive, key_agreement_roundtrip)
{
	cipher_suite_test_key_agreement_roundtrip(&suite);
}

TEST(cipher_suite_2_positive, kem_roundtrip)
{
	cipher_suite_test_kem_roundtrip(&suite);
}

TEST(cipher_suite_2_positive, kdf)
{
	cipher_suite_test_kdf(&suite);
}

TEST(cipher_suite_2_positive, aead)
{
	cipher_suite_test_aead(&suite);
}

TEST(cipher_suite_2_positive, aead_empty_plaintext)
{
	cipher_suite_test_aead_empty_plaintext(&suite);
}

TEST(cipher_suite_2_positive, hash)
{
	cipher_suite_test_hash(&suite);
}

TEST_GROUP_RUNNER(cipher_suite_2_positive)
{
	RUN_TEST_CASE(cipher_suite_2_positive, enum_getters);
	RUN_TEST_CASE(cipher_suite_2_positive, sign_verify);
	RUN_TEST_CASE(cipher_suite_2_positive, key_agreement_roundtrip);
	RUN_TEST_CASE(cipher_suite_2_positive, kem_roundtrip);
	RUN_TEST_CASE(cipher_suite_2_positive, kdf);
	RUN_TEST_CASE(cipher_suite_2_positive, aead);
	RUN_TEST_CASE(cipher_suite_2_positive, aead_empty_plaintext);
	RUN_TEST_CASE(cipher_suite_2_positive, hash);
}

TEST_GROUP(cipher_suite_2_negative);

TEST_SETUP(cipher_suite_2_negative)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
}

TEST_TEAR_DOWN(cipher_suite_2_negative)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_2_negative, sign_verify_zero_input)
{
	cipher_suite_test_sign_verify_zero_input(&suite);
}

TEST(cipher_suite_2_negative, sign_null_args)
{
	cipher_suite_test_sign_null_args(&suite);
}

TEST(cipher_suite_2_negative, sign_small_buffer)
{
	cipher_suite_test_sign_small_buffer(&suite);
}

TEST(cipher_suite_2_negative, sign_destroyed_key)
{
	cipher_suite_test_sign_destroyed_key(&suite);
}

TEST(cipher_suite_2_negative, sign_public_key)
{
	cipher_suite_test_sign_public_key(&suite);
}

TEST(cipher_suite_2_negative, verify_null_args)
{
	cipher_suite_test_verify_null_args(&suite);
}

TEST(cipher_suite_2_negative, verify_corrupted_signature)
{
	cipher_suite_test_verify_corrupted_signature(&suite);
}

TEST(cipher_suite_2_negative, verify_bitflip_halves)
{
	cipher_suite_test_verify_bitflip_halves(&suite);
}

TEST(cipher_suite_2_negative, verify_bad_signature_length)
{
	cipher_suite_test_verify_bad_signature_length(&suite);
}

TEST(cipher_suite_2_negative, verify_bad_public_key_length)
{
	cipher_suite_test_verify_bad_public_key_length(&suite);
}

TEST(cipher_suite_2_negative, generate_key_pair_null_args)
{
	cipher_suite_test_generate_key_pair_null_args(&suite);
}

TEST(cipher_suite_2_negative, generate_key_pair_small_buffer)
{
	cipher_suite_test_generate_key_pair_small_buffer(&suite);
}

TEST(cipher_suite_2_negative, key_agreement_null_args)
{
	cipher_suite_test_key_agreement_null_args(&suite);
}

TEST(cipher_suite_2_negative, key_agreement_bad_point)
{
	cipher_suite_test_key_agreement_bad_point(&suite);
}

TEST(cipher_suite_2_negative, key_agreement_peer_key_too_short)
{
	cipher_suite_test_key_agreement_peer_key_too_short(&suite);
}

TEST(cipher_suite_2_negative, key_agreement_peer_key_too_long)
{
	cipher_suite_test_key_agreement_peer_key_too_long(&suite);
}

TEST(cipher_suite_2_negative, key_agreement_wrong_key_type)
{
	cipher_suite_test_key_agreement_wrong_key_type(&suite);
}

TEST(cipher_suite_2_negative, key_agreement_destroyed_key)
{
	cipher_suite_test_key_agreement_destroyed_key(&suite);
}

TEST(cipher_suite_2_negative, destroy_key_null_args)
{
	cipher_suite_test_destroy_key_null_args(&suite);
}

TEST(cipher_suite_2_negative, destroy_key_invalid_handle)
{
	cipher_suite_test_destroy_key_invalid_handle(&suite);
}

TEST(cipher_suite_2_negative, extract_null_args)
{
	cipher_suite_test_extract_null_args(&suite);
}

TEST(cipher_suite_2_negative, extract_wrong_key_type)
{
	cipher_suite_test_extract_wrong_key_type(&suite);
}

TEST(cipher_suite_2_negative, extract_destroyed_key)
{
	cipher_suite_test_extract_destroyed_key(&suite);
}

TEST(cipher_suite_2_negative, expand_null_args)
{
	cipher_suite_test_expand_null_args(&suite);
}

TEST(cipher_suite_2_negative, expand_wrong_key_type)
{
	cipher_suite_test_expand_wrong_key_type(&suite);
}

TEST(cipher_suite_2_negative, expand_destroyed_key)
{
	cipher_suite_test_expand_destroyed_key(&suite);
}

TEST(cipher_suite_2_negative, expand_output_too_large)
{
	cipher_suite_test_expand_output_too_large(&suite);
}

TEST(cipher_suite_2_negative, aead_tag_tamper)
{
	cipher_suite_test_aead_tag_tamper(&suite);
}

TEST(cipher_suite_2_negative, aead_aad_tamper)
{
	cipher_suite_test_aead_aad_tamper(&suite);
}

TEST(cipher_suite_2_negative, encrypt_null_args)
{
	cipher_suite_test_encrypt_null_args(&suite);
}

TEST(cipher_suite_2_negative, encrypt_wrong_key_type)
{
	cipher_suite_test_encrypt_wrong_key_type(&suite);
}

TEST(cipher_suite_2_negative, encrypt_destroyed_key)
{
	cipher_suite_test_encrypt_destroyed_key(&suite);
}

TEST(cipher_suite_2_negative, decrypt_null_args)
{
	cipher_suite_test_decrypt_null_args(&suite);
}

TEST(cipher_suite_2_negative, decrypt_wrong_key_type)
{
	cipher_suite_test_decrypt_wrong_key_type(&suite);
}

TEST(cipher_suite_2_negative, decrypt_destroyed_key)
{
	cipher_suite_test_decrypt_destroyed_key(&suite);
}

TEST(cipher_suite_2_negative, hash_null_args)
{
	cipher_suite_test_hash_null_args(&suite);
}

TEST(cipher_suite_2_negative, hash_small_buffer)
{
	cipher_suite_test_hash_small_buffer(&suite);
}

TEST_GROUP_RUNNER(cipher_suite_2_negative)
{
	/* Signature. */
	RUN_TEST_CASE(cipher_suite_2_negative, sign_verify_zero_input);
	RUN_TEST_CASE(cipher_suite_2_negative, sign_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, sign_small_buffer);
	RUN_TEST_CASE(cipher_suite_2_negative, sign_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2_negative, sign_public_key);
	RUN_TEST_CASE(cipher_suite_2_negative, verify_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, verify_corrupted_signature);
	RUN_TEST_CASE(cipher_suite_2_negative, verify_bitflip_halves);
	RUN_TEST_CASE(cipher_suite_2_negative, verify_bad_signature_length);
	RUN_TEST_CASE(cipher_suite_2_negative, verify_bad_public_key_length);

	/* Key exchange and key lifecycle. */
	RUN_TEST_CASE(cipher_suite_2_negative, generate_key_pair_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, generate_key_pair_small_buffer);
	RUN_TEST_CASE(cipher_suite_2_negative, key_agreement_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, key_agreement_bad_point);
	RUN_TEST_CASE(cipher_suite_2_negative,
		      key_agreement_peer_key_too_short);
	RUN_TEST_CASE(cipher_suite_2_negative, key_agreement_peer_key_too_long);
	RUN_TEST_CASE(cipher_suite_2_negative, key_agreement_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_2_negative, key_agreement_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2_negative, destroy_key_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, destroy_key_invalid_handle);

	/* Key derivation. */
	RUN_TEST_CASE(cipher_suite_2_negative, extract_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, extract_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_2_negative, extract_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2_negative, expand_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, expand_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_2_negative, expand_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2_negative, expand_output_too_large);

	/* AEAD. */
	RUN_TEST_CASE(cipher_suite_2_negative, aead_tag_tamper);
	RUN_TEST_CASE(cipher_suite_2_negative, aead_aad_tamper);
	RUN_TEST_CASE(cipher_suite_2_negative, encrypt_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, encrypt_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_2_negative, encrypt_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2_negative, decrypt_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, decrypt_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_2_negative, decrypt_destroyed_key);

	/* Hash. */
	RUN_TEST_CASE(cipher_suite_2_negative, hash_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, hash_small_buffer);
}
