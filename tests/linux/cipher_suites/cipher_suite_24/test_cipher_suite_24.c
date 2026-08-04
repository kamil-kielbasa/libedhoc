/**
 * \file    test_cipher_suite_24.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for cipher suite 24
 *          (P-384 / ES384 / A256GCM / SHA-384).
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

/* A fixed, valid P-384 test scalar reused by the sign / ECDH cases. */
static const uint8_t p384_private_key[] = {
	0x77, 0xcf, 0x27, 0x52, 0xe3, 0x10, 0x50, 0xdd, 0xaa, 0x25, 0x4c, 0xcc,
	0xf7, 0xce, 0xa4, 0xaf, 0x68, 0xde, 0xbe, 0xdf, 0x20, 0xbf, 0xc8, 0x0b,
	0xdc, 0x2f, 0x58, 0x1d, 0x33, 0x6e, 0x1a, 0x18, 0xbd, 0xc2, 0xec, 0x8a,
	0xc5, 0x0e, 0x93, 0x2b, 0x68, 0xcd, 0x77, 0xf4, 0xf0, 0xaa, 0xf7, 0x3d,
};

/* The matching uncompressed P-384 public key (0x04 | X | Y). */
static const uint8_t p384_public_key[] = {
	0x04, 0xeb, 0x3a, 0x93, 0x4e, 0xd0, 0x89, 0x70, 0xd0, 0x50, 0xd5,
	0x85, 0xe8, 0x49, 0x47, 0x8d, 0xae, 0x2d, 0xf6, 0xb2, 0x8f, 0x45,
	0x63, 0x5c, 0x58, 0x20, 0xd3, 0xc0, 0x8d, 0x7f, 0xc6, 0x4f, 0x26,
	0x8a, 0x72, 0xbb, 0xd4, 0x4e, 0x7e, 0x4c, 0x29, 0xad, 0x2d, 0xec,
	0x68, 0xa8, 0xe7, 0x8d, 0x6b, 0x63, 0x7a, 0x00, 0x37, 0xce, 0x55,
	0xce, 0x61, 0x45, 0x0e, 0x91, 0x99, 0xfe, 0x2b, 0xa8, 0x2f, 0xa0,
	0xb4, 0x5b, 0x84, 0x98, 0x0e, 0x7c, 0xa0, 0x3e, 0x44, 0x52, 0x8b,
	0x91, 0x79, 0x24, 0x1c, 0x92, 0x2f, 0x63, 0xc5, 0xc7, 0x21, 0x03,
	0x2d, 0xfe, 0x9f, 0x8a, 0x56, 0x4e, 0xab, 0x91, 0xcb,
};

/* HKDF-SHA-384 known-answer test: the RFC 5869 Appendix A.1 IKM / salt / info
 * (RFC 5869 only publishes SHA-256 / SHA-1 vectors, so this SHA-384 OKM was
 * computed offline). */
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
	0x9b, 0x50, 0x97, 0xa8, 0x60, 0x38, 0xb8, 0x05, 0x30, 0x90, 0x76,
	0xa4, 0x4b, 0x3a, 0x9f, 0x38, 0x06, 0x3e, 0x25, 0xb5, 0x16, 0xdc,
	0xbf, 0x36, 0x9f, 0x39, 0x4c, 0xfa, 0xb4, 0x36, 0x85, 0xf7, 0x48,
	0xb6, 0x45, 0x77, 0x63, 0xe4, 0xf0, 0x20, 0x4f, 0xc5,
};

/* SHA-384 known-answer test: the digest of the single ASCII byte 'A' (0x41),
 * i.e. the value of `printf 'A' | sha384sum`. */
static const uint8_t hash_input[] = { 'A' };
static const uint8_t hash_expected[] = {
	0xad, 0x14, 0xaa, 0xf2, 0x50, 0x20, 0xbe, 0xf2, 0xfd, 0x4e, 0x3e, 0xb5,
	0xec, 0x0c, 0x50, 0x27, 0x2c, 0xdf, 0xd6, 0x60, 0x74, 0xb0, 0xed, 0x03,
	0x7c, 0x9a, 0x11, 0x25, 0x43, 0x21, 0xaa, 0xc0, 0x72, 0x99, 0x85, 0x37,
	0x4b, 0xee, 0xaa, 0x5b, 0x80, 0xa5, 0x04, 0xd0, 0x48, 0xbe, 0x18, 0x64,
};

static const struct cipher_suite_descriptor suite = {
	.id = EDHOC_CIPHER_SUITE_24,
	.name = "cipher suite 24 (P-384 / ES384 / A256GCM / SHA-384)",
	.expected = {
		.value = 24,
		.supports_dh_nike = true,
		.kem_encapsulation_key_length = 48,
		.kem_ciphertext_length = 48,
		.nike_key_length = 48,
		.sign_length = 96,
		.aead_key_length = 32,
		.aead_tag_length = 16,
		.aead_iv_length = 12,
		.hash_length = 48,
		.mac_length = 16,
	},
	.sign = {
		.import = CIPHER_SUITE_SIGN_ECDSA_SHA384,
		.private_key = { p384_private_key,
				 ARRAY_SIZE(p384_private_key) },
		.public_key = { p384_public_key,
				ARRAY_SIZE(p384_public_key) },
	},
	.nike = {
		.curve = CIPHER_SUITE_NIKE_P384,
		.private_key = { p384_private_key,
				 ARRAY_SIZE(p384_private_key) },
	},
	.aead = CIPHER_SUITE_AEAD_AES_GCM,
	.kdf = {
		.algorithm = CIPHER_SUITE_KDF_HKDF_SHA384,
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

TEST_GROUP(cipher_suite_24_positive);

TEST_SETUP(cipher_suite_24_positive)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
}

TEST_TEAR_DOWN(cipher_suite_24_positive)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_24_positive, enum_getters)
{
	cipher_suite_test_enum_getters(&suite);
}

TEST(cipher_suite_24_positive, sign_verify)
{
	cipher_suite_test_sign_verify(&suite);
}

TEST(cipher_suite_24_positive, key_agreement_roundtrip)
{
	cipher_suite_test_key_agreement_roundtrip(&suite);
}

TEST(cipher_suite_24_positive, kem_roundtrip)
{
	cipher_suite_test_kem_roundtrip(&suite);
}

TEST(cipher_suite_24_positive, kdf)
{
	cipher_suite_test_kdf(&suite);
}

TEST(cipher_suite_24_positive, aead)
{
	cipher_suite_test_aead(&suite);
}

TEST(cipher_suite_24_positive, aead_empty_plaintext)
{
	cipher_suite_test_aead_empty_plaintext(&suite);
}

TEST(cipher_suite_24_positive, hash)
{
	cipher_suite_test_hash(&suite);
}

TEST_GROUP_RUNNER(cipher_suite_24_positive)
{
	RUN_TEST_CASE(cipher_suite_24_positive, enum_getters);
	RUN_TEST_CASE(cipher_suite_24_positive, sign_verify);
	RUN_TEST_CASE(cipher_suite_24_positive, key_agreement_roundtrip);
	RUN_TEST_CASE(cipher_suite_24_positive, kem_roundtrip);
	RUN_TEST_CASE(cipher_suite_24_positive, kdf);
	RUN_TEST_CASE(cipher_suite_24_positive, aead);
	RUN_TEST_CASE(cipher_suite_24_positive, aead_empty_plaintext);
	RUN_TEST_CASE(cipher_suite_24_positive, hash);
}

TEST_GROUP(cipher_suite_24_negative);

TEST_SETUP(cipher_suite_24_negative)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
}

TEST_TEAR_DOWN(cipher_suite_24_negative)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_24_negative, sign_verify_zero_input)
{
	cipher_suite_test_sign_verify_zero_input(&suite);
}

TEST(cipher_suite_24_negative, sign_null_args)
{
	cipher_suite_test_sign_null_args(&suite);
}

TEST(cipher_suite_24_negative, sign_small_buffer)
{
	cipher_suite_test_sign_small_buffer(&suite);
}

TEST(cipher_suite_24_negative, sign_destroyed_key)
{
	cipher_suite_test_sign_destroyed_key(&suite);
}

TEST(cipher_suite_24_negative, sign_public_key)
{
	cipher_suite_test_sign_public_key(&suite);
}

TEST(cipher_suite_24_negative, verify_null_args)
{
	cipher_suite_test_verify_null_args(&suite);
}

TEST(cipher_suite_24_negative, verify_corrupted_signature)
{
	cipher_suite_test_verify_corrupted_signature(&suite);
}

TEST(cipher_suite_24_negative, verify_bitflip_halves)
{
	cipher_suite_test_verify_bitflip_halves(&suite);
}

TEST(cipher_suite_24_negative, verify_bad_signature_length)
{
	cipher_suite_test_verify_bad_signature_length(&suite);
}

TEST(cipher_suite_24_negative, generate_key_pair_null_args)
{
	cipher_suite_test_generate_key_pair_null_args(&suite);
}

TEST(cipher_suite_24_negative, generate_key_pair_small_buffer)
{
	cipher_suite_test_generate_key_pair_small_buffer(&suite);
}

TEST(cipher_suite_24_negative, key_agreement_null_args)
{
	cipher_suite_test_key_agreement_null_args(&suite);
}

TEST(cipher_suite_24_negative, key_agreement_bad_point)
{
	cipher_suite_test_key_agreement_bad_point(&suite);
}

TEST(cipher_suite_24_negative, key_agreement_peer_key_too_short)
{
	cipher_suite_test_key_agreement_peer_key_too_short(&suite);
}

TEST(cipher_suite_24_negative, key_agreement_peer_key_too_long)
{
	cipher_suite_test_key_agreement_peer_key_too_long(&suite);
}

TEST(cipher_suite_24_negative, key_agreement_wrong_key_type)
{
	cipher_suite_test_key_agreement_wrong_key_type(&suite);
}

TEST(cipher_suite_24_negative, key_agreement_destroyed_key)
{
	cipher_suite_test_key_agreement_destroyed_key(&suite);
}

TEST(cipher_suite_24_negative, destroy_key_null_args)
{
	cipher_suite_test_destroy_key_null_args(&suite);
}

TEST(cipher_suite_24_negative, destroy_key_invalid_handle)
{
	cipher_suite_test_destroy_key_invalid_handle(&suite);
}

TEST(cipher_suite_24_negative, extract_null_args)
{
	cipher_suite_test_extract_null_args(&suite);
}

TEST(cipher_suite_24_negative, extract_wrong_key_type)
{
	cipher_suite_test_extract_wrong_key_type(&suite);
}

TEST(cipher_suite_24_negative, extract_destroyed_key)
{
	cipher_suite_test_extract_destroyed_key(&suite);
}

TEST(cipher_suite_24_negative, expand_null_args)
{
	cipher_suite_test_expand_null_args(&suite);
}

TEST(cipher_suite_24_negative, expand_wrong_key_type)
{
	cipher_suite_test_expand_wrong_key_type(&suite);
}

TEST(cipher_suite_24_negative, expand_destroyed_key)
{
	cipher_suite_test_expand_destroyed_key(&suite);
}

TEST(cipher_suite_24_negative, expand_output_too_large)
{
	cipher_suite_test_expand_output_too_large(&suite);
}

TEST(cipher_suite_24_negative, aead_tag_tamper)
{
	cipher_suite_test_aead_tag_tamper(&suite);
}

TEST(cipher_suite_24_negative, aead_aad_tamper)
{
	cipher_suite_test_aead_aad_tamper(&suite);
}

TEST(cipher_suite_24_negative, encrypt_null_args)
{
	cipher_suite_test_encrypt_null_args(&suite);
}

TEST(cipher_suite_24_negative, encrypt_wrong_key_type)
{
	cipher_suite_test_encrypt_wrong_key_type(&suite);
}

TEST(cipher_suite_24_negative, encrypt_destroyed_key)
{
	cipher_suite_test_encrypt_destroyed_key(&suite);
}

TEST(cipher_suite_24_negative, decrypt_null_args)
{
	cipher_suite_test_decrypt_null_args(&suite);
}

TEST(cipher_suite_24_negative, decrypt_wrong_key_type)
{
	cipher_suite_test_decrypt_wrong_key_type(&suite);
}

TEST(cipher_suite_24_negative, decrypt_destroyed_key)
{
	cipher_suite_test_decrypt_destroyed_key(&suite);
}

TEST(cipher_suite_24_negative, hash_null_args)
{
	cipher_suite_test_hash_null_args(&suite);
}

TEST(cipher_suite_24_negative, hash_small_buffer)
{
	cipher_suite_test_hash_small_buffer(&suite);
}

TEST_GROUP_RUNNER(cipher_suite_24_negative)
{
	/* Signature. */
	RUN_TEST_CASE(cipher_suite_24_negative, sign_verify_zero_input);
	RUN_TEST_CASE(cipher_suite_24_negative, sign_null_args);
	RUN_TEST_CASE(cipher_suite_24_negative, sign_small_buffer);
	RUN_TEST_CASE(cipher_suite_24_negative, sign_destroyed_key);
	RUN_TEST_CASE(cipher_suite_24_negative, sign_public_key);
	RUN_TEST_CASE(cipher_suite_24_negative, verify_null_args);
	RUN_TEST_CASE(cipher_suite_24_negative, verify_corrupted_signature);
	RUN_TEST_CASE(cipher_suite_24_negative, verify_bitflip_halves);
	RUN_TEST_CASE(cipher_suite_24_negative, verify_bad_signature_length);

	/* Key exchange and key lifecycle. */
	RUN_TEST_CASE(cipher_suite_24_negative, generate_key_pair_null_args);
	RUN_TEST_CASE(cipher_suite_24_negative, generate_key_pair_small_buffer);
	RUN_TEST_CASE(cipher_suite_24_negative, key_agreement_null_args);
	RUN_TEST_CASE(cipher_suite_24_negative, key_agreement_bad_point);
	RUN_TEST_CASE(cipher_suite_24_negative,
		      key_agreement_peer_key_too_short);
	RUN_TEST_CASE(cipher_suite_24_negative,
		      key_agreement_peer_key_too_long);
	RUN_TEST_CASE(cipher_suite_24_negative, key_agreement_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_24_negative, key_agreement_destroyed_key);
	RUN_TEST_CASE(cipher_suite_24_negative, destroy_key_null_args);
	RUN_TEST_CASE(cipher_suite_24_negative, destroy_key_invalid_handle);

	/* Key derivation. */
	RUN_TEST_CASE(cipher_suite_24_negative, extract_null_args);
	RUN_TEST_CASE(cipher_suite_24_negative, extract_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_24_negative, extract_destroyed_key);
	RUN_TEST_CASE(cipher_suite_24_negative, expand_null_args);
	RUN_TEST_CASE(cipher_suite_24_negative, expand_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_24_negative, expand_destroyed_key);
	RUN_TEST_CASE(cipher_suite_24_negative, expand_output_too_large);

	/* AEAD. */
	RUN_TEST_CASE(cipher_suite_24_negative, aead_tag_tamper);
	RUN_TEST_CASE(cipher_suite_24_negative, aead_aad_tamper);
	RUN_TEST_CASE(cipher_suite_24_negative, encrypt_null_args);
	RUN_TEST_CASE(cipher_suite_24_negative, encrypt_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_24_negative, encrypt_destroyed_key);
	RUN_TEST_CASE(cipher_suite_24_negative, decrypt_null_args);
	RUN_TEST_CASE(cipher_suite_24_negative, decrypt_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_24_negative, decrypt_destroyed_key);

	/* Hash. */
	RUN_TEST_CASE(cipher_suite_24_negative, hash_null_args);
	RUN_TEST_CASE(cipher_suite_24_negative, hash_small_buffer);
}
