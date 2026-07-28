/**
 * \file    test_cipher_suite_pqc_1.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for post-quantum cipher suite 1
 *          (ML-KEM-512 / ML-DSA-44 / AES-CCM-16-128-128 / SHAKE256).
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
#include <edhoc/values.h>
#include "edhoc_macros_internal.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Standard library headers: */
#include <stdint.h>

/* Fixed ML-DSA-44 key pair (public + secret) for the sign / verify tests. */
#include "test_vector_ml_dsa_44_keypair.h"

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

/*
 * The EDHOC SHAKE256 KDF is KMAC256 (RFC 9528 Section 4.1.2), keyed by the
 * first argument with an empty customization string S = "":
 *   EDHOC_Extract(salt, IKM)   = KMAC256(salt, IKM, 8*hash_len, "")
 *   EDHOC_Expand(PRK, info, L) = KMAC256(PRK,  info, 8*L,       "")
 * Both directions are anchored on the same NIST SP 800-185 "KMAC256 Sample #5"
 * vector (K = 0x40..0x5f, X = 0x00..0xc7, S = "", L = 512): extract keys on the
 * salt (= K) and consumes the IKM (= X), expand keys on the PRK (= K) and
 * consumes the info (= X), so each must reproduce the same 64-byte output.
 * https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
 */
static const uint8_t kmac256_kat_key[] = {
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
	0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
	0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
};
static const uint8_t kmac256_kat_data[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
	0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
	0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
	0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
	0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
	0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
	0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
	0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};
static const uint8_t kmac256_kat_expected[] = {
	0x75, 0x35, 0x8c, 0xf3, 0x9e, 0x41, 0x49, 0x4e, 0x94, 0x97, 0x07,
	0x92, 0x7c, 0xee, 0x0a, 0xf2, 0x0a, 0x3f, 0xf5, 0x53, 0x90, 0x4c,
	0x86, 0xb0, 0x8f, 0x21, 0xcc, 0x41, 0x4b, 0xcf, 0xd6, 0x91, 0x58,
	0x9d, 0x27, 0xcf, 0x5e, 0x15, 0x36, 0x9c, 0xbb, 0xff, 0x8b, 0x9a,
	0x4c, 0x2e, 0xb1, 0x78, 0x00, 0x85, 0x5d, 0x02, 0x35, 0xff, 0x63,
	0x5d, 0xa8, 0x25, 0x33, 0xec, 0x6b, 0x75, 0x9b, 0x69,
};

/*
 * NIST SHA-3 XOF example "SHAKE256_Msg1600": the input is 1600 bits (200 bytes)
 * of 0xA3 and the output is truncated to 64 bytes.
 * https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
 */
static const uint8_t shake256_input[] = {
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
	0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
};
static const uint8_t shake256_expected[] = {
	0xcd, 0x8a, 0x92, 0x0e, 0xd1, 0x41, 0xaa, 0x04, 0x07, 0xa2, 0x2d,
	0x59, 0x28, 0x86, 0x52, 0xe9, 0xd9, 0xf1, 0xa7, 0xee, 0x0c, 0x1e,
	0x7c, 0x1c, 0xa6, 0x99, 0x42, 0x4d, 0xa8, 0x4a, 0x90, 0x4d, 0x2d,
	0x70, 0x0c, 0xaa, 0xe7, 0x39, 0x6e, 0xce, 0x96, 0x60, 0x44, 0x40,
	0x57, 0x7d, 0xa4, 0xf3, 0xaa, 0x22, 0xae, 0xb8, 0x85, 0x7f, 0x96,
	0x1c, 0x4c, 0xd8, 0xe0, 0x6f, 0x0a, 0xe6, 0x61, 0x0b,
};

/* The post-quantum suite loads its oversized ML-DSA-44 signing key into its own
 * software keystore; this import is intentionally not part of the public suite
 * header. */
extern int edhoc_cipher_suite_pqc_1_import_signing_key(
	const uint8_t *signing_key, size_t signing_key_length, void *key_id);

/* Bulk keystore reset (releases every credential key between repeated
 * handshakes); also intentionally not part of the public suite header. */
extern void edhoc_cipher_suite_pqc_1_keystore_release_all(void);

static const struct cipher_suite_descriptor suite = {
	.id = EDHOC_CIPHER_SUITE_PQC_1,
	.name = "cipher suite PQC 1 "
		"(ML-KEM-512 / ML-DSA-44 / AES-CCM-16-128-128 / SHAKE256)",
	.expected = {
		.value = EDHOC_CIPHER_SUITE_PQC_1,
		.supports_dh_nike = false,
		.kem_encapsulation_key_length = 800,
		.kem_ciphertext_length = 768,
		.nike_key_length = 0,
		.sign_length = 2420,
		.aead_key_length = 16,
		.aead_tag_length = 16,
		.aead_iv_length = 13,
		.hash_length = 64,
		.mac_length = 16,
	},
	.sign = {
		.import = CIPHER_SUITE_SIGN_ML_DSA_44,
		.private_key = { ml_dsa_44_secret_key,
				 ARRAY_SIZE(ml_dsa_44_secret_key) },
		.public_key = { ml_dsa_44_public_key,
				ARRAY_SIZE(ml_dsa_44_public_key) },
	},
	.nike = {
		.curve = CIPHER_SUITE_NIKE_NONE,
		.private_key = { NULL, 0 },
	},
	.aead = CIPHER_SUITE_AEAD_AES_CCM,
	.kdf = {
		.algorithm = CIPHER_SUITE_KDF_KMAC256,
		.ikm = { kmac256_kat_data, ARRAY_SIZE(kmac256_kat_data) },
		.salt = { kmac256_kat_key, ARRAY_SIZE(kmac256_kat_key) },
		.info = { kmac256_kat_data, ARRAY_SIZE(kmac256_kat_data) },
		.okm = { kmac256_kat_expected,
			 ARRAY_SIZE(kmac256_kat_expected) },
	},
	.hash = {
		.input = { shake256_input, ARRAY_SIZE(shake256_input) },
		.expected = { shake256_expected,
			      ARRAY_SIZE(shake256_expected) },
	},
	.import_signing_key = edhoc_cipher_suite_pqc_1_import_signing_key,
};

/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(cipher_suite_pqc_1_positive);

TEST_SETUP(cipher_suite_pqc_1_positive)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
}

TEST_TEAR_DOWN(cipher_suite_pqc_1_positive)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_pqc_1_positive, enum_getters)
{
	cipher_suite_test_enum_getters(&suite);
}

TEST(cipher_suite_pqc_1_positive, kem_roundtrip)
{
	cipher_suite_test_kem_roundtrip(&suite);
}

TEST(cipher_suite_pqc_1_positive, sign_verify)
{
	cipher_suite_test_sign_verify(&suite);
}

TEST(cipher_suite_pqc_1_positive, kdf)
{
	cipher_suite_test_kmac256_kat(&suite);
}

TEST(cipher_suite_pqc_1_positive, expand_handles)
{
	cipher_suite_test_expand_handles(&suite);
}

TEST(cipher_suite_pqc_1_positive, aead)
{
	cipher_suite_test_aead(&suite);
}

TEST(cipher_suite_pqc_1_positive, aead_empty_plaintext)
{
	cipher_suite_test_aead_empty_plaintext(&suite);
}

TEST(cipher_suite_pqc_1_positive, hash)
{
	cipher_suite_test_hash(&suite);
}

TEST(cipher_suite_pqc_1_positive, hash_abort_frees_pool_slot)
{
	cipher_suite_test_hash_abort_frees_pool_slot(&suite);
}

TEST_GROUP_RUNNER(cipher_suite_pqc_1_positive)
{
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, enum_getters);
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, kem_roundtrip);
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, sign_verify);
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, kdf);
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, expand_handles);
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, aead);
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, aead_empty_plaintext);
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, hash);
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, hash_abort_frees_pool_slot);
}

TEST_GROUP(cipher_suite_pqc_1_negative);

TEST_SETUP(cipher_suite_pqc_1_negative)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
}

TEST_TEAR_DOWN(cipher_suite_pqc_1_negative)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_pqc_1_negative, destroy_key_null_args)
{
	cipher_suite_test_destroy_key_null_args(&suite);
}

TEST(cipher_suite_pqc_1_negative, destroy_key_invalid_handle)
{
	cipher_suite_test_destroy_key_invalid_handle(&suite);
}

TEST(cipher_suite_pqc_1_negative, generate_key_pair_null_args)
{
	cipher_suite_test_generate_key_pair_null_args(&suite);
}

TEST(cipher_suite_pqc_1_negative, generate_key_pair_small_buffer)
{
	cipher_suite_test_generate_key_pair_small_buffer(&suite);
}

TEST(cipher_suite_pqc_1_negative, encapsulate_null_args)
{
	cipher_suite_test_encapsulate_null_args(&suite);
}

TEST(cipher_suite_pqc_1_negative, encapsulate_bad_encapsulation_key_length)
{
	cipher_suite_test_encapsulate_bad_encapsulation_key_length(&suite);
}

TEST(cipher_suite_pqc_1_negative, encapsulate_ciphertext_too_small)
{
	cipher_suite_test_encapsulate_ciphertext_too_small(&suite);
}

TEST(cipher_suite_pqc_1_negative, decapsulate_null_args)
{
	cipher_suite_test_decapsulate_null_args(&suite);
}

TEST(cipher_suite_pqc_1_negative, decapsulate_bad_ciphertext_length)
{
	cipher_suite_test_decapsulate_bad_ciphertext_length(&suite);
}

TEST(cipher_suite_pqc_1_negative, decapsulate_stale_handle)
{
	cipher_suite_test_decapsulate_stale_handle(&suite);
}

TEST(cipher_suite_pqc_1_negative, key_agreement_not_permitted)
{
	cipher_suite_test_key_agreement_not_permitted(&suite);
}

TEST(cipher_suite_pqc_1_negative, sign_null_args)
{
	cipher_suite_test_sign_null_args(&suite);
}

TEST(cipher_suite_pqc_1_negative, sign_small_buffer)
{
	cipher_suite_test_sign_small_buffer(&suite);
}

TEST(cipher_suite_pqc_1_negative, sign_destroyed_key)
{
	cipher_suite_test_sign_destroyed_key(&suite);
}

TEST(cipher_suite_pqc_1_negative, verify_null_args)
{
	cipher_suite_test_verify_null_args(&suite);
}

TEST(cipher_suite_pqc_1_negative, verify_bad_public_key_length)
{
	cipher_suite_test_verify_bad_public_key_length(&suite);
}

TEST(cipher_suite_pqc_1_negative, verify_bad_signature_length)
{
	cipher_suite_test_verify_bad_signature_length(&suite);
}

TEST(cipher_suite_pqc_1_negative, verify_corrupted_signature)
{
	cipher_suite_test_verify_corrupted_signature(&suite);
}

TEST(cipher_suite_pqc_1_negative, verify_tampered_input)
{
	cipher_suite_test_verify_tampered_input(&suite);
}

TEST(cipher_suite_pqc_1_negative, extract_null_args)
{
	cipher_suite_test_extract_null_args(&suite);
}

TEST(cipher_suite_pqc_1_negative, extract_destroyed_key)
{
	cipher_suite_test_extract_destroyed_key(&suite);
}

TEST(cipher_suite_pqc_1_negative, expand_null_args)
{
	cipher_suite_test_expand_derive_null_args(&suite);
}

TEST(cipher_suite_pqc_1_negative, expand_invalid_usage)
{
	cipher_suite_test_expand_invalid_usage(&suite);
}

TEST(cipher_suite_pqc_1_negative, expand_raw_null_args)
{
	cipher_suite_test_expand_raw_null_args(&suite);
}

TEST(cipher_suite_pqc_1_negative, encrypt_null_args)
{
	cipher_suite_test_encrypt_null_args(&suite);
}

TEST(cipher_suite_pqc_1_negative, decrypt_null_args)
{
	cipher_suite_test_decrypt_null_args(&suite);
}

TEST(cipher_suite_pqc_1_negative, aead_tag_tamper)
{
	cipher_suite_test_aead_tag_tamper(&suite);
}

TEST(cipher_suite_pqc_1_negative, hash_null_args)
{
	cipher_suite_test_hash_null_args(&suite);
}

TEST(cipher_suite_pqc_1_negative, hash_small_buffer)
{
	cipher_suite_test_hash_small_buffer(&suite);
}

TEST(cipher_suite_pqc_1_negative, import_signing_key_null_args)
{
	cipher_suite_test_import_signing_key_null_args(&suite);
}

TEST(cipher_suite_pqc_1_negative, import_signing_key_bad_length)
{
	cipher_suite_test_import_signing_key_bad_length(&suite);
}

TEST(cipher_suite_pqc_1_negative, keystore_exhaustion)
{
	cipher_suite_test_keystore_exhaustion(&suite);
}

TEST(cipher_suite_pqc_1_negative, decapsulate_wrong_key_type_handle)
{
	cipher_suite_test_decapsulate_wrong_key_type_handle(&suite);
}

TEST(cipher_suite_pqc_1_negative, sign_wrong_key_type_handle)
{
	cipher_suite_test_sign_wrong_key_type_handle(&suite);
}

TEST(cipher_suite_pqc_1_negative, expand_stale_prk)
{
	cipher_suite_test_expand_derive_stale_prk(&suite);
}

TEST(cipher_suite_pqc_1_negative, expand_destroyed_key)
{
	cipher_suite_test_expand_destroyed_key(&suite);
}

TEST(cipher_suite_pqc_1_negative, import_signing_key_keystore_full)
{
	cipher_suite_test_import_signing_key_keystore_full(&suite);
}

TEST(cipher_suite_pqc_1_negative, keystore_release_all_frees_slots)
{
	psa_key_id_t key_ids[16] = { 0 };
	size_t filled = 0;
	int last = EDHOC_SUCCESS;

	/* Fill every software-keystore slot. */
	for (size_t i = 0; i < ARRAY_SIZE(key_ids); ++i) {
		last = edhoc_cipher_suite_pqc_1_import_signing_key(
			ml_dsa_44_secret_key, ARRAY_SIZE(ml_dsa_44_secret_key),
			&key_ids[i]);

		if (EDHOC_SUCCESS != last) {
			break;
		}

		++filled;
	}

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, last);
	TEST_ASSERT_GREATER_THAN(0, filled);

	/* A bulk release frees every slot, so the next import succeeds again. */
	edhoc_cipher_suite_pqc_1_keystore_release_all();

	psa_key_id_t key_id = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_cipher_suite_pqc_1_import_signing_key(
				  ml_dsa_44_secret_key,
				  ARRAY_SIZE(ml_dsa_44_secret_key), &key_id));

	/* Leave the keystore clean for subsequent tests. */
	edhoc_cipher_suite_pqc_1_keystore_release_all();
}

TEST_GROUP_RUNNER(cipher_suite_pqc_1_negative)
{
	/* Argument validation. */
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, destroy_key_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, destroy_key_invalid_handle);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, generate_key_pair_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      generate_key_pair_small_buffer);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, encapsulate_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      encapsulate_bad_encapsulation_key_length);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      encapsulate_ciphertext_too_small);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, decapsulate_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      decapsulate_bad_ciphertext_length);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, decapsulate_stale_handle);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, key_agreement_not_permitted);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, sign_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, sign_small_buffer);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, sign_destroyed_key);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, verify_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      verify_bad_public_key_length);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, verify_bad_signature_length);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, verify_corrupted_signature);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, verify_tampered_input);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, extract_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, extract_destroyed_key);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, expand_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, expand_invalid_usage);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, expand_raw_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, encrypt_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, decrypt_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, aead_tag_tamper);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, hash_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, hash_small_buffer);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      import_signing_key_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      import_signing_key_bad_length);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, keystore_exhaustion);

	/* Wrong-key-type handles and stale KDF pseudorandom keys. */
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      decapsulate_wrong_key_type_handle);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, sign_wrong_key_type_handle);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, expand_stale_prk);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, expand_destroyed_key);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      import_signing_key_keystore_full);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      keystore_release_all_frees_slots);
}
