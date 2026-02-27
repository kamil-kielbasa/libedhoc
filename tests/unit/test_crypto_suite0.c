/**
 * \file    test_crypto_suite0.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for cipher suite 0.
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Cipher suite 0 header: */
#include "edhoc_cipher_suite_0.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* EDHOC headers: */
#include <edhoc_crypto.h>
#include <edhoc_values.h>
#include <edhoc_macros.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* PSA crypto header: */
#include <psa/crypto.h>

/* Compact25519 crypto headers: */
#include <compact_x25519.h>
#include <compact_ed25519.h>

/* Module defines ---------------------------------------------------------- */
#define INPUT_TO_SIGN_LEN ((size_t)128)

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

static const struct edhoc_keys *edhoc_keys;
static const struct edhoc_crypto *edhoc_crypto;

static int ret = PSA_ERROR_GENERIC_ERROR;

/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(crypto_suite0);

TEST_SETUP(crypto_suite0)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
	edhoc_keys = edhoc_cipher_suite_0_get_keys();
	edhoc_crypto = edhoc_cipher_suite_0_get_crypto();
}

TEST_TEAR_DOWN(crypto_suite0)
{
	mbedtls_psa_crypto_free();
}

/**
 * @scenario  ECDSA (Ed25519) sign and verify with cipher suite 0.
 * @env       PSA crypto initialized; cipher suite 0 keys and crypto bound.
 * @action    Import Ed25519 key pair, sign random input, verify signature.
 * @expected  Signature and verify succeed; signature verifies correctly.
 */
TEST(crypto_suite0, ecdsa)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	const uint8_t priv_key[ED25519_PRIVATE_KEY_SIZE] = {
		0xef, 0x14, 0x0f, 0xf9, 0x00, 0xb0, 0xab, 0x03,
		0xf0, 0xc0, 0x8d, 0x87, 0x9c, 0xbb, 0xd4, 0xb3,
		0x1e, 0xa7, 0x1e, 0x6e, 0x7e, 0xe7, 0xff, 0xcb,
		0x7e, 0x79, 0x55, 0x77, 0x7a, 0x33, 0x27, 0x99,

		0xa1, 0xdb, 0x47, 0xb9, 0x51, 0x84, 0x85, 0x4a,
		0xd1, 0x2a, 0x0c, 0x1a, 0x35, 0x4e, 0x41, 0x8a,
		0xac, 0xe3, 0x3a, 0xa0, 0xf2, 0xc6, 0x62, 0xc0,
		0x0b, 0x3a, 0xc5, 0x5d, 0xe9, 0x2f, 0x93, 0x59,
	};

	const uint8_t pub_key[ED25519_PUBLIC_KEY_SIZE] = {
		0xa1, 0xdb, 0x47, 0xb9, 0x51, 0x84, 0x85, 0x4a,
		0xd1, 0x2a, 0x0c, 0x1a, 0x35, 0x4e, 0x41, 0x8a,
		0xac, 0xe3, 0x3a, 0xa0, 0xf2, 0xc6, 0x62, 0xc0,
		0x0b, 0x3a, 0xc5, 0x5d, 0xe9, 0x2f, 0x93, 0x59,
	};

	/* Random input for signature. */
	uint8_t input[INPUT_TO_SIGN_LEN] = { 0 };
	ret = psa_generate_random(input, ARRAY_SIZE(input));
	TEST_ASSERT_EQUAL(PSA_SUCCESS, ret);

	/* Generate signature. */
	size_t sign_len = 0;
	uint8_t sign[ED25519_SIGNATURE_SIZE] = { 0 };

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_SIGNATURE, priv_key,
				     ARRAY_SIZE(priv_key), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->signature(NULL, &key_id, input, ARRAY_SIZE(input),
				      sign, ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Verify signature. */
	ret = edhoc_keys->import_key(NULL, EDHOC_KT_VERIFY, pub_key,
				     ARRAY_SIZE(pub_key), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->verify(NULL, &key_id, input, ARRAY_SIZE(input),
				   sign, sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

/**
 * @scenario  ECDH (X25519) key agreement with cipher suite 0.
 * @env       PSA crypto initialized; cipher suite 0 keys and crypto bound.
 * @action    Generate two key pairs (Alice, Bob), compute shared secrets via
 *            key_agreement, compare results.
 * @expected  Both parties derive identical shared secret.
 */
TEST(crypto_suite0, ecdh)
{
	psa_key_id_t key_id_a = PSA_KEY_HANDLE_INIT;
	psa_key_id_t key_id_b = PSA_KEY_HANDLE_INIT;

	/* Alice ECDH key pair. */
	size_t priv_key_len_a = 0;
	uint8_t priv_key_a[X25519_KEY_SIZE] = { 0 };

	size_t pub_key_len_a = 0;
	uint8_t pub_key_a[X25519_KEY_SIZE] = { 0 };

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_MAKE_KEY_PAIR, NULL, 0,
				     &key_id_a);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->make_key_pair(NULL, &key_id_a, priv_key_a,
					  ARRAY_SIZE(priv_key_a),
					  &priv_key_len_a, pub_key_a,
					  ARRAY_SIZE(pub_key_a),
					  &pub_key_len_a);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(priv_key_a), priv_key_len_a);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(pub_key_a), pub_key_len_a);

	ret = edhoc_keys->destroy_key(NULL, &key_id_a);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Bob ECDH key pair. */
	size_t priv_key_len_b = 0;
	uint8_t priv_key_b[X25519_KEY_SIZE] = { 0 };

	size_t pub_key_len_b = 0;
	uint8_t pub_key_b[X25519_KEY_SIZE] = { 0 };

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_MAKE_KEY_PAIR, NULL, 0,
				     &key_id_b);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->make_key_pair(NULL, &key_id_b, priv_key_b,
					  ARRAY_SIZE(priv_key_b),
					  &priv_key_len_b, pub_key_b,
					  ARRAY_SIZE(pub_key_b),
					  &pub_key_len_b);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(priv_key_b), priv_key_len_b);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(pub_key_b), pub_key_len_b);

	ret = edhoc_keys->destroy_key(NULL, &key_id_b);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Shared secret for Alice. */
	size_t shr_sec_len_a = 0;
	uint8_t shr_sec_a[X25519_SHARED_SIZE] = { 0 };

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_KEY_AGREEMENT, priv_key_a,
				     priv_key_len_a, &key_id_a);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->key_agreement(NULL, &key_id_a, pub_key_b,
					  pub_key_len_b, shr_sec_a,
					  ARRAY_SIZE(shr_sec_a),
					  &shr_sec_len_a);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(shr_sec_a), shr_sec_len_a);

	ret = edhoc_keys->destroy_key(NULL, &key_id_a);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Shared secret for Bob. */
	size_t shr_sec_len_b = 0;
	uint8_t shr_sec_b[X25519_SHARED_SIZE] = { 0 };

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_KEY_AGREEMENT, priv_key_b,
				     priv_key_len_b, &key_id_b);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->key_agreement(NULL, &key_id_b, pub_key_a,
					  pub_key_len_a, shr_sec_b,
					  ARRAY_SIZE(shr_sec_b),
					  &shr_sec_len_b);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(shr_sec_b), shr_sec_len_b);

	ret = edhoc_keys->destroy_key(NULL, &key_id_b);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, ret);

	/* Compare if Alice and Bob has the same shared secrets. */
	TEST_ASSERT_EQUAL(shr_sec_len_a, shr_sec_len_b);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(shr_sec_a, shr_sec_b, shr_sec_len_a);
}

/**
 * @scenario  HKDF extract and expand with cipher suite 0 (RFC 5869 Test Case 1).
 * @env       PSA crypto initialized; cipher suite 0 keys and crypto bound.
 * @action    Run HKDF extract with IKM and salt, then expand with info;
 *            compare PRK and OKM to RFC 5869 vectors.
 * @expected  PRK and OKM match RFC 5869 A.1 Test Case 1 expected values.
 */
TEST(crypto_suite0, hkdf)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	/* Test vectors taken from RFC 5869: A.1. Test Case 1. */
	const uint8_t ikm[] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	};

	const uint8_t salt[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
	};

	const uint8_t info[] = {
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
	};

	const size_t L = 42;

	const uint8_t prk[] = {
		0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
		0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
		0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
		0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
	};

	const uint8_t okm[] = {
		0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90,
		0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d,
		0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d,
		0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
		0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
	};

	/* HDFK extract part. */
	size_t comp_prk_len = 0;
	uint8_t comp_prk[32] = { 0 };

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_EXTRACT, ikm,
				     ARRAY_SIZE(ikm), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->extract(NULL, &key_id, salt, ARRAY_SIZE(salt),
				    comp_prk, ARRAY_SIZE(comp_prk),
				    &comp_prk_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(comp_prk), comp_prk_len);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(comp_prk_len, ARRAY_SIZE(prk));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(comp_prk, prk, comp_prk_len);

	/* HDFK expand part. */
	uint8_t comp_okm[L];
	memset(comp_okm, 0, sizeof(comp_okm));

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_EXPAND, comp_prk,
				     ARRAY_SIZE(comp_prk), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->expand(NULL, &key_id, info, ARRAY_SIZE(info),
				   comp_okm, ARRAY_SIZE(comp_okm));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(comp_okm, okm, ARRAY_SIZE(okm));
}

/**
 * @scenario  AEAD encrypt and decrypt with cipher suite 0.
 * @env       PSA crypto initialized; cipher suite 0 keys and crypto bound.
 * @action    Encrypt plaintext with key, IV, AAD; decrypt ciphertext.
 * @expected  Decrypted output matches original plaintext.
 */
TEST(crypto_suite0, aead)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	/* AEAD key, iv and aad. */
	const uint8_t key[16] = {
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
	};
	const uint8_t iv[13] = {
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2,
	};
	const uint8_t aad[4] = {
		0,
		1,
		2,
		3,
	};

	/* AEAD encryption. */
	const uint8_t ptxt[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_ENCRYPT, key,
				     ARRAY_SIZE(key), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	size_t ctxt_len = 0;
	uint8_t ctxt[18] = { 0 };
	ret = edhoc_crypto->encrypt(NULL, &key_id, iv, ARRAY_SIZE(iv), aad,
				    ARRAY_SIZE(aad), ptxt, ARRAY_SIZE(ptxt),
				    ctxt, ARRAY_SIZE(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ctxt), ctxt_len);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* AEAD decryption. */
	size_t dec_ctxt_len = 0;
	uint8_t dec_ctxt[ARRAY_SIZE(ptxt)] = { 0 };

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_DECRYPT, key,
				     ARRAY_SIZE(key), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->decrypt(NULL, &key_id, iv, ARRAY_SIZE(iv), aad,
				    ARRAY_SIZE(aad), ctxt, ctxt_len, dec_ctxt,
				    ARRAY_SIZE(dec_ctxt), &dec_ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ptxt), dec_ctxt_len);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Verify if plaintext is equal to decrypted ciphertext. */
	TEST_ASSERT_EQUAL_UINT8_ARRAY(ptxt, dec_ctxt, ARRAY_SIZE(ptxt));
}

/**
 * @scenario  Hash (SHA-256) primitive with cipher suite 0.
 * @env       PSA crypto initialized; cipher suite 0 crypto bound.
 * @action    Hash single-byte input 'A', compare to known expected hash.
 * @expected  Hash output matches expected SHA-256 value.
 */
TEST(crypto_suite0, hash)
{
	/* Input for hash function and expected hash. */
	const uint8_t input[] = { 'A' };

	const uint8_t exp_hash[32] = {
		0x55, 0x9a, 0xea, 0xd0, 0x82, 0x64, 0xd5, 0x79,
		0x5d, 0x39, 0x09, 0x71, 0x8c, 0xdd, 0x05, 0xab,
		0xd4, 0x95, 0x72, 0xe8, 0x4f, 0xe5, 0x55, 0x90,
		0xee, 0xf3, 0x1a, 0x88, 0xa0, 0x8f, 0xdf, 0xfd,
	};

	/* Hashing operation. */
	size_t hash_len = 0;
	uint8_t hash[32] = { 0 };

	ret = edhoc_crypto->hash(NULL, input, ARRAY_SIZE(input), hash,
				 ARRAY_SIZE(hash), &hash_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(hash), hash_len);

	/* Verify if hashes are equals. */
	TEST_ASSERT_EQUAL_UINT8_ARRAY(hash, exp_hash, ARRAY_SIZE(exp_hash));
}

TEST(crypto_suite0, key_import_invalid_type)
{
	psa_key_id_t kid;
	uint8_t key[32] = { 0 };
	ret = edhoc_cipher_suite_0_key_import(NULL, 99, key, 32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(crypto_suite0, key_destroy_null)
{
	ret = edhoc_cipher_suite_0_key_destroy(NULL, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite0, make_key_pair_null_args)
{
	psa_key_id_t kid;
	uint8_t priv[32], pub[32];
	size_t priv_len, pub_len;

	ret = edhoc_cipher_suite_0_make_key_pair(NULL, NULL, priv, 32,
						 &priv_len, pub, 32, &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_suite_0_make_key_pair(NULL, &kid, NULL, 32,
						 &priv_len, pub, 32, &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_suite_0_make_key_pair(NULL, &kid, priv, 32,
						 &priv_len, NULL, 32, &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite0, make_key_pair_bad_size)
{
	psa_key_id_t kid = 0;
	uint8_t priv[32], pub[32];
	size_t priv_len, pub_len;

	ret = edhoc_cipher_suite_0_make_key_pair(NULL, &kid, priv, 16,
						 &priv_len, pub, 32, &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(crypto_suite0, key_agreement_null_args)
{
	uint8_t shr_sec[32];
	size_t shr_sec_len;

	ret = edhoc_cipher_suite_0_key_agreement(NULL, NULL, NULL, 0, shr_sec,
						 32, &shr_sec_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite0, signature_null_args)
{
	uint8_t sign[64];
	size_t sign_len;

	ret = edhoc_cipher_suite_0_signature(NULL, NULL, NULL, 0, sign, 64,
					     &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite0, verify_null_args)
{
	ret = edhoc_cipher_suite_0_verify(NULL, NULL, NULL, 0, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite0, extract_null_args)
{
	uint8_t prk[32];
	size_t prk_len;

	ret = edhoc_cipher_suite_0_extract(NULL, NULL, NULL, 0, prk, 32,
					   &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite0, expand_null_args)
{
	uint8_t okm[32];

	ret = edhoc_cipher_suite_0_expand(NULL, NULL, NULL, 0, okm, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite0, encrypt_null_args)
{
	uint8_t ctxt[64];
	size_t ctxt_len;

	ret = edhoc_cipher_suite_0_encrypt(NULL, NULL, NULL, 0, NULL, 0, NULL,
					   0, ctxt, 64, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite0, decrypt_null_args)
{
	uint8_t ptxt[64];
	size_t ptxt_len;

	ret = edhoc_cipher_suite_0_decrypt(NULL, NULL, NULL, 0, NULL, 0, NULL,
					   0, ptxt, 64, &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite0, extract_destroyed_key)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_EXTRACT, raw_key,
					      32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_cipher_suite_0_key_destroy(NULL, &kid);

	uint8_t salt[32] = { 0xAA };
	uint8_t prk[32];
	size_t prk_len;
	ret = edhoc_cipher_suite_0_extract(NULL, &kid, salt, 32, prk, 32,
					   &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(crypto_suite0, expand_destroyed_key)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_EXPAND, raw_key,
					      32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_cipher_suite_0_key_destroy(NULL, &kid);

	uint8_t info[16] = { 0 };
	uint8_t okm[32];
	ret = edhoc_cipher_suite_0_expand(NULL, &kid, info, 16, okm, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(crypto_suite0, encrypt_destroyed_key)
{
	psa_key_id_t kid;
	uint8_t raw_key[16];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_ENCRYPT, raw_key,
					      16, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_cipher_suite_0_key_destroy(NULL, &kid);

	uint8_t nonce[13] = { 0 };
	uint8_t ad[16] = { 0 };
	uint8_t ptxt[16] = { 0 };
	uint8_t ctxt[32];
	size_t ctxt_len;
	ret = edhoc_cipher_suite_0_encrypt(NULL, &kid, nonce, 13, ad, 16, ptxt,
					   16, ctxt, 32, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(crypto_suite0, decrypt_destroyed_key)
{
	psa_key_id_t kid;
	uint8_t raw_key[16];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_DECRYPT, raw_key,
					      16, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_cipher_suite_0_key_destroy(NULL, &kid);

	uint8_t nonce[13] = { 0 };
	uint8_t ad[16] = { 0 };
	uint8_t ctxt[32] = { 0 };
	uint8_t ptxt[32];
	size_t ptxt_len;
	ret = edhoc_cipher_suite_0_decrypt(NULL, &kid, nonce, 13, ad, 16, ctxt,
					   32, ptxt, 32, &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(crypto_suite0, hash_wrong_size)
{
	uint8_t input[16] = { 0 };
	uint8_t hash[4];
	size_t hash_len;
	ret = edhoc_cipher_suite_0_hash(NULL, input, 16, hash, 4, &hash_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(crypto_suite0, hash_null_args)
{
	uint8_t hash[32];
	size_t hash_len;

	ret = edhoc_cipher_suite_0_hash(NULL, NULL, 0, hash, 32, &hash_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

/**
 * @scenario  key_agreement with wrong peer_pub_key_len.
 * @env       PSA initialized, valid key ID from key_import.
 * @action    Call key_agreement with peer_pub_key_len = 16 (not 32).
 * @expected  Returns EDHOC_ERROR_CRYPTO_FAILURE (size mismatch).
 */
TEST(crypto_suite0, key_agreement_bad_size)
{
	psa_key_id_t kid;
	uint8_t raw_key[32] = { 0 };
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, 32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t peer[32] = { 0 };
	uint8_t secret[32];
	size_t secret_len;
	ret = edhoc_cipher_suite_0_key_agreement(NULL, &kid, peer, 16, secret,
						 32, &secret_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_0_key_destroy(NULL, &kid);
}

/**
 * @scenario  key_agreement with wrong shr_sec_size.
 * @env       PSA initialized, valid key ID from key_import.
 * @action    Call key_agreement with shr_sec_size = 16 (not 32).
 * @expected  Returns EDHOC_ERROR_CRYPTO_FAILURE (size mismatch).
 */
TEST(crypto_suite0, key_agreement_bad_secret_size)
{
	psa_key_id_t kid;
	uint8_t raw_key[32] = { 0 };
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, 32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t peer[32] = { 0 };
	uint8_t secret[32];
	size_t secret_len;
	ret = edhoc_cipher_suite_0_key_agreement(NULL, &kid, peer, 32, secret,
						 16, &secret_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_0_key_destroy(NULL, &kid);
}

/**
 * @scenario  signature with wrong sign_size.
 * @env       PSA initialized, valid key ID from key_import for signature.
 * @action    Call signature with sign_size = 32 (not 64).
 * @expected  Returns EDHOC_ERROR_CRYPTO_FAILURE (size mismatch).
 */
TEST(crypto_suite0, signature_bad_size)
{
	psa_key_id_t kid;
	uint8_t raw_key[64] = { 0 };
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      64, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t input[16] = { 0x42 };
	uint8_t sign[64];
	size_t sign_len;
	ret = edhoc_cipher_suite_0_signature(NULL, &kid, input, 16, sign, 32,
					     &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_0_key_destroy(NULL, &kid);
}

/**
 * @scenario  verify with wrong sign_len.
 * @env       PSA initialized, valid key ID from key_import for verify.
 * @action    Call verify with sign_len = 32 (not 64).
 * @expected  Returns EDHOC_ERROR_CRYPTO_FAILURE (size mismatch).
 */
TEST(crypto_suite0, verify_bad_sign_len)
{
	psa_key_id_t kid;
	uint8_t raw_key[32] = { 0 };
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_VERIFY, raw_key,
					      32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t input[16] = { 0x42 };
	uint8_t sign[64] = { 0 };
	ret = edhoc_cipher_suite_0_verify(NULL, &kid, input, 16, sign, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_0_key_destroy(NULL, &kid);
}

/**
 * @scenario  key_agreement with destroyed key (covers psa_export_key fail).
 * @env       Import key, destroy it, then call key_agreement.
 * @action    key_agreement with destroyed key.
 * @expected  Returns EDHOC_ERROR_CRYPTO_FAILURE.
 */
TEST(crypto_suite0, key_agreement_destroyed_key)
{
	psa_key_id_t kid;
	uint8_t raw_key[32] = { 0 };
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, 32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	edhoc_cipher_suite_0_key_destroy(NULL, &kid);

	uint8_t peer[32] = { 0 };
	uint8_t secret[32];
	size_t secret_len;
	ret = edhoc_cipher_suite_0_key_agreement(NULL, &kid, peer, 32, secret,
						 32, &secret_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

/**
 * @scenario  signature with destroyed key (covers psa_export_key fail).
 * @env       Import 64-byte key, destroy it, then call signature.
 * @action    signature with destroyed key.
 * @expected  Returns EDHOC_ERROR_CRYPTO_FAILURE.
 */
TEST(crypto_suite0, signature_destroyed_key)
{
	psa_key_id_t kid;
	uint8_t raw_key[64] = { 0 };
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      64, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	edhoc_cipher_suite_0_key_destroy(NULL, &kid);

	uint8_t input[16] = { 0x42 };
	uint8_t sign[64];
	size_t sign_len;
	ret = edhoc_cipher_suite_0_signature(NULL, &kid, input, 16, sign, 64,
					     &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

/**
 * @scenario  verify with destroyed key (covers psa_export_key fail).
 * @env       Import key, destroy it, then call verify.
 * @action    verify with destroyed key.
 * @expected  Returns EDHOC_ERROR_CRYPTO_FAILURE.
 */
TEST(crypto_suite0, verify_destroyed_key)
{
	psa_key_id_t kid;
	uint8_t raw_key[32] = { 0 };
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_VERIFY, raw_key,
					      32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	edhoc_cipher_suite_0_key_destroy(NULL, &kid);

	uint8_t input[16] = { 0x42 };
	uint8_t sign[64] = { 0 };
	ret = edhoc_cipher_suite_0_verify(NULL, &kid, input, 16, sign, 64);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

/**
 * @scenario  encrypt with wrong key type (EXTRACT key used for AEAD).
 * @env       PSA initialized, key imported as EXTRACT type.
 * @action    Call encrypt with the EXTRACT key.
 * @expected  psa_aead_encrypt fails -> EDHOC_ERROR_CRYPTO_FAILURE.
 */
TEST(crypto_suite0, encrypt_wrong_key_type)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_EXTRACT, raw_key,
					      32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[13] = { 0 };
	uint8_t ad[16] = { 0 };
	uint8_t ptxt[16] = { 0 };
	uint8_t ctxt[32];
	size_t ctxt_len;
	ret = edhoc_cipher_suite_0_encrypt(NULL, &kid, nonce, 13, ad, 16, ptxt,
					   16, ctxt, 32, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_0_key_destroy(NULL, &kid);
}

/**
 * @scenario  decrypt with wrong key type (EXPAND key used for AEAD).
 * @env       PSA initialized, key imported as EXPAND type.
 * @action    Call decrypt with the EXPAND key.
 * @expected  psa_aead_decrypt fails -> EDHOC_ERROR_CRYPTO_FAILURE.
 */
TEST(crypto_suite0, decrypt_wrong_key_type)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_EXPAND, raw_key,
					      32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[13] = { 0 };
	uint8_t ad[16] = { 0 };
	uint8_t ctxt[32] = { 0 };
	uint8_t ptxt[32];
	size_t ptxt_len;
	ret = edhoc_cipher_suite_0_decrypt(NULL, &kid, nonce, 13, ad, 16, ctxt,
					   24, ptxt, 32, &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_0_key_destroy(NULL, &kid);
}

/**
 * @scenario  extract with wrong key type triggers derivation setup failure.
 * @env       PSA initialized, key imported as ENCRYPT type (AES-CCM algorithm).
 * @action    Call extract with the ENCRYPT key.
 * @expected  psa_key_derivation_setup fails -> EDHOC_ERROR_CRYPTO_FAILURE.
 */
TEST(crypto_suite0, extract_wrong_key_type)
{
	psa_key_id_t kid;
	uint8_t raw_key[16];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_ENCRYPT, raw_key,
					      16, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t salt[16] = { 0 };
	uint8_t prk[32];
	size_t prk_len;
	ret = edhoc_cipher_suite_0_extract(NULL, &kid, salt, 16, prk, 32,
					   &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_0_key_destroy(NULL, &kid);
}

/**
 * @scenario  expand with wrong key type triggers derivation setup failure.
 * @env       PSA initialized, key imported as ENCRYPT type (AES-CCM algorithm).
 * @action    Call expand with the ENCRYPT key.
 * @expected  psa_key_derivation_setup fails -> EDHOC_ERROR_CRYPTO_FAILURE.
 */
TEST(crypto_suite0, expand_wrong_key_type)
{
	psa_key_id_t kid;
	uint8_t raw_key[16];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_ENCRYPT, raw_key,
					      16, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t info[16] = { 0 };
	uint8_t okm[32];
	ret = edhoc_cipher_suite_0_expand(NULL, &kid, info, 16, okm, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_0_key_destroy(NULL, &kid);
}

/**
 * @scenario  signature with destroyed key (valid sizes but bad key).
 * @env       Import sign key, destroy, call signature with correct buffer sizes.
 * @action    psa_sign_message fails -> EDHOC_ERROR_CRYPTO_FAILURE.
 * @expected  Returns EDHOC_ERROR_CRYPTO_FAILURE.
 */
TEST(crypto_suite0, signature_destroyed_key_v2)
{
	psa_key_id_t kid;
	uint8_t raw_key[64];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      64, &kid);
	if (EDHOC_SUCCESS != ret)
		return;

	edhoc_cipher_suite_0_key_destroy(NULL, &kid);

	uint8_t input[32] = { 0 };
	uint8_t sign[64];
	size_t sign_len;
	ret = edhoc_cipher_suite_0_signature(NULL, &kid, input, 32, sign, 64,
					     &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST_GROUP_RUNNER(crypto_suite0)
{
	RUN_TEST_CASE(crypto_suite0, ecdsa);
	RUN_TEST_CASE(crypto_suite0, ecdh);
	RUN_TEST_CASE(crypto_suite0, hkdf);
	RUN_TEST_CASE(crypto_suite0, aead);
	RUN_TEST_CASE(crypto_suite0, hash);
	RUN_TEST_CASE(crypto_suite0, key_import_invalid_type);
	RUN_TEST_CASE(crypto_suite0, key_destroy_null);
	RUN_TEST_CASE(crypto_suite0, make_key_pair_null_args);
	RUN_TEST_CASE(crypto_suite0, make_key_pair_bad_size);
	RUN_TEST_CASE(crypto_suite0, key_agreement_null_args);
	RUN_TEST_CASE(crypto_suite0, signature_null_args);
	RUN_TEST_CASE(crypto_suite0, verify_null_args);
	RUN_TEST_CASE(crypto_suite0, extract_null_args);
	RUN_TEST_CASE(crypto_suite0, expand_null_args);
	RUN_TEST_CASE(crypto_suite0, encrypt_null_args);
	RUN_TEST_CASE(crypto_suite0, decrypt_null_args);
	RUN_TEST_CASE(crypto_suite0, extract_destroyed_key);
	RUN_TEST_CASE(crypto_suite0, expand_destroyed_key);
	RUN_TEST_CASE(crypto_suite0, encrypt_destroyed_key);
	RUN_TEST_CASE(crypto_suite0, decrypt_destroyed_key);
	RUN_TEST_CASE(crypto_suite0, hash_wrong_size);
	RUN_TEST_CASE(crypto_suite0, hash_null_args);
	RUN_TEST_CASE(crypto_suite0, key_agreement_bad_size);
	RUN_TEST_CASE(crypto_suite0, key_agreement_bad_secret_size);
	RUN_TEST_CASE(crypto_suite0, signature_bad_size);
	RUN_TEST_CASE(crypto_suite0, verify_bad_sign_len);
	RUN_TEST_CASE(crypto_suite0, key_agreement_destroyed_key);
	RUN_TEST_CASE(crypto_suite0, signature_destroyed_key);
	RUN_TEST_CASE(crypto_suite0, verify_destroyed_key);
	RUN_TEST_CASE(crypto_suite0, encrypt_wrong_key_type);
	RUN_TEST_CASE(crypto_suite0, decrypt_wrong_key_type);
	RUN_TEST_CASE(crypto_suite0, extract_wrong_key_type);
	RUN_TEST_CASE(crypto_suite0, expand_wrong_key_type);
	RUN_TEST_CASE(crypto_suite0, signature_destroyed_key_v2);
}
