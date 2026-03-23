/**
 * \file    test_crypto_suite2.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for cipher suite 2.
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Cipher suite 2 header: */
#include "edhoc_cipher_suite_2.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
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

/* Module defines ---------------------------------------------------------- */
#define INPUT_TO_SIGN_LEN ((size_t)128)

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

static const struct edhoc_keys *edhoc_keys;
static const struct edhoc_crypto *edhoc_crypto;

static int ret = EDHOC_ERROR_GENERIC_ERROR;

/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(crypto_suite2);

TEST_SETUP(crypto_suite2)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
	edhoc_keys = edhoc_cipher_suite_2_get_keys();
	edhoc_crypto = edhoc_cipher_suite_2_get_crypto();
}

TEST_TEAR_DOWN(crypto_suite2)
{
	mbedtls_psa_crypto_free();
}

/**
 * @scenario  ECDSA (P-256) sign and verify with cipher suite 2.
 * @env       PSA crypto initialized; cipher suite 2 keys and crypto bound.
 * @action    Import P-256 key pair, sign random input, verify signature.
 * @expected  Signature and verify succeed; signature verifies correctly.
 */
TEST(crypto_suite2, ecdsa)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	const uint8_t priv_key[ECC_COMP_KEY_LEN] = {
		0xfb, 0x13, 0xad, 0xeb, 0x65, 0x18, 0xce, 0xe5,
		0xf8, 0x84, 0x17, 0x66, 0x08, 0x41, 0x14, 0x2e,
		0x83, 0x0a, 0x81, 0xfe, 0x33, 0x43, 0x80, 0xa9,
		0x53, 0x40, 0x6a, 0x13, 0x05, 0xe8, 0x70, 0x6b,
	};

	const uint8_t pub_key[ECC_UNCOMP_KEY_LEN] = {
		0x04,

		0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc,
		0x8e, 0xd6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40,
		0x5c, 0x47, 0xbf, 0x16, 0xdf, 0x96, 0x66, 0x0a,
		0x41, 0x29, 0x8c, 0xb4, 0x30, 0x7f, 0x7e, 0xb6,

		0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b, 0x8a,
		0x82, 0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb,
		0x52, 0xa3, 0x87, 0xd2, 0x57, 0xe6, 0xdb, 0x3c,
		0x2a, 0x93, 0xdf, 0x21, 0xff, 0x3a, 0xff, 0xc8,
	};

	/* Random input for signature. */
	uint8_t input[INPUT_TO_SIGN_LEN] = { 0 };
	ret = psa_generate_random(input, ARRAY_SIZE(input));
	TEST_ASSERT_EQUAL(PSA_SUCCESS, ret);

	/* Generate signature. */
	size_t sign_len = 0;
	uint8_t sign[ECC_ECDSA_SIGN_LEN] = { 0 };

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
 * @scenario  ECDH (P-256) key agreement with cipher suite 2.
 * @env       PSA crypto initialized; cipher suite 2 keys and crypto bound.
 * @action    Generate two key pairs (Alice, Bob), compute shared secrets via
 *            key_agreement, compare results.
 * @expected  Both parties derive identical shared secret.
 */
TEST(crypto_suite2, ecdh)
{
	psa_key_id_t key_id_a = PSA_KEY_HANDLE_INIT;
	psa_key_id_t key_id_b = PSA_KEY_HANDLE_INIT;

	/* Alice ECDH public and private keys. */
	size_t priv_key_len_a = 0;
	uint8_t priv_key_a[ECC_COMP_KEY_LEN] = { 0 };

	size_t pub_key_len_a = 0;
	uint8_t pub_key_a[ECC_COMP_KEY_LEN] = { 0 };

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

	/* Bob ECDH public and private keys. */
	size_t priv_key_len_b = 0;
	uint8_t priv_key_b[ECC_COMP_KEY_LEN] = { 0 };

	size_t pub_key_len_b = 0;
	uint8_t pub_key_b[ECC_COMP_KEY_LEN] = { 0 };

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
	uint8_t shr_sec_a[ECC_ECDH_KEY_AGREEMENT_LEN] = { 0 };

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
	uint8_t shr_sec_b[ECC_ECDH_KEY_AGREEMENT_LEN] = { 0 };

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
 * @scenario  HKDF extract and expand with cipher suite 2 (RFC 5869 Test Case 1).
 * @env       PSA crypto initialized; cipher suite 2 keys and crypto bound.
 * @action    Run HKDF extract with IKM and salt, then expand with info;
 *            compare PRK and OKM to RFC 5869 vectors.
 * @expected  PRK and OKM match RFC 5869 A.1 Test Case 1 expected values.
 */
TEST(crypto_suite2, hkdf)
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

	TEST_ASSERT_EQUAL(ARRAY_SIZE(prk), comp_prk_len);
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
 * @scenario  AEAD encrypt and decrypt with cipher suite 2.
 * @env       PSA crypto initialized; cipher suite 2 keys and crypto bound.
 * @action    Encrypt plaintext with key, IV, AAD; decrypt ciphertext.
 * @expected  Decrypted output matches original plaintext.
 */
TEST(crypto_suite2, aead)
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
 * @scenario  Hash (SHA-256) primitive with cipher suite 2.
 * @env       PSA crypto initialized; cipher suite 2 crypto bound.
 * @action    Hash single-byte input 'A', compare to known expected hash.
 * @expected  Hash output matches expected SHA-256 value.
 */
TEST(crypto_suite2, hash)
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

TEST(crypto_suite2, key_import_invalid_type)
{
	psa_key_id_t kid;
	uint8_t key[32] = { 0 };
	ret = edhoc_cipher_suite_2_key_import(NULL, 99, key, 32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

/**
 * @scenario  psa_import_key rejects malformed material (covers import error path).
 */
TEST(crypto_suite2, key_import_rejects_invalid_key_material)
{
	psa_key_id_t kid;

	const uint8_t short_priv[16] = { 0 };
	ret = edhoc_cipher_suite_2_key_import(
		NULL, EDHOC_KT_SIGNATURE, short_priv, sizeof(short_priv), &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	const uint8_t short_aes[8] = { 0 };
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_ENCRYPT, short_aes,
					      sizeof(short_aes), &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	uint8_t zero_ecdh[ECC_COMP_KEY_LEN] = { 0 };
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      zero_ecdh, sizeof(zero_ecdh),
					      &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	uint8_t short_pub[40];
	memset(short_pub, 0x5a, sizeof(short_pub));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_VERIFY, short_pub,
					      sizeof(short_pub), &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

/**
 * @scenario  HKDF-Extract: capacity above PSA limit fails at set_capacity.
 */
TEST(crypto_suite2, extract_prk_capacity_too_large)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];

	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_generate_random(raw_key, sizeof(raw_key)));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_EXTRACT, raw_key,
					      sizeof(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t salt[8] = { 0x01 };
	enum { prk_buf_len = 4096 };
	uint8_t prk[prk_buf_len];
	size_t prk_len = 0;

	ret = edhoc_cipher_suite_2_extract(NULL, &kid, salt, sizeof(salt), prk,
					   sizeof(prk), &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);
}

/**
 * @scenario  HKDF-Expand: capacity above PSA limit fails at set_capacity.
 */
TEST(crypto_suite2, expand_okm_length_too_large)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];

	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_generate_random(raw_key, sizeof(raw_key)));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_EXPAND, raw_key,
					      sizeof(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t info[4] = { 0xab, 0xcd, 0xef, 0x01 };
	enum { okm_len = 65536 };
	uint8_t *okm = malloc(okm_len);

	TEST_ASSERT_NOT_NULL(okm);
	ret = edhoc_cipher_suite_2_expand(NULL, &kid, info, sizeof(info), okm,
					  okm_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
	free(okm);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);
}

/**
 * @scenario  AEAD encrypt/decrypt with zero-length plaintext (NULL buffers OK for PSA).
 */
TEST(crypto_suite2, aead_zero_length_plaintext)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	const uint8_t key[AEAD_KEY_LEN] = {
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
	};
	const uint8_t nonce[13] = { 0 };
	const uint8_t ad[4] = { 0x10, 0x11, 0x12, 0x13 };

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_ENCRYPT, key,
				     ARRAY_SIZE(key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t ctxt[32];
	size_t ctxt_len = 0;
	ret = edhoc_crypto->encrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce), ad,
				    ARRAY_SIZE(ad), NULL, (size_t)0, ctxt,
				    sizeof(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_DECRYPT, key,
				     ARRAY_SIZE(key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	size_t ptxt_len = 0;
	ret = edhoc_crypto->decrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce), ad,
				    ARRAY_SIZE(ad), ctxt, ctxt_len, NULL,
				    (size_t)0, &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL((size_t)0, ptxt_len);

	ret = edhoc_keys->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(crypto_suite2, key_destroy_null)
{
	ret = edhoc_cipher_suite_2_key_destroy(NULL, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite2, make_key_pair_null_args)
{
	psa_key_id_t kid;
	uint8_t priv[32], pub[32];
	size_t priv_len, pub_len;

	ret = edhoc_cipher_suite_2_make_key_pair(NULL, NULL, priv, 32,
						 &priv_len, pub, 32, &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_suite_2_make_key_pair(NULL, &kid, NULL, 32,
						 &priv_len, pub, 32, &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite2, key_agreement_null_args)
{
	uint8_t shr_sec[32];
	size_t shr_sec_len;

	ret = edhoc_cipher_suite_2_key_agreement(NULL, NULL, NULL, 0, shr_sec,
						 32, &shr_sec_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite2, signature_null_args)
{
	uint8_t sign[64];
	size_t sign_len;

	ret = edhoc_cipher_suite_2_signature(NULL, NULL, NULL, 0, sign, 64,
					     &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite2, verify_null_args)
{
	ret = edhoc_cipher_suite_2_verify(NULL, NULL, NULL, 0, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite2, extract_null_args)
{
	uint8_t prk[32];
	size_t prk_len;

	ret = edhoc_cipher_suite_2_extract(NULL, NULL, NULL, 0, prk, 32,
					   &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite2, expand_null_args)
{
	uint8_t okm[32];

	ret = edhoc_cipher_suite_2_expand(NULL, NULL, NULL, 0, okm, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite2, encrypt_null_args)
{
	uint8_t ctxt[64];
	size_t ctxt_len;

	ret = edhoc_cipher_suite_2_encrypt(NULL, NULL, NULL, 0, NULL, 0, NULL,
					   0, ctxt, 64, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite2, decrypt_null_args)
{
	uint8_t ptxt[64];
	size_t ptxt_len;

	ret = edhoc_cipher_suite_2_decrypt(NULL, NULL, NULL, 0, NULL, 0, NULL,
					   0, ptxt, 64, &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite2, hash_null_args)
{
	uint8_t hash[32];
	size_t hash_len;

	ret = edhoc_cipher_suite_2_hash(NULL, NULL, 0, hash, 32, &hash_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(crypto_suite2, extract_destroyed_key)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_EXTRACT, raw_key,
					      32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);

	uint8_t salt[32] = { 0xAA };
	uint8_t prk[32];
	size_t prk_len;
	ret = edhoc_cipher_suite_2_extract(NULL, &kid, salt, 32, prk, 32,
					   &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(crypto_suite2, expand_destroyed_key)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_EXPAND, raw_key,
					      32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);

	uint8_t info[16] = { 0 };
	uint8_t okm[32];
	ret = edhoc_cipher_suite_2_expand(NULL, &kid, info, 16, okm, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(crypto_suite2, encrypt_destroyed_key)
{
	psa_key_id_t kid;
	uint8_t raw_key[16];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_ENCRYPT, raw_key,
					      16, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);

	uint8_t nonce[13] = { 0 };
	uint8_t ad[16] = { 0 };
	uint8_t ptxt[16] = { 0 };
	uint8_t ctxt[32];
	size_t ctxt_len;
	ret = edhoc_cipher_suite_2_encrypt(NULL, &kid, nonce, 13, ad, 16, ptxt,
					   16, ctxt, 32, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(crypto_suite2, decrypt_destroyed_key)
{
	psa_key_id_t kid;
	uint8_t raw_key[16];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_DECRYPT, raw_key,
					      16, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);

	uint8_t nonce[13] = { 0 };
	uint8_t ad[16] = { 0 };
	uint8_t ctxt[32] = { 0 };
	uint8_t ptxt[32];
	size_t ptxt_len;
	ret = edhoc_cipher_suite_2_decrypt(NULL, &kid, nonce, 13, ad, 16, ctxt,
					   32, ptxt, 32, &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(crypto_suite2, key_agreement_destroyed_key)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, 32, &kid);
	if (EDHOC_SUCCESS != ret) {
		return;
	}
	edhoc_cipher_suite_2_key_destroy(NULL, &kid);

	uint8_t peer_pub[32] = { 0 };
	uint8_t shr_sec[32];
	size_t shr_sec_len;
	ret = edhoc_cipher_suite_2_key_agreement(NULL, &kid, peer_pub, 32,
						 shr_sec, 32, &shr_sec_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(crypto_suite2, signature_destroyed_key)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);

	uint8_t input[32] = { 0 };
	uint8_t sign[64];
	size_t sign_len;
	ret = edhoc_cipher_suite_2_signature(NULL, &kid, input, 32, sign, 64,
					     &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(crypto_suite2, verify_destroyed_key)
{
	psa_key_id_t gen_kid;
	psa_key_attributes_t gen_attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&gen_attr,
				PSA_KEY_USAGE_SIGN_MESSAGE |
					PSA_KEY_USAGE_VERIFY_MESSAGE |
					PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&gen_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&gen_attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&gen_attr, 256);
	psa_status_t psa_ret = psa_generate_key(&gen_attr, &gen_kid);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_ret);

	uint8_t pub_key[65];
	size_t pub_key_len;
	psa_ret = psa_export_public_key(gen_kid, pub_key, sizeof(pub_key),
					&pub_key_len);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_ret);
	psa_destroy_key(gen_kid);

	psa_key_id_t kid;
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_VERIFY, pub_key,
					      pub_key_len, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	edhoc_cipher_suite_2_key_destroy(NULL, &kid);

	uint8_t input[32] = { 0 };
	uint8_t sign[64] = { 0 };
	ret = edhoc_cipher_suite_2_verify(NULL, &kid, input, 32, sign, 64);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(crypto_suite2, hash_wrong_size)
{
	uint8_t input[16] = { 0 };
	uint8_t hash[4];
	size_t hash_len;
	ret = edhoc_cipher_suite_2_hash(NULL, input, 16, hash, 4, &hash_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(crypto_suite2, make_key_pair_bad_size)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, 32, &kid);
	if (EDHOC_SUCCESS != ret) {
		return;
	}

	uint8_t priv[32], pub[65];
	size_t priv_len, pub_len;
	ret = edhoc_cipher_suite_2_make_key_pair(NULL, &kid, priv, 16,
						 &priv_len, pub, 16, &pub_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);
}

/**
 * @scenario  key_agreement with wrong peer_pub_key_len.
 * @env       PSA initialized, valid ECDH key imported.
 * @action    Call key_agreement with peer_pub_key_len = 16 (not 32).
 * @expected  Returns EDHOC_ERROR_CRYPTO_FAILURE (size mismatch).
 */
TEST(crypto_suite2, key_agreement_bad_peer_size)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, 32, &kid);
	if (EDHOC_SUCCESS != ret)
		return;

	uint8_t peer[32] = { 0 };
	uint8_t secret[32];
	size_t secret_len;
	ret = edhoc_cipher_suite_2_key_agreement(NULL, &kid, peer, 16, secret,
						 32, &secret_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);
}

/**
 * @scenario  key_agreement with wrong shr_sec_size.
 * @env       PSA initialized, valid ECDH key imported.
 * @action    Call key_agreement with shr_sec_size = 16 (not 32).
 * @expected  Returns EDHOC_ERROR_CRYPTO_FAILURE (size mismatch).
 */
TEST(crypto_suite2, key_agreement_bad_secret_size)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, 32, &kid);
	if (EDHOC_SUCCESS != ret)
		return;

	uint8_t peer[32] = { 0 };
	uint8_t secret[32];
	size_t secret_len;
	ret = edhoc_cipher_suite_2_key_agreement(NULL, &kid, peer, 32, secret,
						 16, &secret_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);
}

/**
 * @scenario  key_agreement with invalid compressed point (decompression failure).
 * @env       PSA initialized, valid ECDH key imported.
 * @action    Call key_agreement with peer_pub_key as invalid point (0xFF bytes).
 * @expected  Returns EDHOC_ERROR_CRYPTO_FAILURE (decompress failure).
 */
TEST(crypto_suite2, key_agreement_bad_point)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, 32, &kid);
	if (EDHOC_SUCCESS != ret)
		return;

	uint8_t bad_peer[32];
	memset(bad_peer, 0xFF, sizeof(bad_peer));
	uint8_t secret[32];
	size_t secret_len;
	ret = edhoc_cipher_suite_2_key_agreement(NULL, &kid, bad_peer, 32,
						 secret, 32, &secret_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);
}

/**
 * @scenario  signature with wrong sign_size.
 * @env       PSA initialized, valid ECDSA key imported.
 * @action    Call signature with sign_size = 32 (not 64).
 * @expected  Returns EDHOC_ERROR_CRYPTO_FAILURE (size mismatch).
 */
TEST(crypto_suite2, signature_bad_size)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t input[16] = { 0x42 };
	uint8_t sign[64];
	size_t sign_len;
	ret = edhoc_cipher_suite_2_signature(NULL, &kid, input, 16, sign, 32,
					     &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);
}

/**
 * @scenario  verify with wrong sign_len.
 * @env       PSA initialized, valid ECDSA verify key from generated key pair.
 * @action    Call verify with sign_len = 32 (not 64).
 * @expected  Returns EDHOC_ERROR_CRYPTO_FAILURE (size mismatch).
 */
TEST(crypto_suite2, verify_bad_sign_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT |
					       PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);

	psa_key_id_t pair_kid;
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_generate_key(&attr, &pair_kid));

	uint8_t pub_key[65];
	size_t pub_key_len = 0;
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_export_public_key(pair_kid, pub_key,
						sizeof(pub_key), &pub_key_len));

	psa_key_id_t kid;
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_VERIFY, pub_key,
					      pub_key_len, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t input[16] = { 0x42 };
	uint8_t sign[64] = { 0 };
	ret = edhoc_cipher_suite_2_verify(NULL, &kid, input, 16, sign, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	psa_destroy_key(pair_kid);
	edhoc_cipher_suite_2_key_destroy(NULL, &kid);
}

/**
 * @scenario  encrypt with wrong key type (EXTRACT key used for AEAD).
 * @env       PSA initialized, key imported as EXTRACT type.
 * @action    Call encrypt with the EXTRACT key.
 * @expected  psa_get_key_attributes succeeds but psa_aead_encrypt fails.
 */
TEST(crypto_suite2, encrypt_wrong_key_type)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_EXTRACT, raw_key,
					      32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[13] = { 0 };
	uint8_t ad[16] = { 0 };
	uint8_t ptxt[16] = { 0 };
	uint8_t ctxt[32];
	size_t ctxt_len;
	ret = edhoc_cipher_suite_2_encrypt(NULL, &kid, nonce, 13, ad, 16, ptxt,
					   16, ctxt, 32, &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);
}

/**
 * @scenario  decrypt with wrong key type (EXPAND key used for AEAD).
 * @env       PSA initialized, key imported as EXPAND type.
 * @action    Call decrypt with the EXPAND key.
 * @expected  psa_get_key_attributes succeeds but psa_aead_decrypt fails.
 */
TEST(crypto_suite2, decrypt_wrong_key_type)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_EXPAND, raw_key,
					      32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[13] = { 0 };
	uint8_t ad[16] = { 0 };
	uint8_t ctxt[32] = { 0 };
	uint8_t ptxt[32];
	size_t ptxt_len;
	ret = edhoc_cipher_suite_2_decrypt(NULL, &kid, nonce, 13, ad, 16, ctxt,
					   24, ptxt, 32, &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);
}

/**
 * @scenario  signature with destroyed key (covers psa_sign_message fail).
 * @env       Import signature key, destroy it, call signature with correct sizes.
 * @action    signature with destroyed key passes size check but fails PSA.
 * @expected  Returns EDHOC_ERROR_CRYPTO_FAILURE.
 */
TEST(crypto_suite2, signature_destroyed_key_v2)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      32, &kid);
	if (EDHOC_SUCCESS != ret)
		return;

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);

	uint8_t input[32] = { 0 };
	uint8_t sign[64];
	size_t sign_len;
	ret = edhoc_cipher_suite_2_signature(NULL, &kid, input, 32, sign, 64,
					     &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

/**
 * @scenario  key_destroy with invalid (non-existent) key ID.
 * @env       PSA initialized. Use a fabricated invalid key ID.
 * @action    Call key_destroy with invalid key ID.
 * @expected  psa_destroy_key fails -> EDHOC_ERROR_CRYPTO_FAILURE.
 */
TEST(crypto_suite2, key_destroy_invalid_id)
{
	psa_key_id_t kid = 0xDEADBEEF;
	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

/**
 * @scenario  extract with wrong key type triggers derivation setup failure.
 * @env       PSA initialized, key imported as SIGNATURE type.
 * @action    Call extract with the SIGNATURE key (ECDSA algorithm).
 * @expected  psa_key_derivation_setup fails -> EDHOC_ERROR_CRYPTO_FAILURE.
 */
TEST(crypto_suite2, extract_wrong_key_type)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t salt[16] = { 0 };
	uint8_t prk[32];
	size_t prk_len;
	ret = edhoc_cipher_suite_2_extract(NULL, &kid, salt, 16, prk, 32,
					   &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);
}

/**
 * @scenario  expand with wrong key type triggers derivation setup failure.
 * @env       PSA initialized, key imported as SIGNATURE type.
 * @action    Call expand with the SIGNATURE key (ECDSA algorithm).
 * @expected  psa_key_derivation_setup fails -> EDHOC_ERROR_CRYPTO_FAILURE.
 */
TEST(crypto_suite2, expand_wrong_key_type)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t info[16] = { 0 };
	uint8_t okm[32];
	ret = edhoc_cipher_suite_2_expand(NULL, &kid, info, 16, okm, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);
}

/**
 * @scenario  key_agreement with wrong key type (SIGNATURE key for ECDH).
 * @env       PSA initialized. Generate valid compressed peer key. Import
 *            local key as SIGNATURE type (ECDSA algorithm).
 * @action    Call key_agreement. Decompression succeeds, attributes readable,
 *            but psa_raw_key_agreement fails with algorithm mismatch.
 * @expected  Returns EDHOC_ERROR_CRYPTO_FAILURE at the key agreement step.
 */
TEST(crypto_suite2, key_agreement_wrong_key_type)
{
	/* Generate a valid P-256 key pair to get a valid compressed public key */
	psa_key_id_t gen_kid;
	psa_key_attributes_t gen_attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&gen_attr, PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&gen_attr, PSA_ALG_ECDH);
	psa_set_key_type(&gen_attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&gen_attr, 256);
	psa_status_t psa_ret = psa_generate_key(&gen_attr, &gen_kid);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_ret);

	uint8_t uncomp_pub[65];
	size_t uncomp_pub_len;
	psa_ret = psa_export_public_key(gen_kid, uncomp_pub, sizeof(uncomp_pub),
					&uncomp_pub_len);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_ret);
	psa_destroy_key(gen_kid);

	/* Compress the public key: take X coordinate with 0x02/0x03 prefix */
	uint8_t comp_pub[33];
	comp_pub[0] = (uncomp_pub[64] & 1) ? 0x03 : 0x02;
	memcpy(&comp_pub[1], &uncomp_pub[1], 32);

	/* Import a key as SIGNATURE type (ECDSA algorithm, not ECDH) */
	psa_key_id_t sig_kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      32, &sig_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t shr_sec[32];
	size_t shr_sec_len;
	ret = edhoc_cipher_suite_2_key_agreement(NULL, &sig_kid, comp_pub, 33,
						 shr_sec, 32, &shr_sec_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &sig_kid);
}

/**
 * @scenario  make_key_pair with destroyed key.
 * @env       Generate a key pair key, destroy it.
 * @action    Call make_key_pair with the destroyed key.
 * @expected  psa_export_key fails -> EDHOC_ERROR_CRYPTO_FAILURE.
 */
TEST(crypto_suite2, make_key_pair_destroyed_key)
{
	psa_key_id_t kid;
	uint8_t raw_key[32];
	psa_generate_random(raw_key, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_MAKE_KEY_PAIR,
					      raw_key, 32, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	edhoc_cipher_suite_2_key_destroy(NULL, &kid);

	uint8_t priv[32], pub[32];
	size_t priv_len, pub_len;
	ret = edhoc_cipher_suite_2_make_key_pair(NULL, &kid, priv, 32,
						 &priv_len, pub, 32, &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

/**
 * @scenario  signature with verify-only (public) key — psa_sign_hash must fail.
 */
TEST(crypto_suite2, signature_public_key_rejected)
{
	const uint8_t pub_key[ECC_UNCOMP_KEY_LEN] = {
		0x04, 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e,
		0xd6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf,
		0x16, 0xdf, 0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30,
		0x7f, 0x7e, 0xb6, 0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b,
		0x8a, 0x82, 0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52,
		0xa3, 0x87, 0xd2, 0x57, 0xe6, 0xdb, 0x3c, 0x2a, 0x93, 0xdf,
		0x21, 0xff, 0x3a, 0xff, 0xc8,
	};

	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	ret = edhoc_keys->import_key(NULL, EDHOC_KT_VERIFY, pub_key,
				     ARRAY_SIZE(pub_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t input[16] = { 0x01 };
	uint8_t sign[ECC_ECDSA_SIGN_LEN];
	size_t sign_len = 0;
	ret = edhoc_crypto->signature(NULL, &kid, input, ARRAY_SIZE(input),
				      sign, ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_keys->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

/**
 * @scenario  verify with corrupted signature — psa_verify_hash fails after hash.
 */
TEST(crypto_suite2, verify_corrupted_signature)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	const uint8_t priv_key[ECC_COMP_KEY_LEN] = {
		0xfb, 0x13, 0xad, 0xeb, 0x65, 0x18, 0xce, 0xe5,
		0xf8, 0x84, 0x17, 0x66, 0x08, 0x41, 0x14, 0x2e,
		0x83, 0x0a, 0x81, 0xfe, 0x33, 0x43, 0x80, 0xa9,
		0x53, 0x40, 0x6a, 0x13, 0x05, 0xe8, 0x70, 0x6b,
	};
	const uint8_t pub_key[ECC_UNCOMP_KEY_LEN] = {
		0x04, 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e,
		0xd6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf,
		0x16, 0xdf, 0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30,
		0x7f, 0x7e, 0xb6, 0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b,
		0x8a, 0x82, 0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52,
		0xa3, 0x87, 0xd2, 0x57, 0xe6, 0xdb, 0x3c, 0x2a, 0x93, 0xdf,
		0x21, 0xff, 0x3a, 0xff, 0xc8,
	};

	uint8_t input[32];
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_generate_random(input, sizeof(input)));

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_SIGNATURE, priv_key,
				     ARRAY_SIZE(priv_key), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t sign[ECC_ECDSA_SIGN_LEN];
	size_t sign_len = 0;
	ret = edhoc_crypto->signature(NULL, &key_id, input, ARRAY_SIZE(input),
				      sign, ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL((size_t)ECC_ECDSA_SIGN_LEN, sign_len);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_VERIFY, pub_key,
				     ARRAY_SIZE(pub_key), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	sign[0] ^= (uint8_t)0xFF;
	ret = edhoc_crypto->verify(NULL, &key_id, input, ARRAY_SIZE(input),
				   sign, sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

/**
 * @scenario  signature and verify with input_len == 0.
 */
TEST(crypto_suite2, signature_verify_zero_input_len)
{
	const uint8_t priv_key[ECC_COMP_KEY_LEN] = {
		0xfb, 0x13, 0xad, 0xeb, 0x65, 0x18, 0xce, 0xe5,
		0xf8, 0x84, 0x17, 0x66, 0x08, 0x41, 0x14, 0x2e,
		0x83, 0x0a, 0x81, 0xfe, 0x33, 0x43, 0x80, 0xa9,
		0x53, 0x40, 0x6a, 0x13, 0x05, 0xe8, 0x70, 0x6b,
	};
	const uint8_t pub_key[ECC_UNCOMP_KEY_LEN] = {
		0x04, 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e,
		0xd6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf,
		0x16, 0xdf, 0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30,
		0x7f, 0x7e, 0xb6, 0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b,
		0x8a, 0x82, 0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52,
		0xa3, 0x87, 0xd2, 0x57, 0xe6, 0xdb, 0x3c, 0x2a, 0x93, 0xdf,
		0x21, 0xff, 0x3a, 0xff, 0xc8,
	};

	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	ret = edhoc_keys->import_key(NULL, EDHOC_KT_SIGNATURE, priv_key,
				     ARRAY_SIZE(priv_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t dummy = 0;
	uint8_t sign[ECC_ECDSA_SIGN_LEN];
	size_t sign_len = 0;
	ret = edhoc_crypto->signature(NULL, &kid, &dummy, 0, sign,
				      ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_keys->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_VERIFY, pub_key,
				     ARRAY_SIZE(pub_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t fake_sign[ECC_ECDSA_SIGN_LEN] = { 0 };
	ret = edhoc_crypto->verify(NULL, &kid, &dummy, 0, fake_sign,
				   ARRAY_SIZE(fake_sign));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_keys->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST_GROUP_RUNNER(crypto_suite2)
{
	RUN_TEST_CASE(crypto_suite2, ecdsa);
	RUN_TEST_CASE(crypto_suite2, ecdh);
	RUN_TEST_CASE(crypto_suite2, hkdf);
	RUN_TEST_CASE(crypto_suite2, aead);
	RUN_TEST_CASE(crypto_suite2, hash);
	RUN_TEST_CASE(crypto_suite2, key_import_invalid_type);
	RUN_TEST_CASE(crypto_suite2, key_import_rejects_invalid_key_material);
	RUN_TEST_CASE(crypto_suite2, extract_prk_capacity_too_large);
	RUN_TEST_CASE(crypto_suite2, expand_okm_length_too_large);
	RUN_TEST_CASE(crypto_suite2, aead_zero_length_plaintext);
	RUN_TEST_CASE(crypto_suite2, key_destroy_null);
	RUN_TEST_CASE(crypto_suite2, make_key_pair_null_args);
	RUN_TEST_CASE(crypto_suite2, key_agreement_null_args);
	RUN_TEST_CASE(crypto_suite2, signature_null_args);
	RUN_TEST_CASE(crypto_suite2, verify_null_args);
	RUN_TEST_CASE(crypto_suite2, extract_null_args);
	RUN_TEST_CASE(crypto_suite2, expand_null_args);
	RUN_TEST_CASE(crypto_suite2, encrypt_null_args);
	RUN_TEST_CASE(crypto_suite2, decrypt_null_args);
	RUN_TEST_CASE(crypto_suite2, hash_null_args);
	RUN_TEST_CASE(crypto_suite2, extract_destroyed_key);
	RUN_TEST_CASE(crypto_suite2, expand_destroyed_key);
	RUN_TEST_CASE(crypto_suite2, encrypt_destroyed_key);
	RUN_TEST_CASE(crypto_suite2, decrypt_destroyed_key);
	RUN_TEST_CASE(crypto_suite2, key_agreement_destroyed_key);
	RUN_TEST_CASE(crypto_suite2, signature_destroyed_key);
	RUN_TEST_CASE(crypto_suite2, verify_destroyed_key);
	RUN_TEST_CASE(crypto_suite2, hash_wrong_size);
	RUN_TEST_CASE(crypto_suite2, make_key_pair_bad_size);
	RUN_TEST_CASE(crypto_suite2, key_agreement_bad_peer_size);
	RUN_TEST_CASE(crypto_suite2, key_agreement_bad_secret_size);
	RUN_TEST_CASE(crypto_suite2, key_agreement_bad_point);
	RUN_TEST_CASE(crypto_suite2, signature_bad_size);
	RUN_TEST_CASE(crypto_suite2, verify_bad_sign_len);
	RUN_TEST_CASE(crypto_suite2, encrypt_wrong_key_type);
	RUN_TEST_CASE(crypto_suite2, decrypt_wrong_key_type);
	RUN_TEST_CASE(crypto_suite2, signature_destroyed_key_v2);
	RUN_TEST_CASE(crypto_suite2, key_destroy_invalid_id);
	RUN_TEST_CASE(crypto_suite2, extract_wrong_key_type);
	RUN_TEST_CASE(crypto_suite2, expand_wrong_key_type);
	RUN_TEST_CASE(crypto_suite2, key_agreement_wrong_key_type);
	RUN_TEST_CASE(crypto_suite2, make_key_pair_destroyed_key);
	RUN_TEST_CASE(crypto_suite2, signature_public_key_rejected);
	RUN_TEST_CASE(crypto_suite2, verify_corrupted_signature);
	RUN_TEST_CASE(crypto_suite2, signature_verify_zero_input_len);
}
