/**
 * \file    test_cipher_suite_0.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for cipher suite 0.
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
#include <stdlib.h>

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
static const struct edhoc_cipher_suite *edhoc_suite;

static int ret = EDHOC_ERROR_GENERIC_ERROR;

/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(cipher_suite_0);

TEST_SETUP(cipher_suite_0)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
	edhoc_keys = edhoc_cipher_suite_0_get_keys();
	edhoc_crypto = edhoc_cipher_suite_0_get_crypto();
	edhoc_suite = edhoc_cipher_suite_0_get_suite();
}

TEST_TEAR_DOWN(cipher_suite_0)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_0, eddsa)
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

	const uint8_t pub_key[] = {
		0xa1, 0xdb, 0x47, 0xb9, 0x51, 0x84, 0x85, 0x4a,
		0xd1, 0x2a, 0x0c, 0x1a, 0x35, 0x4e, 0x41, 0x8a,
		0xac, 0xe3, 0x3a, 0xa0, 0xf2, 0xc6, 0x62, 0xc0,
		0x0b, 0x3a, 0xc5, 0x5d, 0xe9, 0x2f, 0x93, 0x59,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->ecc_key_length, ARRAY_SIZE(pub_key));

	/* Random input for signature. */
	uint8_t input[INPUT_TO_SIGN_LEN] = { 0 };
	ret = psa_generate_random(input, ARRAY_SIZE(input));
	TEST_ASSERT_EQUAL(PSA_SUCCESS, ret);

	size_t sign_len = 0;
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));

	/* Generate signature. */
	ret = edhoc_keys->import_key(NULL, EDHOC_KT_SIGNATURE, priv_key,
				     ARRAY_SIZE(priv_key), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->signature(NULL, &key_id, input, ARRAY_SIZE(input),
				      sign, ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_VERIFY, pub_key,
				     ARRAY_SIZE(pub_key), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Verify signature. */
	ret = edhoc_crypto->verify(NULL, &key_id, input, ARRAY_SIZE(input),
				   sign, sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_0, ecdh)
{
	psa_key_id_t key_id_a = PSA_KEY_HANDLE_INIT;
	psa_key_id_t key_id_b = PSA_KEY_HANDLE_INIT;

	size_t priv_key_len_a = 0;
	uint8_t priv_key_a[edhoc_suite->ecc_key_length];
	memset(priv_key_a, 0, sizeof(priv_key_a));

	size_t pub_key_len_a = 0;
	uint8_t pub_key_a[edhoc_suite->ecc_key_length];
	memset(pub_key_a, 0, sizeof(pub_key_a));

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
	uint8_t priv_key_b[edhoc_suite->ecc_key_length];
	memset(priv_key_b, 0, sizeof(priv_key_b));

	size_t pub_key_len_b = 0;
	uint8_t pub_key_b[edhoc_suite->ecc_key_length];
	memset(pub_key_b, 0, sizeof(pub_key_b));

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
	uint8_t shr_sec_a[edhoc_suite->ecc_key_length];
	memset(shr_sec_a, 0, sizeof(shr_sec_a));

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
	uint8_t shr_sec_b[edhoc_suite->ecc_key_length];
	memset(shr_sec_b, 0, sizeof(shr_sec_b));

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

TEST(cipher_suite_0, hkdf)
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
	uint8_t comp_prk[edhoc_suite->hash_length];
	memset(comp_prk, 0, sizeof(comp_prk));

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

TEST(cipher_suite_0, aead)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	/* AEAD key, iv and aad. */
	const uint8_t key[] = {
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->aead_key_length, ARRAY_SIZE(key));
	const uint8_t iv[] = {
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 0, 0,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->aead_iv_length, ARRAY_SIZE(iv));
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

TEST(cipher_suite_0, hash)
{
	/* Input for hash function and expected hash. */
	const uint8_t input[] = { 'A' };

	const uint8_t exp_hash[] = {
		0x55, 0x9a, 0xea, 0xd0, 0x82, 0x64, 0xd5, 0x79,
		0x5d, 0x39, 0x09, 0x71, 0x8c, 0xdd, 0x05, 0xab,
		0xd4, 0x95, 0x72, 0xe8, 0x4f, 0xe5, 0x55, 0x90,
		0xee, 0xf3, 0x1a, 0x88, 0xa0, 0x8f, 0xdf, 0xfd,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->hash_length, ARRAY_SIZE(exp_hash));

	/* Hashing operation. */
	size_t hash_len = 0;
	uint8_t hash[edhoc_suite->hash_length];
	memset(hash, 0, sizeof(hash));

	ret = edhoc_crypto->hash(NULL, input, ARRAY_SIZE(input), hash,
				 ARRAY_SIZE(hash), &hash_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(hash), hash_len);

	/* Verify if hashes are equals. */
	TEST_ASSERT_EQUAL_UINT8_ARRAY(hash, exp_hash, ARRAY_SIZE(exp_hash));
}

TEST(cipher_suite_0, key_import_invalid_type)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t key[edhoc_suite->ecc_key_length];
	memset(key, 0, sizeof(key));
	ret = edhoc_cipher_suite_0_key_import(NULL, 99, key, ARRAY_SIZE(key),
					      &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_0, key_destroy_null)
{
	ret = edhoc_cipher_suite_0_key_destroy(NULL, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_0, make_key_pair_null_args)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t priv[edhoc_suite->ecc_key_length];
	memset(priv, 0, sizeof(priv));
	uint8_t pub[edhoc_suite->ecc_key_length];
	memset(pub, 0, sizeof(pub));
	size_t priv_len = 0;
	size_t pub_len = 0;

	ret = edhoc_cipher_suite_0_make_key_pair(NULL, NULL, priv,
						 ARRAY_SIZE(priv), &priv_len,
						 pub, ARRAY_SIZE(pub),
						 &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_suite_0_make_key_pair(NULL, &kid, NULL,
						 ARRAY_SIZE(priv), &priv_len,
						 pub, ARRAY_SIZE(pub),
						 &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_suite_0_make_key_pair(NULL, &kid, priv,
						 ARRAY_SIZE(priv), &priv_len,
						 NULL, ARRAY_SIZE(pub),
						 &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_0, make_key_pair_bad_size)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t priv[edhoc_suite->ecc_key_length];
	memset(priv, 0, sizeof(priv));
	uint8_t pub[edhoc_suite->ecc_key_length];
	memset(pub, 0, sizeof(pub));
	size_t priv_len = 0;
	size_t pub_len = 0;

	ret = edhoc_cipher_suite_0_make_key_pair(NULL, &kid, priv, 16,
						 &priv_len, pub,
						 ARRAY_SIZE(pub), &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_0, key_agreement_null_args)
{
	uint8_t shr_sec[edhoc_suite->ecc_key_length];
	memset(shr_sec, 0, sizeof(shr_sec));
	size_t shr_sec_len = 0;

	ret = edhoc_cipher_suite_0_key_agreement(NULL, NULL, NULL, 0, shr_sec,
						 ARRAY_SIZE(shr_sec),
						 &shr_sec_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_0, signature_null_args)
{
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;

	ret = edhoc_cipher_suite_0_signature(NULL, NULL, NULL, 0, sign,
					     ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_0, verify_null_args)
{
	ret = edhoc_cipher_suite_0_verify(NULL, NULL, NULL, 0, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_0, extract_null_args)
{
	uint8_t prk[edhoc_suite->hash_length];
	memset(prk, 0, sizeof(prk));
	size_t prk_len = 0;

	ret = edhoc_cipher_suite_0_extract(NULL, NULL, NULL, 0, prk,
					   ARRAY_SIZE(prk), &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_0, expand_null_args)
{
	uint8_t okm[edhoc_suite->hash_length];
	memset(okm, 0, sizeof(okm));

	ret = edhoc_cipher_suite_0_expand(NULL, NULL, NULL, 0, okm,
					  ARRAY_SIZE(okm));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_0, encrypt_null_args)
{
	uint8_t ctxt[64] = { 0 };
	size_t ctxt_len = 0;

	ret = edhoc_cipher_suite_0_encrypt(NULL, NULL, NULL, 0, NULL, 0, NULL,
					   0, ctxt, ARRAY_SIZE(ctxt),
					   &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_0, decrypt_null_args)
{
	uint8_t ptxt[64] = { 0 };
	size_t ptxt_len = 0;

	ret = edhoc_cipher_suite_0_decrypt(NULL, NULL, NULL, 0, NULL, 0, NULL,
					   0, ptxt, ARRAY_SIZE(ptxt),
					   &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_0, extract_destroyed_key)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_EXTRACT, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_cipher_suite_0_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t salt[32] = { 0xAA };
	uint8_t prk[edhoc_suite->hash_length];
	memset(prk, 0, sizeof(prk));
	size_t prk_len = 0;

	ret = edhoc_cipher_suite_0_extract(NULL, &kid, salt, ARRAY_SIZE(salt),
					   prk, ARRAY_SIZE(prk), &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_0, expand_destroyed_key)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_EXPAND, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_cipher_suite_0_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t info[16] = { 0 };
	uint8_t okm[edhoc_suite->hash_length];
	memset(okm, 0, sizeof(okm));

	ret = edhoc_cipher_suite_0_expand(NULL, &kid, info, ARRAY_SIZE(info),
					  okm, ARRAY_SIZE(okm));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_0, encrypt_destroyed_key)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->aead_key_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_ENCRYPT, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_cipher_suite_0_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[edhoc_suite->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));
	const uint8_t ad[16] = { 0 };
	const uint8_t ptxt[16] = { 0 };
	uint8_t ctxt[32] = { 0 };
	size_t ctxt_len = 0;

	ret = edhoc_cipher_suite_0_encrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce),
					   ad, ARRAY_SIZE(ad), ptxt,
					   ARRAY_SIZE(ptxt), ctxt,
					   ARRAY_SIZE(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_0, decrypt_destroyed_key)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->aead_key_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_DECRYPT, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_cipher_suite_0_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[edhoc_suite->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));
	const uint8_t ad[16] = { 0 };
	const uint8_t ctxt[32] = { 0 };
	uint8_t ptxt[32] = { 0 };
	size_t ptxt_len = 0;

	ret = edhoc_cipher_suite_0_decrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce),
					   ad, ARRAY_SIZE(ad), ctxt,
					   ARRAY_SIZE(ctxt), ptxt,
					   ARRAY_SIZE(ptxt), &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_0, hash_wrong_size)
{
	const uint8_t input[16] = { 0 };
	uint8_t hash[4] = { 0 };
	size_t hash_len = 0;

	ret = edhoc_cipher_suite_0_hash(NULL, input, ARRAY_SIZE(input), hash,
					ARRAY_SIZE(hash), &hash_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_0, hash_null_args)
{
	uint8_t hash[edhoc_suite->hash_length];
	memset(hash, 0, sizeof(hash));
	size_t hash_len = 0;

	ret = edhoc_cipher_suite_0_hash(NULL, NULL, 0, hash, ARRAY_SIZE(hash),
					&hash_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_0, key_agreement_bad_size)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, ARRAY_SIZE(raw_key),
					      &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t peer[edhoc_suite->ecc_key_length];
	memset(peer, 0, sizeof(peer));
	uint8_t secret[edhoc_suite->ecc_key_length];
	memset(secret, 0, sizeof(secret));
	size_t secret_len = 0;

	ret = edhoc_cipher_suite_0_key_agreement(
		NULL, &kid, peer, 16, secret, ARRAY_SIZE(secret), &secret_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_0_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_0, key_agreement_bad_secret_size)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, ARRAY_SIZE(raw_key),
					      &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t peer[edhoc_suite->ecc_key_length];
	memset(peer, 0, sizeof(peer));
	uint8_t secret[edhoc_suite->ecc_key_length];
	memset(secret, 0, sizeof(secret));
	size_t secret_len = 0;

	ret = edhoc_cipher_suite_0_key_agreement(
		NULL, &kid, peer, ARRAY_SIZE(peer), secret, 16, &secret_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_0_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_0, signature_bad_size)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[ED25519_PRIVATE_KEY_SIZE];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t input[16] = { 0x42 };
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;

	ret = edhoc_cipher_suite_0_signature(
		NULL, &kid, input, ARRAY_SIZE(input), sign, 32, &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_0_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_0, verify_bad_sign_len)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_VERIFY, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t input[16] = { 0x42 };
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));

	ret = edhoc_cipher_suite_0_verify(NULL, &kid, input, ARRAY_SIZE(input),
					  sign, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_0_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_0, key_agreement_destroyed_key)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, ARRAY_SIZE(raw_key),
					      &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_cipher_suite_0_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t peer[edhoc_suite->ecc_key_length];
	memset(peer, 0, sizeof(peer));
	uint8_t secret[edhoc_suite->ecc_key_length];
	memset(secret, 0, sizeof(secret));
	size_t secret_len = 0;

	ret = edhoc_cipher_suite_0_key_agreement(NULL, &kid, peer,
						 ARRAY_SIZE(peer), secret,
						 ARRAY_SIZE(secret),
						 &secret_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_0, signature_destroyed_key)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[ED25519_PRIVATE_KEY_SIZE];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_cipher_suite_0_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t input[16] = { 0x42 };
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;

	ret = edhoc_cipher_suite_0_signature(NULL, &kid, input,
					     ARRAY_SIZE(input), sign,
					     ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_0, verify_destroyed_key)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_VERIFY, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	edhoc_cipher_suite_0_key_destroy(NULL, &kid);

	const uint8_t input[16] = { 0x42 };
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));

	ret = edhoc_cipher_suite_0_verify(NULL, &kid, input, ARRAY_SIZE(input),
					  sign, ARRAY_SIZE(sign));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_0, encrypt_wrong_key_type)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_EXTRACT, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[edhoc_suite->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));
	const uint8_t ad[16] = { 0 };
	const uint8_t ptxt[16] = { 0 };
	uint8_t ctxt[32] = { 0 };
	size_t ctxt_len = 0;

	ret = edhoc_cipher_suite_0_encrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce),
					   ad, ARRAY_SIZE(ad), ptxt,
					   ARRAY_SIZE(ptxt), ctxt,
					   ARRAY_SIZE(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_0_key_destroy(NULL, &kid);
}

TEST(cipher_suite_0, decrypt_wrong_key_type)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_EXPAND, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[edhoc_suite->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));
	const uint8_t ad[16] = { 0 };
	const uint8_t ctxt[32] = { 0 };
	uint8_t ptxt[32] = { 0 };
	size_t ptxt_len = 0;

	ret = edhoc_cipher_suite_0_decrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce),
					   ad, ARRAY_SIZE(ad), ctxt,
					   ARRAY_SIZE(ctxt), ptxt,
					   ARRAY_SIZE(ptxt), &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_0_key_destroy(NULL, &kid);
}

TEST(cipher_suite_0, extract_wrong_key_type)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->aead_key_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_ENCRYPT, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t salt[16] = { 0 };
	uint8_t prk[edhoc_suite->hash_length];
	memset(prk, 0, sizeof(prk));
	size_t prk_len = 0;
	ret = edhoc_cipher_suite_0_extract(NULL, &kid, salt, ARRAY_SIZE(salt),
					   prk, ARRAY_SIZE(prk), &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	edhoc_cipher_suite_0_key_destroy(NULL, &kid);
}

TEST(cipher_suite_0, expand_wrong_key_type)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->aead_key_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_ENCRYPT, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t info[16] = { 0 };
	uint8_t okm[edhoc_suite->hash_length];
	memset(okm, 0, sizeof(okm));

	ret = edhoc_cipher_suite_0_expand(NULL, &kid, info, ARRAY_SIZE(info),
					  okm, ARRAY_SIZE(okm));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_0_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_0, signature_destroyed_key_v2)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[ED25519_PRIVATE_KEY_SIZE];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_cipher_suite_0_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t input[32] = { 0 };
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;

	ret = edhoc_cipher_suite_0_signature(NULL, &kid, input,
					     ARRAY_SIZE(input), sign,
					     ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_0, signature_bitflip_r_and_s)
{
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

	const uint8_t pub_key[] = {
		0xa1, 0xdb, 0x47, 0xb9, 0x51, 0x84, 0x85, 0x4a,
		0xd1, 0x2a, 0x0c, 0x1a, 0x35, 0x4e, 0x41, 0x8a,
		0xac, 0xe3, 0x3a, 0xa0, 0xf2, 0xc6, 0x62, 0xc0,
		0x0b, 0x3a, 0xc5, 0x5d, 0xe9, 0x2f, 0x93, 0x59,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->ecc_key_length, ARRAY_SIZE(pub_key));

	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	uint8_t input[32] = { 0 };
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_generate_random(input, sizeof(input)));

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_SIGNATURE, priv_key,
				     ARRAY_SIZE(priv_key), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;
	ret = edhoc_crypto->signature(NULL, &key_id, input, ARRAY_SIZE(input),
				      sign, ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL((size_t)edhoc_suite->ecc_sign_length, sign_len);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_VERIFY, pub_key,
				     ARRAY_SIZE(pub_key), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Corrupt one bit in the R component (first half). */
	uint8_t tampered[edhoc_suite->ecc_sign_length];
	memset(tampered, 0, sizeof(tampered));
	memcpy(tampered, sign, sizeof(tampered));
	tampered[0] ^= (uint8_t)0x01;
	ret = edhoc_crypto->verify(NULL, &key_id, input, ARRAY_SIZE(input),
				   tampered, sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	/* Corrupt one bit in the S component (second half). */
	memcpy(tampered, sign, sizeof(tampered));
	tampered[edhoc_suite->ecc_key_length] ^= (uint8_t)0x01;
	ret = edhoc_crypto->verify(NULL, &key_id, input, ARRAY_SIZE(input),
				   tampered, sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	/* The pristine signature must still verify. */
	ret = edhoc_crypto->verify(NULL, &key_id, input, ARRAY_SIZE(input),
				   sign, sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_0, aead_tag_tamper_detected)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	const uint8_t key[] = {
		9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->aead_key_length, ARRAY_SIZE(key));
	const uint8_t iv[] = {
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->aead_iv_length, ARRAY_SIZE(iv));
	const uint8_t aad[5] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
	const uint8_t ptxt[16] = {
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	};

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_ENCRYPT, key,
				     ARRAY_SIZE(key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t ctxt[ARRAY_SIZE(ptxt) + edhoc_suite->aead_tag_length];
	memset(ctxt, 0, sizeof(ctxt));
	size_t ctxt_len = 0;
	ret = edhoc_crypto->encrypt(NULL, &kid, iv, ARRAY_SIZE(iv), aad,
				    ARRAY_SIZE(aad), ptxt, ARRAY_SIZE(ptxt),
				    ctxt, ARRAY_SIZE(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ctxt), ctxt_len);

	ret = edhoc_keys->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Flip the last byte: that lands inside the 8-byte CCM tag. */
	ctxt[ctxt_len - 1] ^= (uint8_t)0x80;

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_DECRYPT, key,
				     ARRAY_SIZE(key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t dec[ARRAY_SIZE(ptxt)] = { 0 };
	size_t dec_len = 0;
	ret = edhoc_crypto->decrypt(NULL, &kid, iv, ARRAY_SIZE(iv), aad,
				    ARRAY_SIZE(aad), ctxt, ctxt_len, dec,
				    ARRAY_SIZE(dec), &dec_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_keys->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_0, aead_aad_tamper_detected)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	const uint8_t key[] = {
		3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->aead_key_length, ARRAY_SIZE(key));
	const uint8_t iv[] = {
		13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->aead_iv_length, ARRAY_SIZE(iv));
	const uint8_t aad_enc[4] = { 0x01, 0x02, 0x03, 0x04 };
	const uint8_t aad_dec[4] = { 0x01, 0x02, 0x03, 0x05 };
	const uint8_t ptxt[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_ENCRYPT, key,
				     ARRAY_SIZE(key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t ctxt[ARRAY_SIZE(ptxt) + edhoc_suite->aead_tag_length];
	memset(ctxt, 0, sizeof(ctxt));
	size_t ctxt_len = 0;
	ret = edhoc_crypto->encrypt(NULL, &kid, iv, ARRAY_SIZE(iv), aad_enc,
				    ARRAY_SIZE(aad_enc), ptxt, ARRAY_SIZE(ptxt),
				    ctxt, ARRAY_SIZE(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_DECRYPT, key,
				     ARRAY_SIZE(key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t dec[ARRAY_SIZE(ptxt)] = { 0 };
	size_t dec_len = 0;
	ret = edhoc_crypto->decrypt(NULL, &kid, iv, ARRAY_SIZE(iv), aad_dec,
				    ARRAY_SIZE(aad_dec), ctxt, ctxt_len, dec,
				    ARRAY_SIZE(dec), &dec_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_keys->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_0, hkdf_sha256_second_kat)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	const uint8_t ikm[32] = {
		0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24,
		0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24,
		0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24,
		0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24,
	};
	const uint8_t salt[16] = {
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
		0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
	};
	/* ASCII "edhoc cs0 kat". */
	const uint8_t info[13] = {
		0x65, 0x64, 0x68, 0x6f, 0x63, 0x20, 0x63,
		0x73, 0x30, 0x20, 0x6b, 0x61, 0x74,
	};

	const uint8_t prk[] = {
		0x71, 0x3f, 0x14, 0xa9, 0x34, 0xaa, 0xfb, 0x7f,
		0x5c, 0x8c, 0x5b, 0xb9, 0x7a, 0x99, 0x55, 0x8e,
		0x46, 0xf8, 0x98, 0x52, 0xe9, 0xac, 0xc5, 0xfd,
		0xb7, 0x3c, 0xa7, 0x86, 0x02, 0x6b, 0x3a, 0xe5,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->hash_length, ARRAY_SIZE(prk));

	const uint8_t okm[] = {
		0x28, 0xd3, 0xe1, 0x11, 0x2e, 0x71, 0x00, 0x33,
		0x12, 0xab, 0x4e, 0xa4, 0xdf, 0x44, 0x2d, 0x40,
		0xcf, 0x0a, 0x5e, 0xe2, 0xfa, 0x31, 0xc3, 0xef,
		0x2f, 0x35, 0xa6, 0xba, 0x31, 0x19, 0xa5, 0xb3,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->hash_length, ARRAY_SIZE(okm));

	size_t comp_prk_len = 0;
	uint8_t comp_prk[edhoc_suite->hash_length];
	memset(comp_prk, 0, sizeof(comp_prk));

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

	TEST_ASSERT_EQUAL_UINT8_ARRAY(prk, comp_prk, ARRAY_SIZE(prk));

	uint8_t comp_okm[edhoc_suite->hash_length];
	memset(comp_okm, 0, sizeof(comp_okm));
	ret = edhoc_keys->import_key(NULL, EDHOC_KT_EXPAND, comp_prk,
				     ARRAY_SIZE(comp_prk), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->expand(NULL, &key_id, info, ARRAY_SIZE(info),
				   comp_okm, ARRAY_SIZE(comp_okm));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(okm, comp_okm, ARRAY_SIZE(okm));
}

TEST(cipher_suite_0, key_import_rejects_invalid_key_material)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;

	const uint8_t short_priv[16] = { 0 };
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_SIGNATURE,
					      short_priv,
					      ARRAY_SIZE(short_priv), &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	const uint8_t short_aes[8] = { 0 };
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_ENCRYPT, short_aes,
					      ARRAY_SIZE(short_aes), &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	const uint8_t short_ecdh[16] = { 0 };
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      short_ecdh,
					      ARRAY_SIZE(short_ecdh), &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	uint8_t short_pub[40];
	memset(short_pub, 0x5a, sizeof(short_pub));
	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_VERIFY, short_pub,
					      ARRAY_SIZE(short_pub), &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_0, extract_prk_capacity_too_large)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_EXTRACT, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t salt[8] = { 0x01 };
	enum { prk_buf_len = 4096 };
	uint8_t prk[prk_buf_len];
	memset(prk, 0, sizeof(prk));
	size_t prk_len = 0;

	ret = edhoc_cipher_suite_0_extract(NULL, &kid, salt, ARRAY_SIZE(salt),
					   prk, ARRAY_SIZE(prk), &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_0_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_0, expand_okm_length_too_large)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_0_key_import(NULL, EDHOC_KT_EXPAND, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t info[4] = { 0xab, 0xcd, 0xef, 0x01 };
	enum { okm_len = 65536 };
	uint8_t *okm = malloc(okm_len);
	TEST_ASSERT_NOT_NULL(okm);

	ret = edhoc_cipher_suite_0_expand(NULL, &kid, info, ARRAY_SIZE(info),
					  okm, okm_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
	free(okm);

	ret = edhoc_cipher_suite_0_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_0, aead_zero_length_plaintext)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	const uint8_t key[] = {
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->aead_key_length, ARRAY_SIZE(key));
	uint8_t nonce[edhoc_suite->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));
	const uint8_t ad[4] = { 0x10, 0x11, 0x12, 0x13 };

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_ENCRYPT, key,
				     ARRAY_SIZE(key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t ctxt[32] = { 0 };
	size_t ctxt_len = 0;
	ret = edhoc_crypto->encrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce), ad,
				    ARRAY_SIZE(ad), NULL, (size_t)0, ctxt,
				    ARRAY_SIZE(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL((size_t)edhoc_suite->aead_tag_length, ctxt_len);

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

TEST_GROUP_RUNNER(cipher_suite_0)
{
	RUN_TEST_CASE(cipher_suite_0, eddsa);
	RUN_TEST_CASE(cipher_suite_0, ecdh);
	RUN_TEST_CASE(cipher_suite_0, hkdf);
	RUN_TEST_CASE(cipher_suite_0, aead);
	RUN_TEST_CASE(cipher_suite_0, hash);
	RUN_TEST_CASE(cipher_suite_0, key_import_invalid_type);
	RUN_TEST_CASE(cipher_suite_0, key_destroy_null);
	RUN_TEST_CASE(cipher_suite_0, make_key_pair_null_args);
	RUN_TEST_CASE(cipher_suite_0, make_key_pair_bad_size);
	RUN_TEST_CASE(cipher_suite_0, key_agreement_null_args);
	RUN_TEST_CASE(cipher_suite_0, signature_null_args);
	RUN_TEST_CASE(cipher_suite_0, verify_null_args);
	RUN_TEST_CASE(cipher_suite_0, extract_null_args);
	RUN_TEST_CASE(cipher_suite_0, expand_null_args);
	RUN_TEST_CASE(cipher_suite_0, encrypt_null_args);
	RUN_TEST_CASE(cipher_suite_0, decrypt_null_args);
	RUN_TEST_CASE(cipher_suite_0, extract_destroyed_key);
	RUN_TEST_CASE(cipher_suite_0, expand_destroyed_key);
	RUN_TEST_CASE(cipher_suite_0, encrypt_destroyed_key);
	RUN_TEST_CASE(cipher_suite_0, decrypt_destroyed_key);
	RUN_TEST_CASE(cipher_suite_0, hash_wrong_size);
	RUN_TEST_CASE(cipher_suite_0, hash_null_args);
	RUN_TEST_CASE(cipher_suite_0, key_agreement_bad_size);
	RUN_TEST_CASE(cipher_suite_0, key_agreement_bad_secret_size);
	RUN_TEST_CASE(cipher_suite_0, signature_bad_size);
	RUN_TEST_CASE(cipher_suite_0, verify_bad_sign_len);
	RUN_TEST_CASE(cipher_suite_0, key_agreement_destroyed_key);
	RUN_TEST_CASE(cipher_suite_0, signature_destroyed_key);
	RUN_TEST_CASE(cipher_suite_0, verify_destroyed_key);
	RUN_TEST_CASE(cipher_suite_0, encrypt_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_0, decrypt_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_0, extract_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_0, expand_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_0, signature_destroyed_key_v2);
	RUN_TEST_CASE(cipher_suite_0, signature_bitflip_r_and_s);
	RUN_TEST_CASE(cipher_suite_0, aead_tag_tamper_detected);
	RUN_TEST_CASE(cipher_suite_0, aead_aad_tamper_detected);
	RUN_TEST_CASE(cipher_suite_0, hkdf_sha256_second_kat);
	RUN_TEST_CASE(cipher_suite_0, key_import_rejects_invalid_key_material);
	RUN_TEST_CASE(cipher_suite_0, extract_prk_capacity_too_large);
	RUN_TEST_CASE(cipher_suite_0, expand_okm_length_too_large);
	RUN_TEST_CASE(cipher_suite_0, aead_zero_length_plaintext);
}
