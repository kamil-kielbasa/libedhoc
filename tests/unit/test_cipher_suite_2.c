/**
 * \file    test_cipher_suite_2.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for cipher suite 2.
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
static const struct edhoc_cipher_suite *edhoc_suite;

static int ret = EDHOC_ERROR_GENERIC_ERROR;

/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(cipher_suite_2);

TEST_SETUP(cipher_suite_2)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
	edhoc_keys = edhoc_cipher_suite_2_get_keys();
	edhoc_crypto = edhoc_cipher_suite_2_get_crypto();
	edhoc_suite = edhoc_cipher_suite_2_get_suite();
}

TEST_TEAR_DOWN(cipher_suite_2)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_2, ecdsa)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	const uint8_t priv_key[] = {
		0xfb, 0x13, 0xad, 0xeb, 0x65, 0x18, 0xce, 0xe5,
		0xf8, 0x84, 0x17, 0x66, 0x08, 0x41, 0x14, 0x2e,
		0x83, 0x0a, 0x81, 0xfe, 0x33, 0x43, 0x80, 0xa9,
		0x53, 0x40, 0x6a, 0x13, 0x05, 0xe8, 0x70, 0x6b,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->ecc_key_length, ARRAY_SIZE(priv_key));

	const uint8_t pub_key[] = {
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
	TEST_ASSERT_EQUAL(1U + 2U * edhoc_suite->ecc_key_length,
			  ARRAY_SIZE(pub_key));

	/* Random input for signature. */
	uint8_t input[INPUT_TO_SIGN_LEN] = { 0 };
	ret = psa_generate_random(input, ARRAY_SIZE(input));
	TEST_ASSERT_EQUAL(PSA_SUCCESS, ret);

	/* Generate signature. */
	size_t sign_len = 0;
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));

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

TEST(cipher_suite_2, ecdh)
{
	psa_key_id_t key_id_a = PSA_KEY_HANDLE_INIT;
	psa_key_id_t key_id_b = PSA_KEY_HANDLE_INIT;

	/* Alice ECDH public and private keys. */
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

	/* Bob ECDH public and private keys. */
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

TEST(cipher_suite_2, hkdf)
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

TEST(cipher_suite_2, aead)
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

TEST(cipher_suite_2, hash)
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

TEST(cipher_suite_2, key_import_invalid_type)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t key[edhoc_suite->ecc_key_length];
	memset(key, 0, sizeof(key));
	ret = edhoc_cipher_suite_2_key_import(NULL, 99, key, ARRAY_SIZE(key),
					      &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2, key_import_rejects_invalid_key_material)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;

	const uint8_t short_priv[16] = { 0 };
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_SIGNATURE,
					      short_priv,
					      ARRAY_SIZE(short_priv), &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	const uint8_t short_aes[8] = { 0 };
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_ENCRYPT, short_aes,
					      ARRAY_SIZE(short_aes), &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	uint8_t zero_ecdh[edhoc_suite->ecc_key_length];
	memset(zero_ecdh, 0, sizeof(zero_ecdh));

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      zero_ecdh, ARRAY_SIZE(zero_ecdh),
					      &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	uint8_t short_pub[40];
	memset(short_pub, 0x5a, sizeof(short_pub));

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_VERIFY, short_pub,
					      ARRAY_SIZE(short_pub), &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2, extract_prk_capacity_too_large)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_EXTRACT, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t salt[8] = { 0x01 };
	enum { prk_buf_len = 4096 };
	uint8_t prk[prk_buf_len];
	memset(prk, 0, sizeof(prk));
	size_t prk_len = 0;

	ret = edhoc_cipher_suite_2_extract(NULL, &kid, salt, ARRAY_SIZE(salt),
					   prk, ARRAY_SIZE(prk), &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, expand_okm_length_too_large)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_EXPAND, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t info[4] = { 0xab, 0xcd, 0xef, 0x01 };
	enum { okm_len = 65536 };
	uint8_t *okm = malloc(okm_len);

	TEST_ASSERT_NOT_NULL(okm);
	ret = edhoc_cipher_suite_2_expand(NULL, &kid, info, ARRAY_SIZE(info),
					  okm, okm_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
	free(okm);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, aead_zero_length_plaintext)
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

	uint8_t ctxt[32];
	size_t ctxt_len = 0;
	ret = edhoc_crypto->encrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce), ad,
				    ARRAY_SIZE(ad), NULL, (size_t)0, ctxt,
				    ARRAY_SIZE(ctxt), &ctxt_len);
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

TEST(cipher_suite_2, key_destroy_null)
{
	ret = edhoc_cipher_suite_2_key_destroy(NULL, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2, make_key_pair_null_args)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t priv[edhoc_suite->ecc_key_length];
	memset(priv, 0, sizeof(priv));
	uint8_t pub[edhoc_suite->ecc_key_length];
	memset(pub, 0, sizeof(pub));
	size_t priv_len = 0;
	size_t pub_len = 0;

	ret = edhoc_cipher_suite_2_make_key_pair(NULL, NULL, priv,
						 ARRAY_SIZE(priv), &priv_len,
						 pub, ARRAY_SIZE(pub),
						 &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_suite_2_make_key_pair(NULL, &kid, NULL,
						 ARRAY_SIZE(priv), &priv_len,
						 pub, ARRAY_SIZE(pub),
						 &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2, key_agreement_null_args)
{
	uint8_t shr_sec[edhoc_suite->ecc_key_length];
	memset(shr_sec, 0, sizeof(shr_sec));
	size_t shr_sec_len = 0;

	ret = edhoc_cipher_suite_2_key_agreement(NULL, NULL, NULL, 0, shr_sec,
						 ARRAY_SIZE(shr_sec),
						 &shr_sec_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2, signature_null_args)
{
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;

	ret = edhoc_cipher_suite_2_signature(NULL, NULL, NULL, 0, sign,
					     ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2, verify_null_args)
{
	ret = edhoc_cipher_suite_2_verify(NULL, NULL, NULL, 0, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2, extract_null_args)
{
	uint8_t prk[edhoc_suite->hash_length];
	memset(prk, 0, sizeof(prk));
	size_t prk_len = 0;

	ret = edhoc_cipher_suite_2_extract(NULL, NULL, NULL, 0, prk,
					   ARRAY_SIZE(prk), &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2, expand_null_args)
{
	uint8_t okm[edhoc_suite->hash_length];
	memset(okm, 0, sizeof(okm));

	ret = edhoc_cipher_suite_2_expand(NULL, NULL, NULL, 0, okm,
					  ARRAY_SIZE(okm));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2, encrypt_null_args)
{
	uint8_t ctxt[64];
	memset(ctxt, 0, sizeof(ctxt));
	size_t ctxt_len = 0;

	ret = edhoc_cipher_suite_2_encrypt(NULL, NULL, NULL, 0, NULL, 0, NULL,
					   0, ctxt, ARRAY_SIZE(ctxt),
					   &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2, decrypt_null_args)
{
	uint8_t ptxt[64];
	memset(ptxt, 0, sizeof(ptxt));
	size_t ptxt_len = 0;

	ret = edhoc_cipher_suite_2_decrypt(NULL, NULL, NULL, 0, NULL, 0, NULL,
					   0, ptxt, ARRAY_SIZE(ptxt),
					   &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2, hash_null_args)
{
	uint8_t hash[edhoc_suite->hash_length];
	memset(hash, 0, sizeof(hash));
	size_t hash_len = 0;

	ret = edhoc_cipher_suite_2_hash(NULL, NULL, 0, hash, ARRAY_SIZE(hash),
					&hash_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2, extract_destroyed_key)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_EXTRACT, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t salt[32] = { 0xAA };
	uint8_t prk[edhoc_suite->hash_length];
	memset(prk, 0, sizeof(prk));
	size_t prk_len = 0;

	ret = edhoc_cipher_suite_2_extract(NULL, &kid, salt, ARRAY_SIZE(salt),
					   prk, ARRAY_SIZE(prk), &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2, expand_destroyed_key)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_EXPAND, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t info[16] = { 0 };
	uint8_t okm[edhoc_suite->hash_length];
	memset(okm, 0, sizeof(okm));

	ret = edhoc_cipher_suite_2_expand(NULL, &kid, info, ARRAY_SIZE(info),
					  okm, ARRAY_SIZE(okm));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2, encrypt_destroyed_key)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->aead_key_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_ENCRYPT, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[edhoc_suite->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));
	const uint8_t ad[16] = { 0 };
	const uint8_t ptxt[16] = { 0 };
	uint8_t ctxt[32];
	memset(ctxt, 0, sizeof(ctxt));
	size_t ctxt_len = 0;

	ret = edhoc_cipher_suite_2_encrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce),
					   ad, ARRAY_SIZE(ad), ptxt,
					   ARRAY_SIZE(ptxt), ctxt,
					   ARRAY_SIZE(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2, decrypt_destroyed_key)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->aead_key_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_DECRYPT, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[edhoc_suite->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));
	const uint8_t ad[16] = { 0 };
	const uint8_t ctxt[32] = { 0 };
	uint8_t ptxt[32];
	memset(ptxt, 0, sizeof(ptxt));
	size_t ptxt_len = 0;

	ret = edhoc_cipher_suite_2_decrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce),
					   ad, ARRAY_SIZE(ad), ctxt,
					   ARRAY_SIZE(ctxt), ptxt,
					   ARRAY_SIZE(ptxt), &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2, key_agreement_destroyed_key)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));
	raw_key[sizeof(raw_key) - 1] = 0x01;

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, ARRAY_SIZE(raw_key),
					      &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t peer_pub[edhoc_suite->ecc_key_length];
	memset(peer_pub, 0, sizeof(peer_pub));
	uint8_t shr_sec[edhoc_suite->ecc_key_length];
	memset(shr_sec, 0, sizeof(shr_sec));
	size_t shr_sec_len = 0;

	ret = edhoc_cipher_suite_2_key_agreement(NULL, &kid, peer_pub,
						 ARRAY_SIZE(peer_pub), shr_sec,
						 ARRAY_SIZE(shr_sec),
						 &shr_sec_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2, signature_destroyed_key)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));
	raw_key[sizeof(raw_key) - 1] = 0x01;

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t input[32] = { 0 };
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;

	ret = edhoc_cipher_suite_2_signature(NULL, &kid, input,
					     ARRAY_SIZE(input), sign,
					     ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2, verify_destroyed_key)
{
	psa_key_id_t gen_kid = PSA_KEY_HANDLE_INIT;
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
	size_t pub_key_len = 0;
	psa_ret = psa_export_public_key(gen_kid, pub_key, sizeof(pub_key),
					&pub_key_len);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_ret);

	psa_ret = psa_destroy_key(gen_kid);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_ret);

	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_VERIFY, pub_key,
					      pub_key_len, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t input[32] = { 0 };
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));
	ret = edhoc_cipher_suite_2_verify(NULL, &kid, input, ARRAY_SIZE(input),
					  sign, ARRAY_SIZE(sign));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2, hash_wrong_size)
{
	const uint8_t input[16] = { 0 };
	uint8_t hash[4] = { 0 };
	size_t hash_len = 0;

	ret = edhoc_cipher_suite_2_hash(NULL, input, ARRAY_SIZE(input), hash,
					ARRAY_SIZE(hash), &hash_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2, make_key_pair_bad_size)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));
	raw_key[sizeof(raw_key) - 1] = 0x01;

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, ARRAY_SIZE(raw_key),
					      &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t priv[edhoc_suite->ecc_key_length];
	memset(priv, 0, sizeof(priv));
	uint8_t pub[65];
	memset(pub, 0, sizeof(pub));
	size_t priv_len = 0;
	size_t pub_len = 0;

	ret = edhoc_cipher_suite_2_make_key_pair(NULL, &kid, priv, 16,
						 &priv_len, pub, 16, &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, key_agreement_bad_peer_size)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));
	raw_key[sizeof(raw_key) - 1] = 0x01;

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, ARRAY_SIZE(raw_key),
					      &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t peer[edhoc_suite->ecc_key_length];
	memset(peer, 0, sizeof(peer));
	uint8_t secret[edhoc_suite->ecc_key_length];
	memset(secret, 0, sizeof(secret));
	size_t secret_len = 0;

	ret = edhoc_cipher_suite_2_key_agreement(
		NULL, &kid, peer, 16, secret, ARRAY_SIZE(secret), &secret_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, key_agreement_bad_secret_size)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));
	raw_key[sizeof(raw_key) - 1] = 0x01;

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, ARRAY_SIZE(raw_key),
					      &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t peer[edhoc_suite->ecc_key_length];
	memset(peer, 0, sizeof(peer));
	uint8_t secret[edhoc_suite->ecc_key_length];
	memset(secret, 0, sizeof(secret));
	size_t secret_len = 0;

	ret = edhoc_cipher_suite_2_key_agreement(
		NULL, &kid, peer, ARRAY_SIZE(peer), secret, 16, &secret_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, key_agreement_bad_point)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));
	raw_key[sizeof(raw_key) - 1] = 0x01;

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, ARRAY_SIZE(raw_key),
					      &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t bad_peer[edhoc_suite->ecc_key_length];
	memset(bad_peer, 0xFF, sizeof(bad_peer));
	uint8_t secret[edhoc_suite->ecc_key_length];
	memset(secret, 0, sizeof(secret));
	size_t secret_len = 0;

	ret = edhoc_cipher_suite_2_key_agreement(NULL, &kid, bad_peer,
						 ARRAY_SIZE(bad_peer), secret,
						 ARRAY_SIZE(secret),
						 &secret_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, signature_bad_size)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));
	raw_key[sizeof(raw_key) - 1] = 0x01;

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t input[16] = { 0x42 };
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;

	ret = edhoc_cipher_suite_2_signature(
		NULL, &kid, input, ARRAY_SIZE(input), sign, 32, &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, verify_bad_sign_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT |
					       PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);

	psa_key_id_t pair_kid = PSA_KEY_HANDLE_INIT;
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_generate_key(&attr, &pair_kid));

	uint8_t pub_key[65];
	size_t pub_key_len = 0;
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_export_public_key(pair_kid, pub_key,
						sizeof(pub_key), &pub_key_len));

	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_VERIFY, pub_key,
					      pub_key_len, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t input[16] = { 0x42 };
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));

	ret = edhoc_cipher_suite_2_verify(NULL, &kid, input, ARRAY_SIZE(input),
					  sign, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	psa_status_t psa_ret = psa_destroy_key(pair_kid);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, encrypt_wrong_key_type)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_EXTRACT, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[edhoc_suite->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));
	const uint8_t ad[16] = { 0 };
	const uint8_t ptxt[16] = { 0 };
	uint8_t ctxt[32];
	memset(ctxt, 0, sizeof(ctxt));
	size_t ctxt_len = 0;

	ret = edhoc_cipher_suite_2_encrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce),
					   ad, ARRAY_SIZE(ad), ptxt,
					   ARRAY_SIZE(ptxt), ctxt,
					   ARRAY_SIZE(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, decrypt_wrong_key_type)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_EXPAND, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[edhoc_suite->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));
	const uint8_t ad[16] = { 0 };
	const uint8_t ctxt[32] = { 0 };
	uint8_t ptxt[32];
	memset(ptxt, 0, sizeof(ptxt));
	size_t ptxt_len = 0;

	ret = edhoc_cipher_suite_2_decrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce),
					   ad, ARRAY_SIZE(ad), ctxt,
					   ARRAY_SIZE(ctxt), ptxt,
					   ARRAY_SIZE(ptxt), &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, signature_destroyed_key_v2)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));
	raw_key[sizeof(raw_key) - 1] = 0x01;

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t input[32] = { 0 };
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;

	ret = edhoc_cipher_suite_2_signature(NULL, &kid, input,
					     ARRAY_SIZE(input), sign,
					     ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2, key_destroy_invalid_id)
{
	psa_key_id_t kid = 0xDEADBEEF;
	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2, extract_wrong_key_type)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));
	raw_key[sizeof(raw_key) - 1] = 0x01;

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t salt[16] = { 0 };
	uint8_t prk[edhoc_suite->hash_length];
	memset(prk, 0, sizeof(prk));
	size_t prk_len = 0;

	ret = edhoc_cipher_suite_2_extract(NULL, &kid, salt, ARRAY_SIZE(salt),
					   prk, ARRAY_SIZE(prk), &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, expand_wrong_key_type)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));
	raw_key[sizeof(raw_key) - 1] = 0x01;

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      ARRAY_SIZE(raw_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t info[16] = { 0 };
	uint8_t okm[edhoc_suite->hash_length];
	memset(okm, 0, sizeof(okm));

	ret = edhoc_cipher_suite_2_expand(NULL, &kid, info, ARRAY_SIZE(info),
					  okm, ARRAY_SIZE(okm));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, key_agreement_wrong_key_type)
{
	psa_key_id_t gen_kid = PSA_KEY_HANDLE_INIT;
	psa_key_attributes_t gen_attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&gen_attr, PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&gen_attr, PSA_ALG_ECDH);
	psa_set_key_type(&gen_attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&gen_attr, 256);
	psa_status_t psa_ret = psa_generate_key(&gen_attr, &gen_kid);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_ret);

	uint8_t uncomp_pub[65];
	size_t uncomp_pub_len = 0;
	psa_ret = psa_export_public_key(gen_kid, uncomp_pub, sizeof(uncomp_pub),
					&uncomp_pub_len);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_ret);

	psa_ret = psa_destroy_key(gen_kid);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_ret);

	/* Compress the public key: take X coordinate with 0x02/0x03 prefix */
	uint8_t comp_pub[33];
	comp_pub[0] = (uncomp_pub[64] & 1) ? 0x03 : 0x02;
	memcpy(&comp_pub[1], &uncomp_pub[1], 32);

	/* Import a key as SIGNATURE type (ECDSA algorithm, not ECDH) */
	psa_key_id_t sig_kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));
	raw_key[sizeof(raw_key) - 1] = 0x01;

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_SIGNATURE, raw_key,
					      ARRAY_SIZE(raw_key), &sig_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t shr_sec[edhoc_suite->ecc_key_length];
	memset(shr_sec, 0, sizeof(shr_sec));
	size_t shr_sec_len = 0;

	ret = edhoc_cipher_suite_2_key_agreement(NULL, &sig_kid, comp_pub,
						 ARRAY_SIZE(comp_pub), shr_sec,
						 ARRAY_SIZE(shr_sec),
						 &shr_sec_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &sig_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, make_key_pair_destroyed_key)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));
	raw_key[sizeof(raw_key) - 1] = 0x01;

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_MAKE_KEY_PAIR,
					      raw_key, ARRAY_SIZE(raw_key),
					      &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t priv[edhoc_suite->ecc_key_length];
	memset(priv, 0, sizeof(priv));
	uint8_t pub[edhoc_suite->ecc_key_length];
	memset(pub, 0, sizeof(pub));
	size_t priv_len = 0;
	size_t pub_len = 0;

	ret = edhoc_cipher_suite_2_make_key_pair(NULL, &kid, priv,
						 ARRAY_SIZE(priv), &priv_len,
						 pub, ARRAY_SIZE(pub),
						 &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2, signature_public_key_rejected)
{
	const uint8_t pub_key[] = {
		0x04, 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e,
		0xd6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf,
		0x16, 0xdf, 0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30,
		0x7f, 0x7e, 0xb6, 0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b,
		0x8a, 0x82, 0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52,
		0xa3, 0x87, 0xd2, 0x57, 0xe6, 0xdb, 0x3c, 0x2a, 0x93, 0xdf,
		0x21, 0xff, 0x3a, 0xff, 0xc8,
	};
	TEST_ASSERT_EQUAL(1U + 2U * edhoc_suite->ecc_key_length,
			  ARRAY_SIZE(pub_key));

	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	ret = edhoc_keys->import_key(NULL, EDHOC_KT_VERIFY, pub_key,
				     ARRAY_SIZE(pub_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t input[16] = { 0x01 };
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;
	ret = edhoc_crypto->signature(NULL, &kid, input, ARRAY_SIZE(input),
				      sign, ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_keys->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, verify_corrupted_signature)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	const uint8_t priv_key[] = {
		0xfb, 0x13, 0xad, 0xeb, 0x65, 0x18, 0xce, 0xe5,
		0xf8, 0x84, 0x17, 0x66, 0x08, 0x41, 0x14, 0x2e,
		0x83, 0x0a, 0x81, 0xfe, 0x33, 0x43, 0x80, 0xa9,
		0x53, 0x40, 0x6a, 0x13, 0x05, 0xe8, 0x70, 0x6b,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->ecc_key_length, ARRAY_SIZE(priv_key));

	const uint8_t pub_key[] = {
		0x04, 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e,
		0xd6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf,
		0x16, 0xdf, 0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30,
		0x7f, 0x7e, 0xb6, 0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b,
		0x8a, 0x82, 0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52,
		0xa3, 0x87, 0xd2, 0x57, 0xe6, 0xdb, 0x3c, 0x2a, 0x93, 0xdf,
		0x21, 0xff, 0x3a, 0xff, 0xc8,
	};
	TEST_ASSERT_EQUAL(1U + 2U * edhoc_suite->ecc_key_length,
			  ARRAY_SIZE(pub_key));

	uint8_t input[32];
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

	sign[0] ^= (uint8_t)0xFF;
	ret = edhoc_crypto->verify(NULL, &key_id, input, ARRAY_SIZE(input),
				   sign, sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, signature_verify_zero_input_len)
{
	const uint8_t priv_key[] = {
		0xfb, 0x13, 0xad, 0xeb, 0x65, 0x18, 0xce, 0xe5,
		0xf8, 0x84, 0x17, 0x66, 0x08, 0x41, 0x14, 0x2e,
		0x83, 0x0a, 0x81, 0xfe, 0x33, 0x43, 0x80, 0xa9,
		0x53, 0x40, 0x6a, 0x13, 0x05, 0xe8, 0x70, 0x6b,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->ecc_key_length, ARRAY_SIZE(priv_key));

	const uint8_t pub_key[] = {
		0x04, 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e,
		0xd6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf,
		0x16, 0xdf, 0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30,
		0x7f, 0x7e, 0xb6, 0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b,
		0x8a, 0x82, 0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52,
		0xa3, 0x87, 0xd2, 0x57, 0xe6, 0xdb, 0x3c, 0x2a, 0x93, 0xdf,
		0x21, 0xff, 0x3a, 0xff, 0xc8,
	};
	TEST_ASSERT_EQUAL(1U + 2U * edhoc_suite->ecc_key_length,
			  ARRAY_SIZE(pub_key));

	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	ret = edhoc_keys->import_key(NULL, EDHOC_KT_SIGNATURE, priv_key,
				     ARRAY_SIZE(priv_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t dummy = 0;
	uint8_t sign[edhoc_suite->ecc_sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;
	ret = edhoc_crypto->signature(NULL, &kid, &dummy, 0, sign,
				      ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_keys->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_VERIFY, pub_key,
				     ARRAY_SIZE(pub_key), &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t fake_sign[edhoc_suite->ecc_sign_length];
	memset(fake_sign, 0, sizeof(fake_sign));
	ret = edhoc_crypto->verify(NULL, &kid, &dummy, 0, fake_sign,
				   ARRAY_SIZE(fake_sign));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_keys->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, key_agreement_peer_key_oversized_33)
{
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key[edhoc_suite->ecc_key_length];
	memset(raw_key, 0, sizeof(raw_key));
	raw_key[sizeof(raw_key) - 1] = 0x01;

	ret = edhoc_cipher_suite_2_key_import(NULL, EDHOC_KT_KEY_AGREEMENT,
					      raw_key, ARRAY_SIZE(raw_key),
					      &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t peer[33] = { 0 };
	memset(peer, 0x41, sizeof(peer));
	uint8_t secret[edhoc_suite->ecc_key_length];
	memset(secret, 0, sizeof(secret));
	size_t secret_len = 0;

	ret = edhoc_cipher_suite_2_key_agreement(NULL, &kid, peer,
						 ARRAY_SIZE(peer), secret,
						 ARRAY_SIZE(secret),
						 &secret_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_cipher_suite_2_key_destroy(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2, signature_bitflip_r_and_s)
{
	const uint8_t priv_key[] = {
		0xfb, 0x13, 0xad, 0xeb, 0x65, 0x18, 0xce, 0xe5,
		0xf8, 0x84, 0x17, 0x66, 0x08, 0x41, 0x14, 0x2e,
		0x83, 0x0a, 0x81, 0xfe, 0x33, 0x43, 0x80, 0xa9,
		0x53, 0x40, 0x6a, 0x13, 0x05, 0xe8, 0x70, 0x6b,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->ecc_key_length, ARRAY_SIZE(priv_key));

	const uint8_t pub_key[] = {
		0x04, 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e,
		0xd6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf,
		0x16, 0xdf, 0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30,
		0x7f, 0x7e, 0xb6, 0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b,
		0x8a, 0x82, 0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52,
		0xa3, 0x87, 0xd2, 0x57, 0xe6, 0xdb, 0x3c, 0x2a, 0x93, 0xdf,
		0x21, 0xff, 0x3a, 0xff, 0xc8,
	};
	TEST_ASSERT_EQUAL(1U + 2U * edhoc_suite->ecc_key_length,
			  ARRAY_SIZE(pub_key));

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

	/* Corrupt one bit in the r component (first half). */
	uint8_t tampered[edhoc_suite->ecc_sign_length];
	memset(tampered, 0, sizeof(tampered));
	memcpy(tampered, sign, sizeof(tampered));
	tampered[0] ^= (uint8_t)0x01;
	ret = edhoc_crypto->verify(NULL, &key_id, input, ARRAY_SIZE(input),
				   tampered, sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	/* Corrupt one bit in the s component (second half). */
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

TEST(cipher_suite_2, aead_tag_tamper_detected)
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

TEST(cipher_suite_2, aead_aad_tamper_detected)
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

TEST(cipher_suite_2, hkdf_sha256_second_kat)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	const uint8_t ikm[32] = {
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
	};
	const uint8_t salt[16] = {
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	};
	/* ASCII "edhoc cs2 kat". */
	const uint8_t info[13] = {
		0x65, 0x64, 0x68, 0x6f, 0x63, 0x20, 0x63,
		0x73, 0x32, 0x20, 0x6b, 0x61, 0x74,
	};

	const uint8_t prk[] = {
		0x70, 0x38, 0xde, 0x16, 0xec, 0x5b, 0xda, 0xef,
		0xc3, 0x6c, 0x54, 0x89, 0xeb, 0x9b, 0x9d, 0x75,
		0xe5, 0xc4, 0x42, 0xf4, 0x6b, 0xff, 0x18, 0x71,
		0x96, 0x00, 0x3e, 0xf8, 0xdc, 0xee, 0x1a, 0xbc,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->hash_length, ARRAY_SIZE(prk));

	const uint8_t okm[] = {
		0x3f, 0xce, 0x03, 0x9e, 0xc6, 0xbb, 0xfa, 0xe4,
		0xec, 0xf8, 0x7e, 0xff, 0x9f, 0x64, 0x5e, 0x12,
		0x61, 0x73, 0x01, 0x97, 0x18, 0x51, 0xab, 0x8c,
		0xee, 0xcf, 0x64, 0x2a, 0xcd, 0xad, 0x8a, 0x5c,
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

TEST_GROUP_RUNNER(cipher_suite_2)
{
	RUN_TEST_CASE(cipher_suite_2, ecdsa);
	RUN_TEST_CASE(cipher_suite_2, ecdh);
	RUN_TEST_CASE(cipher_suite_2, hkdf);
	RUN_TEST_CASE(cipher_suite_2, aead);
	RUN_TEST_CASE(cipher_suite_2, hash);
	RUN_TEST_CASE(cipher_suite_2, key_import_invalid_type);
	RUN_TEST_CASE(cipher_suite_2, key_import_rejects_invalid_key_material);
	RUN_TEST_CASE(cipher_suite_2, extract_prk_capacity_too_large);
	RUN_TEST_CASE(cipher_suite_2, expand_okm_length_too_large);
	RUN_TEST_CASE(cipher_suite_2, aead_zero_length_plaintext);
	RUN_TEST_CASE(cipher_suite_2, key_destroy_null);
	RUN_TEST_CASE(cipher_suite_2, make_key_pair_null_args);
	RUN_TEST_CASE(cipher_suite_2, key_agreement_null_args);
	RUN_TEST_CASE(cipher_suite_2, signature_null_args);
	RUN_TEST_CASE(cipher_suite_2, verify_null_args);
	RUN_TEST_CASE(cipher_suite_2, extract_null_args);
	RUN_TEST_CASE(cipher_suite_2, expand_null_args);
	RUN_TEST_CASE(cipher_suite_2, encrypt_null_args);
	RUN_TEST_CASE(cipher_suite_2, decrypt_null_args);
	RUN_TEST_CASE(cipher_suite_2, hash_null_args);
	RUN_TEST_CASE(cipher_suite_2, extract_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2, expand_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2, encrypt_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2, decrypt_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2, key_agreement_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2, signature_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2, verify_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2, hash_wrong_size);
	RUN_TEST_CASE(cipher_suite_2, make_key_pair_bad_size);
	RUN_TEST_CASE(cipher_suite_2, key_agreement_bad_peer_size);
	RUN_TEST_CASE(cipher_suite_2, key_agreement_bad_secret_size);
	RUN_TEST_CASE(cipher_suite_2, key_agreement_bad_point);
	RUN_TEST_CASE(cipher_suite_2, signature_bad_size);
	RUN_TEST_CASE(cipher_suite_2, verify_bad_sign_len);
	RUN_TEST_CASE(cipher_suite_2, encrypt_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_2, decrypt_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_2, signature_destroyed_key_v2);
	RUN_TEST_CASE(cipher_suite_2, key_destroy_invalid_id);
	RUN_TEST_CASE(cipher_suite_2, extract_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_2, expand_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_2, key_agreement_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_2, make_key_pair_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2, signature_public_key_rejected);
	RUN_TEST_CASE(cipher_suite_2, verify_corrupted_signature);
	RUN_TEST_CASE(cipher_suite_2, signature_verify_zero_input_len);
	RUN_TEST_CASE(cipher_suite_2, key_agreement_peer_key_oversized_33);
	RUN_TEST_CASE(cipher_suite_2, signature_bitflip_r_and_s);
	RUN_TEST_CASE(cipher_suite_2, aead_tag_tamper_detected);
	RUN_TEST_CASE(cipher_suite_2, aead_aad_tamper_detected);
	RUN_TEST_CASE(cipher_suite_2, hkdf_sha256_second_kat);
}
