/**
 * \file    test_cipher_suite_exp_pqc_1.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for experimental PQC cipher suite 1.
 *
 *          Covers ML-KEM-512, ML-DSA-44, SHAKE256, the KMAC256 KDF
 *          (EDHOC_Extract / EDHOC_Expand) and AES-CCM. The KMAC256 KDF is
 *          verified against the published NIST SP 800-185 "KMAC256 Sample #5"
 *          vector through both extract and expand.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Cipher suite header: */
#include "edhoc_exp_pqc_cipher_suite_1.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* EDHOC headers: */
#include <edhoc/edhoc_crypto.h>
#include <edhoc/edhoc_values.h>
#include <edhoc/edhoc_macros.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* PSA crypto header: */
#include <psa/crypto.h>

/* liboqs header: */
#include <oqs/oqs.h>

/* Module defines ---------------------------------------------------------- */

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

static const struct edhoc_keys *edhoc_keys;
static const struct edhoc_crypto_pqc *edhoc_crypto;
static const struct edhoc_cipher_suite_pqc *edhoc_suite;

static int ret = EDHOC_ERROR_GENERIC_ERROR;

/* Static function declarations -------------------------------------------- */
/* Static function definitions --------------------------------------------- */
/* Module interface function definitions ----------------------------------- */

TEST_GROUP(cipher_suite_exp_pqc_1);

TEST_SETUP(cipher_suite_exp_pqc_1)
{
	OQS_init();
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());
	edhoc_keys = edhoc_exp_pqc_cipher_suite_1_get_keys();
	edhoc_crypto = edhoc_exp_pqc_cipher_suite_1_get_crypto();
	edhoc_suite = edhoc_exp_pqc_cipher_suite_1_get_suite();
}

TEST_TEAR_DOWN(cipher_suite_exp_pqc_1)
{
	mbedtls_psa_crypto_free();
	OQS_destroy();
}

TEST(cipher_suite_exp_pqc_1, mlkem512_roundtrip)
{
	psa_key_id_t make_key_id = PSA_KEY_HANDLE_INIT;
	psa_key_id_t agreement_key_id = PSA_KEY_HANDLE_INIT;

	uint8_t decapsulation_key[EDHOC_EXP_PQC_CS1_MLKEM512_DK_LEN] = { 0 };
	uint8_t encapsulation_key[EDHOC_EXP_PQC_CS1_MLKEM512_EK_LEN] = { 0 };
	uint8_t ciphertext[EDHOC_EXP_PQC_CS1_MLKEM512_CT_LEN] = { 0 };
	uint8_t shared_secret_responder[EDHOC_EXP_PQC_CS1_MLKEM512_SS_LEN] = {
		0
	};
	uint8_t shared_secret_initiator[EDHOC_EXP_PQC_CS1_MLKEM512_SS_LEN] = {
		0
	};
	size_t decapsulation_key_len = 0;
	size_t encapsulation_key_len = 0;
	size_t ciphertext_len = 0;
	size_t shared_secret_responder_len = 0;
	size_t shared_secret_initiator_len = 0;

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_MAKE_KEY_PAIR, NULL, 0,
				     &make_key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->make_key_pair(NULL, &make_key_id, decapsulation_key,
					  sizeof(decapsulation_key),
					  &decapsulation_key_len,
					  encapsulation_key,
					  sizeof(encapsulation_key),
					  &encapsulation_key_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_EXP_PQC_CS1_MLKEM512_DK_LEN,
			  decapsulation_key_len);
	TEST_ASSERT_EQUAL(EDHOC_EXP_PQC_CS1_MLKEM512_EK_LEN,
			  encapsulation_key_len);

	ret = edhoc_keys->destroy_key(NULL, &make_key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->encapsulate(NULL, NULL, encapsulation_key,
					encapsulation_key_len, ciphertext,
					sizeof(ciphertext), &ciphertext_len,
					shared_secret_responder,
					sizeof(shared_secret_responder),
					&shared_secret_responder_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_EXP_PQC_CS1_MLKEM512_CT_LEN, ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_EXP_PQC_CS1_MLKEM512_SS_LEN,
			  shared_secret_responder_len);

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_KEY_AGREEMENT,
				     decapsulation_key, decapsulation_key_len,
				     &agreement_key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->decapsulate(NULL, &agreement_key_id, ciphertext,
					ciphertext_len, shared_secret_initiator,
					sizeof(shared_secret_initiator),
					&shared_secret_initiator_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_EXP_PQC_CS1_MLKEM512_SS_LEN,
			  shared_secret_initiator_len);

	ret = edhoc_keys->destroy_key(NULL, &agreement_key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(shared_secret_responder,
				      shared_secret_initiator,
				      EDHOC_EXP_PQC_CS1_MLKEM512_SS_LEN);
}

TEST(cipher_suite_exp_pqc_1, mldsa44_roundtrip)
{
	psa_key_id_t sign_kid = PSA_KEY_HANDLE_INIT;
	psa_key_id_t verify_kid = PSA_KEY_HANDLE_INIT;

	static const uint8_t message[] =
		"EDHOC exp PQC cipher suite 1 ML-DSA-44 signature test";
	const size_t message_len = sizeof(message) - 1;

	uint8_t verification_key[EDHOC_EXP_PQC_CS1_MLDSA44_PK_LEN] = { 0 };
	uint8_t signing_key[EDHOC_EXP_PQC_CS1_MLDSA44_SK_LEN] = { 0 };
	uint8_t signature[EDHOC_EXP_PQC_CS1_MLDSA44_SIG_LEN] = { 0 };
	size_t signature_len = 0;

	TEST_ASSERT_EQUAL(OQS_SUCCESS, OQS_SIG_ml_dsa_44_keypair(
					       verification_key, signing_key));

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_SIGNATURE, signing_key,
				     sizeof(signing_key), &sign_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->signature(NULL, &sign_kid, message, message_len,
				      signature, sizeof(signature),
				      &signature_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_EXP_PQC_CS1_MLDSA44_SIG_LEN, signature_len);

	ret = edhoc_keys->destroy_key(NULL, &sign_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_VERIFY, verification_key,
				     sizeof(verification_key), &verify_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->verify(NULL, &verify_kid, message, message_len,
				   signature, signature_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	signature[signature_len / 2] ^= 0x01;
	ret = edhoc_crypto->verify(NULL, &verify_kid, message, message_len,
				   signature, signature_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->destroy_key(NULL, &verify_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_exp_pqc_1, shake256_hash)
{
	static const uint8_t input[] =
		"EDHOC exp PQC cipher suite 1 SHAKE256 hash input";
	uint8_t hash[64] = { 0 };
	size_t hash_len = 0;

	ret = edhoc_crypto->hash(NULL, input, sizeof(input) - 1, hash,
				 sizeof(hash), &hash_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(64, hash_len);
}

/*
 * KMAC256 KDF known-answer test anchored on a PUBLISHED vector: NIST SP 800-185
 * "KMAC256 Sample #5", the only one-shot NIST KMAC256 sample whose
 * customization string S is empty -- exactly the shape RFC 9528 Section 4.1
 * uses.
 *
 *   K (key)  = 0x40 0x41 ... 0x5f   (32 bytes)
 *   X (data) = 0x00 0x01 ... 0xc7   (200 bytes)
 *   S        = "" (empty customization string)
 *   L        = 512 bits (non-XOF)
 *   O        = KMAC256(K, X, 512, "")   (64 bytes, EXPECTED_KMAC256_NIST below)
 *
 * Source: NIST SP 800-185 KMAC_samples.pdf, "KMAC256 Sample #5":
 *   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
 * The identical vector is embedded upstream as "NIST KMAC256 test vector 5" in
 * XKCP tests/UnitTests/testSP800-185.c (performTestKMAC_NIST).
 *
 * EDHOC_Extract(salt, IKM) and EDHOC_Expand(PRK, info, L) are both
 * KMAC256(key, msg, 8*output_length, ""), so this single vector anchors BOTH
 * KDF directions:
 *   - Extract: salt = K, IKM = X           -> PRK = O (64 bytes)
 *   - Expand:  PRK  = K (32 bytes), info = X, L = 64 -> OKM = O (64 bytes)
 */
TEST(cipher_suite_exp_pqc_1, kmac256_nist_kat)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	uint8_t key[32]; /* K = 0x40 .. 0x5f (salt for Extract, PRK for Expand) */
	uint8_t data[200]; /* X = 0x00 .. 0xc7 (IKM for Extract, info for Expand) */

	/* O = KMAC256(K, X, 512, "") -- NIST SP 800-185 KMAC256 Sample #5. */
	const uint8_t EXPECTED_KMAC256_NIST[64] = {
		0x75, 0x35, 0x8c, 0xf3, 0x9e, 0x41, 0x49, 0x4e, 0x94, 0x97,
		0x07, 0x92, 0x7c, 0xee, 0x0a, 0xf2, 0x0a, 0x3f, 0xf5, 0x53,
		0x90, 0x4c, 0x86, 0xb0, 0x8f, 0x21, 0xcc, 0x41, 0x4b, 0xcf,
		0xd6, 0x91, 0x58, 0x9d, 0x27, 0xcf, 0x5e, 0x15, 0x36, 0x9c,
		0xbb, 0xff, 0x8b, 0x9a, 0x4c, 0x2e, 0xb1, 0x78, 0x00, 0x85,
		0x5d, 0x02, 0x35, 0xff, 0x63, 0x5d, 0xa8, 0x25, 0x33, 0xec,
		0x6b, 0x75, 0x9b, 0x69,
	};

	uint8_t prk[EDHOC_EXP_PQC_CS1_HASH_LEN] = { 0 };
	uint8_t okm[EDHOC_EXP_PQC_CS1_HASH_LEN] = { 0 };
	size_t prk_len = 0;
	size_t i;

	for (i = 0; i < sizeof(key); ++i)
		key[i] = (uint8_t)(0x40 + i); /* 0x40 .. 0x5f */
	for (i = 0; i < sizeof(data); ++i)
		data[i] = (uint8_t)i; /* 0x00 .. 0xc7 */

	/* Extract direction: salt = K, IKM = X -> PRK = O. */
	ret = edhoc_keys->import_key(NULL, EDHOC_KT_EXTRACT, data, sizeof(data),
				     &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->extract(NULL, &key_id, key, sizeof(key), prk,
				    sizeof(prk), &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(64, prk_len);
	TEST_ASSERT_EQUAL(edhoc_suite->hash_length, prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(EXPECTED_KMAC256_NIST, prk, sizeof(prk));

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Expand direction: PRK = K, info = X, L = 64 -> OKM = O. */
	ret = edhoc_keys->import_key(NULL, EDHOC_KT_EXPAND, key, sizeof(key),
				     &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->expand(NULL, &key_id, data, sizeof(data), okm,
				   sizeof(okm));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(64, sizeof(okm));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(EXPECTED_KMAC256_NIST, okm, sizeof(okm));

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_exp_pqc_1, aead_encrypt_decrypt)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	const uint8_t key[] = {
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->aead_key_length, ARRAY_SIZE(key));
	const uint8_t iv[] = {
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 0, 0,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->aead_iv_length, ARRAY_SIZE(iv));
	const uint8_t aad[4] = { 0, 1, 2, 3 };
	const uint8_t ptxt[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	uint8_t ctxt[26] = { 0 };
	uint8_t dec[10] = { 0 };
	size_t ctxt_len = 0;
	size_t dec_len = 0;

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_ENCRYPT, key, sizeof(key),
				     &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->encrypt(NULL, &key_id, iv, sizeof(iv), aad,
				    sizeof(aad), ptxt, sizeof(ptxt), ctxt,
				    sizeof(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_DECRYPT, key, sizeof(key),
				     &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->decrypt(NULL, &key_id, iv, sizeof(iv), aad,
				    sizeof(aad), ctxt, ctxt_len, dec,
				    sizeof(dec), &dec_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(sizeof(ptxt), dec_len);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(ptxt, dec, sizeof(ptxt));
}

TEST_GROUP_RUNNER(cipher_suite_exp_pqc_1)
{
	RUN_TEST_CASE(cipher_suite_exp_pqc_1, mlkem512_roundtrip);
	RUN_TEST_CASE(cipher_suite_exp_pqc_1, mldsa44_roundtrip);
	RUN_TEST_CASE(cipher_suite_exp_pqc_1, shake256_hash);
	RUN_TEST_CASE(cipher_suite_exp_pqc_1, kmac256_nist_kat);
	RUN_TEST_CASE(cipher_suite_exp_pqc_1, aead_encrypt_decrypt);
}
