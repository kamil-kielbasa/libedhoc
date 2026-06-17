/**
 * \file    test_cipher_suite_exp_pqc_1.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for experimental PQC cipher suite 1.
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
#include <edhoc_crypto.h>
#include <edhoc_values.h>
#include <edhoc_macros.h>

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

TEST(cipher_suite_exp_pqc_1, kmac_extract_expand)
{
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	/* Test vectors taken from RFC 5869 Appendix A.1 (same IKM/salt/info as
	 * cipher suite 0 HKDF test). KMAC256 output differs from HMAC-SHA256
	 * PRK/OKM; this test verifies extract/expand round-trip and expand
	 * determinism.
	 */
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
	const size_t okm_len = 42;

	uint8_t prk[EDHOC_EXP_PQC_CS1_HASH_LEN] = { 0 };
	uint8_t okm[42] = { 0 };
	uint8_t okm2[42] = { 0 };
	size_t prk_len = 0;

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_EXTRACT, ikm,
				     ARRAY_SIZE(ikm), &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->extract(NULL, &key_id, salt, ARRAY_SIZE(salt), prk,
				    sizeof(prk), &prk_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(edhoc_suite->hash_length, prk_len);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->import_key(NULL, EDHOC_KT_EXPAND, prk, prk_len,
				     &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->expand(NULL, &key_id, info, ARRAY_SIZE(info), okm,
				   okm_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->expand(NULL, &key_id, info, ARRAY_SIZE(info), okm2,
				   okm_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(okm, okm2, okm_len);
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
	RUN_TEST_CASE(cipher_suite_exp_pqc_1, kmac_extract_expand);
	RUN_TEST_CASE(cipher_suite_exp_pqc_1, aead_encrypt_decrypt);
}
