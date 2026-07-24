/**
 * \file    test_cipher_suite_pqc_1.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for post-quantum cipher suite 1 on the handle-only
 *          crypto vtable (ML-KEM-512 / ML-DSA-44 / AES-CCM-16-128-128 /
 *          SHAKE256).
 *
 *          Two Unity suites keep the intent explicit:
 *            - cipher_suite_pqc_1_positive: correct behaviour and known-answer
 *              tests.
 *            - cipher_suite_pqc_1_negative: argument validation, wrong/stale
 *              keys and tamper detection (every case expects an error).
 *
 *          Buffer sizes come from the cipher suite descriptor. The ML-DSA-44
 *          key sizes the descriptor does not carry come from the fixed test
 *          key pair in test_vector_ml_dsa_44_keypair.h, which also keeps this
 *          test free of any liboqs header.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Cipher suite header: */
#include "edhoc_cipher_suite_pqc_1.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* EDHOC headers: */
#include <edhoc/crypto.h>
#include <edhoc/cipher_suite.h>
#include <edhoc/values.h>
#include "edhoc_macros_internal.h"

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* PSA crypto header: */
#include <psa/crypto.h>

/* Fixed ML-DSA-44 key pair (public + secret) for the sign / verify tests. */
#include "test_vector_ml_dsa_44_keypair.h"

/* edhoc_cipher_suite_pqc_1_import_signing_key() is intentionally not part of
 * the public suite header (the classic suites import the signing key with
 * psa_import_key). The test declares it to load the oversized ML-DSA-44 private
 * key into the suite's software keystore. */
extern int edhoc_cipher_suite_pqc_1_import_signing_key(
	const uint8_t *signing_key, size_t signing_key_length, void *key_id);

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

static const struct edhoc_crypto *edhoc_crypto;
static const struct edhoc_cipher_suite *edhoc_suite;

static int ret = EDHOC_ERROR_GENERIC_ERROR;

/* Static function declarations -------------------------------------------- */

/** \brief Import raw bytes as an exportable PSA secret (KMAC IKM / PRK). */
static psa_key_id_t import_secret(const uint8_t *raw, size_t raw_len);

/** \brief Import raw bytes as the suite AES-CCM AEAD key. */
static psa_key_id_t import_aead_key(const uint8_t *raw, size_t raw_len);

/** \brief Export the bytes of an exportable PSA secret handle. */
static void export_secret(psa_key_id_t key_id, uint8_t *out, size_t out_size,
			  size_t *out_len);

/* Static function definitions --------------------------------------------- */

static psa_key_id_t import_secret(const uint8_t *raw, size_t raw_len)
{
	/* Exportable RAW_DATA, matching how the suite stores KMAC-consumed
	 * secrets so extract / expand can read them back. */
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr, PSA_KEY_TYPE_RAW_DATA);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
	psa_set_key_bits(&attr, (size_t)PSA_BYTES_TO_BITS(raw_len));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_import_key(&attr, raw, raw_len, &kid));

	return kid;
}

static psa_key_id_t import_aead_key(const uint8_t *raw, size_t raw_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_usage_flags(&attr,
				PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attr, PSA_ALG_AEAD_WITH_SHORTENED_TAG(
					     PSA_ALG_CCM,
					     edhoc_suite->aead_tag_length));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_import_key(&attr, raw, raw_len, &kid));

	return kid;
}

static void export_secret(psa_key_id_t key_id, uint8_t *out, size_t out_size,
			  size_t *out_len)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_export_key(key_id, out, out_size, out_len));
}

/* Module interface function definitions ----------------------------------- */

/* ========================================================================= */
/* Positive suite: correct behaviour and known-answer tests.                 */
/* ========================================================================= */

TEST_GROUP(cipher_suite_pqc_1_positive);

TEST_SETUP(cipher_suite_pqc_1_positive)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());

	edhoc_crypto = edhoc_cipher_suite_pqc_1_get_crypto();
	edhoc_suite = edhoc_cipher_suite_pqc_1_get_suite();
}

TEST_TEAR_DOWN(cipher_suite_pqc_1_positive)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_pqc_1_positive, enum_getters)
{
	/* The enum-keyed getters dispatch to this suite's reference getters. */
	TEST_ASSERT_EQUAL_PTR(edhoc_crypto, edhoc_cipher_suite_get_crypto(
						    EDHOC_CIPHER_SUITE_PQC_1));
	TEST_ASSERT_EQUAL_PTR(edhoc_suite, edhoc_cipher_suite_get_params(
						   EDHOC_CIPHER_SUITE_PQC_1));

	/* Every descriptor parameter has its canonical value (ML-KEM-512 /
	 * ML-DSA-44 / AES-CCM-16-128-128 / SHAKE256). */
	TEST_ASSERT_EQUAL_INT32(EDHOC_CIPHER_SUITE_PQC_1, edhoc_suite->value);
	TEST_ASSERT_FALSE(edhoc_suite->supports_dh_nike);
	TEST_ASSERT_EQUAL(800, edhoc_suite->kem_encapsulation_key_length);
	TEST_ASSERT_EQUAL(768, edhoc_suite->kem_ciphertext_length);
	TEST_ASSERT_EQUAL(0, edhoc_suite->nike_key_length);
	TEST_ASSERT_EQUAL(2420, edhoc_suite->sign_length);
	TEST_ASSERT_EQUAL(16, edhoc_suite->aead_key_length);
	TEST_ASSERT_EQUAL(16, edhoc_suite->aead_tag_length);
	TEST_ASSERT_EQUAL(13, edhoc_suite->aead_iv_length);
	TEST_ASSERT_EQUAL(64, edhoc_suite->hash_length);
	TEST_ASSERT_EQUAL(16, edhoc_suite->mac_length);

	/* Every crypto operation is wired. */
	TEST_ASSERT_NOT_NULL(edhoc_crypto->destroy_key);
	TEST_ASSERT_NOT_NULL(edhoc_crypto->generate_key_pair);
	TEST_ASSERT_NOT_NULL(edhoc_crypto->encapsulate);
	TEST_ASSERT_NOT_NULL(edhoc_crypto->decapsulate);
	TEST_ASSERT_NOT_NULL(edhoc_crypto->key_agreement);
	TEST_ASSERT_NOT_NULL(edhoc_crypto->sign);
	TEST_ASSERT_NOT_NULL(edhoc_crypto->verify);
	TEST_ASSERT_NOT_NULL(edhoc_crypto->extract);
	TEST_ASSERT_NOT_NULL(edhoc_crypto->expand);
	TEST_ASSERT_NOT_NULL(edhoc_crypto->expand_raw);
	TEST_ASSERT_NOT_NULL(edhoc_crypto->aead_encrypt);
	TEST_ASSERT_NOT_NULL(edhoc_crypto->aead_decrypt);
	TEST_ASSERT_NOT_NULL(edhoc_crypto->hash_init);
	TEST_ASSERT_NOT_NULL(edhoc_crypto->hash_update);
	TEST_ASSERT_NOT_NULL(edhoc_crypto->hash_finish);
	TEST_ASSERT_NOT_NULL(edhoc_crypto->hash_abort);
}

TEST(cipher_suite_pqc_1_positive, mlkem512_roundtrip)
{
	psa_key_id_t decaps_kid = PSA_KEY_ID_NULL;
	psa_key_id_t encaps_decaps_kid = 0xFFFFFFFFu;
	psa_key_id_t shared_secret_responder_kid = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret_initiator_kid = PSA_KEY_ID_NULL;

	uint8_t encapsulation_key[edhoc_suite->kem_encapsulation_key_length];
	memset(encapsulation_key, 0, sizeof(encapsulation_key));
	uint8_t ciphertext[edhoc_suite->kem_ciphertext_length];
	memset(ciphertext, 0, sizeof(ciphertext));
	size_t encapsulation_key_len = 0;
	size_t ciphertext_len = 0;

	/* Initiator: generate the ephemeral ML-KEM key pair (message_1). */
	ret = edhoc_crypto->generate_key_pair(NULL, &decaps_kid,
					      encapsulation_key,
					      sizeof(encapsulation_key),
					      &encapsulation_key_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(edhoc_suite->kem_encapsulation_key_length,
			  encapsulation_key_len);

	/* Responder: encapsulate (message_2). ML-KEM keeps no ephemeral for a
	 * static DH, so the decapsulation handle comes back as the null key. */
	ret = edhoc_crypto->encapsulate(
		NULL, encapsulation_key, encapsulation_key_len,
		&encaps_decaps_kid, &shared_secret_responder_kid, ciphertext,
		sizeof(ciphertext), &ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(edhoc_suite->kem_ciphertext_length, ciphertext_len);
	TEST_ASSERT_EQUAL(PSA_KEY_ID_NULL, encaps_decaps_kid);

	/* Initiator: decapsulate (after message_2). */
	ret = edhoc_crypto->decapsulate(NULL, &decaps_kid, ciphertext,
					ciphertext_len,
					&shared_secret_initiator_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Both parties agree on the ML-KEM shared secret. */
	uint8_t shared_secret_responder[edhoc_suite->hash_length];
	memset(shared_secret_responder, 0, sizeof(shared_secret_responder));
	uint8_t shared_secret_initiator[edhoc_suite->hash_length];
	memset(shared_secret_initiator, 0, sizeof(shared_secret_initiator));
	size_t responder_len = 0;
	size_t initiator_len = 0;

	export_secret(shared_secret_responder_kid, shared_secret_responder,
		      sizeof(shared_secret_responder), &responder_len);
	export_secret(shared_secret_initiator_kid, shared_secret_initiator,
		      sizeof(shared_secret_initiator), &initiator_len);

	TEST_ASSERT_EQUAL(initiator_len, responder_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(shared_secret_responder,
				      shared_secret_initiator, responder_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &decaps_kid));
	TEST_ASSERT_EQUAL(
		EDHOC_SUCCESS,
		edhoc_crypto->destroy_key(NULL, &shared_secret_responder_kid));
	TEST_ASSERT_EQUAL(
		EDHOC_SUCCESS,
		edhoc_crypto->destroy_key(NULL, &shared_secret_initiator_kid));
}

TEST(cipher_suite_pqc_1_positive, mldsa44_sign_verify)
{
	psa_key_id_t signing_kid = PSA_KEY_ID_NULL;

	const char message[] = "EDHOC PQC cipher suite 1 ML-DSA-44 signature";
	const size_t message_len = sizeof(message) - 1;

	uint8_t signature[edhoc_suite->sign_length];
	memset(signature, 0, sizeof(signature));
	size_t signature_len = 0;

	ret = edhoc_cipher_suite_pqc_1_import_signing_key(
		ml_dsa_44_secret_key, sizeof(ml_dsa_44_secret_key),
		&signing_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->sign(NULL, &signing_kid, (const uint8_t *)message,
				 message_len, signature, sizeof(signature),
				 &signature_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(edhoc_suite->sign_length, signature_len);

	ret = edhoc_crypto->verify(NULL, ml_dsa_44_public_key,
				   sizeof(ml_dsa_44_public_key),
				   (const uint8_t *)message, message_len,
				   signature, signature_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &signing_kid));
}

TEST(cipher_suite_pqc_1_positive, kmac256_kat)
{
	/*
	 * The EDHOC SHAKE256 KDF is KMAC256 (RFC 9528 Section 4.1.2), keyed by
	 * the first argument with an empty customization string S = "":
	 *   EDHOC_Extract(salt, IKM)   = KMAC256(salt, IKM, 8*hash_len, "")
	 *   EDHOC_Expand(PRK, info, L) = KMAC256(PRK,  info, 8*L,       "")
	 * Both directions are anchored on the same NIST SP 800-185 "KMAC256
	 * Sample #5" vector (K = 0x40..0x5f, X = 0x00..0xc7, S = "", L = 512):
	 * extract keys on the salt (= K) and consumes the IKM (= X), expand
	 * keys on the PRK (= K) and consumes the info (= X), so each must
	 * reproduce the same 64-byte output.
	 * https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
	 */
	uint8_t key[32] = { 0 };
	uint8_t data[200] = { 0 };

	for (size_t i = 0; i < ARRAY_SIZE(key); ++i) {
		key[i] = (uint8_t)(0x40 + i);
	}

	for (size_t i = 0; i < ARRAY_SIZE(data); ++i) {
		data[i] = (uint8_t)i;
	}

	const uint8_t expected[] = {
		0x75, 0x35, 0x8c, 0xf3, 0x9e, 0x41, 0x49, 0x4e, 0x94, 0x97,
		0x07, 0x92, 0x7c, 0xee, 0x0a, 0xf2, 0x0a, 0x3f, 0xf5, 0x53,
		0x90, 0x4c, 0x86, 0xb0, 0x8f, 0x21, 0xcc, 0x41, 0x4b, 0xcf,
		0xd6, 0x91, 0x58, 0x9d, 0x27, 0xcf, 0x5e, 0x15, 0x36, 0x9c,
		0xbb, 0xff, 0x8b, 0x9a, 0x4c, 0x2e, 0xb1, 0x78, 0x00, 0x85,
		0x5d, 0x02, 0x35, 0xff, 0x63, 0x5d, 0xa8, 0x25, 0x33, 0xec,
		0x6b, 0x75, 0x9b, 0x69,
	};
	TEST_ASSERT_EQUAL(sizeof(expected), edhoc_suite->hash_length);

	/* Extract keys on the salt (= K) and consumes the IKM (= X). */
	psa_key_id_t ikm_kid = import_secret(data, sizeof(data));
	psa_key_id_t prk_kid = PSA_KEY_ID_NULL;
	ret = edhoc_crypto->extract(NULL, &ikm_kid, key, sizeof(key), &prk_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t prk[edhoc_suite->hash_length];
	memset(prk, 0, sizeof(prk));
	size_t prk_len = 0;

	export_secret(prk_kid, prk, sizeof(prk), &prk_len);

	TEST_ASSERT_EQUAL(sizeof(expected), prk_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, prk, prk_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &ikm_kid));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &prk_kid));

	/* Expand keys on the PRK (= K) and consumes the info (= X). */
	psa_key_id_t expand_prk_kid = import_secret(key, sizeof(key));
	uint8_t okm[edhoc_suite->hash_length];
	memset(okm, 0, sizeof(okm));

	ret = edhoc_crypto->expand_raw(NULL, &expand_prk_kid, data,
				       sizeof(data), okm, sizeof(okm));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, okm, sizeof(okm));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &expand_prk_kid));
}

TEST(cipher_suite_pqc_1_positive, expand_kdf_and_aead_handles)
{
	static const uint8_t prk_bytes[] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
	};
	static const uint8_t info[] = { 'e', 'x', 'p', 'a', 'n', 'd' };

	psa_key_id_t prk_kid = import_secret(prk_bytes, sizeof(prk_bytes));

	/* KDF usage: the derived key handle expands to exactly the same bytes
	 * that expand_raw produces over identical info. */
	psa_key_id_t kdf_kid = PSA_KEY_ID_NULL;
	ret = edhoc_crypto->expand(NULL, &prk_kid, info, sizeof(info),
				   EDHOC_KEY_USAGE_KDF, &kdf_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t okm_from_handle[edhoc_suite->hash_length];
	memset(okm_from_handle, 0, sizeof(okm_from_handle));
	uint8_t okm_from_raw[edhoc_suite->hash_length];
	memset(okm_from_raw, 0, sizeof(okm_from_raw));
	size_t okm_from_handle_len = 0;

	export_secret(kdf_kid, okm_from_handle, sizeof(okm_from_handle),
		      &okm_from_handle_len);

	TEST_ASSERT_EQUAL(edhoc_suite->hash_length, okm_from_handle_len);

	ret = edhoc_crypto->expand_raw(NULL, &prk_kid, info, sizeof(info),
				       okm_from_raw, sizeof(okm_from_raw));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(okm_from_raw, okm_from_handle,
				      sizeof(okm_from_raw));

	/* AEAD usage: the derived key handle is a working AES-CCM key -- prove
	 * it by encrypting and decrypting through the suite. */
	psa_key_id_t aead_kid = PSA_KEY_ID_NULL;
	ret = edhoc_crypto->expand(NULL, &prk_kid, info, sizeof(info),
				   EDHOC_KEY_USAGE_AEAD, &aead_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[edhoc_suite->aead_iv_length];
	memset(nonce, 0x5a, sizeof(nonce));
	const uint8_t aad[4] = { 1, 2, 3, 4 };
	const uint8_t plaintext[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	uint8_t ciphertext[sizeof(plaintext) + edhoc_suite->aead_tag_length];
	memset(ciphertext, 0, sizeof(ciphertext));
	uint8_t decrypted[sizeof(plaintext)];
	memset(decrypted, 0, sizeof(decrypted));
	size_t ciphertext_len = 0;
	size_t decrypted_len = 0;

	ret = edhoc_crypto->aead_encrypt(NULL, &aead_kid, nonce, sizeof(nonce),
					 aad, sizeof(aad), plaintext,
					 sizeof(plaintext), ciphertext,
					 sizeof(ciphertext), &ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->aead_decrypt(NULL, &aead_kid, nonce, sizeof(nonce),
					 aad, sizeof(aad), ciphertext,
					 ciphertext_len, decrypted,
					 sizeof(decrypted), &decrypted_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(sizeof(plaintext), decrypted_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(plaintext, decrypted, sizeof(plaintext));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &kdf_kid));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &aead_kid));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &prk_kid));
}

TEST(cipher_suite_pqc_1_positive, aead_encrypt_decrypt)
{
	const uint8_t key[16] = {
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
	};
	const uint8_t iv[13] = {
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 0, 0,
	};
	const uint8_t aad[4] = { 0, 1, 2, 3 };
	const uint8_t plaintext[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	uint8_t ciphertext[sizeof(plaintext) + edhoc_suite->aead_tag_length];
	memset(ciphertext, 0, sizeof(ciphertext));
	uint8_t decrypted[sizeof(plaintext)];
	memset(decrypted, 0, sizeof(decrypted));
	size_t ciphertext_len = 0;
	size_t decrypted_len = 0;

	TEST_ASSERT_EQUAL(edhoc_suite->aead_key_length, sizeof(key));
	TEST_ASSERT_EQUAL(edhoc_suite->aead_iv_length, sizeof(iv));

	psa_key_id_t key_kid = import_aead_key(key, sizeof(key));

	ret = edhoc_crypto->aead_encrypt(NULL, &key_kid, iv, sizeof(iv), aad,
					 sizeof(aad), plaintext,
					 sizeof(plaintext), ciphertext,
					 sizeof(ciphertext), &ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->aead_decrypt(NULL, &key_kid, iv, sizeof(iv), aad,
					 sizeof(aad), ciphertext,
					 ciphertext_len, decrypted,
					 sizeof(decrypted), &decrypted_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(sizeof(plaintext), decrypted_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(plaintext, decrypted, sizeof(plaintext));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &key_kid));
}

TEST(cipher_suite_pqc_1_positive, aead_empty_plaintext)
{
	/* EDHOC message_4 encrypts an empty EAD_4, so the AEAD must round-trip
	 * a zero-length plaintext: the ciphertext is the authentication tag
	 * alone and decryption returns no plaintext bytes. */
	const uint8_t key[16] = {
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
	};
	const uint8_t iv[13] = {
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 0, 0,
	};
	const uint8_t aad[4] = { 0, 1, 2, 3 };
	const uint8_t plaintext[1] = { 0 };
	uint8_t ciphertext[edhoc_suite->aead_tag_length];
	memset(ciphertext, 0, sizeof(ciphertext));
	uint8_t decrypted[1];
	memset(decrypted, 0, sizeof(decrypted));
	size_t ciphertext_len = 0;
	size_t decrypted_len = 123;

	psa_key_id_t key_kid = import_aead_key(key, sizeof(key));

	ret = edhoc_crypto->aead_encrypt(NULL, &key_kid, iv, sizeof(iv), aad,
					 sizeof(aad), plaintext, 0, ciphertext,
					 sizeof(ciphertext), &ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(edhoc_suite->aead_tag_length, ciphertext_len);

	ret = edhoc_crypto->aead_decrypt(NULL, &key_kid, iv, sizeof(iv), aad,
					 sizeof(aad), ciphertext,
					 ciphertext_len, decrypted, 0,
					 &decrypted_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(0, decrypted_len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &key_kid));
}

TEST(cipher_suite_pqc_1_positive, shake256_multipart)
{
	/*
	 * NIST SHA-3 XOF example "SHAKE256_Msg1600": the input is 1600 bits
	 * (200 bytes) of 0xA3 and the output is truncated to 64 bytes.
	 * https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
	 */
	uint8_t input[200] = { 0 };
	memset(input, 0xa3,
	       sizeof(input)); /* KAT message: 200 bytes of 0xA3. */

	const uint8_t expected[] = {
		0xcd, 0x8a, 0x92, 0x0e, 0xd1, 0x41, 0xaa, 0x04, 0x07, 0xa2,
		0x2d, 0x59, 0x28, 0x86, 0x52, 0xe9, 0xd9, 0xf1, 0xa7, 0xee,
		0x0c, 0x1e, 0x7c, 0x1c, 0xa6, 0x99, 0x42, 0x4d, 0xa8, 0x4a,
		0x90, 0x4d, 0x2d, 0x70, 0x0c, 0xaa, 0xe7, 0x39, 0x6e, 0xce,
		0x96, 0x60, 0x44, 0x40, 0x57, 0x7d, 0xa4, 0xf3, 0xaa, 0x22,
		0xae, 0xb8, 0x85, 0x7f, 0x96, 0x1c, 0x4c, 0xd8, 0xe0, 0x6f,
		0x0a, 0xe6, 0x61, 0x0b,
	};

	/* Absorb the input in two chunks to exercise the multipart path. */
	void *operation = NULL;
	ret = edhoc_crypto->hash_init(NULL, &operation);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_NOT_NULL(operation);

	ret = edhoc_crypto->hash_update(NULL, operation, input, 100);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_crypto->hash_update(NULL, operation, input + 100,
					sizeof(input) - 100);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t hash[edhoc_suite->hash_length];
	memset(hash, 0, sizeof(hash));
	size_t hash_len = 0;
	ret = edhoc_crypto->hash_finish(NULL, operation, hash, sizeof(hash),
					&hash_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(sizeof(expected), hash_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, hash, sizeof(expected));
}

TEST(cipher_suite_pqc_1_positive, hash_abort_frees_pool_slot)
{
	static const uint8_t input[] = "EDHOC PQC hash abort input";

	/* Fill the whole operation pool. */
	void *operations[16] = { 0 };
	size_t live = 0;
	for (size_t i = 0; i < ARRAY_SIZE(operations); ++i) {
		if (EDHOC_SUCCESS !=
		    edhoc_crypto->hash_init(NULL, &operations[i])) {
			break;
		}
		++live;
	}
	TEST_ASSERT_GREATER_THAN(0, live);

	/* With the pool full, a further init fails. */
	void *overflow = NULL;
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE,
			  edhoc_crypto->hash_init(NULL, &overflow));

	/* Aborting one operation must return its slot to the pool, so a fresh
	 * init succeeds again. */
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->hash_abort(NULL, operations[0]));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->hash_init(NULL, &operations[0]));

	/* The reused slot still produces a correct digest. */
	ret = edhoc_crypto->hash_update(NULL, operations[0], input,
					sizeof(input) - 1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t hash[edhoc_suite->hash_length];
	memset(hash, 0, sizeof(hash));
	size_t hash_len = 0;

	ret = edhoc_crypto->hash_finish(NULL, operations[0], hash, sizeof(hash),
					&hash_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(edhoc_suite->hash_length, hash_len);

	/* Release the remaining live operations. */
	for (size_t i = 1; i < live; ++i) {
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_crypto->hash_abort(
							 NULL, operations[i]));
	}
}

TEST_GROUP_RUNNER(cipher_suite_pqc_1_positive)
{
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, enum_getters);
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, mlkem512_roundtrip);
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, mldsa44_sign_verify);
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, kmac256_kat);
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, expand_kdf_and_aead_handles);
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, aead_encrypt_decrypt);
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, aead_empty_plaintext);
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, shake256_multipart);
	RUN_TEST_CASE(cipher_suite_pqc_1_positive, hash_abort_frees_pool_slot);
}

/* ========================================================================= */
/* Negative suite: argument validation, wrong/stale keys, tamper detection.  */
/* ========================================================================= */

TEST_GROUP(cipher_suite_pqc_1_negative);

TEST_SETUP(cipher_suite_pqc_1_negative)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());

	edhoc_crypto = edhoc_cipher_suite_pqc_1_get_crypto();
	edhoc_suite = edhoc_cipher_suite_pqc_1_get_suite();
}

TEST_TEAR_DOWN(cipher_suite_pqc_1_negative)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_pqc_1_negative, destroy_key_null)
{
	ret = edhoc_crypto->destroy_key(NULL, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, destroy_key_invalid_id)
{
	psa_key_id_t kid = 0xDEADBEEF;

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_pqc_1_negative, generate_key_pair_null_args)
{
	psa_key_id_t decaps_kid = PSA_KEY_ID_NULL;
	uint8_t encapsulation_key[edhoc_suite->kem_encapsulation_key_length];
	memset(encapsulation_key, 0, sizeof(encapsulation_key));
	size_t encapsulation_key_len = 0;

	ret = edhoc_crypto->generate_key_pair(NULL, NULL, encapsulation_key,
					      sizeof(encapsulation_key),
					      &encapsulation_key_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->generate_key_pair(NULL, &decaps_kid, NULL,
					      sizeof(encapsulation_key),
					      &encapsulation_key_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->generate_key_pair(NULL, &decaps_kid,
					      encapsulation_key, 0,
					      &encapsulation_key_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->generate_key_pair(NULL, &decaps_kid,
					      encapsulation_key,
					      sizeof(encapsulation_key), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, generate_key_pair_buffer_too_small)
{
	psa_key_id_t decaps_kid = PSA_KEY_ID_NULL;
	uint8_t encapsulation_key[edhoc_suite->kem_encapsulation_key_length - 1];
	memset(encapsulation_key, 0, sizeof(encapsulation_key));
	size_t encapsulation_key_len = 0;

	ret = edhoc_crypto->generate_key_pair(NULL, &decaps_kid,
					      encapsulation_key,
					      sizeof(encapsulation_key),
					      &encapsulation_key_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(cipher_suite_pqc_1_negative, encapsulate_null_args)
{
	psa_key_id_t decaps_kid = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret_kid = PSA_KEY_ID_NULL;
	uint8_t encapsulation_key[edhoc_suite->kem_encapsulation_key_length];
	memset(encapsulation_key, 0, sizeof(encapsulation_key));
	uint8_t ciphertext[edhoc_suite->kem_ciphertext_length];
	memset(ciphertext, 0, sizeof(ciphertext));
	size_t ciphertext_len = 0;

	ret = edhoc_crypto->encapsulate(NULL, NULL, sizeof(encapsulation_key),
					&decaps_kid, &shared_secret_kid,
					ciphertext, sizeof(ciphertext),
					&ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->encapsulate(NULL, encapsulation_key, 0, &decaps_kid,
					&shared_secret_kid, ciphertext,
					sizeof(ciphertext), &ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->encapsulate(NULL, encapsulation_key,
					sizeof(encapsulation_key), NULL,
					&shared_secret_kid, ciphertext,
					sizeof(ciphertext), &ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->encapsulate(NULL, encapsulation_key,
					sizeof(encapsulation_key), &decaps_kid,
					NULL, ciphertext, sizeof(ciphertext),
					&ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->encapsulate(NULL, encapsulation_key,
					sizeof(encapsulation_key), &decaps_kid,
					&shared_secret_kid, NULL,
					sizeof(ciphertext), &ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->encapsulate(NULL, encapsulation_key,
					sizeof(encapsulation_key), &decaps_kid,
					&shared_secret_kid, ciphertext,
					sizeof(ciphertext), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, encapsulate_bad_encapsulation_key_length)
{
	psa_key_id_t decaps_kid = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret_kid = PSA_KEY_ID_NULL;
	uint8_t encapsulation_key[edhoc_suite->kem_encapsulation_key_length];
	memset(encapsulation_key, 0, sizeof(encapsulation_key));
	uint8_t ciphertext[edhoc_suite->kem_ciphertext_length];
	memset(ciphertext, 0, sizeof(ciphertext));
	size_t ciphertext_len = 0;

	ret = edhoc_crypto->encapsulate(NULL, encapsulation_key,
					sizeof(encapsulation_key) - 1,
					&decaps_kid, &shared_secret_kid,
					ciphertext, sizeof(ciphertext),
					&ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, encapsulate_ciphertext_too_small)
{
	psa_key_id_t decaps_kid = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret_kid = PSA_KEY_ID_NULL;
	uint8_t encapsulation_key[edhoc_suite->kem_encapsulation_key_length];
	memset(encapsulation_key, 0, sizeof(encapsulation_key));
	uint8_t ciphertext[edhoc_suite->kem_ciphertext_length - 1];
	memset(ciphertext, 0, sizeof(ciphertext));
	size_t ciphertext_len = 0;

	ret = edhoc_crypto->encapsulate(NULL, encapsulation_key,
					sizeof(encapsulation_key), &decaps_kid,
					&shared_secret_kid, ciphertext,
					sizeof(ciphertext), &ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(cipher_suite_pqc_1_negative, decapsulate_null_args)
{
	psa_key_id_t decaps_kid = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret_kid = PSA_KEY_ID_NULL;
	uint8_t ciphertext[edhoc_suite->kem_ciphertext_length];
	memset(ciphertext, 0, sizeof(ciphertext));

	ret = edhoc_crypto->decapsulate(NULL, NULL, ciphertext,
					sizeof(ciphertext), &shared_secret_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->decapsulate(NULL, &decaps_kid, NULL,
					sizeof(ciphertext), &shared_secret_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->decapsulate(NULL, &decaps_kid, ciphertext, 0,
					&shared_secret_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->decapsulate(NULL, &decaps_kid, ciphertext,
					sizeof(ciphertext), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, decapsulate_bad_ciphertext_length)
{
	psa_key_id_t decaps_kid = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret_kid = PSA_KEY_ID_NULL;
	uint8_t ciphertext[edhoc_suite->kem_ciphertext_length];
	memset(ciphertext, 0, sizeof(ciphertext));

	ret = edhoc_crypto->decapsulate(NULL, &decaps_kid, ciphertext,
					sizeof(ciphertext) - 1,
					&shared_secret_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, decapsulate_stale_handle)
{
	psa_key_id_t decaps_kid = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret_kid = PSA_KEY_ID_NULL;
	uint8_t encapsulation_key[edhoc_suite->kem_encapsulation_key_length];
	memset(encapsulation_key, 0, sizeof(encapsulation_key));
	uint8_t ciphertext[edhoc_suite->kem_ciphertext_length];
	memset(ciphertext, 0, sizeof(ciphertext));
	size_t encapsulation_key_len = 0;

	ret = edhoc_crypto->generate_key_pair(NULL, &decaps_kid,
					      encapsulation_key,
					      sizeof(encapsulation_key),
					      &encapsulation_key_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Free the decapsulation slot, then use its stale handle. */
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &decaps_kid));

	ret = edhoc_crypto->decapsulate(NULL, &decaps_kid, ciphertext,
					sizeof(ciphertext), &shared_secret_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_pqc_1_negative, key_agreement_not_permitted)
{
	psa_key_id_t private_key_id = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret_kid = PSA_KEY_ID_NULL;
	const uint8_t peer_public_key[32] = { 0 };

	/* ML-KEM is not a NIKE: static Diffie-Hellman is unsupported. */
	ret = edhoc_crypto->key_agreement(NULL, &private_key_id,
					  peer_public_key,
					  sizeof(peer_public_key),
					  &shared_secret_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(cipher_suite_pqc_1_negative, sign_null_args)
{
	psa_key_id_t signing_kid = PSA_KEY_ID_NULL;
	const uint8_t input[16] = { 0 };
	uint8_t signature[edhoc_suite->sign_length];
	memset(signature, 0, sizeof(signature));
	size_t signature_len = 0;

	ret = edhoc_crypto->sign(NULL, NULL, input, sizeof(input), signature,
				 sizeof(signature), &signature_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->sign(NULL, &signing_kid, NULL, sizeof(input),
				 signature, sizeof(signature), &signature_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->sign(NULL, &signing_kid, input, 0, signature,
				 sizeof(signature), &signature_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->sign(NULL, &signing_kid, input, sizeof(input), NULL,
				 sizeof(signature), &signature_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->sign(NULL, &signing_kid, input, sizeof(input),
				 signature, 0, &signature_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->sign(NULL, &signing_kid, input, sizeof(input),
				 signature, sizeof(signature), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, sign_buffer_too_small)
{
	psa_key_id_t signing_kid = PSA_KEY_ID_NULL;
	const uint8_t input[16] = { 0 };
	uint8_t signature[edhoc_suite->sign_length - 1];
	memset(signature, 0, sizeof(signature));
	size_t signature_len = 0;

	/* The buffer-size check precedes the key load. */
	ret = edhoc_crypto->sign(NULL, &signing_kid, input, sizeof(input),
				 signature, sizeof(signature), &signature_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(cipher_suite_pqc_1_negative, sign_stale_handle)
{
	psa_key_id_t signing_kid = PSA_KEY_ID_NULL;
	const uint8_t input[16] = { 0 };
	uint8_t signature[edhoc_suite->sign_length];
	size_t signature_len = 0;
	memset(signature, 0, sizeof(signature));

	ret = edhoc_cipher_suite_pqc_1_import_signing_key(
		ml_dsa_44_secret_key, sizeof(ml_dsa_44_secret_key),
		&signing_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &signing_kid));

	ret = edhoc_crypto->sign(NULL, &signing_kid, input, sizeof(input),
				 signature, sizeof(signature), &signature_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_pqc_1_negative, verify_null_args)
{
	const uint8_t input[16] = { 0 };
	uint8_t signature[edhoc_suite->sign_length];
	memset(signature, 0, sizeof(signature));

	ret = edhoc_crypto->verify(NULL, NULL, sizeof(ml_dsa_44_public_key),
				   input, sizeof(input), signature,
				   sizeof(signature));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->verify(NULL, ml_dsa_44_public_key, 0, input,
				   sizeof(input), signature, sizeof(signature));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->verify(NULL, ml_dsa_44_public_key,
				   sizeof(ml_dsa_44_public_key), NULL,
				   sizeof(input), signature, sizeof(signature));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->verify(NULL, ml_dsa_44_public_key,
				   sizeof(ml_dsa_44_public_key), input, 0,
				   signature, sizeof(signature));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->verify(NULL, ml_dsa_44_public_key,
				   sizeof(ml_dsa_44_public_key), input,
				   sizeof(input), NULL, sizeof(signature));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->verify(NULL, ml_dsa_44_public_key,
				   sizeof(ml_dsa_44_public_key), input,
				   sizeof(input), signature, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, verify_bad_public_key_length)
{
	const uint8_t input[16] = { 0 };
	uint8_t signature[edhoc_suite->sign_length];
	memset(signature, 0, sizeof(signature));

	ret = edhoc_crypto->verify(NULL, ml_dsa_44_public_key,
				   sizeof(ml_dsa_44_public_key) - 1, input,
				   sizeof(input), signature, sizeof(signature));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, verify_bad_signature_length)
{
	const uint8_t input[16] = { 0 };
	uint8_t signature[edhoc_suite->sign_length];
	memset(signature, 0, sizeof(signature));

	ret = edhoc_crypto->verify(NULL, ml_dsa_44_public_key,
				   sizeof(ml_dsa_44_public_key), input,
				   sizeof(input), signature,
				   sizeof(signature) - 1);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, verify_tampered_signature)
{
	psa_key_id_t signing_kid = PSA_KEY_ID_NULL;
	const char message[] = "ML-DSA-44 tamper detection message";
	const size_t message_len = sizeof(message) - 1;
	uint8_t signature[edhoc_suite->sign_length];
	memset(signature, 0, sizeof(signature));
	size_t signature_len = 0;

	ret = edhoc_cipher_suite_pqc_1_import_signing_key(
		ml_dsa_44_secret_key, sizeof(ml_dsa_44_secret_key),
		&signing_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_crypto->sign(NULL, &signing_kid, (const uint8_t *)message,
				 message_len, signature, sizeof(signature),
				 &signature_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &signing_kid));

	signature[signature_len / 2] ^= 0x01;
	ret = edhoc_crypto->verify(NULL, ml_dsa_44_public_key,
				   sizeof(ml_dsa_44_public_key),
				   (const uint8_t *)message, message_len,
				   signature, signature_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_pqc_1_negative, verify_tampered_input)
{
	psa_key_id_t signing_kid = PSA_KEY_ID_NULL;
	uint8_t message[] = "ML-DSA-44 input tamper detection message";
	const size_t message_len = sizeof(message) - 1;
	uint8_t signature[edhoc_suite->sign_length];
	memset(signature, 0, sizeof(signature));
	size_t signature_len = 0;

	ret = edhoc_cipher_suite_pqc_1_import_signing_key(
		ml_dsa_44_secret_key, sizeof(ml_dsa_44_secret_key),
		&signing_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	ret = edhoc_crypto->sign(NULL, &signing_kid, message, message_len,
				 signature, sizeof(signature), &signature_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &signing_kid));

	message[0] ^= 0x01;
	ret = edhoc_crypto->verify(NULL, ml_dsa_44_public_key,
				   sizeof(ml_dsa_44_public_key), message,
				   message_len, signature, signature_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_pqc_1_negative, extract_null_args)
{
	psa_key_id_t ikm_kid = PSA_KEY_ID_NULL;
	psa_key_id_t prk_kid = PSA_KEY_ID_NULL;
	const uint8_t salt[16] = { 0 };

	ret = edhoc_crypto->extract(NULL, NULL, salt, sizeof(salt), &prk_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->extract(NULL, &ikm_kid, NULL, sizeof(salt),
				    &prk_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->extract(NULL, &ikm_kid, salt, 0, &prk_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->extract(NULL, &ikm_kid, salt, sizeof(salt), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, extract_stale_ikm)
{
	const uint8_t ikm[32] = { 1, 2, 3, 4 };
	const uint8_t salt[16] = { 5, 6, 7, 8 };
	psa_key_id_t prk_kid = PSA_KEY_ID_NULL;

	psa_key_id_t ikm_kid = import_secret(ikm, sizeof(ikm));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &ikm_kid));

	ret = edhoc_crypto->extract(NULL, &ikm_kid, salt, sizeof(salt),
				    &prk_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_pqc_1_negative, expand_null_args)
{
	psa_key_id_t prk_kid = PSA_KEY_ID_NULL;
	psa_key_id_t out_kid = PSA_KEY_ID_NULL;
	const uint8_t info[8] = { 0 };

	ret = edhoc_crypto->expand(NULL, NULL, info, sizeof(info),
				   EDHOC_KEY_USAGE_KDF, &out_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->expand(NULL, &prk_kid, NULL, sizeof(info),
				   EDHOC_KEY_USAGE_KDF, &out_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->expand(NULL, &prk_kid, info, 0, EDHOC_KEY_USAGE_KDF,
				   &out_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->expand(NULL, &prk_kid, info, sizeof(info),
				   EDHOC_KEY_USAGE_KDF, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, expand_invalid_usage)
{
	psa_key_id_t prk_kid = PSA_KEY_ID_NULL;
	psa_key_id_t out_kid = PSA_KEY_ID_NULL;
	const uint8_t info[8] = { 0 };

	/* The usage switch rejects unknown values before touching the key. */
	ret = edhoc_crypto->expand(NULL, &prk_kid, info, sizeof(info),
				   (enum edhoc_key_usage)99, &out_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, expand_raw_null_args)
{
	psa_key_id_t prk_kid = PSA_KEY_ID_NULL;
	const uint8_t info[8] = { 0 };
	uint8_t output[edhoc_suite->hash_length];
	memset(output, 0, sizeof(output));

	ret = edhoc_crypto->expand_raw(NULL, NULL, info, sizeof(info), output,
				       sizeof(output));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->expand_raw(NULL, &prk_kid, NULL, sizeof(info),
				       output, sizeof(output));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->expand_raw(NULL, &prk_kid, info, 0, output,
				       sizeof(output));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->expand_raw(NULL, &prk_kid, info, sizeof(info), NULL,
				       sizeof(output));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->expand_raw(NULL, &prk_kid, info, sizeof(info),
				       output, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, aead_encrypt_null_args)
{
	psa_key_id_t key_kid = PSA_KEY_ID_NULL;
	const uint8_t nonce[13] = { 0 };
	const uint8_t aad[4] = { 0 };
	const uint8_t plaintext[8] = { 0 };
	uint8_t ciphertext[24] = { 0 };
	size_t ciphertext_len = 0;

	ret = edhoc_crypto->aead_encrypt(NULL, NULL, nonce, sizeof(nonce), aad,
					 sizeof(aad), plaintext,
					 sizeof(plaintext), ciphertext,
					 sizeof(ciphertext), &ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->aead_encrypt(NULL, &key_kid, NULL, sizeof(nonce),
					 aad, sizeof(aad), plaintext,
					 sizeof(plaintext), ciphertext,
					 sizeof(ciphertext), &ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->aead_encrypt(NULL, &key_kid, nonce, sizeof(nonce),
					 NULL, sizeof(aad), plaintext,
					 sizeof(plaintext), ciphertext,
					 sizeof(ciphertext), &ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->aead_encrypt(NULL, &key_kid, nonce, sizeof(nonce),
					 aad, sizeof(aad), plaintext,
					 sizeof(plaintext), NULL,
					 sizeof(ciphertext), &ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->aead_encrypt(NULL, &key_kid, nonce, sizeof(nonce),
					 aad, sizeof(aad), plaintext,
					 sizeof(plaintext), ciphertext,
					 sizeof(ciphertext), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, aead_decrypt_null_args)
{
	psa_key_id_t key_kid = PSA_KEY_ID_NULL;
	const uint8_t nonce[13] = { 0 };
	const uint8_t aad[4] = { 0 };
	const uint8_t ciphertext[24] = { 0 };
	uint8_t plaintext[8] = { 0 };
	size_t plaintext_len = 0;

	ret = edhoc_crypto->aead_decrypt(NULL, NULL, nonce, sizeof(nonce), aad,
					 sizeof(aad), ciphertext,
					 sizeof(ciphertext), plaintext,
					 sizeof(plaintext), &plaintext_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->aead_decrypt(NULL, &key_kid, NULL, sizeof(nonce),
					 aad, sizeof(aad), ciphertext,
					 sizeof(ciphertext), plaintext,
					 sizeof(plaintext), &plaintext_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->aead_decrypt(NULL, &key_kid, nonce, sizeof(nonce),
					 aad, sizeof(aad), NULL,
					 sizeof(ciphertext), plaintext,
					 sizeof(plaintext), &plaintext_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->aead_decrypt(NULL, &key_kid, nonce, sizeof(nonce),
					 aad, sizeof(aad), ciphertext,
					 sizeof(ciphertext), plaintext,
					 sizeof(plaintext), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, aead_decrypt_tampered)
{
	const uint8_t key[16] = {
		9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6,
	};
	const uint8_t iv[13] = {
		1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7,
	};
	const uint8_t aad[4] = { 4, 3, 2, 1 };
	const uint8_t plaintext[8] = { 8, 7, 6, 5, 4, 3, 2, 1 };
	uint8_t ciphertext[sizeof(plaintext) + edhoc_suite->aead_tag_length];
	memset(ciphertext, 0, sizeof(ciphertext));
	uint8_t decrypted[sizeof(plaintext)];
	memset(decrypted, 0, sizeof(decrypted));
	size_t ciphertext_len = 0;
	size_t decrypted_len = 0;

	psa_key_id_t key_kid = import_aead_key(key, sizeof(key));

	ret = edhoc_crypto->aead_encrypt(NULL, &key_kid, iv, sizeof(iv), aad,
					 sizeof(aad), plaintext,
					 sizeof(plaintext), ciphertext,
					 sizeof(ciphertext), &ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Flip a ciphertext byte: authentication must fail. */
	ciphertext[0] ^= 0x01;
	ret = edhoc_crypto->aead_decrypt(NULL, &key_kid, iv, sizeof(iv), aad,
					 sizeof(aad), ciphertext,
					 ciphertext_len, decrypted,
					 sizeof(decrypted), &decrypted_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &key_kid));
}

TEST(cipher_suite_pqc_1_negative, hash_init_null)
{
	ret = edhoc_crypto->hash_init(NULL, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, hash_abort_null)
{
	/* hash_abort delegates to hash_release, which rejects a NULL handle. */
	ret = edhoc_crypto->hash_abort(NULL, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, hash_update_null_args)
{
	const uint8_t input[8] = { 0 };

	/* Null operation handle: no slot is reserved. */
	ret = edhoc_crypto->hash_update(NULL, NULL, input, sizeof(input));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	/* Null input on a live operation, then release the slot. */
	void *operation = NULL;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->hash_init(NULL, &operation));
	ret = edhoc_crypto->hash_update(NULL, operation, NULL, sizeof(input));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->hash_abort(NULL, operation));
}

TEST(cipher_suite_pqc_1_negative, hash_finish_null_args)
{
	uint8_t hash[edhoc_suite->hash_length];
	memset(hash, 0, sizeof(hash));
	size_t hash_len = 0;

	/* Null operation handle: no slot is reserved. */
	ret = edhoc_crypto->hash_finish(NULL, NULL, hash, sizeof(hash),
					&hash_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	/* Null outputs on a live operation do not release it, so abort at the
	 * end to return the slot to the pool. */
	void *operation = NULL;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->hash_init(NULL, &operation));
	ret = edhoc_crypto->hash_finish(NULL, operation, NULL, sizeof(hash),
					&hash_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	ret = edhoc_crypto->hash_finish(NULL, operation, hash, sizeof(hash),
					NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->hash_abort(NULL, operation));
}

TEST(cipher_suite_pqc_1_negative, hash_finish_buffer_too_small)
{
	void *operation = NULL;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->hash_init(NULL, &operation));

	uint8_t hash[edhoc_suite->hash_length - 1];
	memset(hash, 0, sizeof(hash));
	size_t hash_len = 0;

	/* Finish releases the operation even when the buffer is too small. */
	ret = edhoc_crypto->hash_finish(NULL, operation, hash, sizeof(hash),
					&hash_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(cipher_suite_pqc_1_negative, import_signing_key_null_args)
{
	psa_key_id_t signing_kid = PSA_KEY_ID_NULL;

	ret = edhoc_cipher_suite_pqc_1_import_signing_key(
		NULL, sizeof(ml_dsa_44_secret_key), &signing_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_cipher_suite_pqc_1_import_signing_key(
		ml_dsa_44_secret_key, sizeof(ml_dsa_44_secret_key), NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, import_signing_key_bad_length)
{
	psa_key_id_t signing_kid = PSA_KEY_ID_NULL;

	ret = edhoc_cipher_suite_pqc_1_import_signing_key(
		ml_dsa_44_secret_key, sizeof(ml_dsa_44_secret_key) - 1,
		&signing_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_pqc_1_negative, keystore_exhaustion)
{
	/* Fill the software keystore until it rejects a new key, then release
	 * every slot that was taken (the keystore is static across tests). */
	psa_key_id_t decaps_kids[16] = { 0 };
	uint8_t encapsulation_key[edhoc_suite->kem_encapsulation_key_length];
	memset(encapsulation_key, 0, sizeof(encapsulation_key));
	size_t encapsulation_key_len = 0;
	size_t filled = 0;
	int last = EDHOC_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(decaps_kids); ++i) {
		last = edhoc_crypto->generate_key_pair(
			NULL, &decaps_kids[i], encapsulation_key,
			sizeof(encapsulation_key), &encapsulation_key_len);
		if (EDHOC_SUCCESS != last) {
			break;
		}
		++filled;
	}

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, last);
	TEST_ASSERT_GREATER_THAN(0, filled);

	for (size_t i = 0; i < filled; ++i) {
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_crypto->destroy_key(NULL,
							    &decaps_kids[i]));
	}
}

TEST(cipher_suite_pqc_1_negative, decapsulate_wrong_key_type_handle)
{
	/* A signing-key slot holds an ML-DSA-44 secret, whose length differs
	 * from an ML-KEM-512 decapsulation key, so borrowing it as a
	 * decapsulation key is a valid keystore handle but must still be
	 * rejected on the length check. */
	psa_key_id_t signing_kid = PSA_KEY_ID_NULL;
	psa_key_id_t shared_secret_kid = PSA_KEY_ID_NULL;
	uint8_t ciphertext[edhoc_suite->kem_ciphertext_length];
	memset(ciphertext, 0, sizeof(ciphertext));

	ret = edhoc_cipher_suite_pqc_1_import_signing_key(
		ml_dsa_44_secret_key, sizeof(ml_dsa_44_secret_key),
		&signing_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->decapsulate(NULL, &signing_kid, ciphertext,
					sizeof(ciphertext), &shared_secret_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &signing_kid));
}

TEST(cipher_suite_pqc_1_negative, sign_wrong_key_type_handle)
{
	/* A decapsulation-key slot holds an ML-KEM-512 secret, whose length
	 * differs from an ML-DSA-44 signing key, so signing with it must be
	 * rejected on the length check. */
	psa_key_id_t decaps_kid = PSA_KEY_ID_NULL;
	uint8_t encapsulation_key[edhoc_suite->kem_encapsulation_key_length];
	memset(encapsulation_key, 0, sizeof(encapsulation_key));
	size_t encapsulation_key_len = 0;
	const uint8_t input[16] = { 0 };
	uint8_t signature[edhoc_suite->sign_length];
	memset(signature, 0, sizeof(signature));
	size_t signature_len = 0;

	ret = edhoc_crypto->generate_key_pair(NULL, &decaps_kid,
					      encapsulation_key,
					      sizeof(encapsulation_key),
					      &encapsulation_key_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->sign(NULL, &decaps_kid, input, sizeof(input),
				 signature, sizeof(signature), &signature_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &decaps_kid));
}

TEST(cipher_suite_pqc_1_negative, expand_stale_prk)
{
	/* A destroyed PRK handle cannot be exported, so expand must fail. */
	const uint8_t prk_material[32] = { 1, 2, 3, 4 };
	const uint8_t info[8] = { 5, 6, 7, 8 };
	psa_key_id_t out_kid = PSA_KEY_ID_NULL;

	psa_key_id_t prk_kid =
		import_secret(prk_material, sizeof(prk_material));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &prk_kid));

	ret = edhoc_crypto->expand(NULL, &prk_kid, info, sizeof(info),
				   EDHOC_KEY_USAGE_KDF, &out_kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_pqc_1_negative, expand_raw_stale_prk)
{
	/* A destroyed PRK handle cannot be exported, so expand_raw must fail. */
	const uint8_t prk_material[32] = { 1, 2, 3, 4 };
	const uint8_t info[8] = { 5, 6, 7, 8 };
	uint8_t output[edhoc_suite->hash_length];
	memset(output, 0, sizeof(output));

	psa_key_id_t prk_kid =
		import_secret(prk_material, sizeof(prk_material));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &prk_kid));

	ret = edhoc_crypto->expand_raw(NULL, &prk_kid, info, sizeof(info),
				       output, sizeof(output));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_pqc_1_negative, import_signing_key_keystore_full)
{
	/* Filling the keystore with signing keys must make the next import fail
	 * on the store path; release every reserved slot afterwards. */
	psa_key_id_t signing_kids[16] = { 0 };
	size_t filled = 0;
	int last = EDHOC_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(signing_kids); ++i) {
		last = edhoc_cipher_suite_pqc_1_import_signing_key(
			ml_dsa_44_secret_key, sizeof(ml_dsa_44_secret_key),
			&signing_kids[i]);
		if (EDHOC_SUCCESS != last) {
			break;
		}
		++filled;
	}

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, last);
	TEST_ASSERT_GREATER_THAN(0, filled);

	for (size_t i = 0; i < filled; ++i) {
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  edhoc_crypto->destroy_key(NULL,
							    &signing_kids[i]));
	}
}

TEST_GROUP_RUNNER(cipher_suite_pqc_1_negative)
{
	/* Argument validation. */
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, destroy_key_null);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, destroy_key_invalid_id);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, generate_key_pair_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      generate_key_pair_buffer_too_small);
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
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, sign_buffer_too_small);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, sign_stale_handle);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, verify_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      verify_bad_public_key_length);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, verify_bad_signature_length);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, verify_tampered_signature);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, verify_tampered_input);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, extract_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, extract_stale_ikm);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, expand_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, expand_invalid_usage);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, expand_raw_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, aead_encrypt_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, aead_decrypt_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, aead_decrypt_tampered);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, hash_init_null);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, hash_abort_null);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, hash_update_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, hash_finish_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      hash_finish_buffer_too_small);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      import_signing_key_null_args);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      import_signing_key_bad_length);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, keystore_exhaustion);

	/* Wrong-key-type handles, stale KDF PRKs and keystore exhaustion. */
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      decapsulate_wrong_key_type_handle);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, sign_wrong_key_type_handle);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, expand_stale_prk);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative, expand_raw_stale_prk);
	RUN_TEST_CASE(cipher_suite_pqc_1_negative,
		      import_signing_key_keystore_full);
}
