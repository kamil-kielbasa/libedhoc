/**
 * \file    test_cipher_suite_2.c
 * \author  Kamil Kielbasa
 * \brief   Module tests for cipher suite 2 on the handle-only crypto vtable.
 *
 *          Two Unity suites keep the intent explicit:
 *            - cipher_suite_2_positive: correct behaviour and known-answer tests.
 *            - cipher_suite_2_negative: argument validation, wrong/stale keys and
 *              tamper detection (every case expects an error).
 *
 *          The suite exposes only \c edhoc_cipher_suite_2_get_crypto() and
 *          \c edhoc_cipher_suite_2_get_suite(); keys live in the PSA key store
 *          and are referenced through \c psa_key_id_t handles. Where the legacy
 *          tests read raw key material, these validate behaviour end-to-end:
 *            - ECDH agreement is checked by feeding both parties' shared-secret
 *              handles through \c expand_raw and comparing the outputs (the
 *              secret is never exported).
 *            - HKDF is checked by \c extract -> \c expand_raw against the
 *              RFC 5869 OKM (the intermediate PRK handle is not exportable).
 *
 * \copyright Copyright (c) 2026
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
#include <edhoc/crypto.h>
#include <edhoc/cipher_suite.h>
#include <edhoc/values.h>
#include "edhoc_macros_internal.h"

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* PSA crypto header: */
#include <psa/crypto.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

static const struct edhoc_crypto *edhoc_crypto;
static const struct edhoc_cipher_suite *edhoc_suite;

static int ret = EDHOC_ERROR_GENERIC_ERROR;

/* A fixed, valid P-256 test scalar reused by the sign / ECDH cases. */
static const uint8_t p256_priv_key[] = {
	0xfb, 0x13, 0xad, 0xeb, 0x65, 0x18, 0xce, 0xe5, 0xf8, 0x84, 0x17,
	0x66, 0x08, 0x41, 0x14, 0x2e, 0x83, 0x0a, 0x81, 0xfe, 0x33, 0x43,
	0x80, 0xa9, 0x53, 0x40, 0x6a, 0x13, 0x05, 0xe8, 0x70, 0x6b,
};

/* The matching uncompressed P-256 public key (0x04 | X | Y). */
static const uint8_t p256_pub_key[] = {
	0x04, 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e, 0xd6,
	0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf, 0x16, 0xdf,
	0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30, 0x7f, 0x7e, 0xb6,
	0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b, 0x8a, 0x82, 0x11, 0x33,
	0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52, 0xa3, 0x87, 0xd2, 0x57, 0xe6,
	0xdb, 0x3c, 0x2a, 0x93, 0xdf, 0x21, 0xff, 0x3a, 0xff, 0xc8,
};

/* Static function declarations -------------------------------------------- */

/** \brief Import a raw P-256 scalar as an ECDSA (sign) private key. */
static psa_key_id_t import_ecdsa_priv(const uint8_t *priv, size_t priv_len);

/** \brief Import a raw P-256 scalar as an ECDH (key-agreement) private key. */
static psa_key_id_t import_ecdh_priv(const uint8_t *priv, size_t priv_len);

/** \brief Import raw bytes as a DERIVE key usable for HKDF extract and expand. */
static psa_key_id_t import_kdf_key(const uint8_t *raw, size_t raw_len);

/** \brief Import raw bytes as the suite AES-CCM AEAD key. */
static psa_key_id_t import_aead_key(const uint8_t *raw, size_t raw_len);

/* Static function definitions --------------------------------------------- */

static psa_key_id_t import_ecdsa_priv(const uint8_t *priv, size_t priv_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_import_key(&attr, priv, priv_len, &kid));

	return kid;
}

static psa_key_id_t import_ecdh_priv(const uint8_t *priv, size_t priv_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_import_key(&attr, priv, priv_len, &kid));

	return kid;
}

static psa_key_id_t import_kdf_key(const uint8_t *raw, size_t raw_len)
{
	/* Permit HKDF-Expand (primary) and HKDF-Extract (enrollment) so the same
	 * handle can seed both edhoc_crypto->extract and ->expand_raw, mirroring
	 * how the suite marks its derived keys. */
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
	psa_set_key_enrollment_algorithm(&attr,
					 PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));

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

/* Module interface function definitions ----------------------------------- */

/* ========================================================================= */
/* Positive suite: correct behaviour and known-answer tests.                 */
/* ========================================================================= */

TEST_GROUP(cipher_suite_2_positive);

TEST_SETUP(cipher_suite_2_positive)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());

	edhoc_crypto = edhoc_cipher_suite_2_get_crypto();
	edhoc_suite = edhoc_cipher_suite_2_get_suite();
}

TEST_TEAR_DOWN(cipher_suite_2_positive)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_2_positive, enum_getters)
{
	/* The enum-keyed getters dispatch to this suite's reference getters. */
	TEST_ASSERT_EQUAL_PTR(edhoc_crypto, edhoc_cipher_suite_get_crypto(
						    EDHOC_CIPHER_SUITE_2));
	TEST_ASSERT_EQUAL_PTR(edhoc_suite, edhoc_cipher_suite_get_params(
						   EDHOC_CIPHER_SUITE_2));

	/* Every cipher suite 2 descriptor parameter has its canonical value
	 * (P-256 / ES256 / AES-CCM-16-64-128 / SHA-256). */
	TEST_ASSERT_EQUAL_INT32(2, edhoc_suite->value);
	TEST_ASSERT_TRUE(edhoc_suite->supports_dh_nike);
	TEST_ASSERT_EQUAL(32, edhoc_suite->kem_encapsulation_key_length);
	TEST_ASSERT_EQUAL(32, edhoc_suite->kem_ciphertext_length);
	TEST_ASSERT_EQUAL(32, edhoc_suite->nike_key_length);
	TEST_ASSERT_EQUAL(64, edhoc_suite->sign_length);
	TEST_ASSERT_EQUAL(16, edhoc_suite->aead_key_length);
	TEST_ASSERT_EQUAL(8, edhoc_suite->aead_tag_length);
	TEST_ASSERT_EQUAL(13, edhoc_suite->aead_iv_length);
	TEST_ASSERT_EQUAL(32, edhoc_suite->hash_length);
	TEST_ASSERT_EQUAL(8, edhoc_suite->mac_length);

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

TEST(cipher_suite_2_positive, ecdsa)
{
	TEST_ASSERT_EQUAL(edhoc_suite->nike_key_length,
			  ARRAY_SIZE(p256_priv_key));
	TEST_ASSERT_EQUAL(1U + 2U * edhoc_suite->nike_key_length,
			  ARRAY_SIZE(p256_pub_key));

	uint8_t input[128] = { 0 };
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_generate_random(input, ARRAY_SIZE(input)));

	psa_key_id_t key_id =
		import_ecdsa_priv(p256_priv_key, ARRAY_SIZE(p256_priv_key));

	uint8_t sign[edhoc_suite->sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;

	ret = edhoc_crypto->sign(NULL, &key_id, input, ARRAY_SIZE(input), sign,
				 ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(edhoc_suite->sign_length, sign_len);

	ret = edhoc_crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* verify() takes the peer's raw public key; no key handle involved. */
	ret = edhoc_crypto->verify(NULL, p256_pub_key, ARRAY_SIZE(p256_pub_key),
				   input, ARRAY_SIZE(input), sign, sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2_positive, ecdh)
{
	/* Two ephemeral key pairs; a correct agreement yields one shared secret
	 * from either side. The secret is non-exportable, so equality is proven
	 * by deriving through expand_raw and comparing the outputs. */
	psa_key_id_t kid_a = PSA_KEY_ID_NULL;
	psa_key_id_t kid_b = PSA_KEY_ID_NULL;

	uint8_t pub_a[edhoc_suite->nike_key_length];
	uint8_t pub_b[edhoc_suite->nike_key_length];
	memset(pub_a, 0, sizeof(pub_a));
	memset(pub_b, 0, sizeof(pub_b));
	size_t pub_a_len = 0;
	size_t pub_b_len = 0;

	ret = edhoc_crypto->generate_key_pair(NULL, &kid_a, pub_a,
					      ARRAY_SIZE(pub_a), &pub_a_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(edhoc_suite->nike_key_length, pub_a_len);

	ret = edhoc_crypto->generate_key_pair(NULL, &kid_b, pub_b,
					      ARRAY_SIZE(pub_b), &pub_b_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(edhoc_suite->nike_key_length, pub_b_len);

	psa_key_id_t ss_a = PSA_KEY_ID_NULL;
	psa_key_id_t ss_b = PSA_KEY_ID_NULL;

	ret = edhoc_crypto->key_agreement(NULL, &kid_a, pub_b, pub_b_len,
					  &ss_a);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->key_agreement(NULL, &kid_b, pub_a, pub_a_len,
					  &ss_b);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t info[] = { 'e', 'd', 'h', 'o', 'c', 'k', 'a', 't' };
	uint8_t out_a[32] = { 0 };
	uint8_t out_b[32] = { 0 };

	ret = edhoc_crypto->expand_raw(NULL, &ss_a, info, ARRAY_SIZE(info),
				       out_a, ARRAY_SIZE(out_a));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->expand_raw(NULL, &ss_b, info, ARRAY_SIZE(info),
				       out_b, ARRAY_SIZE(out_b));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(out_a, out_b, ARRAY_SIZE(out_a));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &ss_a));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &ss_b));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &kid_a));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &kid_b));
}

TEST(cipher_suite_2_positive, kem_roundtrip)
{
	/* NIKE-as-KEM shim: encapsulate to a responder's public key, then have
	 * the responder decapsulate the ciphertext; both secrets must match. */
	psa_key_id_t resp_decaps = PSA_KEY_ID_NULL;

	uint8_t resp_pub[edhoc_suite->nike_key_length];
	memset(resp_pub, 0, sizeof(resp_pub));
	size_t resp_pub_len = 0;

	ret = edhoc_crypto->generate_key_pair(NULL, &resp_decaps, resp_pub,
					      ARRAY_SIZE(resp_pub),
					      &resp_pub_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	psa_key_id_t init_decaps = PSA_KEY_ID_NULL;
	psa_key_id_t ss_init = PSA_KEY_ID_NULL;

	uint8_t ciphertext[edhoc_suite->kem_ciphertext_length];
	memset(ciphertext, 0, sizeof(ciphertext));
	size_t ciphertext_len = 0;

	ret = edhoc_crypto->encapsulate(NULL, resp_pub, resp_pub_len,
					&init_decaps, &ss_init, ciphertext,
					ARRAY_SIZE(ciphertext),
					&ciphertext_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(edhoc_suite->kem_ciphertext_length, ciphertext_len);

	psa_key_id_t ss_resp = PSA_KEY_ID_NULL;

	ret = edhoc_crypto->decapsulate(NULL, &resp_decaps, ciphertext,
					ciphertext_len, &ss_resp);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t info[] = { 'k', 'e', 'm' };
	uint8_t out_init[32] = { 0 };
	uint8_t out_resp[32] = { 0 };

	ret = edhoc_crypto->expand_raw(NULL, &ss_init, info, ARRAY_SIZE(info),
				       out_init, ARRAY_SIZE(out_init));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->expand_raw(NULL, &ss_resp, info, ARRAY_SIZE(info),
				       out_resp, ARRAY_SIZE(out_resp));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(out_init, out_resp, ARRAY_SIZE(out_init));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &ss_init));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &ss_resp));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &init_decaps));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_crypto->destroy_key(NULL, &resp_decaps));
}

TEST(cipher_suite_2_positive, hkdf)
{
	/* RFC 5869 A.1, Test Case 1. The intermediate PRK handle is not
	 * exportable, so the KAT is asserted on the OKM (extract -> expand_raw),
	 * which transitively validates the extract step. */
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
	const uint8_t okm[] = {
		0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90,
		0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d,
		0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d,
		0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
		0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
	};

	psa_key_id_t ikm_id = import_kdf_key(ikm, ARRAY_SIZE(ikm));

	psa_key_id_t prk_id = PSA_KEY_ID_NULL;

	ret = edhoc_crypto->extract(NULL, &ikm_id, salt, ARRAY_SIZE(salt),
				    &prk_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->destroy_key(NULL, &ikm_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t comp_okm[ARRAY_SIZE(okm)] = { 0 };

	ret = edhoc_crypto->expand_raw(NULL, &prk_id, info, ARRAY_SIZE(info),
				       comp_okm, ARRAY_SIZE(comp_okm));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->destroy_key(NULL, &prk_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(okm, comp_okm, ARRAY_SIZE(okm));
}

TEST(cipher_suite_2_positive, aead)
{
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

	psa_key_id_t key_id = import_aead_key(key, ARRAY_SIZE(key));

	uint8_t ctxt[ARRAY_SIZE(ptxt) + edhoc_suite->aead_tag_length];
	memset(ctxt, 0, sizeof(ctxt));
	size_t ctxt_len = 0;

	ret = edhoc_crypto->aead_encrypt(NULL, &key_id, iv, ARRAY_SIZE(iv), aad,
					 ARRAY_SIZE(aad), ptxt,
					 ARRAY_SIZE(ptxt), ctxt,
					 ARRAY_SIZE(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ctxt), ctxt_len);

	uint8_t dec[ARRAY_SIZE(ptxt)] = { 0 };
	size_t dec_len = 0;

	ret = edhoc_crypto->aead_decrypt(NULL, &key_id, iv, ARRAY_SIZE(iv), aad,
					 ARRAY_SIZE(aad), ctxt, ctxt_len, dec,
					 ARRAY_SIZE(dec), &dec_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ptxt), dec_len);

	ret = edhoc_crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(ptxt, dec, ARRAY_SIZE(ptxt));
}

TEST(cipher_suite_2_positive, aead_zero_length_plaintext)
{
	const uint8_t key[] = {
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->aead_key_length, ARRAY_SIZE(key));

	uint8_t nonce[edhoc_suite->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));

	const uint8_t ad[4] = { 0x10, 0x11, 0x12, 0x13 };

	psa_key_id_t kid = import_aead_key(key, ARRAY_SIZE(key));

	uint8_t ctxt[32] = { 0 };
	size_t ctxt_len = 0;

	ret = edhoc_crypto->aead_encrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce),
					 ad, ARRAY_SIZE(ad), NULL, (size_t)0,
					 ctxt, ARRAY_SIZE(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(edhoc_suite->aead_tag_length, ctxt_len);

	size_t ptxt_len = 0;

	ret = edhoc_crypto->aead_decrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce),
					 ad, ARRAY_SIZE(ad), ctxt, ctxt_len,
					 NULL, (size_t)0, &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL((size_t)0, ptxt_len);

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2_positive, hash)
{
	const uint8_t input[] = { 'A' };
	const uint8_t exp_hash[] = {
		0x55, 0x9a, 0xea, 0xd0, 0x82, 0x64, 0xd5, 0x79,
		0x5d, 0x39, 0x09, 0x71, 0x8c, 0xdd, 0x05, 0xab,
		0xd4, 0x95, 0x72, 0xe8, 0x4f, 0xe5, 0x55, 0x90,
		0xee, 0xf3, 0x1a, 0x88, 0xa0, 0x8f, 0xdf, 0xfd,
	};
	TEST_ASSERT_EQUAL(edhoc_suite->hash_length, ARRAY_SIZE(exp_hash));

	/* Multipart hash: init -> update -> finish. */
	void *op = NULL;

	ret = edhoc_crypto->hash_init(NULL, &op);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->hash_update(NULL, op, input, ARRAY_SIZE(input));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t hash[edhoc_suite->hash_length];
	memset(hash, 0, sizeof(hash));
	size_t hash_len = 0;

	ret = edhoc_crypto->hash_finish(NULL, op, hash, ARRAY_SIZE(hash),
					&hash_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(hash), hash_len);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(hash, exp_hash, ARRAY_SIZE(exp_hash));
}

TEST_GROUP_RUNNER(cipher_suite_2_positive)
{
	RUN_TEST_CASE(cipher_suite_2_positive, enum_getters);
	RUN_TEST_CASE(cipher_suite_2_positive, ecdsa);
	RUN_TEST_CASE(cipher_suite_2_positive, ecdh);
	RUN_TEST_CASE(cipher_suite_2_positive, kem_roundtrip);
	RUN_TEST_CASE(cipher_suite_2_positive, hkdf);
	RUN_TEST_CASE(cipher_suite_2_positive, aead);
	RUN_TEST_CASE(cipher_suite_2_positive, aead_zero_length_plaintext);
	RUN_TEST_CASE(cipher_suite_2_positive, hash);
}

/* ========================================================================= */
/* Negative suite: argument validation, wrong/stale keys, tamper detection.  */
/* ========================================================================= */

TEST_GROUP(cipher_suite_2_negative);

TEST_SETUP(cipher_suite_2_negative)
{
	TEST_ASSERT_EQUAL(PSA_SUCCESS, psa_crypto_init());

	edhoc_crypto = edhoc_cipher_suite_2_get_crypto();
	edhoc_suite = edhoc_cipher_suite_2_get_suite();
}

TEST_TEAR_DOWN(cipher_suite_2_negative)
{
	mbedtls_psa_crypto_free();
}

TEST(cipher_suite_2_negative, verify_corrupted_signature)
{
	uint8_t input[32] = { 0 };
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_generate_random(input, sizeof(input)));

	psa_key_id_t key_id =
		import_ecdsa_priv(p256_priv_key, ARRAY_SIZE(p256_priv_key));

	uint8_t sign[edhoc_suite->sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;

	ret = edhoc_crypto->sign(NULL, &key_id, input, ARRAY_SIZE(input), sign,
				 ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	sign[0] ^= (uint8_t)0xFF;

	ret = edhoc_crypto->verify(NULL, p256_pub_key, ARRAY_SIZE(p256_pub_key),
				   input, ARRAY_SIZE(input), sign, sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2_negative, signature_bitflip_r_and_s)
{
	uint8_t input[32] = { 0 };
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_generate_random(input, sizeof(input)));

	psa_key_id_t key_id =
		import_ecdsa_priv(p256_priv_key, ARRAY_SIZE(p256_priv_key));

	uint8_t sign[edhoc_suite->sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;

	ret = edhoc_crypto->sign(NULL, &key_id, input, ARRAY_SIZE(input), sign,
				 ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->destroy_key(NULL, &key_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t tampered[edhoc_suite->sign_length];
	memset(tampered, 0, sizeof(tampered));

	/* Corrupt one bit in the r component (first half). */
	memcpy(tampered, sign, sizeof(tampered));
	tampered[0] ^= (uint8_t)0x01;
	ret = edhoc_crypto->verify(NULL, p256_pub_key, ARRAY_SIZE(p256_pub_key),
				   input, ARRAY_SIZE(input), tampered,
				   sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	/* Corrupt one bit in the s component (second half). */
	memcpy(tampered, sign, sizeof(tampered));
	tampered[edhoc_suite->nike_key_length] ^= (uint8_t)0x01;
	ret = edhoc_crypto->verify(NULL, p256_pub_key, ARRAY_SIZE(p256_pub_key),
				   input, ARRAY_SIZE(input), tampered,
				   sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	/* The pristine signature must still verify. */
	ret = edhoc_crypto->verify(NULL, p256_pub_key, ARRAY_SIZE(p256_pub_key),
				   input, ARRAY_SIZE(input), sign, sign_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2_negative, sign_public_key_rejected)
{
	/* A public key cannot sign: importing it as a public key and asking the
	 * suite to sign with that handle must fail. */
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_import_key(&attr, p256_pub_key,
					 ARRAY_SIZE(p256_pub_key), &kid));

	const uint8_t input[16] = { 0x01 };
	uint8_t sign[edhoc_suite->sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;

	ret = edhoc_crypto->sign(NULL, &kid, input, ARRAY_SIZE(input), sign,
				 ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2_negative, sign_and_verify_zero_input_len)
{
	psa_key_id_t kid =
		import_ecdsa_priv(p256_priv_key, ARRAY_SIZE(p256_priv_key));

	uint8_t dummy = 0;
	uint8_t sign[edhoc_suite->sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;

	ret = edhoc_crypto->sign(NULL, &kid, &dummy, 0, sign, ARRAY_SIZE(sign),
				 &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t fake_sign[edhoc_suite->sign_length];
	memset(fake_sign, 0, sizeof(fake_sign));

	ret = edhoc_crypto->verify(NULL, p256_pub_key, ARRAY_SIZE(p256_pub_key),
				   &dummy, 0, fake_sign, ARRAY_SIZE(fake_sign));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2_negative, aead_tag_tamper_detected)
{
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

	psa_key_id_t kid = import_aead_key(key, ARRAY_SIZE(key));

	uint8_t ctxt[ARRAY_SIZE(ptxt) + edhoc_suite->aead_tag_length];
	memset(ctxt, 0, sizeof(ctxt));
	size_t ctxt_len = 0;

	ret = edhoc_crypto->aead_encrypt(NULL, &kid, iv, ARRAY_SIZE(iv), aad,
					 ARRAY_SIZE(aad), ptxt,
					 ARRAY_SIZE(ptxt), ctxt,
					 ARRAY_SIZE(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(ARRAY_SIZE(ctxt), ctxt_len);

	/* Flip the last byte: that lands inside the CCM tag. */
	ctxt[ctxt_len - 1] ^= (uint8_t)0x80;

	uint8_t dec[ARRAY_SIZE(ptxt)] = { 0 };
	size_t dec_len = 0;

	ret = edhoc_crypto->aead_decrypt(NULL, &kid, iv, ARRAY_SIZE(iv), aad,
					 ARRAY_SIZE(aad), ctxt, ctxt_len, dec,
					 ARRAY_SIZE(dec), &dec_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2_negative, aead_aad_tamper_detected)
{
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

	psa_key_id_t kid = import_aead_key(key, ARRAY_SIZE(key));

	uint8_t ctxt[ARRAY_SIZE(ptxt) + edhoc_suite->aead_tag_length];
	memset(ctxt, 0, sizeof(ctxt));
	size_t ctxt_len = 0;

	ret = edhoc_crypto->aead_encrypt(NULL, &kid, iv, ARRAY_SIZE(iv),
					 aad_enc, ARRAY_SIZE(aad_enc), ptxt,
					 ARRAY_SIZE(ptxt), ctxt,
					 ARRAY_SIZE(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t dec[ARRAY_SIZE(ptxt)] = { 0 };
	size_t dec_len = 0;

	ret = edhoc_crypto->aead_decrypt(NULL, &kid, iv, ARRAY_SIZE(iv),
					 aad_dec, ARRAY_SIZE(aad_dec), ctxt,
					 ctxt_len, dec, ARRAY_SIZE(dec),
					 &dec_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2_negative, generate_key_pair_null_args)
{
	psa_key_id_t kid = PSA_KEY_ID_NULL;

	uint8_t pub[edhoc_suite->nike_key_length];
	memset(pub, 0, sizeof(pub));
	size_t pub_len = 0;

	ret = edhoc_crypto->generate_key_pair(NULL, NULL, pub, ARRAY_SIZE(pub),
					      &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	ret = edhoc_crypto->generate_key_pair(NULL, &kid, NULL, ARRAY_SIZE(pub),
					      &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2_negative, generate_key_pair_bad_size)
{
	psa_key_id_t kid = PSA_KEY_ID_NULL;

	uint8_t pub[16] = { 0 };
	size_t pub_len = 0;

	ret = edhoc_crypto->generate_key_pair(NULL, &kid, pub, ARRAY_SIZE(pub),
					      &pub_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(cipher_suite_2_negative, key_agreement_null_args)
{
	psa_key_id_t ss = PSA_KEY_ID_NULL;

	ret = edhoc_crypto->key_agreement(NULL, NULL, NULL, 0, &ss);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2_negative, key_agreement_bad_point)
{
	psa_key_id_t kid =
		import_ecdh_priv(p256_priv_key, ARRAY_SIZE(p256_priv_key));

	/* Correct length, but not a valid X coordinate on the curve. */
	uint8_t bad_peer[edhoc_suite->nike_key_length];
	memset(bad_peer, 0xFF, sizeof(bad_peer));

	psa_key_id_t ss = PSA_KEY_ID_NULL;

	ret = edhoc_crypto->key_agreement(NULL, &kid, bad_peer,
					  ARRAY_SIZE(bad_peer), &ss);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2_negative, key_agreement_peer_key_too_short)
{
	psa_key_id_t kid =
		import_ecdh_priv(p256_priv_key, ARRAY_SIZE(p256_priv_key));

	/* A peer key shorter than the curve length is rejected, not asserted. */
	uint8_t short_peer[16];
	memset(short_peer, 0x41, sizeof(short_peer));

	psa_key_id_t ss = PSA_KEY_ID_NULL;

	ret = edhoc_crypto->key_agreement(NULL, &kid, short_peer,
					  ARRAY_SIZE(short_peer), &ss);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2_negative, key_agreement_peer_key_too_long)
{
	psa_key_id_t kid =
		import_ecdh_priv(p256_priv_key, ARRAY_SIZE(p256_priv_key));

	/* A peer key longer than the curve length is rejected, not asserted. */
	uint8_t long_peer[edhoc_suite->nike_key_length + 1U];
	memset(long_peer, 0x41, sizeof(long_peer));

	psa_key_id_t ss = PSA_KEY_ID_NULL;

	ret = edhoc_crypto->key_agreement(NULL, &kid, long_peer,
					  ARRAY_SIZE(long_peer), &ss);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2_negative, key_agreement_wrong_key_type)
{
	/* An ECDSA (sign) key must not be usable for ECDH agreement. */
	psa_key_id_t sig_kid =
		import_ecdsa_priv(p256_priv_key, ARRAY_SIZE(p256_priv_key));

	uint8_t peer[edhoc_suite->nike_key_length];
	memset(peer, 0, sizeof(peer));
	peer[sizeof(peer) - 1] = 0x02;

	psa_key_id_t ss = PSA_KEY_ID_NULL;

	ret = edhoc_crypto->key_agreement(NULL, &sig_kid, peer,
					  ARRAY_SIZE(peer), &ss);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_crypto->destroy_key(NULL, &sig_kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2_negative, key_agreement_destroyed_key)
{
	psa_key_id_t kid =
		import_ecdh_priv(p256_priv_key, ARRAY_SIZE(p256_priv_key));

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t peer[edhoc_suite->nike_key_length];
	memset(peer, 0, sizeof(peer));
	peer[sizeof(peer) - 1] = 0x02;

	psa_key_id_t ss = PSA_KEY_ID_NULL;

	ret = edhoc_crypto->key_agreement(NULL, &kid, peer, ARRAY_SIZE(peer),
					  &ss);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2_negative, signature_null_args)
{
	uint8_t sign[edhoc_suite->sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;

	ret = edhoc_crypto->sign(NULL, NULL, NULL, 0, sign, ARRAY_SIZE(sign),
				 &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2_negative, signature_bad_size)
{
	psa_key_id_t kid =
		import_ecdsa_priv(p256_priv_key, ARRAY_SIZE(p256_priv_key));

	const uint8_t input[16] = { 0x42 };
	uint8_t sign[edhoc_suite->sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;

	/* sign_size below the fixed signature length is rejected. */
	ret = edhoc_crypto->sign(NULL, &kid, input, ARRAY_SIZE(input), sign, 32,
				 &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2_negative, signature_destroyed_key)
{
	psa_key_id_t kid =
		import_ecdsa_priv(p256_priv_key, ARRAY_SIZE(p256_priv_key));

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t input[32] = { 0 };
	uint8_t sign[edhoc_suite->sign_length];
	memset(sign, 0, sizeof(sign));
	size_t sign_len = 0;

	ret = edhoc_crypto->sign(NULL, &kid, input, ARRAY_SIZE(input), sign,
				 ARRAY_SIZE(sign), &sign_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2_negative, verify_null_args)
{
	ret = edhoc_crypto->verify(NULL, NULL, 0, NULL, 0, NULL, 0);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2_negative, verify_bad_sign_len)
{
	const uint8_t input[16] = { 0x42 };
	uint8_t sign[edhoc_suite->sign_length];
	memset(sign, 0, sizeof(sign));

	/* signature_length below the fixed signature length is rejected. */
	ret = edhoc_crypto->verify(NULL, p256_pub_key, ARRAY_SIZE(p256_pub_key),
				   input, ARRAY_SIZE(input), sign, 32);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2_negative, extract_null_args)
{
	psa_key_id_t prk = PSA_KEY_ID_NULL;

	ret = edhoc_crypto->extract(NULL, NULL, NULL, 0, &prk);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2_negative, extract_wrong_key_type)
{
	psa_key_id_t kid =
		import_ecdsa_priv(p256_priv_key, ARRAY_SIZE(p256_priv_key));

	const uint8_t salt[16] = { 0 };
	psa_key_id_t prk = PSA_KEY_ID_NULL;

	ret = edhoc_crypto->extract(NULL, &kid, salt, ARRAY_SIZE(salt), &prk);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2_negative, extract_destroyed_key)
{
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	psa_key_id_t kid = import_kdf_key(raw_key, ARRAY_SIZE(raw_key));

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t salt[16] = { 0 };
	psa_key_id_t prk = PSA_KEY_ID_NULL;

	ret = edhoc_crypto->extract(NULL, &kid, salt, ARRAY_SIZE(salt), &prk);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2_negative, expand_null_args)
{
	uint8_t okm[edhoc_suite->hash_length];
	memset(okm, 0, sizeof(okm));

	ret = edhoc_crypto->expand_raw(NULL, NULL, NULL, 0, okm,
				       ARRAY_SIZE(okm));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2_negative, expand_wrong_key_type)
{
	psa_key_id_t kid =
		import_ecdsa_priv(p256_priv_key, ARRAY_SIZE(p256_priv_key));

	const uint8_t info[16] = { 0 };
	uint8_t okm[edhoc_suite->hash_length];
	memset(okm, 0, sizeof(okm));

	ret = edhoc_crypto->expand_raw(NULL, &kid, info, ARRAY_SIZE(info), okm,
				       ARRAY_SIZE(okm));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2_negative, expand_destroyed_key)
{
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	psa_key_id_t kid = import_kdf_key(raw_key, ARRAY_SIZE(raw_key));

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	const uint8_t info[16] = { 0 };
	uint8_t okm[edhoc_suite->hash_length];
	memset(okm, 0, sizeof(okm));

	ret = edhoc_crypto->expand_raw(NULL, &kid, info, ARRAY_SIZE(info), okm,
				       ARRAY_SIZE(okm));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2_negative, expand_okm_length_too_large)
{
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	psa_key_id_t kid = import_kdf_key(raw_key, ARRAY_SIZE(raw_key));

	const uint8_t info[4] = { 0xab, 0xcd, 0xef, 0x01 };
	enum { okm_len = 65536 };
	uint8_t *okm = malloc(okm_len);
	TEST_ASSERT_NOT_NULL(okm);

	/* HKDF-Expand caps output at 255 * hash_length; a larger request fails. */
	ret = edhoc_crypto->expand_raw(NULL, &kid, info, ARRAY_SIZE(info), okm,
				       okm_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
	free(okm);

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2_negative, encrypt_null_args)
{
	uint8_t ctxt[64] = { 0 };
	size_t ctxt_len = 0;

	ret = edhoc_crypto->aead_encrypt(NULL, NULL, NULL, 0, NULL, 0, NULL, 0,
					 ctxt, ARRAY_SIZE(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2_negative, encrypt_wrong_key_type)
{
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	psa_key_id_t kid = import_kdf_key(raw_key, ARRAY_SIZE(raw_key));

	uint8_t nonce[edhoc_suite->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));

	const uint8_t ad[16] = { 0 };
	const uint8_t ptxt[16] = { 0 };
	uint8_t ctxt[32] = { 0 };
	size_t ctxt_len = 0;

	ret = edhoc_crypto->aead_encrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce),
					 ad, ARRAY_SIZE(ad), ptxt,
					 ARRAY_SIZE(ptxt), ctxt,
					 ARRAY_SIZE(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2_negative, encrypt_destroyed_key)
{
	uint8_t raw_key[edhoc_suite->aead_key_length];
	memset(raw_key, 0, sizeof(raw_key));

	psa_key_id_t kid = import_aead_key(raw_key, ARRAY_SIZE(raw_key));

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[edhoc_suite->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));

	const uint8_t ad[16] = { 0 };
	const uint8_t ptxt[16] = { 0 };
	uint8_t ctxt[32] = { 0 };
	size_t ctxt_len = 0;

	ret = edhoc_crypto->aead_encrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce),
					 ad, ARRAY_SIZE(ad), ptxt,
					 ARRAY_SIZE(ptxt), ctxt,
					 ARRAY_SIZE(ctxt), &ctxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2_negative, decrypt_null_args)
{
	uint8_t ptxt[64] = { 0 };
	size_t ptxt_len = 0;

	ret = edhoc_crypto->aead_decrypt(NULL, NULL, NULL, 0, NULL, 0, NULL, 0,
					 ptxt, ARRAY_SIZE(ptxt), &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2_negative, decrypt_wrong_key_type)
{
	uint8_t raw_key[edhoc_suite->hash_length];
	memset(raw_key, 0, sizeof(raw_key));

	psa_key_id_t kid = import_kdf_key(raw_key, ARRAY_SIZE(raw_key));

	uint8_t nonce[edhoc_suite->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));

	const uint8_t ad[16] = { 0 };
	const uint8_t ctxt[32] = { 0 };
	uint8_t ptxt[32] = { 0 };
	size_t ptxt_len = 0;

	ret = edhoc_crypto->aead_decrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce),
					 ad, ARRAY_SIZE(ad), ctxt,
					 ARRAY_SIZE(ctxt), ptxt,
					 ARRAY_SIZE(ptxt), &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(cipher_suite_2_negative, decrypt_destroyed_key)
{
	uint8_t raw_key[edhoc_suite->aead_key_length];
	memset(raw_key, 0, sizeof(raw_key));

	psa_key_id_t kid = import_aead_key(raw_key, ARRAY_SIZE(raw_key));

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t nonce[edhoc_suite->aead_iv_length];
	memset(nonce, 0, sizeof(nonce));

	const uint8_t ad[16] = { 0 };
	const uint8_t ctxt[32] = { 0 };
	uint8_t ptxt[32] = { 0 };
	size_t ptxt_len = 0;

	ret = edhoc_crypto->aead_decrypt(NULL, &kid, nonce, ARRAY_SIZE(nonce),
					 ad, ARRAY_SIZE(ad), ctxt,
					 ARRAY_SIZE(ctxt), ptxt,
					 ARRAY_SIZE(ptxt), &ptxt_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2_negative, hash_null_args)
{
	/* hash_init requires an output operation slot. */
	ret = edhoc_crypto->hash_init(NULL, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);

	/* hash_update requires an operation and input. */
	uint8_t input[4] = { 0 };
	ret = edhoc_crypto->hash_update(NULL, NULL, input, ARRAY_SIZE(input));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2_negative, hash_wrong_size)
{
	const uint8_t input[16] = { 0 };

	void *op = NULL;

	ret = edhoc_crypto->hash_init(NULL, &op);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_crypto->hash_update(NULL, op, input, ARRAY_SIZE(input));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* A hash buffer smaller than the digest is rejected. */
	uint8_t hash[4] = { 0 };
	size_t hash_len = 0;

	ret = edhoc_crypto->hash_finish(NULL, op, hash, ARRAY_SIZE(hash),
					&hash_len);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST(cipher_suite_2_negative, key_destroy_null)
{
	ret = edhoc_crypto->destroy_key(NULL, NULL);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(cipher_suite_2_negative, key_destroy_invalid_id)
{
	psa_key_id_t kid = 0xDEADBEEF;

	ret = edhoc_crypto->destroy_key(NULL, &kid);
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CRYPTO_FAILURE, ret);
}

TEST_GROUP_RUNNER(cipher_suite_2_negative)
{
	/* Tamper / corruption detection. */
	RUN_TEST_CASE(cipher_suite_2_negative, verify_corrupted_signature);
	RUN_TEST_CASE(cipher_suite_2_negative, signature_bitflip_r_and_s);
	RUN_TEST_CASE(cipher_suite_2_negative, sign_public_key_rejected);
	RUN_TEST_CASE(cipher_suite_2_negative, sign_and_verify_zero_input_len);
	RUN_TEST_CASE(cipher_suite_2_negative, aead_tag_tamper_detected);
	RUN_TEST_CASE(cipher_suite_2_negative, aead_aad_tamper_detected);

	/* Argument validation. */
	RUN_TEST_CASE(cipher_suite_2_negative, generate_key_pair_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, generate_key_pair_bad_size);
	RUN_TEST_CASE(cipher_suite_2_negative, key_agreement_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, signature_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, signature_bad_size);
	RUN_TEST_CASE(cipher_suite_2_negative, verify_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, verify_bad_sign_len);
	RUN_TEST_CASE(cipher_suite_2_negative, extract_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, expand_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, expand_okm_length_too_large);
	RUN_TEST_CASE(cipher_suite_2_negative, encrypt_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, decrypt_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, hash_null_args);
	RUN_TEST_CASE(cipher_suite_2_negative, hash_wrong_size);
	RUN_TEST_CASE(cipher_suite_2_negative, key_destroy_null);
	RUN_TEST_CASE(cipher_suite_2_negative, key_destroy_invalid_id);

	/* Wrong key type / stale handle rejection. */
	RUN_TEST_CASE(cipher_suite_2_negative, key_agreement_bad_point);
	RUN_TEST_CASE(cipher_suite_2_negative,
		      key_agreement_peer_key_too_short);
	RUN_TEST_CASE(cipher_suite_2_negative, key_agreement_peer_key_too_long);
	RUN_TEST_CASE(cipher_suite_2_negative, key_agreement_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_2_negative, key_agreement_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2_negative, signature_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2_negative, extract_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_2_negative, extract_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2_negative, expand_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_2_negative, expand_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2_negative, encrypt_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_2_negative, encrypt_destroyed_key);
	RUN_TEST_CASE(cipher_suite_2_negative, decrypt_wrong_key_type);
	RUN_TEST_CASE(cipher_suite_2_negative, decrypt_destroyed_key);
}
