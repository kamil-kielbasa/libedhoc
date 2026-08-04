/**
 * \file    cipher_suite_driver.c
 * \author  Kamil Kielbasa
 * \brief   Shared helpers for the parametrized cipher-suite tests: the enum
 *          getter check and the per-flavor key-import routines.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Cipher-suite driver header: */
#include "cipher_suite_driver.h"

/* EDHOC headers: */
#include <edhoc/cipher_suite.h>
#include <edhoc/values.h>

/* PSA crypto header: */
#include <psa/crypto.h>

/* Unity headers: */
#include <unity.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */
/* Static function declarations -------------------------------------------- */

/** \brief Import \p key with the given attributes, aborting on PSA failure. */
static psa_key_id_t cipher_suite_import(const psa_key_attributes_t *attributes,
					const uint8_t *key, size_t key_length);

/* Static function definitions --------------------------------------------- */

static psa_key_id_t cipher_suite_import(const psa_key_attributes_t *attributes,
					const uint8_t *key, size_t key_length)
{
	psa_key_id_t key_id = PSA_KEY_ID_NULL;

	TEST_ASSERT_EQUAL(PSA_SUCCESS,
			  psa_import_key(attributes, key, key_length, &key_id));

	return key_id;
}

/* Module interface function definitions ----------------------------------- */

psa_key_id_t
cipher_suite_import_sign_key(const struct cipher_suite_descriptor *suite,
			     const uint8_t *key, size_t key_length)
{
	/* The post-quantum suite loads its oversized signing key through its own
	 * hook; every other suite imports through PSA per \c suite->sign.import. */
	if (NULL != suite->import_signing_key) {
		psa_key_id_t key_id = PSA_KEY_ID_NULL;
		TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
				  suite->import_signing_key(key, key_length,
							    &key_id));
		return key_id;
	}

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);

	switch (suite->sign.import) {
	case CIPHER_SUITE_SIGN_ED25519:
		/* mbedTLS/PSA has no software EdDSA: the suite exports the seed
		 * and signs with Compact25519, so it is an exportable RAW_DATA
		 * key (the 64-byte seed || public key). */
		psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
		psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);
		break;

	case CIPHER_SUITE_SIGN_ECDSA_SHA256:
		psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
		psa_set_key_algorithm(&attributes,
				      PSA_ALG_ECDSA(PSA_ALG_SHA_256));
		psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(
						      PSA_ECC_FAMILY_SECP_R1));
		break;

	case CIPHER_SUITE_SIGN_ECDSA_SHA384:
		psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
		psa_set_key_algorithm(&attributes,
				      PSA_ALG_ECDSA(PSA_ALG_SHA_384));
		psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(
						      PSA_ECC_FAMILY_SECP_R1));
		break;

	case CIPHER_SUITE_SIGN_ML_DSA_44:
		/* Loaded through suite->import_signing_key above; reaching the
		 * PSA path means the descriptor lacks that hook. */
	default:
		TEST_FAIL_MESSAGE("unsupported signing key import");
		break;
	}

	return cipher_suite_import(&attributes, key, key_length);
}

psa_key_id_t
cipher_suite_import_nike_key(const struct cipher_suite_descriptor *suite,
			     const uint8_t *key, size_t key_length)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);

	switch (suite->nike.curve) {
	case CIPHER_SUITE_NIKE_X25519:
		psa_set_key_type(
			&attributes,
			PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
		break;

	case CIPHER_SUITE_NIKE_P256:
	case CIPHER_SUITE_NIKE_P384:
		psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(
						      PSA_ECC_FAMILY_SECP_R1));
		break;

	default:
		TEST_FAIL_MESSAGE("unsupported static-DH key import");
		break;
	}

	return cipher_suite_import(&attributes, key, key_length);
}

psa_key_id_t
cipher_suite_import_kdf_key(const struct cipher_suite_descriptor *suite,
			    const uint8_t *key, size_t key_length)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_DERIVE);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);

	switch (suite->kdf.algorithm) {
	case CIPHER_SUITE_KDF_HKDF_SHA256:
		/* Permit HKDF-Expand (primary) and HKDF-Extract (enrollment) so
		 * the same handle seeds both extract and expand_raw, mirroring
		 * how the suite marks its derived keys. */
		psa_set_key_algorithm(&attributes,
				      PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
		psa_set_key_enrollment_algorithm(
			&attributes, PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));
		break;

	case CIPHER_SUITE_KDF_HKDF_SHA384:
		psa_set_key_algorithm(&attributes,
				      PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_384));
		psa_set_key_enrollment_algorithm(
			&attributes, PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_384));
		break;

	case CIPHER_SUITE_KDF_KMAC256:
		/* The KMAC256 KDF consumes its secrets as exportable RAW_DATA:
		 * the suite reads the key bytes back to key each KMAC call, and
		 * the tests export a derived PRK to check it. */
		psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);
		psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
		break;

	default:
		TEST_FAIL_MESSAGE("unsupported key-derivation key import");
		break;
	}

	return cipher_suite_import(&attributes, key, key_length);
}

psa_key_id_t
cipher_suite_import_aead_key(const struct cipher_suite_descriptor *suite,
			     const uint8_t *key, size_t key_length)
{
	const size_t tag_length =
		edhoc_cipher_suite_get_params(suite->id)->aead_tag_length;

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attributes,
				PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);

	switch (suite->aead) {
	case CIPHER_SUITE_AEAD_AES_CCM:
		psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
		psa_set_key_algorithm(&attributes,
				      PSA_ALG_AEAD_WITH_SHORTENED_TAG(
					      PSA_ALG_CCM, tag_length));
		break;

	case CIPHER_SUITE_AEAD_CHACHA20_POLY1305:
		psa_set_key_type(&attributes, PSA_KEY_TYPE_CHACHA20);
		psa_set_key_algorithm(&attributes,
				      PSA_ALG_AEAD_WITH_SHORTENED_TAG(
					      PSA_ALG_CHACHA20_POLY1305,
					      tag_length));
		break;

	case CIPHER_SUITE_AEAD_AES_GCM:
		psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
		psa_set_key_algorithm(&attributes,
				      PSA_ALG_AEAD_WITH_SHORTENED_TAG(
					      PSA_ALG_GCM, tag_length));
		break;

	default:
		TEST_FAIL_MESSAGE("unsupported AEAD key import");
		break;
	}

	return cipher_suite_import(&attributes, key, key_length);
}
