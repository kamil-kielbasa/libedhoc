/**
 * \file    test_cipher_suite_0.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for cipher suite 0.
 * \version 0.4
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */

/* Internal test header: */
#include "cipher_suites/cipher_suite_0.h"
#include "cipher_suites/test_cipher_suite_0.h"

/* Standard library headers: */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>

/* EDHOC headers: */
#include "edhoc_crypto.h"
#include "edhoc_values.h"
#include "edhoc_macros.h"

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

static const struct edhoc_keys keys = {
	.generate_key = cipher_suite_0_key_generate,
	.destroy_key = cipher_suite_0_key_destroy,
};

static const struct edhoc_crypto crypto = {
	.make_key_pair = cipher_suite_0_make_key_pair,
	.key_agreement = cipher_suite_0_key_agreement,
	.signature = cipher_suite_0_signature,
	.verify = cipher_suite_0_verify,
	.extract = cipher_suite_0_extract,
	.expand = cipher_suite_0_expand,
	.encrypt = cipher_suite_0_encrypt,
	.decrypt = cipher_suite_0_decrypt,
	.hash = cipher_suite_0_hash,
};

/* Static function declarations -------------------------------------------- */

/**
 * \brief Helper function for printing arrays.
 */
static inline void print_array(const char *name, const uint8_t *buffer,
			       size_t buffer_length);

/* Static function definitions --------------------------------------------- */

static inline void print_array(const char *name, const uint8_t *buffer,
			       size_t buffer_length)
{
	printf("%s:\tLEN( %zu )\n", name, buffer_length);

	for (size_t i = 0; i < buffer_length; ++i) {
		if (0 == i % 16 && i > 0) {
			printf("\n");
		}

		printf("%02x ", buffer[i]);
	}

	printf("\n\n");
}

/* Module interface function definitions ----------------------------------- */

void test_cipher_suite_0_ecdsa(void)
{
	int ret = PSA_ERROR_GENERIC_ERROR;
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	const struct edhoc_keys *edhoc_keys = &keys;
	const struct edhoc_crypto *edhoc_crypto = &crypto;

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

	/**
	 * \brief Random input for signature.
	 */
	uint8_t input[INPUT_TO_SIGN_LEN] = { 0 };
	ret = psa_generate_random(input, ARRAY_SIZE(input));
	assert(PSA_SUCCESS == ret);

	print_array("Input for signature", input, ARRAY_SIZE(input));

	/**
	 * \brief Generate signature.
	 */
	size_t sign_len = 0;
	uint8_t sign[ED25519_SIGNATURE_SIZE] = { 0 };

	ret = edhoc_keys->generate_key(NULL, EDHOC_KT_SIGNATURE, priv_key,
				       ARRAY_SIZE(priv_key), &key_id);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_crypto->signature(NULL, &key_id, input, ARRAY_SIZE(input),
				      sign, ARRAY_SIZE(sign), &sign_len);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	assert(EDHOC_SUCCESS == ret);

	print_array("Signature", sign, sign_len);

	/**
	 * \brief Verify signature.
	 */
	ret = edhoc_keys->generate_key(NULL, EDHOC_KT_VERIFY, pub_key,
				       ARRAY_SIZE(pub_key), &key_id);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_crypto->verify(NULL, &key_id, input, ARRAY_SIZE(input),
				   sign, sign_len);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	assert(EDHOC_SUCCESS == ret);
}

void test_cipher_suite_0_ecdh(void)
{
	int ret = PSA_ERROR_GENERIC_ERROR;
	psa_key_id_t key_id_a = PSA_KEY_HANDLE_INIT;
	psa_key_id_t key_id_b = PSA_KEY_HANDLE_INIT;

	const struct edhoc_keys *edhoc_keys = &keys;
	const struct edhoc_crypto *edhoc_crypto = &crypto;

	/**
	 * \brief Alice ECDH public and private keys. 
	 */
	size_t priv_key_len_a = 0;
	uint8_t priv_key_a[X25519_KEY_SIZE] = { 0 };

	size_t pub_key_len_a = 0;
	uint8_t pub_key_a[X25519_KEY_SIZE] = { 0 };

	ret = edhoc_keys->generate_key(NULL, EDHOC_KT_MAKE_KEY_PAIR, NULL, 0,
				       &key_id_a);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_crypto->make_key_pair(NULL, &key_id_a, priv_key_a,
					  ARRAY_SIZE(priv_key_a),
					  &priv_key_len_a, pub_key_a,
					  ARRAY_SIZE(pub_key_a),
					  &pub_key_len_a);
	assert(EDHOC_SUCCESS == ret);
	assert(ARRAY_SIZE(priv_key_a) == priv_key_len_a);
	assert(ARRAY_SIZE(pub_key_a) == pub_key_len_a);

	ret = edhoc_keys->destroy_key(NULL, &key_id_a);
	assert(EDHOC_SUCCESS == ret);

	print_array("Alice private key", priv_key_a, ARRAY_SIZE(priv_key_a));
	print_array("Alice public key", pub_key_a, ARRAY_SIZE(pub_key_a));

	/**
	 * \brief Bob ECDH public and private keys. 
	 */
	size_t priv_key_len_b = 0;
	uint8_t priv_key_b[X25519_KEY_SIZE] = { 0 };

	size_t pub_key_len_b = 0;
	uint8_t pub_key_b[X25519_KEY_SIZE] = { 0 };

	ret = edhoc_keys->generate_key(NULL, EDHOC_KT_MAKE_KEY_PAIR, NULL, 0,
				       &key_id_b);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_crypto->make_key_pair(NULL, &key_id_b, priv_key_b,
					  ARRAY_SIZE(priv_key_b),
					  &priv_key_len_b, pub_key_b,
					  ARRAY_SIZE(pub_key_b),
					  &pub_key_len_b);
	assert(EDHOC_SUCCESS == ret);
	assert(ARRAY_SIZE(priv_key_b) == priv_key_len_b);
	assert(ARRAY_SIZE(pub_key_b) == pub_key_len_b);

	ret = edhoc_keys->destroy_key(NULL, &key_id_b);
	assert(EDHOC_SUCCESS == ret);

	print_array("Bob private key", priv_key_b, ARRAY_SIZE(priv_key_b));
	print_array("Bob public key", pub_key_b, ARRAY_SIZE(pub_key_b));

	/**
	 * \brief Shared secret for Alice:
         *        - Alice ECDH private key.
         *        - Bob ECDH public key. 
	 */
	size_t shr_sec_len_a = 0;
	uint8_t shr_sec_a[X25519_SHARED_SIZE] = { 0 };

	ret = edhoc_keys->generate_key(NULL, EDHOC_KT_KEY_AGREEMENT, priv_key_a,
				       priv_key_len_a, &key_id_a);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_crypto->key_agreement(NULL, &key_id_a, pub_key_b,
					  pub_key_len_b, shr_sec_a,
					  ARRAY_SIZE(shr_sec_a),
					  &shr_sec_len_a);
	assert(EDHOC_SUCCESS == ret);
	assert(ARRAY_SIZE(shr_sec_a) == shr_sec_len_a);

	ret = edhoc_keys->destroy_key(NULL, &key_id_a);
	assert(EDHOC_SUCCESS == ret);

	print_array("Alice shared secret", shr_sec_a, shr_sec_len_a);

	/**
	 * \brief Shared secret for Bob:
         *        - Bob ECDH private key.
         *        - Alice ECDH public key. 
	 */
	size_t shr_sec_len_b = 0;
	uint8_t shr_sec_b[X25519_SHARED_SIZE] = { 0 };

	ret = edhoc_keys->generate_key(NULL, EDHOC_KT_KEY_AGREEMENT, priv_key_b,
				       priv_key_len_b, &key_id_b);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_crypto->key_agreement(NULL, &key_id_b, pub_key_a,
					  pub_key_len_a, shr_sec_b,
					  ARRAY_SIZE(shr_sec_b),
					  &shr_sec_len_b);
	assert(EDHOC_SUCCESS == ret);
	assert(ARRAY_SIZE(shr_sec_b) == shr_sec_len_b);

	ret = edhoc_keys->destroy_key(NULL, &key_id_b);
	assert(PSA_SUCCESS == ret);

	print_array("Bob shared secret", shr_sec_b, shr_sec_len_b);

	/**
	 * \brief Compare if Alice and Bob has the same shared secrets.
	 */
	assert(shr_sec_len_a == shr_sec_len_b);
	assert(0 == memcmp(shr_sec_a, shr_sec_b, shr_sec_len_a));

	/**
	 * \brief Compare if Alice and Bob has not the same ECDH keys.
	 */
	assert(priv_key_len_a == priv_key_len_b);
	assert(0 != memcmp(priv_key_a, priv_key_b, priv_key_len_a));

	assert(pub_key_len_a == pub_key_len_b);
	assert(0 != memcmp(pub_key_a, pub_key_b, pub_key_len_a));
}

void test_cipher_suite_0_hkdf(void)
{
	int ret = PSA_ERROR_GENERIC_ERROR;
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	const struct edhoc_keys *edhoc_keys = &keys;
	const struct edhoc_crypto *edhoc_crypto = &crypto;

	/**
	 * \brief Test vectors taken from RFC 5869: A.1. Test Case 1.
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

	/**
         * \brief HDFK extract part. 
         */
	size_t comp_prk_len = 0;
	uint8_t comp_prk[32] = { 0 };

	ret = edhoc_keys->generate_key(NULL, EDHOC_KT_EXTRACT, ikm,
				       ARRAY_SIZE(ikm), &key_id);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_crypto->extract(NULL, &key_id, salt, ARRAY_SIZE(salt),
				    comp_prk, ARRAY_SIZE(comp_prk),
				    &comp_prk_len);
	assert(EDHOC_SUCCESS == ret);
	assert(ARRAY_SIZE(comp_prk) == comp_prk_len);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	assert(EDHOC_SUCCESS == ret);

	assert(comp_prk_len == ARRAY_SIZE(prk));
	assert(0 == memcmp(comp_prk, prk, comp_prk_len));

	/**
         * \brief HDFK expand part. 
         */
	uint8_t comp_okm[L];
	memset(comp_okm, 0, sizeof(comp_okm));

	ret = edhoc_keys->generate_key(NULL, EDHOC_KT_EXPAND, comp_prk,
				       ARRAY_SIZE(comp_prk), &key_id);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_crypto->expand(NULL, &key_id, info, ARRAY_SIZE(info),
				   comp_okm, ARRAY_SIZE(comp_okm));
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	assert(EDHOC_SUCCESS == ret);

	assert(0 == memcmp(comp_okm, okm, ARRAY_SIZE(okm)));
}

void test_cipher_suite_0_aead(void)
{
	int ret = PSA_ERROR_GENERIC_ERROR;
	psa_key_id_t key_id = PSA_KEY_HANDLE_INIT;

	const struct edhoc_keys *edhoc_keys = &keys;
	const struct edhoc_crypto *edhoc_crypto = &crypto;

	/**
         * \brief AEAD key, iv and aad.
         */
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

	/**
         * \brief AEAD encryption.
         */
	const uint8_t ptxt[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

	ret = edhoc_keys->generate_key(NULL, EDHOC_KT_ENCRYPT, key,
				       ARRAY_SIZE(key), &key_id);
	assert(EDHOC_SUCCESS == ret);

	size_t ctxt_len = 0;
	uint8_t ctxt[18] = { 0 };
	ret = edhoc_crypto->encrypt(NULL, &key_id, iv, ARRAY_SIZE(iv), aad,
				    ARRAY_SIZE(aad), ptxt, ARRAY_SIZE(ptxt),
				    ctxt, ARRAY_SIZE(ctxt), &ctxt_len);
	assert(EDHOC_SUCCESS == ret);
	assert(ARRAY_SIZE(ctxt) == ctxt_len);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief AEAD decryption.
         */
	size_t dec_ctxt_len = 0;
	uint8_t dec_ctxt[ARRAY_SIZE(ptxt)] = { 0 };

	ret = edhoc_keys->generate_key(NULL, EDHOC_KT_DECRYPT, key,
				       ARRAY_SIZE(key), &key_id);
	assert(EDHOC_SUCCESS == ret);

	ret = edhoc_crypto->decrypt(NULL, &key_id, iv, ARRAY_SIZE(iv), aad,
				    ARRAY_SIZE(aad), ctxt, ctxt_len, dec_ctxt,
				    ARRAY_SIZE(dec_ctxt), &dec_ctxt_len);
	assert(EDHOC_SUCCESS == ret);
	assert(ARRAY_SIZE(ptxt) == dec_ctxt_len);

	ret = edhoc_keys->destroy_key(NULL, &key_id);
	assert(EDHOC_SUCCESS == ret);

	/**
         * \brief Verify if plaintext is equal to decrypted ciphertext.
         */
	assert(0 == memcmp(ptxt, dec_ctxt, ARRAY_SIZE(ptxt)));
}

void test_cipher_suite_0_hash(void)
{
	int ret = PSA_ERROR_GENERIC_ERROR;

	const struct edhoc_crypto *edhoc_crypto = &crypto;

	/**
         * \brief Input for hash function and expected hash. 
         */
	const uint8_t input[] = { 'A' };

	const uint8_t exp_hash[32] = {
		0x55, 0x9a, 0xea, 0xd0, 0x82, 0x64, 0xd5, 0x79,
		0x5d, 0x39, 0x09, 0x71, 0x8c, 0xdd, 0x05, 0xab,
		0xd4, 0x95, 0x72, 0xe8, 0x4f, 0xe5, 0x55, 0x90,
		0xee, 0xf3, 0x1a, 0x88, 0xa0, 0x8f, 0xdf, 0xfd,
	};

	/**
         * \brief Hash operation. 
         */
	size_t hash_len = 0;
	uint8_t hash[32] = { 0 };

	ret = edhoc_crypto->hash(NULL, input, ARRAY_SIZE(input), hash,
				 ARRAY_SIZE(hash), &hash_len);
	assert(EDHOC_SUCCESS == ret);
	assert(ARRAY_SIZE(hash) == hash_len);

	/**
         * \brief Verify if hashes are equals. 
         */
	assert(0 == memcmp(hash, exp_hash, ARRAY_SIZE(exp_hash)));
}
