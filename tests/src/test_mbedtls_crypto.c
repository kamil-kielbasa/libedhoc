/**
 * @file    test_mbedtls_crypto.c
 * @author  Kamil Kielbasa
 * @brief   Unit test for PSA crypto functions (mbedtls backend).
 * @version 0.1
 * @date    2024-01-01
 * 
 * @copyright Copyright (c) 2024
 * 
 */

/* Include files ----------------------------------------------------------- */
#include "test_mbedtls_crypto.h"
#include "edhoc.h"
#include "test_crypto.h"
#include "test_vectors_p256_v16.h"

/* standard library headers: */
#include <stdint.h>
#include <string.h>
#include <assert.h>

/* crypto header: */
#include <psa/crypto.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

static const struct edhoc_keys keys = {
	.generate_key = edhoc_keys_generate,
	.destroy_key = edhoc_keys_destroy,
};

static const struct edhoc_crypto crypto = {
	.make_key_pair = test_crypto_make_key_pair,
	.key_agreement = test_crypto_key_agreement,
	.sign = test_crypto_sign,
	.verify = test_crypto_verify,
	.extract = test_crypto_extract,
	.expand = test_crypto_expand,
	.encrypt = test_crypto_encrypt,
	.decrypt = test_crypto_decrypt,
	.hash = test_crypto_hash,
};

/* Static function declarations -------------------------------------------- */

static inline void print_array(const char *name, const uint8_t *array,
			       size_t array_length);

/* Static function definitions --------------------------------------------- */

static inline void print_array(const char *name, const uint8_t *array,
			       size_t array_length)
{
	printf("%s:\tLEN( %zu )\n", name, array_length);

	for (size_t i = 0; i < array_length; ++i) {
		if (0 == i % 16 && i > 0) {
			printf("\n");
		}

		printf("%02x ", array[i]);
	}

	printf("\n\n");
}

/* Module interface function definitions ----------------------------------- */

void test_mbedtls_crypto_aead(void)
{
	const struct edhoc_keys *kb = &keys;
	const struct edhoc_crypto *cb = &crypto;

	const uint8_t key[16] = {
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3
	};
	const uint8_t iv[13] = { 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2 };
	const uint8_t aad[4] = { 0, 1, 2, 3 };

	psa_status_t ret = PSA_ERROR_GENERIC_ERROR;
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;

	ret = kb->generate_key(EDHOC_KT_ENCRYPT, key, ARRAY_SIZE(key), &kid);
	assert(EDHOC_SUCCESS == ret);

	uint8_t ptxt[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	size_t ctxt_len = 0;
	uint8_t ctxt[50] = { 0 };

	ret = cb->encrypt(&kid, iv, ARRAY_SIZE(iv), aad, ARRAY_SIZE(aad), ptxt,
			  ARRAY_SIZE(ptxt), ctxt, ARRAY_SIZE(ctxt), &ctxt_len);
	assert(EDHOC_SUCCESS == ret);

	ret = kb->destroy_key(&kid);
	assert(EDHOC_SUCCESS == ret);

	print_array("plaintext", ptxt, ARRAY_SIZE(ptxt));
	print_array("ciphertext", ctxt, ctxt_len);

	ret = kb->generate_key(EDHOC_KT_DECRYPT, key, ARRAY_SIZE(key), &kid);
	assert(EDHOC_SUCCESS == ret);

	size_t decrypted_ciphertext_length = 0;
	uint8_t decrypted_ciphertext[20] = { 0 };

	ret = cb->decrypt(&kid, iv, ARRAY_SIZE(iv), aad, ARRAY_SIZE(aad), ctxt,
			  ctxt_len, decrypted_ciphertext,
			  ARRAY_SIZE(decrypted_ciphertext),
			  &decrypted_ciphertext_length);
	assert(EDHOC_SUCCESS == ret);
	print_array("decrypted ciphertext", decrypted_ciphertext,
		    decrypted_ciphertext_length);

	assert(decrypted_ciphertext_length == ARRAY_SIZE(ptxt));
	assert(0 == memcmp(ptxt, decrypted_ciphertext, ARRAY_SIZE(ptxt)));

	ret = kb->destroy_key(&kid);
	assert(EDHOC_SUCCESS == ret);

	printf("\nencrypt & decrypt successfully\n");
}

void test_mbedtls_crypto_ecdsa(void)
{
	const struct edhoc_keys *kb = &keys;
	const struct edhoc_crypto *cb = &crypto;

	uint8_t priv_key[ARRAY_SIZE(test_vector_1_sk_i_raw)] = { 0 };
	memcpy(priv_key, test_vector_1_sk_i_raw, ARRAY_SIZE(priv_key));

	uint8_t pub_key[ARRAY_SIZE(test_vector_1_pk_i_raw)] = { 0 };
	memcpy(pub_key, test_vector_1_pk_i_raw, ARRAY_SIZE(pub_key));

	psa_status_t ret = PSA_ERROR_GENERIC_ERROR;
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;

	ret = kb->generate_key(EDHOC_KT_SIGN, priv_key, ARRAY_SIZE(priv_key),
			       &kid);
	assert(EDHOC_SUCCESS == ret);

	uint8_t message[] = { 0, 1, 2,	3,  4,	5,  6,	7,
			      8, 9, 10, 11, 12, 13, 14, 15 };

	print_array("message", message, ARRAY_SIZE(message));

	size_t sign_len = 0;
	uint8_t sign[64] = { 0 };

	ret = cb->sign(&kid, message, ARRAY_SIZE(message), sign,
		       ARRAY_SIZE(sign), &sign_len);
	assert(EDHOC_SUCCESS == ret);

	print_array("signature", sign, sign_len);

	ret = kb->destroy_key(&kid);
	assert(EDHOC_SUCCESS == ret);

	ret = kb->generate_key(EDHOC_KT_VERIFY, pub_key, ARRAY_SIZE(pub_key),
			       &kid);
	assert(EDHOC_SUCCESS == ret);

	ret = cb->verify(&kid, message, ARRAY_SIZE(message), sign, sign_len);
	assert(EDHOC_SUCCESS == ret);

	ret = kb->destroy_key(&kid);
	assert(EDHOC_SUCCESS == ret);

	printf("\nverified successfully\n");
}

void test_mbedtls_crypto_ecdh(void)
{
	const struct edhoc_keys *kb = &keys;
	const struct edhoc_crypto *cb = &crypto;

	psa_status_t ret = PSA_ERROR_GENERIC_ERROR;
	psa_key_id_t key_identifier_a = PSA_KEY_HANDLE_INIT;
	psa_key_id_t key_identifier_b = PSA_KEY_HANDLE_INIT;

	/* Peer A */
	ret = kb->generate_key(EDHOC_KT_MAKE_KEY_PAIR, NULL, 0,
			       &key_identifier_a);
	assert(EDHOC_SUCCESS == ret);

	uint8_t private_key_a[32] = { 0 };
	size_t private_key_length_a = 0;

	uint8_t public_key_a[32] = { 0 };
	size_t public_key_length_a = 0;

	ret = cb->make_key_pair(&key_identifier_a, private_key_a,
				ARRAY_SIZE(private_key_a),
				&private_key_length_a, public_key_a,
				ARRAY_SIZE(public_key_a), &public_key_length_a);
	assert(EDHOC_SUCCESS == ret);

	ret = kb->destroy_key(&key_identifier_a);
	assert(EDHOC_SUCCESS == ret);

	print_array("Peer A private key", private_key_a, private_key_length_a);
	print_array("Peer A public key", public_key_a, public_key_length_a);

	/* Peer B */
	ret = kb->generate_key(EDHOC_KT_MAKE_KEY_PAIR, NULL, 0,
			       &key_identifier_b);
	assert(EDHOC_SUCCESS == ret);

	uint8_t private_key_b[32] = { 0 };
	size_t private_key_length_b = 0;

	uint8_t public_key_b[32] = { 0 };
	size_t public_key_length_b = 0;

	ret = cb->make_key_pair(&key_identifier_b, private_key_b,
				ARRAY_SIZE(private_key_b),
				&private_key_length_b, public_key_b,
				ARRAY_SIZE(public_key_b), &public_key_length_b);
	assert(EDHOC_SUCCESS == ret);

	ret = kb->destroy_key(&key_identifier_b);
	assert(EDHOC_SUCCESS == ret);

	print_array("Peer B private key", private_key_b, private_key_length_b);
	print_array("Peer B public key", public_key_b, public_key_length_b);

	/* Shared secret for Peer A */
	ret = kb->generate_key(EDHOC_KT_KEY_AGREEMENT, private_key_a,
			       private_key_length_a, &key_identifier_a);
	assert(EDHOC_SUCCESS == ret);

	uint8_t shared_secret_a[32] = { 0 };
	size_t shared_secret_length_a = 0;

	ret = cb->key_agreement(&key_identifier_a, public_key_b,
				public_key_length_b, shared_secret_a,
				ARRAY_SIZE(shared_secret_a),
				&shared_secret_length_a);
	assert(EDHOC_SUCCESS == ret);

	ret = kb->destroy_key(&key_identifier_a);
	assert(EDHOC_SUCCESS == ret);

	print_array("Peer A shared secret", shared_secret_a,
		    shared_secret_length_a);

	/* Shared secret for Peer B */
	ret = kb->generate_key(EDHOC_KT_KEY_AGREEMENT, private_key_b,
			       private_key_length_b, &key_identifier_b);
	assert(EDHOC_SUCCESS == ret);

	uint8_t shared_secret_b[32] = { 0 };
	size_t shared_secret_length_b = 0;

	ret = cb->key_agreement(&key_identifier_b, public_key_a,
				public_key_length_a, shared_secret_b,
				ARRAY_SIZE(shared_secret_b),
				&shared_secret_length_b);
	assert(EDHOC_SUCCESS == ret);

	ret = kb->destroy_key(&key_identifier_b);
	assert(PSA_SUCCESS == ret);

	print_array("Peer B shared secret", shared_secret_b,
		    shared_secret_length_b);

	assert(private_key_length_a == private_key_length_b);
	assert(0 != memcmp(private_key_a, private_key_b, private_key_length_a));

	assert(public_key_length_a == public_key_length_b);
	assert(0 != memcmp(public_key_a, public_key_b, public_key_length_a));

	assert(shared_secret_length_a == shared_secret_length_b);
	assert(0 == memcmp(shared_secret_a, shared_secret_b,
			   shared_secret_length_a));

	printf("\nestablished shared key successfully\n");
}

void test_mbedtls_crypto_hkdf(void)
{
	const struct edhoc_keys *kb = &keys;
	const struct edhoc_crypto *cb = &crypto;

	psa_status_t ret = PSA_ERROR_GENERIC_ERROR;
	psa_key_id_t kid = PSA_KEY_HANDLE_INIT;

	/* HKDF extract part: */

	uint8_t salt[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			   0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
	print_array("HKDF extract salt", salt, ARRAY_SIZE(salt));

	uint8_t ikm[] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
	print_array("HKDF extract IKM", ikm, ARRAY_SIZE(ikm));

	ret = kb->generate_key(EDHOC_KT_EXTRACT, ikm, ARRAY_SIZE(ikm), &kid);
	assert(EDHOC_SUCCESS == ret);

	size_t prk_len = 0;
	uint8_t prk[32] = { 0 };
	const uint8_t exp_prk[32] = { 0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32,
				      0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
				      0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5,
				      0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
				      0xd7, 0xc2, 0xb3, 0xe5 };

	ret = cb->extract(&kid, salt, ARRAY_SIZE(salt), prk, ARRAY_SIZE(prk),
			  &prk_len);
	assert(EDHOC_SUCCESS == ret);

	ret = kb->destroy_key(&kid);
	assert(EDHOC_SUCCESS == ret);

	print_array("HKDF extract PRK", prk, prk_len);

	assert(prk_len == ARRAY_SIZE(exp_prk));
	assert(0 == memcmp(prk, exp_prk, prk_len));

	/* HKDF expand part: */

	print_array("HKDF expand PRK", prk, prk_len);

	ret = kb->generate_key(EDHOC_KT_EXPAND, prk, ARRAY_SIZE(prk), &kid);
	assert(EDHOC_SUCCESS == ret);

	uint8_t info[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
			   0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };

	print_array("HKDF expand info", info, ARRAY_SIZE(info));

	uint8_t okm[42] = { 0 };
	uint8_t exp_okm[ARRAY_SIZE(okm)] = {
		0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90,
		0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d,
		0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d,
		0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
		0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
	};

	ret = cb->expand(&kid, info, ARRAY_SIZE(info), okm, ARRAY_SIZE(okm));
	assert(EDHOC_SUCCESS == ret);
	assert(0 == memcmp(exp_okm, okm, ARRAY_SIZE(okm)));

	ret = kb->destroy_key(&kid);
	assert(EDHOC_SUCCESS == ret);

	print_array("HKDF expand OKM", okm, ARRAY_SIZE(okm));

	printf("\nHKDF's successfully\n");
}

void test_mbedtls_crypto_hash(void)
{
	const struct edhoc_crypto *cb = &crypto;

	const uint8_t input[] = { 'A' };
	size_t hash_length = 0;
	uint8_t hash[32] = { 0 };

	const psa_status_t ret = cb->hash(input, ARRAY_SIZE(input), hash,
					  ARRAY_SIZE(hash), &hash_length);
	assert(EDHOC_SUCCESS == ret);
	assert(ARRAY_SIZE(hash) == hash_length);

	print_array("input for hash:", (uint8_t *)input, ARRAY_SIZE(input));
	print_array("SHA-256 hash:", hash, ARRAY_SIZE(hash));

	const uint8_t expected_hash[32] = {
		0x55, 0x9a, 0xea, 0xd0, 0x82, 0x64, 0xd5, 0x79,
		0x5d, 0x39, 0x09, 0x71, 0x8c, 0xdd, 0x05, 0xab,
		0xd4, 0x95, 0x72, 0xe8, 0x4f, 0xe5, 0x55, 0x90,
		0xee, 0xf3, 0x1a, 0x88, 0xa0, 0x8f, 0xdf, 0xfd,
	};

	assert(0 == memcmp(hash, expected_hash, ARRAY_SIZE(expected_hash)));

	printf("\nHASH successfully\n");
}