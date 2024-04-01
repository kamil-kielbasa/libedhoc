/**
 * \file    edhoc_crypto.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC cryptographic interface.
 * \version 0.1
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CRYPTO_H
#define EDHOC_CRYPTO_H

/* Include files ----------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/**
 * \brief Structure for cipher suite value and related algorithms lengths in bytes.
 */
struct edhoc_cipher_suite {
	/* IANA registery value. */
	int32_t value;

	/* EDHOC AEAD algorithm: key & tag & IV lengths in bytes. */
	size_t aead_key_len;
	size_t aead_tag_len;
	size_t aead_iv_len;

	/* EDHOC hash algorithm: hash length in bytes. */
	size_t hash_len;

	/* EDHOC MAC length in bytes. */
	size_t mac_len;

	/* EDHOC ECC algorithm: key & sign lengths in bytes. */
	size_t ecc_key_len;
	size_t ecc_sign_len;
};

/**
 * \brief Key types used in EDHOC.
 */
enum edhoc_key_type {
	EDHOC_KT_MAKE_KEY_PAIR,
	EDHOC_KT_KEY_AGREEMENT,

	EDHOC_KT_SIGN,
	EDHOC_KT_VERIFY,

	EDHOC_KT_EXTRACT,
	EDHOC_KT_EXPAND,

	EDHOC_KT_ENCRYPT,
	EDHOC_KT_DECRYPT,
};

/**
 * \brief Cryptographic key identifier generation.
 *
 * \param key_type              Requested key type.
 * \param[in] raw_key           Key material in binary format.
 * \param raw_key_len           Size of the \p raw_key buffer in bytes.
 * \param[out] key_id           Key identifier.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_generate_key_t)(enum edhoc_key_type key_type,
				    const uint8_t *raw_key, size_t raw_key_len,
				    void *key_id);

/**
 * \brief Cryptographic key identifier destroying.
 *
 * \param[in] key_id            Key identifier.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_destory_key_t)(void *key_id);

/**
 * \brief Structure for cryptographic key identifiers.
 */
struct edhoc_keys {
	edhoc_generate_key_t generate_key;
	edhoc_destory_key_t destroy_key;
};

/**
 * \brief Cryptographic function for generating ECDH key pair.
 *
 * \param[in] key_id            Key identifier.
 * \param[out] priv_key         Private ECDH key.
 * \param priv_key_size         Size of the \p priv_key buffer in bytes.
 * \param[out] priv_key_len     On success, the number of bytes that make up the ECDH private key.
 * \param[out] pub_key          Public ECDH key.
 * \param pub_key_size          Size of the \p pub_key buffer in bytes.
 * \param[out] pub_key_len      On success, the number of bytes that make up the ECDH private key.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_make_key_pair_t)(const void *key_id, uint8_t *priv_key,
				     size_t priv_key_size, size_t *priv_key_len,
				     uint8_t *pub_key, size_t pub_key_size,
				     size_t *pub_key_len);

/**
 * \brief Cryptographic function for computing ECDH shared secret.
 *
 * \param[in] key_id            Key identifier.
 * \param[in] peer_key          Private ECDH key.
 * \param peer_key_len          Size of the \p peer_key buffer in bytes.
 * \param[out] shr_sec          ECDH shared secret.
 * \param shr_sec_size          Size of the \p shr_sec buffer in bytes.
 * \param[out] shr_sec_len      On success, the number of bytes that make up the ECDH shared secret.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_key_agreement_t)(const void *key_id,
				     const uint8_t *peer_key,
				     size_t peer_key_len, uint8_t *shr_sec,
				     size_t shr_sec_size, size_t *shr_sec_len);

/**
 * \brief Cryptographic function for generating ECDSA sign.
 *
 * \param[in] key_id            Key identifier.
 * \param[in] input             Input message to sign.
 * \param input_len             Size of the \p input buffer in bytes.
 * \param[out] sign             Buffer where the sign is to be written.
 * \param sign_size             Size of the \p sign buffer in bytes.
 * \param[out] sign_len         On success, the number of bytes that make up the sign.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_sign_t)(const void *key_id, const uint8_t *input,
			    size_t input_len, uint8_t *sign, size_t sign_size,
			    size_t *sign_len);

/**
 * \brief Cryptographic function for ECDSA sign verification.
 *
 * \param[in] key_id            Key identifier.
 * \param[in] input             Input message to verify.
 * \param input_len             Size of the \p input buffer in bytes.
 * \param[in] sign              Buffer where the signature is to be written.
 * \param sign_size             Size of the \p sign buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_verify_t)(const void *key_id, const uint8_t *input,
			      size_t input_len, const uint8_t *sign,
			      size_t sign_len);

/**
 * \brief Cryptographic function for HKDF extracting.
 *
 * \param[in] key_id            Key identifier.
 * \param[in] salt              Salt for extract.
 * \param salt_len              Size of the \p salt buffer in bytes.
 * \param[out] prk              Buffer where the psuedo random key is to be written.
 * \param prk_size              Size of the \p prk buffer in bytes.
 * \param[out] prk_len          On success, the number of bytes that make up the psuedo random key.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_extract_t)(const void *key_id, const uint8_t *salt,
			       size_t salt_len, uint8_t *prk, size_t prk_size,
			       size_t *prk_len);

/**
 * \brief Cryptographic function for HKDF expanding.
 *
 * \param[in] key_id            Key identifier.
 * \param[in] info              Information context.
 * \param info_len              Size of the \p info buffer in bytes.
 * \param[out] okm              Buffer where the output keying material is to be written.
 * \param okm_len               Size of the \p okm buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_expand_t)(const void *key_id, const uint8_t *info,
			      size_t info_len, uint8_t *okm, size_t okm_len);

/**
 * \brief Cryptographic function for AEAD encryption.
 *
 * \param[in] key_id            Key identifier.
 * \param[in] nonce             Nonce or IV to use.
 * \param nonce_len             Size of the \p nonce buffer in bytes.
 * \param[in] ad                Additional data that will be authenticated but not encrypted.
 * \param ad_len                Size of the \p ad buffer in bytes.
 * \param[in] ptxt              Data that will be authenticated and encrypted.
 * \param ptxt_len              Size of the \p ptxt buffer in bytes.
 * \param[out] ctxt             Buffer where the authenticated and encrypted data is to be written.
 * \param ctxt_size             Size of the \p ctxt buffer in bytes.
 * \param[out] ctxt_len         On success, the number of bytes that make up the ciphertext.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_encrypt_t)(const void *key_id, const uint8_t *nonce,
			       size_t nonce_len, const uint8_t *ad,
			       size_t ad_len, const uint8_t *ptxt,
			       size_t ptxt_len, uint8_t *ctxt, size_t ctxt_size,
			       size_t *ctxt_len);

/**
 * \brief Cryptographic function for AEAD decryption.
 *
 * \param[in] key_id            Key identifier.
 * \param[in] nonce             Nonce or IV to use.
 * \param nonce_len             Size of the \p nonce buffer in bytes.
 * \param[in] ad                Additional data that will be authenticated but not encrypted.
 * \param ad_len                Size of the \p ad buffer in bytes.
 * \param[in] ctxt              Buffer where the data that has been authenticated and encrypted.
 * \param ctxt_len              Size of the \p ctxt buffer in bytes.
 * \param[out] ptxt             Buffer where the decrypted data is to be written.
 * \param ptxt_size             Size of the \p ptxt buffer in bytes.
 * \param[out] ptxt_len         On success, the number of bytes that make up the plaintext.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_decrypt_t)(const void *key_id, const uint8_t *nonce,
			       size_t nonce_len, const uint8_t *ad,
			       size_t ad_len, const uint8_t *ctxt,
			       size_t ctxt_len, uint8_t *ptxt, size_t ptxt_size,
			       size_t *ptxt_len);

/**
 * \brief Cryptographic function for hash computing.
 *
 * \param[in] input             Input message to hash.
 * \param input_len             Size of the \p input buffer in bytes.
 * \param[in] hash              Buffer where the hash is to be written.
 * \param hash_size             Size of the \p hash buffer in bytes.
 * \param[out] hash_len         On success, the number of bytes that make up the hash.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_hash_t)(const uint8_t *input, size_t input_len,
			    uint8_t *hash, size_t hash_size, size_t *hash_len);

/**
 * \brief Structure for cryptographics operations.
 */
struct edhoc_crypto {
	edhoc_make_key_pair_t make_key_pair;
	edhoc_key_agreement_t key_agreement;

	edhoc_sign_t sign;
	edhoc_verify_t verify;

	edhoc_extract_t extract;
	edhoc_expand_t expand;

	edhoc_encrypt_t encrypt;
	edhoc_decrypt_t decrypt;

	edhoc_hash_t hash;
};

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_CRYPTO_H */