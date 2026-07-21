/**
 * \file    edhoc_cipher_suite_24.c
 * \author  Kamil Kielbasa
 * \brief   Implementation of cipher suite 24
 *          (P-384 / ES384 / A256GCM / SHA-384).
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Include files ----------------------------------------------------------- */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif /* __ZEPHYR__ */

/* Internal test header: */
#include "edhoc_cipher_suite_24.h"

/* Standard library header: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* EDHOC headers: */
#include <edhoc/crypto.h>
#include <edhoc/values.h>
#include "edhoc_macros_internal.h"
#include "edhoc_backend_log.h"

/* PSA crypto header: */
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#include <psa/crypto.h>

/* mbedTLS low-level ECP/bignum (P-384 peer-point decompression): */
#include <mbedtls/private/ecp.h>

/* Threading primitive serializing the multipart hash operation pool: */
#ifdef __ZEPHYR__
#include <zephyr/kernel.h>
#else /* __ZEPHYR__ */
#include <pthread.h>
#endif /* __ZEPHYR__ */

/* Module defines ---------------------------------------------------------- */

#define EDHOC_CIPHER_SUITE_24_VALUE (24)

#define EDHOC_CIPHER_SUITE_24_ECC_COMP_KEY_LEN (48)
#define EDHOC_CIPHER_SUITE_24_ECC_UNCOMP_KEY_LEN (97)

#define EDHOC_CIPHER_SUITE_24_ECC_ECDSA_SIGN_LEN (96)
#define EDHOC_CIPHER_SUITE_24_ECC_ECDH_SHARED_SECRET_LEN (48)

#define EDHOC_CIPHER_SUITE_24_HASH_LEN (48)
#define EDHOC_CIPHER_SUITE_24_HASH_ALG (PSA_ALG_SHA_384)
#define EDHOC_CIPHER_SUITE_24_MAC_LEN (16)

#define EDHOC_CIPHER_SUITE_24_AEAD_KEY_LEN (32)
#define EDHOC_CIPHER_SUITE_24_AEAD_TAG_LEN (16)
#define EDHOC_CIPHER_SUITE_24_AEAD_IV_LEN (12)

#define EDHOC_CIPHER_SUITE_24_KDF_HASH_ALG (PSA_ALG_SHA_384)

#define EDHOC_CIPHER_SUITE_24_HASH_OP_POOL_SIZE (4)

/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static variables and constants ------------------------------------------ */

#ifdef __ZEPHYR__
K_MUTEX_DEFINE(edhoc_mutex);
#else /* __ZEPHYR__ */
static pthread_mutex_t edhoc_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif /* __ZEPHYR__ */

static psa_hash_operation_t
	hash_op_pool[EDHOC_CIPHER_SUITE_24_HASH_OP_POOL_SIZE];
static bool hash_op_in_use[EDHOC_CIPHER_SUITE_24_HASH_OP_POOL_SIZE];

/* Static function declarations -------------------------------------------- */

/** \brief Elliptic curve point decompression. */
static int mbedtls_ecp_decompress(const mbedtls_ecp_group *grp,
				  const uint8_t *raw_key, size_t raw_key_len,
				  uint8_t *decomp_key, size_t decomp_key_size,
				  size_t *decomp_key_len);

/** \brief Set attributes for a DERIVE key (shared secret or pseudorandom key). */
static void set_derive_key_attributes(psa_key_attributes_t *attr);

/** \brief Set attributes for an ephemeral P-384 ECDH key pair. */
static void set_ecdh_keypair_attributes(psa_key_attributes_t *attr);

/** \brief Export a P-384 public key as its 48-byte X coordinate (G_X / G_Y). */
static int export_public_key_x(psa_key_id_t key, uint8_t *out, size_t out_size,
			       size_t *out_length);

/** \brief Destroy a volatile key handle, logging on failure (best effort). */
static void destroy_volatile_key(psa_key_id_t key);

/** \brief Load a PSA key handle from a (possibly unaligned) key-store slot. */
static inline psa_key_id_t load_key_id(const void *key_id);

/** \brief Store a PSA key handle into a (possibly unaligned) key-store slot. */
static inline void store_key_id(void *key_id, psa_key_id_t kid);

/** \brief ECDH key agreement storing the shared secret as a DERIVE key handle. */
static int compute_shared_secret(psa_key_id_t private_key,
				 const uint8_t *peer_public_key,
				 size_t peer_public_key_length,
				 void *shared_secret_key_id);

/** \brief Destroy a key handle (\ref edhoc_crypto.destroy_key). */
static int destroy_key(void *user_context, void *key_id);

/** \brief Generate an ephemeral key pair (\ref edhoc_crypto.generate_key_pair). */
static int generate_key_pair(void *user_context, void *decapsulation_key_id,
			     uint8_t *encapsulation_key,
			     size_t encapsulation_key_size,
			     size_t *encapsulation_key_length);

/** \brief Encapsulate to a peer key (\ref edhoc_crypto.encapsulate). */
static int encapsulate(void *user_context, const uint8_t *encapsulation_key,
		       size_t encapsulation_key_length,
		       void *decapsulation_key_id, void *shared_secret_key_id,
		       uint8_t *ciphertext, size_t ciphertext_size,
		       size_t *ciphertext_length);

/** \brief Decapsulate a ciphertext (\ref edhoc_crypto.decapsulate). */
static int decapsulate(void *user_context, const void *decapsulation_key_id,
		       const uint8_t *ciphertext, size_t ciphertext_length,
		       void *shared_secret_key_id);

/** \brief Static Diffie-Hellman key agreement (\ref edhoc_crypto.key_agreement). */
static int key_agreement(void *user_context, const void *private_key_id,
			 const uint8_t *peer_public_key,
			 size_t peer_public_key_length,
			 void *shared_secret_key_id);

/** \brief Generate an ES384 signature (\ref edhoc_crypto.sign). */
static int sign(void *user_context, const void *private_key_id,
		const uint8_t *input, size_t input_length, uint8_t *signature,
		size_t signature_size, size_t *signature_length);

/** \brief Verify an ES384 signature (\ref edhoc_crypto.verify). */
static int verify(void *user_context, const uint8_t *public_key,
		  size_t public_key_length, const uint8_t *input,
		  size_t input_length, const uint8_t *signature,
		  size_t signature_length);

/** \brief EDHOC_Extract to a pseudorandom key handle (\ref edhoc_crypto.extract). */
static int extract(void *user_context, const void *ikm_key_id,
		   const uint8_t *salt, size_t salt_length, void *prk_key_id);

/** \brief EDHOC_Expand to a key handle (\ref edhoc_crypto.expand). */
static int expand(void *user_context, const void *prk_key_id,
		  const uint8_t *info, size_t info_length,
		  enum edhoc_key_usage usage, void *output_key_id);

/** \brief EDHOC_Expand to raw output (\ref edhoc_crypto.expand_raw). */
static int expand_raw(void *user_context, const void *prk_key_id,
		      const uint8_t *info, size_t info_length, uint8_t *output,
		      size_t output_length);

/** \brief AEAD encryption (\ref edhoc_crypto.aead_encrypt). */
static int aead_encrypt(void *user_context, const void *key_id,
			const uint8_t *nonce, size_t nonce_length,
			const uint8_t *additional_data,
			size_t additional_data_length, const uint8_t *plaintext,
			size_t plaintext_length, uint8_t *ciphertext,
			size_t ciphertext_size, size_t *ciphertext_length);

/** \brief AEAD decryption (\ref edhoc_crypto.aead_decrypt). */
static int aead_decrypt(void *user_context, const void *key_id,
			const uint8_t *nonce, size_t nonce_length,
			const uint8_t *additional_data,
			size_t additional_data_length,
			const uint8_t *ciphertext, size_t ciphertext_length,
			uint8_t *plaintext, size_t plaintext_size,
			size_t *plaintext_length);

/** \brief Lock the hash operation pool mutex (blocking). */
static int edhoc_mutex_lock(void);

/** \brief Unlock the hash operation pool mutex. */
static int edhoc_mutex_unlock(void);

/** \brief Reserve and set up a pool slot for a multipart hash operation. */
static int allocate_hash_slot(void **operation);

/** \brief Release the pool slot backing a multipart hash operation. */
static void release_hash_slot(const void *operation);

/** \brief Begin a multipart hash operation (\ref crypto.hash_init). */
static int hash_init(void *user_context, void **operation);

/** \brief Add input to a multipart hash (\ref crypto.hash_update). */
static int hash_update(void *user_context, void *operation,
		       const uint8_t *input, size_t input_length);

/** \brief Finish a multipart hash (\ref crypto.hash_finish). */
static int hash_finish(void *user_context, void *operation, uint8_t *hash,
		       size_t hash_size, size_t *hash_length);

/** \brief Abort a multipart hash (\ref crypto.hash_abort). */
static int hash_abort(void *user_context, void *operation);

/* Static function definitions --------------------------------------------- */

static int mbedtls_ecp_decompress(const mbedtls_ecp_group *grp,
				  const uint8_t *raw_key, size_t raw_key_len,
				  uint8_t *decomp_key, size_t decomp_key_size,
				  size_t *decomp_key_len)
{
	EDHOC_ASSERT(NULL != grp);
	EDHOC_ASSERT(NULL != raw_key);
	EDHOC_ASSERT(0 != raw_key_len);
	EDHOC_ASSERT(NULL != decomp_key);
	EDHOC_ASSERT(0 != decomp_key_size);
	EDHOC_ASSERT(NULL != decomp_key_len);

	int ret = 0;

	const size_t p_len = mbedtls_mpi_size(&grp->P);

	*decomp_key_len = (2 * p_len) + 1;

	if (decomp_key_size < *decomp_key_len) {
		EDHOC_LOG_ERR("Decompressed key buffer too small: %zu",
			      decomp_key_size);
		return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
	}

	/* Defensive bounds check. Unreachable via the public API. */
	/* LCOV_EXCL_START */
	if (raw_key_len > p_len) {
		EDHOC_LOG_ERR("Raw key length exceeds field size: %zu",
			      raw_key_len);
		return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
	}
	/* LCOV_EXCL_STOP */

	/* decomp_key will consist of 0x04|X|Y */
	(void)memcpy(&decomp_key[1], raw_key, raw_key_len);
	decomp_key[0] = 0x04;

	mbedtls_mpi r = { 0 };
	mbedtls_mpi x = { 0 };
	mbedtls_mpi n = { 0 };

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&x);
	mbedtls_mpi_init(&n);

	/* MBEDTLS_MPI_CHK() assigns to 'ret' inside an 'if'; this is the intended
	 * mbedtls idiom, so suppress bugprone-assignment-in-if-condition here. */
	// NOLINTBEGIN(bugprone-assignment-in-if-condition)

	/* x <= raw_key */
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&x, raw_key, p_len));

	/* r = x^2 */
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &x, &x));

	/* r = x^2 + ad */
	if (NULL == grp->A.MBEDTLS_PRIVATE(p)) {
		// Special case where ad is -3
		MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&r, &r, 3));
	} else {
		MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &grp->A));
	}

	/* r = x^3 + ax */
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &r, &x));

	/* r = x^3 + ax + b */
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &grp->B));

	/* 
	 * Calculate square root of r over finite field P:
	 *   r = sqrt(x^3 + ax + b) = (x^3 + ax + b) ^ ((P + 1) / 4) (mod P)
	 */

	/* n = P + 1 */
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&n, &grp->P, 1));

	/* n = (P + 1) / 4 */
	MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&n, 2));

	/* r ^ ((P + 1) / 4) (mod p) */
	MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&r, &r, &n, &grp->P, NULL));

	/* Select solution that has the correct "sign" (equals odd/even solution in finite group) */
	if ((raw_key[0] == 0x03) != mbedtls_mpi_get_bit(&r, 0)) {
		/* r = p - r */
		MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&r, &grp->P, &r));
	}

	// NOLINTEND(bugprone-assignment-in-if-condition)

	/* y => decomp_key */
	ret = mbedtls_mpi_write_binary(&r, decomp_key + 1 + p_len, p_len);

// cppcheck-suppress unusedLabel
cleanup:
	if (0 != ret) {
		EDHOC_LOG_ERR("Elliptic curve point decompression: %d", ret);
	}

	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&x);
	mbedtls_mpi_free(&n);

	return (ret);
}

static void set_derive_key_attributes(psa_key_attributes_t *attr)
{
	EDHOC_ASSERT(NULL != attr);

	psa_set_key_lifetime(attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(attr, PSA_KEY_TYPE_DERIVE);
	psa_set_key_usage_flags(attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(
		attr, PSA_ALG_HKDF_EXPAND(EDHOC_CIPHER_SUITE_24_KDF_HASH_ALG));
	psa_set_key_enrollment_algorithm(
		attr, PSA_ALG_HKDF_EXTRACT(EDHOC_CIPHER_SUITE_24_KDF_HASH_ALG));
}

static void set_ecdh_keypair_attributes(psa_key_attributes_t *attr)
{
	EDHOC_ASSERT(NULL != attr);

	psa_set_key_lifetime(attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(attr, PSA_ALG_ECDH);
	psa_set_key_type(attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(attr, (size_t)PSA_BYTES_TO_BITS(
				       EDHOC_CIPHER_SUITE_24_ECC_COMP_KEY_LEN));
}

static int export_public_key_x(psa_key_id_t key, uint8_t *out, size_t out_size,
			       size_t *out_len)
{
	EDHOC_ASSERT(PSA_KEY_ID_NULL != key);
	EDHOC_ASSERT(NULL != out);
	EDHOC_ASSERT(0 != out_size);
	EDHOC_ASSERT(NULL != out_len);

	if (out_size < EDHOC_CIPHER_SUITE_24_ECC_COMP_KEY_LEN) {
		EDHOC_LOG_ERR("Public key buffer too small: %zu", out_size);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	uint8_t uncomp[EDHOC_CIPHER_SUITE_24_ECC_UNCOMP_KEY_LEN] = { 0 };
	size_t uncomp_len = 0;

	const psa_status_t status = psa_export_public_key(
		key, uncomp, ARRAY_SIZE(uncomp), &uncomp_len);

	if (PSA_SUCCESS != status ||
	    EDHOC_CIPHER_SUITE_24_ECC_UNCOMP_KEY_LEN != uncomp_len) {
		EDHOC_LOG_ERR("Export public key: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* Uncompressed point is 0x04 | X | Y; EDHOC transports X only. */
	(void)memcpy(out, &uncomp[1], EDHOC_CIPHER_SUITE_24_ECC_COMP_KEY_LEN);
	*out_len = EDHOC_CIPHER_SUITE_24_ECC_COMP_KEY_LEN;

	return EDHOC_SUCCESS;
}

static void destroy_volatile_key(psa_key_id_t key)
{
	if (PSA_KEY_ID_NULL == key) {
		return;
	}

	const psa_status_t status = psa_destroy_key(key);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("Destroy key: %d", status);
	}
}

static inline psa_key_id_t load_key_id(const void *key_id)
{
	psa_key_id_t kid = PSA_KEY_ID_NULL;
	memcpy(&kid, key_id, sizeof(kid));
	return kid;
}

static inline void store_key_id(void *key_id, psa_key_id_t kid)
{
	memcpy(key_id, &kid, sizeof(kid));
}

static int compute_shared_secret(psa_key_id_t priv_key,
				 const uint8_t *peer_pub_key,
				 size_t peer_pub_key_len, void *shr_sec_key_id)
{
	EDHOC_ASSERT(PSA_KEY_ID_NULL != priv_key);
	EDHOC_ASSERT(NULL != peer_pub_key);
	EDHOC_ASSERT(0 != peer_pub_key_len);
	EDHOC_ASSERT(NULL != shr_sec_key_id);

	if (EDHOC_CIPHER_SUITE_24_ECC_COMP_KEY_LEN != peer_pub_key_len) {
		EDHOC_LOG_ERR("Invalid peer public key length: %zu",
			      peer_pub_key_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	psa_key_id_t psa_shared_secret = PSA_KEY_ID_NULL;
	int result = EDHOC_ERROR_CRYPTO_FAILURE;
	int ret = 0;
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

	uint8_t decomp_key[EDHOC_CIPHER_SUITE_24_ECC_UNCOMP_KEY_LEN] = { 0 };
	size_t decomp_key_len = 0;

	mbedtls_ecp_group grp;
	mbedtls_ecp_group_init(&grp);

	ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP384R1);

	if (0 != ret) {
		EDHOC_LOG_ERR("Load ECP group: %d", ret);
		goto exit;
	}

	ret = mbedtls_ecp_decompress(&grp, peer_pub_key, peer_pub_key_len,
				     decomp_key, ARRAY_SIZE(decomp_key),
				     &decomp_key_len);

	if (0 != ret) {
		EDHOC_LOG_ERR("Decompress public key: %d", ret);
		goto exit;
	}

	set_derive_key_attributes(&attr);
	psa_set_key_bits(
		&attr,
		(size_t)PSA_BYTES_TO_BITS(
			EDHOC_CIPHER_SUITE_24_ECC_ECDH_SHARED_SECRET_LEN));

	status = psa_key_agreement(priv_key, decomp_key, decomp_key_len,
				   PSA_ALG_ECDH, &attr, &psa_shared_secret);

	psa_reset_key_attributes(&attr);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("ECDH key agreement: %d", status);
		goto exit;
	}

	store_key_id(shr_sec_key_id, psa_shared_secret);
	result = EDHOC_SUCCESS;

exit:
	mbedtls_ecp_group_free(&grp);
	return result;
}

static int destroy_key(void *user_context, void *key_id)
{
	(void)user_context;

	if (NULL == key_id) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	psa_key_id_t psa_kid = load_key_id(key_id);

	/* Destroying a zeroed / no-key handle is a successful no-op. */
	if (PSA_KEY_ID_NULL == psa_kid) {
		return EDHOC_SUCCESS;
	}

	const psa_status_t status = psa_destroy_key(psa_kid);

	psa_kid = PSA_KEY_ID_NULL;

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("Destroy key: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int generate_key_pair(void *user_context, void *decaps_key_id,
			     uint8_t *encaps_key, size_t encaps_key_size,
			     size_t *encaps_key_len)
{
	(void)user_context;

	if (NULL == decaps_key_id || NULL == encaps_key ||
	    0 == encaps_key_size || NULL == encaps_key_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	set_ecdh_keypair_attributes(&attr);

	psa_key_id_t psa_ephemeral = PSA_KEY_ID_NULL;
	psa_status_t status = psa_generate_key(&attr, &psa_ephemeral);

	psa_reset_key_attributes(&attr);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("Generate key pair: %d", status);
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;
	}

	const int ret = export_public_key_x(psa_ephemeral, encaps_key,
					    encaps_key_size, encaps_key_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Export ephemeral public key: %d", ret);
		destroy_volatile_key(psa_ephemeral);
		return ret;
	}

	store_key_id(decaps_key_id, psa_ephemeral);
	return EDHOC_SUCCESS;
}

static int encapsulate(void *user_context, const uint8_t *encaps_key,
		       size_t encaps_key_len, void *decaps_key_id,
		       void *shr_sec_key_id, uint8_t *ciphertext,
		       size_t ciphertext_size, size_t *ciphertext_len)
{
	(void)user_context;

	if (NULL == encaps_key || 0 == encaps_key_len ||
	    NULL == decaps_key_id || NULL == shr_sec_key_id ||
	    NULL == ciphertext || 0 == ciphertext_size ||
	    NULL == ciphertext_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	/* NIKE-as-KEM: generate an ephemeral pair; its public key is G_Y and
	 * its private key is retained (decaps_key_id) for the static-DH G_IY
	 * agreement in message 3. */
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	set_ecdh_keypair_attributes(&attr);

	psa_key_id_t psa_ephemeral = PSA_KEY_ID_NULL;
	psa_status_t status = psa_generate_key(&attr, &psa_ephemeral);

	psa_reset_key_attributes(&attr);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("Generate ephemeral key pair: %d", status);
		return EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE;
	}

	int ret = export_public_key_x(psa_ephemeral, ciphertext,
				      ciphertext_size, ciphertext_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Export ephemeral public key: %d", ret);
		destroy_volatile_key(psa_ephemeral);
		return ret;
	}

	ret = compute_shared_secret(psa_ephemeral, encaps_key, encaps_key_len,
				    shr_sec_key_id);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Compute shared secret: %d", ret);
		destroy_volatile_key(psa_ephemeral);
		return ret;
	}

	store_key_id(decaps_key_id, psa_ephemeral);
	return EDHOC_SUCCESS;
}

static int decapsulate(void *user_context, const void *decaps_key_id,
		       const uint8_t *ciphertext, size_t ciphertext_len,
		       void *shr_sec_key_id)
{
	(void)user_context;

	if (NULL == decaps_key_id || NULL == ciphertext ||
	    0 == ciphertext_len || NULL == shr_sec_key_id) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_key_id_t psa_decaps = load_key_id(decaps_key_id);

	return compute_shared_secret(psa_decaps, ciphertext, ciphertext_len,
				     shr_sec_key_id);
}

static int key_agreement(void *user_context, const void *priv_key_id,
			 const uint8_t *peer_pub_key, size_t peer_pub_key_len,
			 void *shr_sec_key_id)
{
	(void)user_context;

	if (NULL == priv_key_id || NULL == peer_pub_key ||
	    0 == peer_pub_key_len || NULL == shr_sec_key_id) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_key_id_t psa_priv = load_key_id(priv_key_id);

	return compute_shared_secret(psa_priv, peer_pub_key, peer_pub_key_len,
				     shr_sec_key_id);
}

static int sign(void *user_context, const void *priv_key_id,
		const uint8_t *input, size_t input_len, uint8_t *sign,
		size_t sign_size, size_t *sign_len)
{
	(void)user_context;

	if (NULL == priv_key_id || NULL == input || 0 == input_len ||
	    NULL == sign || 0 == sign_size || NULL == sign_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_CIPHER_SUITE_24_ECC_ECDSA_SIGN_LEN != sign_size) {
		EDHOC_LOG_ERR("Invalid signature size: %zu", sign_size);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	const psa_key_id_t psa_priv = load_key_id(priv_key_id);

	uint8_t digest[PSA_HASH_LENGTH(EDHOC_CIPHER_SUITE_24_HASH_ALG)] = { 0 };
	size_t digest_len = 0;

	psa_status_t status = psa_hash_compute(EDHOC_CIPHER_SUITE_24_HASH_ALG,
					       input, input_len, digest,
					       ARRAY_SIZE(digest), &digest_len);

	if (PSA_SUCCESS != status ||
	    PSA_HASH_LENGTH(EDHOC_CIPHER_SUITE_24_HASH_ALG) != digest_len) {
		EDHOC_LOG_ERR("Hash input: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	status = psa_sign_hash(psa_priv,
			       PSA_ALG_ECDSA(EDHOC_CIPHER_SUITE_24_HASH_ALG),
			       digest, digest_len, sign, sign_size, sign_len);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("ECDSA signature: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	if (EDHOC_CIPHER_SUITE_24_ECC_ECDSA_SIGN_LEN != *sign_len) {
		EDHOC_LOG_ERR("Invalid signature length: %zu", *sign_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int verify(void *user_context, const uint8_t *pub_key,
		  size_t pub_key_len, const uint8_t *input, size_t input_len,
		  const uint8_t *sign, size_t sign_len)
{
	(void)user_context;

	if (NULL == pub_key || 0 == pub_key_len || NULL == input ||
	    0 == input_len || NULL == sign || 0 == sign_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_CIPHER_SUITE_24_ECC_ECDSA_SIGN_LEN != sign_len) {
		EDHOC_LOG_ERR("Invalid signature length: %zu", sign_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	uint8_t digest[PSA_HASH_LENGTH(EDHOC_CIPHER_SUITE_24_HASH_ALG)] = { 0 };
	size_t digest_len = 0;

	psa_status_t status = psa_hash_compute(EDHOC_CIPHER_SUITE_24_HASH_ALG,
					       input, input_len, digest,
					       ARRAY_SIZE(digest), &digest_len);
	if (PSA_SUCCESS != status ||
	    PSA_HASH_LENGTH(EDHOC_CIPHER_SUITE_24_HASH_ALG) != digest_len) {
		EDHOC_LOG_ERR("Hash input: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	/* Peer public key arrives as raw bytes; import it transiently. */
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&attr,
			      PSA_ALG_ECDSA(EDHOC_CIPHER_SUITE_24_HASH_ALG));
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

	psa_key_id_t psa_pub = PSA_KEY_ID_NULL;
	status = psa_import_key(&attr, pub_key, pub_key_len, &psa_pub);

	psa_reset_key_attributes(&attr);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("Import public key: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	status = psa_verify_hash(psa_pub,
				 PSA_ALG_ECDSA(EDHOC_CIPHER_SUITE_24_HASH_ALG),
				 digest, digest_len, sign, sign_len);

	destroy_volatile_key(psa_pub);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("ECDSA verify: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int extract(void *user_context, const void *ikm_key_id,
		   const uint8_t *salt, size_t salt_len, void *prk_key_id)
{
	(void)user_context;

	if (NULL == ikm_key_id || NULL == salt || 0 == salt_len ||
	    NULL == prk_key_id) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_key_id_t psa_ikm = load_key_id(ikm_key_id);
	psa_key_id_t psa_prk = PSA_KEY_ID_NULL;

	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

	psa_status_t status = psa_key_derivation_setup(
		&op, PSA_ALG_HKDF_EXTRACT(EDHOC_CIPHER_SUITE_24_KDF_HASH_ALG));

	if (PSA_SUCCESS != status) {
		goto psa_error;
	}

	status = psa_key_derivation_input_bytes(
		&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len);

	if (PSA_SUCCESS != status) {
		goto psa_error;
	}

	status = psa_key_derivation_input_key(
		&op, PSA_KEY_DERIVATION_INPUT_SECRET, psa_ikm);

	if (PSA_SUCCESS != status) {
		goto psa_error;
	}

	set_derive_key_attributes(&attr);
	psa_set_key_bits(&attr, (size_t)PSA_BYTES_TO_BITS(
					EDHOC_CIPHER_SUITE_24_HASH_LEN));

	status = psa_key_derivation_output_key(&attr, &op, &psa_prk);

	psa_reset_key_attributes(&attr);

	if (PSA_SUCCESS != status) {
		goto psa_error;
	}

	store_key_id(prk_key_id, psa_prk);
	psa_key_derivation_abort(&op);
	return EDHOC_SUCCESS;

psa_error:
	psa_key_derivation_abort(&op);
	EDHOC_LOG_ERR("HKDF extract: %d", status);
	return EDHOC_ERROR_CRYPTO_FAILURE;
}

static int expand(void *user_context, const void *prk_key_id,
		  const uint8_t *info, size_t info_len,
		  enum edhoc_key_usage usage, void *out_key_id)
{
	(void)user_context;

	if (NULL == prk_key_id || NULL == info || 0 == info_len ||
	    NULL == out_key_id) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_key_id_t psa_prk = load_key_id(prk_key_id);
	psa_key_id_t psa_output = PSA_KEY_ID_NULL;

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	size_t output_length = 0;

	switch (usage) {
	case EDHOC_KEY_USAGE_KDF:
		set_derive_key_attributes(&attr);
		output_length = EDHOC_CIPHER_SUITE_24_HASH_LEN;
		break;
	case EDHOC_KEY_USAGE_AEAD:
		psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
		psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT |
						       PSA_KEY_USAGE_DECRYPT);
		psa_set_key_algorithm(
			&attr, PSA_ALG_AEAD_WITH_SHORTENED_TAG(
				       PSA_ALG_GCM,
				       EDHOC_CIPHER_SUITE_24_AEAD_TAG_LEN));
		output_length = EDHOC_CIPHER_SUITE_24_AEAD_KEY_LEN;
		break;
	default:
		EDHOC_LOG_ERR("Unknown key usage: %d", usage);
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	psa_set_key_bits(&attr, (size_t)PSA_BYTES_TO_BITS(output_length));

	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

	psa_status_t status = psa_key_derivation_setup(
		&op, PSA_ALG_HKDF_EXPAND(EDHOC_CIPHER_SUITE_24_KDF_HASH_ALG));

	if (PSA_SUCCESS != status) {
		goto psa_error;
	}

	status = psa_key_derivation_input_key(
		&op, PSA_KEY_DERIVATION_INPUT_SECRET, psa_prk);

	if (PSA_SUCCESS != status) {
		goto psa_error;
	}

	status = psa_key_derivation_input_bytes(
		&op, PSA_KEY_DERIVATION_INPUT_INFO, info, info_len);

	if (PSA_SUCCESS != status) {
		goto psa_error;
	}

	status = psa_key_derivation_set_capacity(&op, output_length);

	if (PSA_SUCCESS != status) {
		goto psa_error;
	}

	status = psa_key_derivation_output_key(&attr, &op, &psa_output);

	if (PSA_SUCCESS != status) {
		goto psa_error;
	}

	store_key_id(out_key_id, psa_output);
	psa_reset_key_attributes(&attr);
	psa_key_derivation_abort(&op);
	return EDHOC_SUCCESS;

psa_error:
	psa_reset_key_attributes(&attr);
	psa_key_derivation_abort(&op);
	EDHOC_LOG_ERR("HKDF expand (key handle): %d", status);
	return EDHOC_ERROR_CRYPTO_FAILURE;
}

static int expand_raw(void *user_context, const void *prk_key_id,
		      const uint8_t *info, size_t info_len, uint8_t *out,
		      size_t out_len)
{
	(void)user_context;

	if (NULL == prk_key_id || NULL == info || 0 == info_len ||
	    NULL == out || 0 == out_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_key_id_t psa_prk = load_key_id(prk_key_id);
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

	psa_status_t status = psa_key_derivation_setup(
		&op, PSA_ALG_HKDF_EXPAND(EDHOC_CIPHER_SUITE_24_KDF_HASH_ALG));
	if (PSA_SUCCESS != status) {
		goto psa_error;
	}

	status = psa_key_derivation_input_key(
		&op, PSA_KEY_DERIVATION_INPUT_SECRET, psa_prk);
	if (PSA_SUCCESS != status) {
		goto psa_error;
	}

	status = psa_key_derivation_input_bytes(
		&op, PSA_KEY_DERIVATION_INPUT_INFO, info, info_len);
	if (PSA_SUCCESS != status) {
		goto psa_error;
	}

	status = psa_key_derivation_set_capacity(&op, out_len);
	if (PSA_SUCCESS != status) {
		goto psa_error;
	}

	status = psa_key_derivation_output_bytes(&op, out, out_len);
	if (PSA_SUCCESS != status) {
		goto psa_error;
	}

	psa_key_derivation_abort(&op);
	return EDHOC_SUCCESS;

psa_error:
	psa_key_derivation_abort(&op);
	EDHOC_LOG_ERR("HKDF expand (raw): %d", status);
	return EDHOC_ERROR_CRYPTO_FAILURE;
}

static int aead_encrypt(void *user_context, const void *key_id,
			const uint8_t *nonce, size_t nonce_len,
			const uint8_t *additional_data,
			size_t additional_data_len, const uint8_t *plaintext,
			size_t plaintext_len, uint8_t *ciphertext,
			size_t ciphertext_size, size_t *ciphertext_len)
{
	(void)user_context;

	/* Plaintext might be a zero-length buffer. */
	if (NULL == key_id || NULL == nonce || 0 == nonce_len ||
	    NULL == additional_data || 0 == additional_data_len ||
	    NULL == ciphertext || 0 == ciphertext_size ||
	    NULL == ciphertext_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_key_id_t psa_kid = load_key_id(key_id);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status = psa_get_key_attributes(psa_kid, &attr);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("Get key attributes: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	status = psa_aead_encrypt(psa_kid, psa_get_key_algorithm(&attr), nonce,
				  nonce_len, additional_data,
				  additional_data_len, plaintext, plaintext_len,
				  ciphertext, ciphertext_size, ciphertext_len);

	psa_reset_key_attributes(&attr);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("AEAD encryption: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int aead_decrypt(void *user_context, const void *key_id,
			const uint8_t *nonce, size_t nonce_len,
			const uint8_t *additional_data,
			size_t additional_data_len, const uint8_t *ciphertext,
			size_t ciphertext_len, uint8_t *plaintext,
			size_t plaintext_size, size_t *plaintext_len)
{
	(void)user_context;

	/* Plaintext might be a zero-length buffer. */
	if (NULL == key_id || NULL == nonce || 0 == nonce_len ||
	    NULL == additional_data || 0 == additional_data_len ||
	    NULL == ciphertext || 0 == ciphertext_len ||
	    NULL == plaintext_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_key_id_t psa_kid = load_key_id(key_id);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status = psa_get_key_attributes(psa_kid, &attr);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("Get key attributes: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	status = psa_aead_decrypt(psa_kid, psa_get_key_algorithm(&attr), nonce,
				  nonce_len, additional_data,
				  additional_data_len, ciphertext,
				  ciphertext_len, plaintext, plaintext_size,
				  plaintext_len);

	psa_reset_key_attributes(&attr);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("AEAD decryption: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int edhoc_mutex_lock(void)
{
#ifdef __ZEPHYR__
	return k_mutex_lock(&edhoc_mutex, K_FOREVER);
#else /* __ZEPHYR__ */
	return pthread_mutex_lock(&edhoc_mutex);
#endif /* __ZEPHYR__ */
}

static int edhoc_mutex_unlock(void)
{
#ifdef __ZEPHYR__
	return k_mutex_unlock(&edhoc_mutex);
#else /* __ZEPHYR__ */
	return pthread_mutex_unlock(&edhoc_mutex);
#endif /* __ZEPHYR__ */
}

static int allocate_hash_slot(void **op)
{
	EDHOC_ASSERT(NULL != op);

	*op = NULL;

	if (0 != edhoc_mutex_lock()) {
		EDHOC_LOG_ERR("Mutex lock failed");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	int result = EDHOC_ERROR_CRYPTO_FAILURE;

	for (size_t i = 0; i < ARRAY_SIZE(hash_op_pool); ++i) {
		if (hash_op_in_use[i]) {
			continue;
		}

		hash_op_pool[i] = (psa_hash_operation_t)PSA_HASH_OPERATION_INIT;

		const psa_status_t status = psa_hash_setup(
			&hash_op_pool[i], EDHOC_CIPHER_SUITE_24_HASH_ALG);

		if (PSA_SUCCESS != status) {
			EDHOC_LOG_ERR("Hash setup: %d", status);
			break;
		}

		hash_op_in_use[i] = true;
		*op = &hash_op_pool[i];
		result = EDHOC_SUCCESS;
		break;
	}

	if (0 != edhoc_mutex_unlock()) {
		EDHOC_LOG_ERR("Mutex unlock failed");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return result;
}

static void release_hash_slot(const void *op)
{
	EDHOC_ASSERT(NULL != op);

	if (0 != edhoc_mutex_lock()) {
		EDHOC_LOG_ERR("Mutex lock failed");
		return;
	}

	for (size_t i = 0; i < ARRAY_SIZE(hash_op_pool); ++i) {
		if (&hash_op_pool[i] == op) {
			hash_op_pool[i] =
				(psa_hash_operation_t)PSA_HASH_OPERATION_INIT;
			hash_op_in_use[i] = false;
			break;
		}
	}

	if (0 != edhoc_mutex_unlock()) {
		EDHOC_LOG_ERR("Mutex unlock failed");
	}
}

static int hash_init(void *user_context, void **op)
{
	(void)user_context;

	if (NULL == op) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const int result = allocate_hash_slot(op);

	if (EDHOC_SUCCESS != result) {
		EDHOC_LOG_ERR("Multipart hash allocation failed");
	}

	return result;
}

static int hash_update(void *user_context, void *op, const uint8_t *input,
		       size_t input_len)
{
	(void)user_context;

	if (NULL == op || NULL == input || 0 == input_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_status_t status =
		psa_hash_update((psa_hash_operation_t *)op, input, input_len);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("Hash update: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int hash_finish(void *user_context, void *op, uint8_t *hash,
		       size_t hash_size, size_t *hash_len)
{
	(void)user_context;

	if (NULL == op || NULL == hash || 0 == hash_size || NULL == hash_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_status_t status = psa_hash_finish((psa_hash_operation_t *)op,
						    hash, hash_size, hash_len);

	release_hash_slot(op);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("Hash finish: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int hash_abort(void *user_context, void *op)
{
	(void)user_context;

	if (NULL == op) {
		return EDHOC_SUCCESS;
	}

	const psa_status_t status = psa_hash_abort((psa_hash_operation_t *)op);

	release_hash_slot(op);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("Hash abort: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

/* Module interface function definitions ----------------------------------- */

const struct edhoc_crypto *edhoc_cipher_suite_24_get_crypto(void)
{
	static const struct edhoc_crypto crypto = {
		.destroy_key = destroy_key,
		.generate_key_pair = generate_key_pair,
		.encapsulate = encapsulate,
		.decapsulate = decapsulate,
		.key_agreement = key_agreement,
		.sign = sign,
		.verify = verify,
		.extract = extract,
		.expand = expand,
		.expand_raw = expand_raw,
		.aead_encrypt = aead_encrypt,
		.aead_decrypt = aead_decrypt,
		.hash_init = hash_init,
		.hash_update = hash_update,
		.hash_finish = hash_finish,
		.hash_abort = hash_abort,
	};

	return &crypto;
}

const struct edhoc_cipher_suite *edhoc_cipher_suite_24_get_suite(void)
{
	static const struct edhoc_cipher_suite suite = {
		.value = EDHOC_CIPHER_SUITE_24_VALUE,
		.supports_dh_nike = true,
		.kem_public_key_length = EDHOC_CIPHER_SUITE_24_ECC_COMP_KEY_LEN,
		.kem_ciphertext_length = EDHOC_CIPHER_SUITE_24_ECC_COMP_KEY_LEN,
		.nike_key_length = EDHOC_CIPHER_SUITE_24_ECC_COMP_KEY_LEN,
		.sign_length = EDHOC_CIPHER_SUITE_24_ECC_ECDSA_SIGN_LEN,
		.aead_key_length = EDHOC_CIPHER_SUITE_24_AEAD_KEY_LEN,
		.aead_tag_length = EDHOC_CIPHER_SUITE_24_AEAD_TAG_LEN,
		.aead_iv_length = EDHOC_CIPHER_SUITE_24_AEAD_IV_LEN,
		.hash_length = EDHOC_CIPHER_SUITE_24_HASH_LEN,
		.mac_length = EDHOC_CIPHER_SUITE_24_MAC_LEN,
	};

	return &suite;
}
