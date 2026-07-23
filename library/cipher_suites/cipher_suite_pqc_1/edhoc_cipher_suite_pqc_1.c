/**
 * \file    edhoc_cipher_suite_pqc_1.c
 * \author  Kamil Kielbasa
 * \brief   Implementation of post-quantum cipher suite 1
 *          (ML-KEM-512 / ML-DSA-44 / AES-CCM-16-128-128 / SHAKE256).
 *
 * \details PQ primitives use liboqs; AES-CCM uses PSA; SHAKE256 hashing uses
 *          the liboqs incremental SHA-3 API and the KMAC256 KDF (RFC 9528
 *          Section 4.1) uses the backend-agnostic edhoc_kdf_kmac256() helper.
 *          The oversized ML-KEM decapsulation key and ML-DSA signing key live
 *          in a small mutex-protected software keystore local to this suite,
 *          because PSA cannot store key material this large; a keystore handle
 *          is tagged past #PSA_KEY_ID_VENDOR_MAX so it never collides with a
 *          \c psa_key_id_t. Every other key stays in PSA.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif /* __ZEPHYR__ */

/* Internal header: */
#include "edhoc_cipher_suite_pqc_1.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* EDHOC headers: */
#include <edhoc/values.h>
#include "edhoc_macros_internal.h"
#include "edhoc_backend_log.h"

/* EDHOC KDF (KMAC256 extract / expand) backend: */
#include "edhoc_kdf_kmac256.h"

/* PSA crypto header (AES-CCM, secret / AEAD key store): */
#include <psa/crypto.h>
#include <mbedtls/platform_util.h>

/* liboqs headers (ML-KEM-512, ML-DSA-44, incremental SHAKE256): */
#include <oqs/oqs.h>
#include <oqs/sha3.h>

/* Threading primitive serializing the keystore and the hash operation pool: */
#ifdef __ZEPHYR__
#include <zephyr/kernel.h>
#else /* __ZEPHYR__ */
#include <pthread.h>
#endif /* __ZEPHYR__ */

/* Module defines ---------------------------------------------------------- */

#define EDHOC_CIPHER_SUITE_PQC_1_VALUE (EDHOC_CIPHER_SUITE_PQC_1)

/* ML-KEM-512 sizes. Wrapping the liboqs macros keeps a KEM backend swap a
 * define-only change. */
#define EDHOC_CIPHER_SUITE_PQC_1_KEM_ENCAPSULATION_KEY_LEN \
	OQS_KEM_ml_kem_512_length_public_key
#define EDHOC_CIPHER_SUITE_PQC_1_KEM_SECRET_KEY_LEN \
	OQS_KEM_ml_kem_512_length_secret_key
#define EDHOC_CIPHER_SUITE_PQC_1_KEM_CIPHERTEXT_LEN \
	OQS_KEM_ml_kem_512_length_ciphertext
#define EDHOC_CIPHER_SUITE_PQC_1_KEM_SHARED_SECRET_LEN \
	OQS_KEM_ml_kem_512_length_shared_secret

/* ML-DSA-44 sizes. Wrapping the liboqs macros keeps a signature backend swap a
 * define-only change. */
#define EDHOC_CIPHER_SUITE_PQC_1_SIG_PUBLIC_KEY_LEN \
	OQS_SIG_ml_dsa_44_length_public_key
#define EDHOC_CIPHER_SUITE_PQC_1_SIG_SECRET_KEY_LEN \
	OQS_SIG_ml_dsa_44_length_secret_key
#define EDHOC_CIPHER_SUITE_PQC_1_SIG_LEN OQS_SIG_ml_dsa_44_length_signature

/* AES-CCM-16-128-128. */
#define EDHOC_CIPHER_SUITE_PQC_1_AEAD_KEY_LEN (16)
#define EDHOC_CIPHER_SUITE_PQC_1_AEAD_TAG_LEN (16)
#define EDHOC_CIPHER_SUITE_PQC_1_AEAD_IV_LEN (13)
#define EDHOC_CIPHER_SUITE_PQC_1_CCM_ALG             \
	PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, \
					EDHOC_CIPHER_SUITE_PQC_1_AEAD_TAG_LEN)

/* SHAKE256 output length (hashing and KDF key material) and the unused
 * static-DH MAC length. */
#define EDHOC_CIPHER_SUITE_PQC_1_HASH_LEN (64)
#define EDHOC_CIPHER_SUITE_PQC_1_MAC_LEN (16)

/* Scratch size for a PSA secret exported before it is fed to KMAC256 (the
 * EDHOC_Extract IKM and the EDHOC_Expand PRK). Sized well past the 64-byte
 * EDHOC hash so any secret imported into this suite round-trips through the
 * KDF, which the KMAC256 known-answer test exercises with a 200-byte input. */
#define EDHOC_CIPHER_SUITE_PQC_1_SECRET_BUF_LEN (256)

/* Software keystore for the oversized ML-KEM / ML-DSA keys. A slot is sized
 * for the largest key it must hold (the ML-DSA signing key). */
#define EDHOC_CIPHER_SUITE_PQC_1_KEYSTORE_SLOTS (8)
#define EDHOC_CIPHER_SUITE_PQC_1_SLOT_MATERIAL_MAX \
	EDHOC_CIPHER_SUITE_PQC_1_SIG_SECRET_KEY_LEN

/**
 * \brief First software-keystore handle value.
 *
 *        PSA key identifiers never exceed #PSA_KEY_ID_VENDOR_MAX, so handles
 *        above it are free and let the backend tell a software-keystore slot
 *        from a \c psa_key_id_t.
 */
#define EDHOC_CIPHER_SUITE_PQC_1_SLOT_HANDLE_BASE \
	((psa_key_id_t)(PSA_KEY_ID_VENDOR_MAX + 1u))

/* Number of concurrent multipart SHAKE256 operations. */
#define EDHOC_CIPHER_SUITE_PQC_1_HASH_OP_POOL_SIZE (4)

/* Module types and type definitions -------------------------------------- */

/** \brief A software-keystore slot holding raw key material. */
struct key_slot {
	/** Whether the slot currently holds a live key. */
	bool in_use;
	/** Raw key material. */
	uint8_t material[EDHOC_CIPHER_SUITE_PQC_1_SLOT_MATERIAL_MAX];
	/** Number of valid bytes in \ref material. */
	size_t material_len;
};

/* Module interface variables and constants -------------------------------- */

/* One mutex guards both the software keystore and the hash operation pool. */
#ifdef __ZEPHYR__
K_MUTEX_DEFINE(edhoc_mutex);
#else /* __ZEPHYR__ */
static pthread_mutex_t edhoc_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif /* __ZEPHYR__ */

/** Software keystore for the oversized ML-KEM / ML-DSA keys. */
static struct key_slot keystore[EDHOC_CIPHER_SUITE_PQC_1_KEYSTORE_SLOTS];

/** Pool of multipart SHAKE256 operations. */
static OQS_SHA3_shake256_inc_ctx
	hash_op_pool[EDHOC_CIPHER_SUITE_PQC_1_HASH_OP_POOL_SIZE];

/** Per-operation liveness flags for \ref hash_op_pool. */
static bool hash_op_in_use[EDHOC_CIPHER_SUITE_PQC_1_HASH_OP_POOL_SIZE];

/* Static function declarations -------------------------------------------- */

/** \brief Lock the shared mutex (blocking). */
static int mutex_lock(void);

/** \brief Unlock the shared mutex. */
static int mutex_unlock(void);

/** \brief Load a key identifier from a handle buffer (alignment-safe). */
static psa_key_id_t load_key_id(const void *key_id);

/** \brief Store a key identifier into a handle buffer (alignment-safe). */
static void store_key_id(void *key_id, psa_key_id_t kid);

/** \brief Whether a handle refers to a software-keystore slot. */
static bool is_keystore_handle(psa_key_id_t handle);

/** \brief Reserve a free software-keystore slot and expose its buffer. */
static int keystore_reserve(size_t length, uint8_t **material,
			    size_t *material_size, psa_key_id_t *handle);

/** \brief Copy raw material into a free software-keystore slot. */
static int keystore_store(const uint8_t *material, size_t length,
			  psa_key_id_t *handle);

/** \brief Expose a read-only view of a software-keystore slot's material. */
static int keystore_borrow(psa_key_id_t handle, const uint8_t **material,
			   size_t *length);

/** \brief Wipe and release a software-keystore slot. */
static int keystore_free(psa_key_id_t handle);

/** \brief Export the bytes of an exportable PSA secret (shared secret / PRK). */
static int export_psa_secret(psa_key_id_t handle, uint8_t *out, size_t out_size,
			     size_t *out_length);

/** \brief Import raw bytes as an exportable PSA RAW_DATA secret. */
static int import_psa_secret(const uint8_t *raw, size_t length,
			     psa_key_id_t *handle);

/** \brief Import raw bytes as a non-exportable PSA AES-CCM key. */
static int import_psa_aead_key(const uint8_t *raw, psa_key_id_t *handle);

/** \brief Reserve a free multipart SHAKE256 operation. */
static int hash_alloc(void **operation);

/** \brief Release a multipart SHAKE256 operation. */
static int hash_release(const void *operation);

/** \brief Destroy a key handle (software-keystore slot or PSA key). */
static int destroy_key(void *user_context, void *key_id);

/** \brief Generate an ML-KEM-512 ephemeral key pair (Initiator). */
static int generate_key_pair(void *user_context, void *decapsulation_key_id,
			     uint8_t *encapsulation_key,
			     size_t encapsulation_key_size,
			     size_t *encapsulation_key_length);

/** \brief ML-KEM-512 encapsulate (Responder). */
static int encapsulate(void *user_context, const uint8_t *encapsulation_key,
		       size_t encapsulation_key_length,
		       void *decapsulation_key_id, void *shared_secret_key_id,
		       uint8_t *ciphertext, size_t ciphertext_size,
		       size_t *ciphertext_length);

/** \brief ML-KEM-512 decapsulate (Initiator). */
static int decapsulate(void *user_context, const void *decapsulation_key_id,
		       const uint8_t *ciphertext, size_t ciphertext_length,
		       void *shared_secret_key_id);

/** \brief Static Diffie-Hellman key agreement (unsupported by ML-KEM). */
static int key_agreement(void *user_context, const void *private_key_id,
			 const uint8_t *peer_public_key,
			 size_t peer_public_key_length,
			 void *shared_secret_key_id);

/** \brief ML-DSA-44 signature. */
static int sign(void *user_context, const void *private_key_id,
		const uint8_t *input, size_t input_length, uint8_t *signature,
		size_t signature_size, size_t *signature_length);

/** \brief ML-DSA-44 signature verification (raw public key). */
static int verify(void *user_context, const uint8_t *public_key,
		  size_t public_key_length, const uint8_t *input,
		  size_t input_length, const uint8_t *signature,
		  size_t signature_length);

/** \brief EDHOC_Extract (KMAC256) producing a PSA secret handle. */
static int extract(void *user_context, const void *ikm_key_id,
		   const uint8_t *salt, size_t salt_length, void *prk_key_id);

/** \brief EDHOC_Expand (KMAC256) producing a key handle. */
static int expand(void *user_context, const void *prk_key_id,
		  const uint8_t *info, size_t info_length,
		  enum edhoc_key_usage usage, void *output_key_id);

/** \brief EDHOC_Expand (KMAC256) producing raw output. */
static int expand_raw(void *user_context, const void *prk_key_id,
		      const uint8_t *info, size_t info_length, uint8_t *output,
		      size_t output_length);

/** \brief AES-CCM-16-128-128 encrypt. */
static int aead_encrypt(void *user_context, const void *key_id,
			const uint8_t *nonce, size_t nonce_length,
			const uint8_t *additional_data,
			size_t additional_data_length, const uint8_t *plaintext,
			size_t plaintext_length, uint8_t *ciphertext,
			size_t ciphertext_size, size_t *ciphertext_length);

/** \brief AES-CCM-16-128-128 decrypt. */
static int aead_decrypt(void *user_context, const void *key_id,
			const uint8_t *nonce, size_t nonce_length,
			const uint8_t *additional_data,
			size_t additional_data_length,
			const uint8_t *ciphertext, size_t ciphertext_length,
			uint8_t *plaintext, size_t plaintext_size,
			size_t *plaintext_length);

/** \brief Begin a multipart SHAKE256 hash. */
static int hash_init(void *user_context, void **operation);

/** \brief Add input to a multipart SHAKE256 hash. */
static int hash_update(void *user_context, void *operation,
		       const uint8_t *input, size_t input_length);

/** \brief Finish a multipart SHAKE256 hash and release it. */
static int hash_finish(void *user_context, void *operation, uint8_t *hash,
		       size_t hash_size, size_t *hash_length);

/** \brief Abort a multipart SHAKE256 hash and release it. */
static int hash_abort(void *user_context, void *operation);

/**
 * \brief Import an ML-DSA-44 signing key into the suite's software keystore.
 *
 *        Deliberately absent from the public suite header (the classic suites
 *        import their signing key with \c psa_import_key, but the 2560-byte
 *        ML-DSA-44 private key does not fit PSA). The module tests reach it
 *        through an \c extern prototype of their own.
 */
int edhoc_cipher_suite_pqc_1_import_signing_key(const uint8_t *signing_key,
						size_t signing_key_length,
						void *key_id);

/* Static function definitions --------------------------------------------- */

static int mutex_lock(void)
{
#ifdef __ZEPHYR__
	return k_mutex_lock(&edhoc_mutex, K_FOREVER);
#else /* __ZEPHYR__ */
	return pthread_mutex_lock(&edhoc_mutex);
#endif /* __ZEPHYR__ */
}

static int mutex_unlock(void)
{
#ifdef __ZEPHYR__
	return k_mutex_unlock(&edhoc_mutex);
#else /* __ZEPHYR__ */
	return pthread_mutex_unlock(&edhoc_mutex);
#endif /* __ZEPHYR__ */
}

static psa_key_id_t load_key_id(const void *key_id)
{
	EDHOC_ASSERT(NULL != key_id);

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	memcpy(&kid, key_id, sizeof(kid));

	return kid;
}

static void store_key_id(void *key_id, psa_key_id_t kid)
{
	EDHOC_ASSERT(NULL != key_id);

	memcpy(key_id, &kid, sizeof(kid));
}

static bool is_keystore_handle(psa_key_id_t handle)
{
	const bool at_or_above_base = handle >=
				      EDHOC_CIPHER_SUITE_PQC_1_SLOT_HANDLE_BASE;
	const bool below_limit = handle <
				 EDHOC_CIPHER_SUITE_PQC_1_SLOT_HANDLE_BASE +
					 (psa_key_id_t)ARRAY_SIZE(keystore);

	return at_or_above_base && below_limit;
}

static int keystore_reserve(size_t length, uint8_t **material,
			    size_t *material_size, psa_key_id_t *handle)
{
	EDHOC_ASSERT(0 != length);
	EDHOC_ASSERT(length <= EDHOC_CIPHER_SUITE_PQC_1_SLOT_MATERIAL_MAX);
	EDHOC_ASSERT(NULL != material);
	EDHOC_ASSERT(NULL != material_size);
	EDHOC_ASSERT(NULL != handle);

	if (0 != mutex_lock()) {
		EDHOC_LOG_ERR("Mutex lock failed");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	int ret = EDHOC_ERROR_CRYPTO_FAILURE;

	for (size_t i = 0; i < ARRAY_SIZE(keystore); ++i) {
		if (keystore[i].in_use) {
			continue;
		}

		keystore[i].in_use = true;
		keystore[i].material_len = length;
		*material = keystore[i].material;
		*material_size = sizeof(keystore[i].material);
		*handle = EDHOC_CIPHER_SUITE_PQC_1_SLOT_HANDLE_BASE +
			  (psa_key_id_t)i;
		ret = EDHOC_SUCCESS;
		break;
	}

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("No free software-keystore slots");
	}

	if (0 != mutex_unlock()) {
		EDHOC_LOG_ERR("Mutex unlock failed");
		ret = EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return ret;
}

static int keystore_store(const uint8_t *material, size_t length,
			  psa_key_id_t *handle)
{
	EDHOC_ASSERT(NULL != material);
	EDHOC_ASSERT(NULL != handle);

	uint8_t *slot = NULL;
	size_t slot_size = 0;
	const int ret = keystore_reserve(length, &slot, &slot_size, handle);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Reserve keystore slot: %d", ret);
		return ret;
	}

	memcpy(slot, material, length);

	return EDHOC_SUCCESS;
}

static int keystore_borrow(psa_key_id_t handle, const uint8_t **material,
			   size_t *length)
{
	EDHOC_ASSERT(NULL != material);
	EDHOC_ASSERT(NULL != length);

	if (!is_keystore_handle(handle)) {
		EDHOC_LOG_ERR("Not a software-keystore handle");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	const size_t index =
		(size_t)(handle - EDHOC_CIPHER_SUITE_PQC_1_SLOT_HANDLE_BASE);

	if (0 != mutex_lock()) {
		EDHOC_LOG_ERR("Mutex lock failed");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	int ret = EDHOC_SUCCESS;

	if (!keystore[index].in_use || 0 == keystore[index].material_len) {
		EDHOC_LOG_ERR("Empty software-keystore slot");
		ret = EDHOC_ERROR_CRYPTO_FAILURE;
	} else {
		/* The material buffer is stable for the slot's lifetime, so the
		 * caller may read it after the lock is dropped; it stays valid
		 * until the handle is destroyed. */
		*material = keystore[index].material;
		*length = keystore[index].material_len;
	}

	if (0 != mutex_unlock()) {
		EDHOC_LOG_ERR("Mutex unlock failed");
		ret = EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return ret;
}

static int keystore_free(psa_key_id_t handle)
{
	if (!is_keystore_handle(handle)) {
		EDHOC_LOG_ERR("Not a software-keystore handle");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	const size_t index =
		(size_t)(handle - EDHOC_CIPHER_SUITE_PQC_1_SLOT_HANDLE_BASE);

	if (0 != mutex_lock()) {
		EDHOC_LOG_ERR("Mutex lock failed");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	mbedtls_platform_zeroize(keystore[index].material,
				 sizeof(keystore[index].material));
	keystore[index].material_len = 0;
	keystore[index].in_use = false;

	int ret = EDHOC_SUCCESS;

	if (0 != mutex_unlock()) {
		EDHOC_LOG_ERR("Mutex unlock failed");
		ret = EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return ret;
}

static int export_psa_secret(psa_key_id_t handle, uint8_t *out, size_t out_size,
			     size_t *out_length)
{
	EDHOC_ASSERT(PSA_KEY_ID_NULL != handle);
	EDHOC_ASSERT(NULL != out);
	EDHOC_ASSERT(0 != out_size);
	EDHOC_ASSERT(NULL != out_length);

	const psa_status_t status =
		psa_export_key(handle, out, out_size, out_length);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("Export secret: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int import_psa_secret(const uint8_t *raw, size_t length,
			     psa_key_id_t *handle)
{
	EDHOC_ASSERT(NULL != raw);
	EDHOC_ASSERT(0 != length);
	EDHOC_ASSERT(NULL != handle);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr, PSA_KEY_TYPE_RAW_DATA);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
	psa_set_key_bits(&attr, (size_t)PSA_BYTES_TO_BITS(length));

	const psa_status_t status = psa_import_key(&attr, raw, length, handle);

	psa_reset_key_attributes(&attr);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("Import secret: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int import_psa_aead_key(const uint8_t *raw, psa_key_id_t *handle)
{
	EDHOC_ASSERT(NULL != raw);
	EDHOC_ASSERT(NULL != handle);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_usage_flags(&attr,
				PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attr, EDHOC_CIPHER_SUITE_PQC_1_CCM_ALG);

	const psa_status_t status = psa_import_key(
		&attr, raw, EDHOC_CIPHER_SUITE_PQC_1_AEAD_KEY_LEN, handle);

	psa_reset_key_attributes(&attr);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("Import AEAD key: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int hash_alloc(void **operation)
{
	EDHOC_ASSERT(NULL != operation);

	if (0 != mutex_lock()) {
		EDHOC_LOG_ERR("Mutex lock failed");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	int ret = EDHOC_ERROR_CRYPTO_FAILURE;

	for (size_t i = 0; i < ARRAY_SIZE(hash_op_pool); ++i) {
		if (hash_op_in_use[i]) {
			continue;
		}

		OQS_SHA3_shake256_inc_init(&hash_op_pool[i]);
		hash_op_in_use[i] = true;
		*operation = &hash_op_pool[i];
		ret = EDHOC_SUCCESS;
		break;
	}

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("No free hash operation slots");
	}

	if (0 != mutex_unlock()) {
		EDHOC_LOG_ERR("Mutex unlock failed");
		ret = EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return ret;
}

static int hash_release(const void *operation)
{
	if (NULL == operation) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (0 != mutex_lock()) {
		EDHOC_LOG_ERR("Mutex lock failed");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	int ret = EDHOC_ERROR_CRYPTO_FAILURE;

	for (size_t i = 0; i < ARRAY_SIZE(hash_op_pool); ++i) {
		if (&hash_op_pool[i] != operation) {
			continue;
		}

		OQS_SHA3_shake256_inc_ctx_release(&hash_op_pool[i]);
		hash_op_in_use[i] = false;
		ret = EDHOC_SUCCESS;
		break;
	}

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Unknown hash operation");
	}

	if (0 != mutex_unlock()) {
		EDHOC_LOG_ERR("Mutex unlock failed");
		ret = EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return ret;
}

static int destroy_key(void *user_context, void *key_id)
{
	(void)user_context;

	if (NULL == key_id) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_key_id_t handle = load_key_id(key_id);

	if (PSA_KEY_ID_NULL == handle) {
		return EDHOC_SUCCESS;
	}

	if (is_keystore_handle(handle)) {
		return keystore_free(handle);
	}

	const psa_status_t status = psa_destroy_key(handle);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("Destroy key: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int generate_key_pair(void *user_context, void *decapsulation_key_id,
			     uint8_t *encapsulation_key,
			     size_t encapsulation_key_size,
			     size_t *encapsulation_key_length)
{
	(void)user_context;

	if (NULL == decapsulation_key_id || NULL == encapsulation_key ||
	    0 == encapsulation_key_size || NULL == encapsulation_key_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (encapsulation_key_size <
	    EDHOC_CIPHER_SUITE_PQC_1_KEM_ENCAPSULATION_KEY_LEN) {
		EDHOC_LOG_ERR("Encapsulation key buffer too small: %zu",
			      encapsulation_key_size);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	/* ML-KEM writes the decapsulation key straight into a keystore slot. */
	uint8_t *decapsulation_key = NULL;
	size_t decapsulation_key_size = 0;
	psa_key_id_t handle = PSA_KEY_ID_NULL;
	int ret = keystore_reserve(EDHOC_CIPHER_SUITE_PQC_1_KEM_SECRET_KEY_LEN,
				   &decapsulation_key, &decapsulation_key_size,
				   &handle);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Reserve decapsulation key slot: %d", ret);
		return ret;
	}

	if (decapsulation_key_size <
	    EDHOC_CIPHER_SUITE_PQC_1_KEM_SECRET_KEY_LEN) {
		EDHOC_LOG_ERR("Decapsulation key slot too small: %zu",
			      decapsulation_key_size);
		ret = EDHOC_ERROR_CRYPTO_FAILURE;
	} else if (OQS_SUCCESS !=
		   OQS_KEM_ml_kem_512_keypair(encapsulation_key,
					      decapsulation_key)) {
		EDHOC_LOG_ERR("ML-KEM keypair");
		ret = EDHOC_ERROR_CRYPTO_FAILURE;
	}

	if (EDHOC_SUCCESS != ret) {
		const int free_ret = keystore_free(handle);

		if (EDHOC_SUCCESS != free_ret) {
			EDHOC_LOG_ERR("Free decapsulation key slot: %d",
				      free_ret);
		}

		mbedtls_platform_zeroize(encapsulation_key,
					 encapsulation_key_size);
		return ret;
	}

	store_key_id(decapsulation_key_id, handle);
	*encapsulation_key_length =
		EDHOC_CIPHER_SUITE_PQC_1_KEM_ENCAPSULATION_KEY_LEN;

	return EDHOC_SUCCESS;
}

static int encapsulate(void *user_context, const uint8_t *encapsulation_key,
		       size_t encapsulation_key_length,
		       void *decapsulation_key_id, void *shared_secret_key_id,
		       uint8_t *ciphertext, size_t ciphertext_size,
		       size_t *ciphertext_length)
{
	(void)user_context;

	if (NULL == encapsulation_key || 0 == encapsulation_key_length ||
	    NULL == decapsulation_key_id || NULL == shared_secret_key_id ||
	    NULL == ciphertext || 0 == ciphertext_size ||
	    NULL == ciphertext_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_CIPHER_SUITE_PQC_1_KEM_ENCAPSULATION_KEY_LEN !=
	    encapsulation_key_length) {
		EDHOC_LOG_ERR("Invalid encapsulation key length: %zu",
			      encapsulation_key_length);
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (ciphertext_size < EDHOC_CIPHER_SUITE_PQC_1_KEM_CIPHERTEXT_LEN) {
		EDHOC_LOG_ERR("Ciphertext buffer too small: %zu",
			      ciphertext_size);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	uint8_t shared_secret[EDHOC_CIPHER_SUITE_PQC_1_KEM_SHARED_SECRET_LEN] = {
		0
	};

	if (OQS_SUCCESS != OQS_KEM_ml_kem_512_encaps(ciphertext, shared_secret,
						     encapsulation_key)) {
		mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
		mbedtls_platform_zeroize(ciphertext, ciphertext_size);
		EDHOC_LOG_ERR("ML-KEM encapsulate");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	psa_key_id_t handle = PSA_KEY_ID_NULL;
	const int ret = import_psa_secret(
		shared_secret, EDHOC_CIPHER_SUITE_PQC_1_KEM_SHARED_SECRET_LEN,
		&handle);

	mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));

	if (EDHOC_SUCCESS != ret) {
		mbedtls_platform_zeroize(ciphertext, ciphertext_size);
		EDHOC_LOG_ERR("Import shared secret: %d", ret);
		return ret;
	}

	/* ML-KEM retains no ephemeral for a static-DH agreement. */
	store_key_id(decapsulation_key_id, PSA_KEY_ID_NULL);
	store_key_id(shared_secret_key_id, handle);
	*ciphertext_length = EDHOC_CIPHER_SUITE_PQC_1_KEM_CIPHERTEXT_LEN;

	return EDHOC_SUCCESS;
}

static int decapsulate(void *user_context, const void *decapsulation_key_id,
		       const uint8_t *ciphertext, size_t ciphertext_length,
		       void *shared_secret_key_id)
{
	(void)user_context;

	if (NULL == decapsulation_key_id || NULL == ciphertext ||
	    0 == ciphertext_length || NULL == shared_secret_key_id) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_CIPHER_SUITE_PQC_1_KEM_CIPHERTEXT_LEN != ciphertext_length) {
		EDHOC_LOG_ERR("Invalid ciphertext length: %zu",
			      ciphertext_length);
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const uint8_t *decapsulation_key = NULL;
	size_t decapsulation_key_len = 0;
	int ret = keystore_borrow(load_key_id(decapsulation_key_id),
				  &decapsulation_key, &decapsulation_key_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Borrow decapsulation key: %d", ret);
		return ret;
	}

	if (EDHOC_CIPHER_SUITE_PQC_1_KEM_SECRET_KEY_LEN !=
	    decapsulation_key_len) {
		EDHOC_LOG_ERR("Invalid decapsulation key length: %zu",
			      decapsulation_key_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	uint8_t shared_secret[EDHOC_CIPHER_SUITE_PQC_1_KEM_SHARED_SECRET_LEN] = {
		0
	};

	if (OQS_SUCCESS != OQS_KEM_ml_kem_512_decaps(shared_secret, ciphertext,
						     decapsulation_key)) {
		mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
		EDHOC_LOG_ERR("ML-KEM decapsulate");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	psa_key_id_t handle = PSA_KEY_ID_NULL;
	ret = import_psa_secret(shared_secret,
				EDHOC_CIPHER_SUITE_PQC_1_KEM_SHARED_SECRET_LEN,
				&handle);

	mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Import shared secret: %d", ret);
		return ret;
	}

	store_key_id(shared_secret_key_id, handle);

	return EDHOC_SUCCESS;
}

static int key_agreement(void *user_context, const void *private_key_id,
			 const uint8_t *peer_public_key,
			 size_t peer_public_key_length,
			 void *shared_secret_key_id)
{
	(void)user_context;
	(void)private_key_id;
	(void)peer_public_key;
	(void)peer_public_key_length;
	(void)shared_secret_key_id;

	EDHOC_LOG_ERR("ML-KEM suite does not support static Diffie-Hellman");
	return EDHOC_ERROR_NOT_PERMITTED;
}

static int sign(void *user_context, const void *private_key_id,
		const uint8_t *input, size_t input_length, uint8_t *signature,
		size_t signature_size, size_t *signature_length)
{
	(void)user_context;

	if (NULL == private_key_id || NULL == input || 0 == input_length ||
	    NULL == signature || 0 == signature_size ||
	    NULL == signature_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (signature_size < EDHOC_CIPHER_SUITE_PQC_1_SIG_LEN) {
		EDHOC_LOG_ERR("Signature buffer too small: %zu",
			      signature_size);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	const uint8_t *signing_key = NULL;
	size_t signing_key_len = 0;
	const int ret = keystore_borrow(load_key_id(private_key_id),
					&signing_key, &signing_key_len);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Borrow signing key: %d", ret);
		return ret;
	}

	if (EDHOC_CIPHER_SUITE_PQC_1_SIG_SECRET_KEY_LEN != signing_key_len) {
		EDHOC_LOG_ERR("Invalid signing key length: %zu",
			      signing_key_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	size_t sig_len = 0;

	if (OQS_SUCCESS != OQS_SIG_ml_dsa_44_sign(signature, &sig_len, input,
						  input_length, signing_key)) {
		EDHOC_LOG_ERR("ML-DSA sign");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	*signature_length = sig_len;

	return EDHOC_SUCCESS;
}

static int verify(void *user_context, const uint8_t *public_key,
		  size_t public_key_length, const uint8_t *input,
		  size_t input_length, const uint8_t *signature,
		  size_t signature_length)
{
	(void)user_context;

	if (NULL == public_key || 0 == public_key_length || NULL == input ||
	    0 == input_length || NULL == signature || 0 == signature_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_CIPHER_SUITE_PQC_1_SIG_PUBLIC_KEY_LEN != public_key_length) {
		EDHOC_LOG_ERR("Invalid verification key length: %zu",
			      public_key_length);
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_CIPHER_SUITE_PQC_1_SIG_LEN != signature_length) {
		EDHOC_LOG_ERR("Invalid signature length: %zu",
			      signature_length);
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (OQS_SUCCESS != OQS_SIG_ml_dsa_44_verify(input, input_length,
						    signature, signature_length,
						    public_key)) {
		EDHOC_LOG_ERR("ML-DSA verify");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int extract(void *user_context, const void *ikm_key_id,
		   const uint8_t *salt, size_t salt_length, void *prk_key_id)
{
	(void)user_context;

	if (NULL == ikm_key_id || NULL == salt || 0 == salt_length ||
	    NULL == prk_key_id) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	uint8_t ikm[EDHOC_CIPHER_SUITE_PQC_1_SECRET_BUF_LEN] = { 0 };
	size_t ikm_len = 0;
	int ret = export_psa_secret(load_key_id(ikm_key_id), ikm, sizeof(ikm),
				    &ikm_len);

	if (EDHOC_SUCCESS != ret) {
		mbedtls_platform_zeroize(ikm, sizeof(ikm));
		EDHOC_LOG_ERR("Export IKM: %d", ret);
		return ret;
	}

	/* RFC 9528 Section 4.1.2: EDHOC_Extract(salt, IKM) = KMAC256(salt,
	 * IKM), i.e. salt is the KMAC key and IKM is the message. */
	uint8_t prk[EDHOC_CIPHER_SUITE_PQC_1_HASH_LEN] = { 0 };
	ret = edhoc_kdf_kmac256(salt, salt_length, ikm, ikm_len, prk,
				EDHOC_CIPHER_SUITE_PQC_1_HASH_LEN);

	mbedtls_platform_zeroize(ikm, sizeof(ikm));

	if (EDHOC_SUCCESS != ret) {
		mbedtls_platform_zeroize(prk, sizeof(prk));
		EDHOC_LOG_ERR("KMAC extract: %d", ret);
		return ret;
	}

	psa_key_id_t handle = PSA_KEY_ID_NULL;
	ret = import_psa_secret(prk, EDHOC_CIPHER_SUITE_PQC_1_HASH_LEN,
				&handle);

	mbedtls_platform_zeroize(prk, sizeof(prk));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Import PRK: %d", ret);
		return ret;
	}

	store_key_id(prk_key_id, handle);

	return EDHOC_SUCCESS;
}

static int expand(void *user_context, const void *prk_key_id,
		  const uint8_t *info, size_t info_length,
		  enum edhoc_key_usage usage, void *output_key_id)
{
	(void)user_context;

	if (NULL == prk_key_id || NULL == info || 0 == info_length ||
	    NULL == output_key_id) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	size_t output_length = 0;

	switch (usage) {
	case EDHOC_KEY_USAGE_KDF:
		output_length = EDHOC_CIPHER_SUITE_PQC_1_HASH_LEN;
		break;
	case EDHOC_KEY_USAGE_AEAD:
		output_length = EDHOC_CIPHER_SUITE_PQC_1_AEAD_KEY_LEN;
		break;
	default:
		EDHOC_LOG_ERR("Invalid key usage: %d", usage);
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	uint8_t prk[EDHOC_CIPHER_SUITE_PQC_1_SECRET_BUF_LEN] = { 0 };
	size_t prk_len = 0;
	int ret = export_psa_secret(load_key_id(prk_key_id), prk, sizeof(prk),
				    &prk_len);

	if (EDHOC_SUCCESS != ret) {
		mbedtls_platform_zeroize(prk, sizeof(prk));
		EDHOC_LOG_ERR("Export PRK: %d", ret);
		return ret;
	}

	/* RFC 9528 Section 4.1.2: EDHOC_Expand(PRK, info, L) = KMAC256(PRK,
	 * info), i.e. PRK is the KMAC key and info is the message. */
	uint8_t okm[EDHOC_CIPHER_SUITE_PQC_1_HASH_LEN] = { 0 };
	ret = edhoc_kdf_kmac256(prk, prk_len, info, info_length, okm,
				output_length);

	mbedtls_platform_zeroize(prk, sizeof(prk));

	if (EDHOC_SUCCESS != ret) {
		mbedtls_platform_zeroize(okm, sizeof(okm));
		EDHOC_LOG_ERR("KMAC expand: %d", ret);
		return ret;
	}

	psa_key_id_t handle = PSA_KEY_ID_NULL;

	switch (usage) {
	case EDHOC_KEY_USAGE_KDF:
		ret = import_psa_secret(okm, output_length, &handle);
		break;
	case EDHOC_KEY_USAGE_AEAD:
		ret = import_psa_aead_key(okm, &handle);
		break;
	default:
		ret = EDHOC_ERROR_INVALID_ARGUMENT;
		break;
	}

	mbedtls_platform_zeroize(okm, sizeof(okm));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Import expanded key: %d", ret);
		return ret;
	}

	store_key_id(output_key_id, handle);

	return EDHOC_SUCCESS;
}

static int expand_raw(void *user_context, const void *prk_key_id,
		      const uint8_t *info, size_t info_length, uint8_t *output,
		      size_t output_length)
{
	(void)user_context;

	if (NULL == prk_key_id || NULL == info || 0 == info_length ||
	    NULL == output || 0 == output_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	uint8_t prk[EDHOC_CIPHER_SUITE_PQC_1_SECRET_BUF_LEN] = { 0 };
	size_t prk_len = 0;
	int ret = export_psa_secret(load_key_id(prk_key_id), prk, sizeof(prk),
				    &prk_len);

	if (EDHOC_SUCCESS != ret) {
		mbedtls_platform_zeroize(prk, sizeof(prk));
		EDHOC_LOG_ERR("Export PRK: %d", ret);
		return ret;
	}

	/* RFC 9528 Section 4.1.2: EDHOC_Expand(PRK, info, L) = KMAC256(PRK,
	 * info), i.e. PRK is the KMAC key and info is the message. */
	ret = edhoc_kdf_kmac256(prk, prk_len, info, info_length, output,
				output_length);

	mbedtls_platform_zeroize(prk, sizeof(prk));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("KMAC expand (raw): %d", ret);
		return ret;
	}

	return EDHOC_SUCCESS;
}

static int aead_encrypt(void *user_context, const void *key_id,
			const uint8_t *nonce, size_t nonce_length,
			const uint8_t *additional_data,
			size_t additional_data_length, const uint8_t *plaintext,
			size_t plaintext_length, uint8_t *ciphertext,
			size_t ciphertext_size, size_t *ciphertext_length)
{
	(void)user_context;

	/* Plaintext might be a zero-length buffer. */
	if (NULL == key_id || NULL == nonce || 0 == nonce_length ||
	    NULL == additional_data || 0 == additional_data_length ||
	    NULL == ciphertext || 0 == ciphertext_size ||
	    NULL == ciphertext_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_key_id_t key = load_key_id(key_id);
	const psa_status_t status = psa_aead_encrypt(
		key, EDHOC_CIPHER_SUITE_PQC_1_CCM_ALG, nonce, nonce_length,
		additional_data, additional_data_length, plaintext,
		plaintext_length, ciphertext, ciphertext_size,
		ciphertext_length);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("AEAD encryption: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int aead_decrypt(void *user_context, const void *key_id,
			const uint8_t *nonce, size_t nonce_length,
			const uint8_t *additional_data,
			size_t additional_data_length,
			const uint8_t *ciphertext, size_t ciphertext_length,
			uint8_t *plaintext, size_t plaintext_size,
			size_t *plaintext_length)
{
	(void)user_context;

	/* Plaintext might be a zero-length buffer (e.g. an empty EAD_4). */
	if (NULL == key_id || NULL == nonce || 0 == nonce_length ||
	    NULL == additional_data || 0 == additional_data_length ||
	    NULL == ciphertext || 0 == ciphertext_length ||
	    NULL == plaintext_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_key_id_t key = load_key_id(key_id);
	const psa_status_t status = psa_aead_decrypt(
		key, EDHOC_CIPHER_SUITE_PQC_1_CCM_ALG, nonce, nonce_length,
		additional_data, additional_data_length, ciphertext,
		ciphertext_length, plaintext, plaintext_size, plaintext_length);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("AEAD decryption: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int hash_init(void *user_context, void **operation)
{
	(void)user_context;

	if (NULL == operation) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	return hash_alloc(operation);
}

static int hash_update(void *user_context, void *operation,
		       const uint8_t *input, size_t input_length)
{
	(void)user_context;

	if (NULL == operation || NULL == input) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	OQS_SHA3_shake256_inc_absorb((OQS_SHA3_shake256_inc_ctx *)operation,
				     input, input_length);

	return EDHOC_SUCCESS;
}

static int hash_finish(void *user_context, void *operation, uint8_t *hash,
		       size_t hash_size, size_t *hash_length)
{
	(void)user_context;

	if (NULL == operation || NULL == hash || NULL == hash_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (hash_size < EDHOC_CIPHER_SUITE_PQC_1_HASH_LEN) {
		EDHOC_LOG_ERR("Hash buffer too small: %zu", hash_size);

		const int release_ret = hash_release(operation);

		if (EDHOC_SUCCESS != release_ret) {
			EDHOC_LOG_ERR("Release hash operation: %d",
				      release_ret);
		}

		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	OQS_SHA3_shake256_inc_finalize((OQS_SHA3_shake256_inc_ctx *)operation);
	OQS_SHA3_shake256_inc_squeeze(hash, EDHOC_CIPHER_SUITE_PQC_1_HASH_LEN,
				      (OQS_SHA3_shake256_inc_ctx *)operation);

	const int ret = hash_release(operation);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Release hash operation: %d", ret);
		return ret;
	}

	*hash_length = EDHOC_CIPHER_SUITE_PQC_1_HASH_LEN;

	return EDHOC_SUCCESS;
}

static int hash_abort(void *user_context, void *operation)
{
	(void)user_context;

	return hash_release(operation);
}

/* Module interface function definitions ----------------------------------- */

const struct edhoc_crypto *edhoc_cipher_suite_pqc_1_get_crypto(void)
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

const struct edhoc_cipher_suite *edhoc_cipher_suite_pqc_1_get_suite(void)
{
	static const struct edhoc_cipher_suite suite = {
		.value = EDHOC_CIPHER_SUITE_PQC_1_VALUE,
		.supports_dh_nike = false,
		.kem_encapsulation_key_length =
			EDHOC_CIPHER_SUITE_PQC_1_KEM_ENCAPSULATION_KEY_LEN,
		.kem_ciphertext_length =
			EDHOC_CIPHER_SUITE_PQC_1_KEM_CIPHERTEXT_LEN,
		.nike_key_length = 0,
		.sign_length = EDHOC_CIPHER_SUITE_PQC_1_SIG_LEN,
		.aead_key_length = EDHOC_CIPHER_SUITE_PQC_1_AEAD_KEY_LEN,
		.aead_tag_length = EDHOC_CIPHER_SUITE_PQC_1_AEAD_TAG_LEN,
		.aead_iv_length = EDHOC_CIPHER_SUITE_PQC_1_AEAD_IV_LEN,
		.hash_length = EDHOC_CIPHER_SUITE_PQC_1_HASH_LEN,
		.mac_length = EDHOC_CIPHER_SUITE_PQC_1_MAC_LEN,
	};

	return &suite;
}

int edhoc_cipher_suite_pqc_1_import_signing_key(const uint8_t *signing_key,
						size_t signing_key_length,
						void *key_id)
{
	if (NULL == signing_key || NULL == key_id) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_CIPHER_SUITE_PQC_1_SIG_SECRET_KEY_LEN != signing_key_length) {
		EDHOC_LOG_ERR("Invalid signing key length: %zu",
			      signing_key_length);
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	psa_key_id_t handle = PSA_KEY_ID_NULL;
	const int ret =
		keystore_store(signing_key, signing_key_length, &handle);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Store signing key: %d", ret);
		return ret;
	}

	store_key_id(key_id, handle);

	return EDHOC_SUCCESS;
}
