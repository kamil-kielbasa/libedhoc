/**
 * \file    edhoc_exp_pqc_cipher_suite_1.c
 * \author  Kamil Kielbasa
 * \brief   Experimental post-quantum cipher suite 1 (draft TBD1 from
 *          draft-spm-lake-pqsuites-02, ML-KEM-512 + ML-DSA-44).
 *
 *          Draft reference:
 *          https://datatracker.ietf.org/doc/html/draft-spm-lake-pqsuites-02
 *
 *          PQ primitives: liboqs. Symmetric AEAD: PSA (mbed TLS).
 *          SHAKE256 hash and KMAC256 extract/expand: liboqs SHA3 (RFC 9528 §4.1).
 *
 *          KMAC256 uses liboqs incremental SHA-3 with manual NIST SP 800-185
 *          encoding. liboqs has no public cSHAKE256/KMAC256 API; the cSHAKE
 *          domain-separation suffix (0x04) is applied via internal Keccak symbols.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */
#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libedhoc, CONFIG_LIBEDHOC_LOG_LEVEL);
#endif

#include "edhoc_exp_pqc_cipher_suite_1.h"

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "edhoc_macros.h"
#include "edhoc_backend_log.h"

#include <psa/crypto.h>
#include <oqs/oqs.h>
#include <oqs/sha3_ops.h>
#include "common/sha3/sha3.h"
#include "common/sha3/xkcp_low/KeccakP-1600/plain-64bits/KeccakP-1600-SnP.h"

/* Module defines ---------------------------------------------------------- */

#define EDHOC_EXP_PQC_CS1_VALUE (-1)

#define EDHOC_EXP_PQC_CS1_MAC_LEN ((size_t)16)

#define EDHOC_EXP_PQC_CS1_AEAD_KEY_LEN ((size_t)16)
#define EDHOC_EXP_PQC_CS1_AEAD_TAG_LEN ((size_t)16)
#define EDHOC_EXP_PQC_CS1_AEAD_IV_LEN ((size_t)13)

#define EDHOC_EXP_PQC_CS1_CCM_ALG                    \
	PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, \
					EDHOC_EXP_PQC_CS1_AEAD_TAG_LEN)

#define EDHOC_EXP_PQC_CS1_CSHAKE256_RATE ((uint32_t)136)
#define EDHOC_EXP_PQC_CS1_CSHAKE256_SUFFIX ((uint8_t)0x04)

#define EDHOC_EXP_PQC_CS1_KECCAK_INC_BYTEPOS_WORD ((size_t)25)
#define EDHOC_EXP_PQC_CS1_KECCAK_PAD_LAST_BYTE ((uint8_t)0x80)

#define EDHOC_EXP_PQC_CS1_KMAC_MAX_ENCODED_KEY_BITS ((size_t)256)
#define EDHOC_EXP_PQC_CS1_KMAC_LONG_KEY_DIGEST_LEN ((size_t)32)
#define EDHOC_EXP_PQC_CS1_KMAC_LEFT_ENCODE_MAX_LEN ((size_t)9)
#define EDHOC_EXP_PQC_CS1_KMAC_STRING_ENC_BUF_LEN ((size_t)16)
#define EDHOC_EXP_PQC_CS1_KMAC_KEY_BUF_LEN ((size_t)256)
#define EDHOC_EXP_PQC_CS1_KMAC_KEY_ENC_BUF_LEN \
	(EDHOC_EXP_PQC_CS1_KMAC_KEY_BUF_LEN +  \
	 EDHOC_EXP_PQC_CS1_KMAC_LEFT_ENCODE_MAX_LEN)
#define EDHOC_EXP_PQC_CS1_KMAC_PADDED_KEY_BUF_LEN     \
	(EDHOC_EXP_PQC_CS1_CSHAKE256_RATE +           \
	 EDHOC_EXP_PQC_CS1_KMAC_LEFT_ENCODE_MAX_LEN + \
	 EDHOC_EXP_PQC_CS1_KMAC_KEY_ENC_BUF_LEN)
#define EDHOC_EXP_PQC_CS1_KMAC_PREFIX_BUF_LEN         \
	(EDHOC_EXP_PQC_CS1_CSHAKE256_RATE +           \
	 EDHOC_EXP_PQC_CS1_KMAC_LEFT_ENCODE_MAX_LEN + \
	 (2U * EDHOC_EXP_PQC_CS1_KMAC_STRING_ENC_BUF_LEN))
#define EDHOC_EXP_PQC_CS1_KMAC_MSG_BUF_LEN           \
	(EDHOC_EXP_PQC_CS1_KMAC_PADDED_KEY_BUF_LEN + \
	 EDHOC_EXP_PQC_CS1_HASH_LEN +                \
	 EDHOC_EXP_PQC_CS1_KMAC_LEFT_ENCODE_MAX_LEN)

#define EDHOC_EXP_PQC_CS1_MAX_SLOTS ((size_t)2)
#define EDHOC_EXP_PQC_CS1_SLOT_HANDLE_BASE    \
	((psa_key_id_t)(PSA_KEY_ID_USER_MAX - \
			(EDHOC_EXP_PQC_CS1_MAX_SLOTS - 1U)))

/* Module types and type definitions -------------------------------------- */

struct exp_pqc_cs1_key_slot {
	bool in_use;
	enum edhoc_key_type key_type;
	uint8_t material[EDHOC_EXP_PQC_CS1_MLDSA44_SK_LEN];
	size_t material_len;
};

/* Module interface variables and constants -------------------------------- */

static struct exp_pqc_cs1_key_slot
	s_exp_pqc_cs1_slots[EDHOC_EXP_PQC_CS1_MAX_SLOTS];

/* Static function declarations -------------------------------------------- */

/** \brief Check whether a key handle refers to a static slot. */
static bool exp_pqc_cs1_is_slot_handle(psa_key_id_t handle);

/** \brief Resolve a static slot from a reserved PSA user key identifier. */
static struct exp_pqc_cs1_key_slot *
exp_pqc_cs1_slot_from_handle(psa_key_id_t handle);

/** \brief Allocate a static slot and return its PSA user key identifier. */
static int exp_pqc_cs1_slot_alloc(enum edhoc_key_type key_type,
				  psa_key_id_t *handle);

/** \brief Release a previously allocated static slot. */
static void exp_pqc_cs1_slot_free(psa_key_id_t handle);

/** \brief Export raw key material from a static slot or PSA key store. */
static int exp_pqc_cs1_export_raw_key(const void *kid, uint8_t *raw,
				      size_t raw_size, size_t *raw_len);

/** \brief Finalize incremental Keccak state for cSHAKE256 (suffix 0x04). */
static void exp_pqc_cs1_keccak_inc_finalize_cshake(void *ctx, uint32_t rate);

/** \brief NIST SP 800-185 left_encode helper. */
static int exp_pqc_cs1_left_encode(uint8_t *out, size_t out_size,
				   size_t *out_len, uint64_t value);

/** \brief NIST SP 800-185 encode_string helper. */
static int exp_pqc_cs1_encode_string(uint8_t *out, size_t out_size,
				     size_t *out_len, const uint8_t *str,
				     size_t str_len);

/** \brief NIST SP 800-185 bytepad helper. */
static int exp_pqc_cs1_bytepad(uint8_t *out, size_t out_size, size_t *out_len,
			       const uint8_t *in, size_t in_len, size_t block);

/** \brief cSHAKE256 via liboqs incremental SHA-3 (void API). */
static int exp_pqc_cs1_cshake256(const uint8_t *in, size_t in_len,
				 const char *func_name, const uint8_t *custom,
				 size_t custom_len, uint8_t *out,
				 size_t out_len);

/** \brief KMAC256 via cSHAKE256 (RFC 9528 Section 4.1 for SHAKE256 suite). */
static int exp_pqc_cs1_kmac256(const uint8_t *key, size_t key_len,
			       const uint8_t *in, size_t in_len,
			       const uint8_t *custom, size_t custom_len,
			       uint8_t *out, size_t out_bits);

/** \brief Import a key for experimental PQC cipher suite 1. */
static int exp_pqc_cs1_key_import(void *user_ctx, enum edhoc_key_type key_type,
				  const uint8_t *raw_key, size_t raw_key_len,
				  void *kid);

/** \brief Destroy a key for experimental PQC cipher suite 1. */
static int exp_pqc_cs1_key_destroy(void *user_ctx, void *kid);

/** \brief Generate an ML-KEM-512 ephemeral key pair. */
static int
exp_pqc_cs1_make_key_pair(void *user_ctx, const void *key_id,
			  uint8_t *private_key, size_t private_key_size,
			  size_t *private_key_length, uint8_t *public_key,
			  size_t public_key_size, size_t *public_key_length);

/** \brief ML-KEM-512 encapsulate (Responder). */
static int exp_pqc_cs1_encapsulate(void *user_ctx, const void *key_id,
				   const uint8_t *peer_public_key,
				   size_t peer_public_key_length,
				   uint8_t *ciphertext, size_t ciphertext_size,
				   size_t *ciphertext_length,
				   uint8_t *shared_secret,
				   size_t shared_secret_size,
				   size_t *shared_secret_length);

/** \brief ML-KEM-512 decapsulate (Initiator). */
static int exp_pqc_cs1_decapsulate(void *user_context, const void *key_id,
				   const uint8_t *ciphertext,
				   size_t ciphertext_length,
				   uint8_t *shared_secret,
				   size_t shared_secret_size,
				   size_t *shared_secret_length);

/** \brief ML-DSA-44 signature. */
static int exp_pqc_cs1_signature(void *user_context, const void *key_id,
				 const uint8_t *input, size_t input_length,
				 uint8_t *signature, size_t signature_size,
				 size_t *signature_length);

/** \brief ML-DSA-44 signature verification. */
static int exp_pqc_cs1_verify(void *user_context, const void *key_id,
			      const uint8_t *input, size_t input_length,
			      const uint8_t *signature,
			      size_t signature_length);

/** \brief SHAKE256 hash. */
static int exp_pqc_cs1_hash(void *user_context, const uint8_t *input,
			    size_t input_length, uint8_t *hash,
			    size_t hash_size, size_t *hash_length);

/** \brief KMAC256 extract (EDHOC_Extract). */
static int exp_pqc_cs1_extract(void *user_context, const void *key_id,
			       const uint8_t *salt, size_t salt_len,
			       uint8_t *pseudo_random_key,
			       size_t pseudo_random_key_size,
			       size_t *pseudo_random_key_length);

/** \brief KMAC256 expand (EDHOC_Expand). */
static int exp_pqc_cs1_expand(void *user_context, const void *key_id,
			      const uint8_t *info, size_t info_length,
			      uint8_t *output_keying_material,
			      size_t output_keying_material_length);

/** \brief AES-CCM-16-128-128 encrypt. */
static int exp_pqc_cs1_encrypt(void *user_context, const void *key_id,
			       const uint8_t *nonce, size_t nonce_length,
			       const uint8_t *additional_data,
			       size_t additional_data_length,
			       const uint8_t *plaintext,
			       size_t plaintext_length, uint8_t *ciphertext,
			       size_t ciphertext_size,
			       size_t *ciphertext_length);

/** \brief AES-CCM-16-128-128 decrypt. */
static int exp_pqc_cs1_decrypt(void *user_context, const void *key_id,
			       const uint8_t *nonce, size_t nonce_length,
			       const uint8_t *additional_data,
			       size_t additional_data_length,
			       const uint8_t *ciphertext,
			       size_t ciphertext_length, uint8_t *plaintext,
			       size_t plaintext_size, size_t *plaintext_length);

/* Static function definitions --------------------------------------------- */

static bool exp_pqc_cs1_is_slot_handle(psa_key_id_t handle)
{
	return handle >= EDHOC_EXP_PQC_CS1_SLOT_HANDLE_BASE &&
	       handle < EDHOC_EXP_PQC_CS1_SLOT_HANDLE_BASE +
				(psa_key_id_t)EDHOC_EXP_PQC_CS1_MAX_SLOTS;
}

static struct exp_pqc_cs1_key_slot *
exp_pqc_cs1_slot_from_handle(psa_key_id_t handle)
{
	if (!exp_pqc_cs1_is_slot_handle(handle))
		return NULL;

	const size_t index =
		(size_t)(handle - EDHOC_EXP_PQC_CS1_SLOT_HANDLE_BASE);

	if (index >= EDHOC_EXP_PQC_CS1_MAX_SLOTS ||
	    !s_exp_pqc_cs1_slots[index].in_use)
		return NULL;

	return &s_exp_pqc_cs1_slots[index];
}

static int exp_pqc_cs1_slot_alloc(enum edhoc_key_type key_type,
				  psa_key_id_t *handle)
{
	size_t i = 0;

	if (NULL == handle) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	for (i = 0; i < EDHOC_EXP_PQC_CS1_MAX_SLOTS; ++i) {
		if (!s_exp_pqc_cs1_slots[i].in_use) {
			s_exp_pqc_cs1_slots[i].in_use = true;
			s_exp_pqc_cs1_slots[i].key_type = key_type;
			s_exp_pqc_cs1_slots[i].material_len = 0;
			memset(s_exp_pqc_cs1_slots[i].material, 0,
			       sizeof(s_exp_pqc_cs1_slots[i].material));
			*handle = EDHOC_EXP_PQC_CS1_SLOT_HANDLE_BASE +
				  (psa_key_id_t)i;
			return EDHOC_SUCCESS;
		}
	}

	EDHOC_LOG_ERR("No free key slots");
	return EDHOC_ERROR_CRYPTO_FAILURE;
}

static void exp_pqc_cs1_slot_free(psa_key_id_t handle)
{
	struct exp_pqc_cs1_key_slot *slot =
		exp_pqc_cs1_slot_from_handle(handle);

	if (NULL == slot)
		return;

	memset(slot, 0, sizeof(*slot));
}

static int exp_pqc_cs1_export_raw_key(const void *kid, uint8_t *raw,
				      size_t raw_size, size_t *raw_len)
{
	if (NULL == kid || NULL == raw || NULL == raw_len) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_key_id_t handle = *(const psa_key_id_t *)kid;

	if (exp_pqc_cs1_is_slot_handle(handle)) {
		const struct exp_pqc_cs1_key_slot *slot =
			exp_pqc_cs1_slot_from_handle(handle);

		if (NULL == slot || 0 == slot->material_len) {
			EDHOC_LOG_ERR("Empty key slot");
			return EDHOC_ERROR_CRYPTO_FAILURE;
		}

		if (raw_size < slot->material_len) {
			EDHOC_LOG_ERR("Export buffer too small: %zu, %zu",
				      raw_size, slot->material_len);
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}

		memcpy(raw, slot->material, slot->material_len);
		*raw_len = slot->material_len;
		return EDHOC_SUCCESS;
	}

	const psa_status_t ret = psa_export_key(handle, raw, raw_size, raw_len);

	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Export key: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static void exp_pqc_cs1_keccak_inc_finalize_cshake(void *ctx, uint32_t rate)
{
	uint64_t *state = ctx;
	const unsigned int pos =
		(unsigned int)state[EDHOC_EXP_PQC_CS1_KECCAK_INC_BYTEPOS_WORD];

	KeccakP1600_AddByte(ctx, EDHOC_EXP_PQC_CS1_CSHAKE256_SUFFIX, pos);
	KeccakP1600_AddByte(ctx, EDHOC_EXP_PQC_CS1_KECCAK_PAD_LAST_BYTE,
			    (unsigned int)(rate - 1U));
	state[EDHOC_EXP_PQC_CS1_KECCAK_INC_BYTEPOS_WORD] = 0;
}

static int exp_pqc_cs1_left_encode(uint8_t *out, size_t out_size,
				   size_t *out_len, uint64_t value)
{
	uint8_t buf[8] = { 0 };
	size_t n = 0;
	size_t i = 0;

	if (0 == value) {
		if (out_size < 1) {
			EDHOC_LOG_ERR("Left encode buffer too small");
			return EDHOC_ERROR_BUFFER_TOO_SMALL;
		}
		out[0] = 0;
		*out_len = 1;
		return EDHOC_SUCCESS;
	}

	while (0 != value) {
		buf[n++] = (uint8_t)(value & 0xFF);
		value >>= 8;
	}

	if (out_size < n + 1) {
		EDHOC_LOG_ERR("Left encode buffer too small");
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	out[0] = (uint8_t)n;
	for (i = 0; i < n; ++i)
		out[1 + i] = buf[n - 1 - i];

	*out_len = n + 1;
	return EDHOC_SUCCESS;
}

static int exp_pqc_cs1_encode_string(uint8_t *out, size_t out_size,
				     size_t *out_len, const uint8_t *str,
				     size_t str_len)
{
	size_t len_enc_len = 0;
	int ret = exp_pqc_cs1_left_encode(out, out_size, &len_enc_len,
					  (uint64_t)(str_len * 8));

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Left encode string length");
		return ret;
	}

	if (out_size < len_enc_len + str_len) {
		EDHOC_LOG_ERR("Encode string buffer too small");
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	if (0 != str_len)
		memcpy(out + len_enc_len, str, str_len);

	*out_len = len_enc_len + str_len;
	return EDHOC_SUCCESS;
}

static int exp_pqc_cs1_bytepad(uint8_t *out, size_t out_size, size_t *out_len,
			       const uint8_t *in, size_t in_len, size_t block)
{
	size_t len_enc_len = 0;
	int ret = exp_pqc_cs1_left_encode(out, out_size, &len_enc_len, block);

	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Left encode block size");
		return ret;
	}

	if (out_size < len_enc_len + in_len) {
		EDHOC_LOG_ERR("Bytepad buffer too small");
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	memcpy(out + len_enc_len, in, in_len);

	const size_t padded = len_enc_len + in_len;
	const size_t pad_len = ((padded + block - 1) / block) * block;

	if (out_size < pad_len) {
		EDHOC_LOG_ERR("Bytepad padded buffer too small");
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	if (pad_len > padded)
		memset(out + padded, 0, pad_len - padded);

	*out_len = pad_len;
	return EDHOC_SUCCESS;
}

static int exp_pqc_cs1_cshake256(const uint8_t *in, size_t in_len,
				 const char *func_name, const uint8_t *custom,
				 size_t custom_len, uint8_t *out,
				 size_t out_len)
{
	uint8_t name_buf[EDHOC_EXP_PQC_CS1_KMAC_STRING_ENC_BUF_LEN] = { 0 };
	uint8_t custom_buf[EDHOC_EXP_PQC_CS1_KMAC_STRING_ENC_BUF_LEN] = { 0 };
	uint8_t prefix_buf[EDHOC_EXP_PQC_CS1_KMAC_PREFIX_BUF_LEN] = { 0 };
	uint8_t padded_prefix[EDHOC_EXP_PQC_CS1_KMAC_PREFIX_BUF_LEN] = { 0 };
	size_t name_len = 0;
	size_t custom_enc_len = 0;
	size_t prefix_len = 0;
	size_t padded_len = 0;
	OQS_SHA3_shake256_inc_ctx state = { 0 };
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	if (NULL == in || NULL == out || 0 == out_len || NULL == func_name) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	ret = exp_pqc_cs1_encode_string(name_buf, sizeof(name_buf), &name_len,
					(const uint8_t *)func_name,
					strlen(func_name));
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Encode function name");
		return ret;
	}

	if (NULL == custom)
		custom_len = 0;

	ret = exp_pqc_cs1_encode_string(custom_buf, sizeof(custom_buf),
					&custom_enc_len, custom, custom_len);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Encode customization string");
		return ret;
	}

	if (name_len + custom_enc_len > sizeof(prefix_buf)) {
		EDHOC_LOG_ERR("Prefix buffer too small");
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	memcpy(prefix_buf, name_buf, name_len);
	memcpy(prefix_buf + name_len, custom_buf, custom_enc_len);
	prefix_len = name_len + custom_enc_len;

	ret = exp_pqc_cs1_bytepad(padded_prefix, sizeof(padded_prefix),
				  &padded_len, prefix_buf, prefix_len,
				  EDHOC_EXP_PQC_CS1_CSHAKE256_RATE);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Bytepad prefix");
		return ret;
	}

	/* liboqs incremental SHA3 API is void; preconditions are checked above. */
	OQS_SHA3_shake256_inc_init(&state);
	OQS_SHA3_shake256_inc_absorb(&state, padded_prefix, padded_len);
	OQS_SHA3_shake256_inc_absorb(&state, in, in_len);
	exp_pqc_cs1_keccak_inc_finalize_cshake(
		state.ctx, EDHOC_EXP_PQC_CS1_CSHAKE256_RATE);
	OQS_SHA3_shake256_inc_squeeze(out, out_len, &state);
	OQS_SHA3_shake256_inc_ctx_release(&state);

	return EDHOC_SUCCESS;
}

static int exp_pqc_cs1_kmac256(const uint8_t *key, size_t key_len,
			       const uint8_t *in, size_t in_len,
			       const uint8_t *custom, size_t custom_len,
			       uint8_t *out, size_t out_bits)
{
	uint8_t key_buf[EDHOC_EXP_PQC_CS1_KMAC_KEY_BUF_LEN] = { 0 };
	uint8_t key_enc[EDHOC_EXP_PQC_CS1_KMAC_KEY_ENC_BUF_LEN] = { 0 };
	uint8_t padded_key[EDHOC_EXP_PQC_CS1_KMAC_PADDED_KEY_BUF_LEN] = { 0 };
	uint8_t msg_buf[EDHOC_EXP_PQC_CS1_KMAC_MSG_BUF_LEN] = { 0 };
	uint8_t right[EDHOC_EXP_PQC_CS1_KMAC_LEFT_ENCODE_MAX_LEN] = { 0 };
	size_t key_enc_len = 0;
	size_t padded_key_len = 0;
	size_t right_len = 0;
	size_t msg_len = 0;
	int ret = EDHOC_ERROR_GENERIC_ERROR;

	if (NULL == key || NULL == out || 0 == out_bits) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (key_len > sizeof(key_buf)) {
		EDHOC_LOG_ERR("Key too long: %zu", key_len);
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	memcpy(key_buf, key, key_len);

	if (key_len * 8 > EDHOC_EXP_PQC_CS1_KMAC_MAX_ENCODED_KEY_BITS) {
		ret = exp_pqc_cs1_cshake256(
			key_buf, key_len, "", NULL, 0, key_buf,
			EDHOC_EXP_PQC_CS1_KMAC_LONG_KEY_DIGEST_LEN);
		if (EDHOC_SUCCESS != ret) {
			EDHOC_LOG_ERR("KMAC key hash");
			return ret;
		}
		key_len = EDHOC_EXP_PQC_CS1_KMAC_LONG_KEY_DIGEST_LEN;
	}

	ret = exp_pqc_cs1_encode_string(key_enc, sizeof(key_enc), &key_enc_len,
					key_buf, key_len);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Encode KMAC key");
		return ret;
	}

	ret = exp_pqc_cs1_bytepad(padded_key, sizeof(padded_key),
				  &padded_key_len, key_enc, key_enc_len,
				  EDHOC_EXP_PQC_CS1_CSHAKE256_RATE);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Bytepad KMAC key");
		return ret;
	}

	ret = exp_pqc_cs1_left_encode(right, sizeof(right), &right_len,
				      out_bits);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Encode output length");
		return ret;
	}

	msg_len = padded_key_len + in_len + right_len;
	if (msg_len > sizeof(msg_buf)) {
		EDHOC_LOG_ERR("KMAC message too long: %zu", msg_len);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	memcpy(msg_buf, padded_key, padded_key_len);
	if (0 != in_len && NULL != in)
		memcpy(msg_buf + padded_key_len, in, in_len);
	memcpy(msg_buf + padded_key_len + in_len, right, right_len);

	return exp_pqc_cs1_cshake256(msg_buf, msg_len, "KMAC256", custom,
				     custom_len, out, out_bits / 8U);
}

static int exp_pqc_cs1_key_import(void *user_ctx, enum edhoc_key_type key_type,
				  const uint8_t *raw_key, size_t raw_key_len,
				  void *kid)
{
	(void)user_ctx;

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t *psa_kid = kid;

	if (NULL == kid) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	*psa_kid = PSA_KEY_HANDLE_INIT;

	switch (key_type) {
	case EDHOC_KT_MAKE_KEY_PAIR:
		return exp_pqc_cs1_slot_alloc(key_type, psa_kid);

	case EDHOC_KT_KEY_AGREEMENT:
		psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
		psa_set_key_type(&attr, PSA_KEY_TYPE_RAW_DATA);
		psa_set_key_bits(&attr, (size_t)PSA_BYTES_TO_BITS(raw_key_len));
		break;

	case EDHOC_KT_SIGNATURE:
		psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
		psa_set_key_type(&attr, PSA_KEY_TYPE_RAW_DATA);
		psa_set_key_bits(&attr, (size_t)PSA_BYTES_TO_BITS(raw_key_len));
		break;

	case EDHOC_KT_VERIFY:
		psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
		psa_set_key_type(&attr, PSA_KEY_TYPE_RAW_DATA);
		psa_set_key_bits(&attr, (size_t)PSA_BYTES_TO_BITS(raw_key_len));
		break;

	case EDHOC_KT_EXTRACT:
	case EDHOC_KT_EXPAND:
		psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
		psa_set_key_type(&attr, PSA_KEY_TYPE_RAW_DATA);
		psa_set_key_bits(&attr, (size_t)PSA_BYTES_TO_BITS(raw_key_len));
		break;

	case EDHOC_KT_ENCRYPT:
		psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
		psa_set_key_algorithm(&attr, EDHOC_EXP_PQC_CS1_CCM_ALG);
		psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
		psa_set_key_bits(&attr,
				 (size_t)PSA_BYTES_TO_BITS(
					 EDHOC_EXP_PQC_CS1_AEAD_KEY_LEN));
		break;

	case EDHOC_KT_DECRYPT:
		psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
		psa_set_key_algorithm(&attr, EDHOC_EXP_PQC_CS1_CCM_ALG);
		psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
		psa_set_key_bits(&attr,
				 (size_t)PSA_BYTES_TO_BITS(
					 EDHOC_EXP_PQC_CS1_AEAD_KEY_LEN));
		break;

	default:
		EDHOC_LOG_ERR("Unknown key type: %d", key_type);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	const psa_status_t psa_ret =
		psa_import_key(&attr, raw_key, raw_key_len, psa_kid);

	if (PSA_SUCCESS != psa_ret) {
		EDHOC_LOG_ERR("Import key: %d", psa_ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int exp_pqc_cs1_key_destroy(void *user_ctx, void *kid)
{
	(void)user_ctx;

	if (NULL == kid) {
		EDHOC_LOG_ERR("Invalid argument");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	psa_key_id_t *psa_kid = kid;

	if (exp_pqc_cs1_is_slot_handle(*psa_kid)) {
		exp_pqc_cs1_slot_free(*psa_kid);
		*psa_kid = PSA_KEY_HANDLE_INIT;
		return EDHOC_SUCCESS;
	}

	const psa_status_t ret = psa_destroy_key(*psa_kid);
	*psa_kid = PSA_KEY_HANDLE_INIT;

	if (PSA_SUCCESS != ret) {
		EDHOC_LOG_ERR("Destroy key: %d", ret);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int
exp_pqc_cs1_make_key_pair(void *user_ctx, const void *key_id,
			  uint8_t *private_key, size_t private_key_size,
			  size_t *private_key_length, uint8_t *public_key,
			  size_t public_key_size, size_t *public_key_length)
{
	(void)user_ctx;

	struct exp_pqc_cs1_key_slot *slot = NULL;

	if (NULL == key_id || NULL == private_key || 0 == private_key_size ||
	    NULL == private_key_length || NULL == public_key ||
	    0 == public_key_size || NULL == public_key_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_key_id_t handle = *(const psa_key_id_t *)key_id;

	slot = exp_pqc_cs1_slot_from_handle(handle);
	if (NULL == slot || EDHOC_KT_MAKE_KEY_PAIR != slot->key_type) {
		EDHOC_LOG_ERR("Invalid make_key_pair slot");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (private_key_size < EDHOC_EXP_PQC_CS1_MLKEM512_DK_LEN ||
	    public_key_size < EDHOC_EXP_PQC_CS1_MLKEM512_EK_LEN) {
		EDHOC_LOG_ERR("Invalid key sizes: %zu, %zu", private_key_size,
			      public_key_size);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	if (OQS_SUCCESS !=
	    OQS_KEM_ml_kem_512_keypair(public_key, private_key)) {
		EDHOC_LOG_ERR("ML-KEM keypair");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	memcpy(slot->material, private_key, EDHOC_EXP_PQC_CS1_MLKEM512_DK_LEN);
	slot->material_len = EDHOC_EXP_PQC_CS1_MLKEM512_DK_LEN;

	*public_key_length = EDHOC_EXP_PQC_CS1_MLKEM512_EK_LEN;
	*private_key_length = EDHOC_EXP_PQC_CS1_MLKEM512_DK_LEN;
	return EDHOC_SUCCESS;
}

static int exp_pqc_cs1_encapsulate(void *user_ctx, const void *key_id,
				   const uint8_t *peer_public_key,
				   size_t peer_public_key_length,
				   uint8_t *ciphertext, size_t ciphertext_size,
				   size_t *ciphertext_length,
				   uint8_t *shared_secret,
				   size_t shared_secret_size,
				   size_t *shared_secret_length)
{
	(void)user_ctx;
	(void)key_id;

	if (NULL == peer_public_key || NULL == ciphertext ||
	    NULL == ciphertext_length || NULL == shared_secret ||
	    NULL == shared_secret_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_EXP_PQC_CS1_MLKEM512_EK_LEN != peer_public_key_length) {
		EDHOC_LOG_ERR("Invalid encapsulation key length: %zu",
			      peer_public_key_length);
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (ciphertext_size < EDHOC_EXP_PQC_CS1_MLKEM512_CT_LEN ||
	    shared_secret_size < EDHOC_EXP_PQC_CS1_MLKEM512_SS_LEN) {
		EDHOC_LOG_ERR("Output buffer too small");
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	if (OQS_SUCCESS != OQS_KEM_ml_kem_512_encaps(ciphertext, shared_secret,
						     peer_public_key)) {
		EDHOC_LOG_ERR("ML-KEM encapsulate");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	*ciphertext_length = EDHOC_EXP_PQC_CS1_MLKEM512_CT_LEN;
	*shared_secret_length = EDHOC_EXP_PQC_CS1_MLKEM512_SS_LEN;
	return EDHOC_SUCCESS;
}

static int exp_pqc_cs1_decapsulate(void *user_context, const void *key_id,
				   const uint8_t *ciphertext,
				   size_t ciphertext_length,
				   uint8_t *shared_secret,
				   size_t shared_secret_size,
				   size_t *shared_secret_length)
{
	uint8_t decapsulation_key[EDHOC_EXP_PQC_CS1_MLKEM512_DK_LEN] = { 0 };
	size_t decapsulation_key_len = 0;
	int ret;

	(void)user_context;

	if (NULL == key_id || NULL == ciphertext || NULL == shared_secret ||
	    NULL == shared_secret_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_EXP_PQC_CS1_MLKEM512_CT_LEN != ciphertext_length) {
		EDHOC_LOG_ERR("Invalid ciphertext length: %zu",
			      ciphertext_length);
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (shared_secret_size < EDHOC_EXP_PQC_CS1_MLKEM512_SS_LEN) {
		EDHOC_LOG_ERR("Shared secret buffer too small");
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	ret = exp_pqc_cs1_export_raw_key(key_id, decapsulation_key,
					 sizeof(decapsulation_key),
					 &decapsulation_key_len);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Export decapsulation key");
		return ret;
	}

	if (EDHOC_EXP_PQC_CS1_MLKEM512_DK_LEN != decapsulation_key_len) {
		EDHOC_LOG_ERR("Invalid decapsulation key length: %zu",
			      decapsulation_key_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	if (OQS_SUCCESS != OQS_KEM_ml_kem_512_decaps(shared_secret, ciphertext,
						     decapsulation_key)) {
		EDHOC_LOG_ERR("ML-KEM decapsulate");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	*shared_secret_length = EDHOC_EXP_PQC_CS1_MLKEM512_SS_LEN;
	return EDHOC_SUCCESS;
}

static int exp_pqc_cs1_signature(void *user_context, const void *key_id,
				 const uint8_t *input, size_t input_length,
				 uint8_t *signature, size_t signature_size,
				 size_t *signature_length)
{
	uint8_t signing_key[EDHOC_EXP_PQC_CS1_MLDSA44_SK_LEN] = { 0 };
	size_t signing_key_len = 0;
	int ret;

	(void)user_context;

	if (NULL == key_id || NULL == input || NULL == signature ||
	    NULL == signature_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (signature_size < EDHOC_EXP_PQC_CS1_MLDSA44_SIG_LEN) {
		EDHOC_LOG_ERR("Signature buffer too small: %zu",
			      signature_size);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	ret = exp_pqc_cs1_export_raw_key(key_id, signing_key,
					 sizeof(signing_key), &signing_key_len);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Export signing key");
		return ret;
	}

	if (EDHOC_EXP_PQC_CS1_MLDSA44_SK_LEN != signing_key_len) {
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

static int exp_pqc_cs1_verify(void *user_context, const void *key_id,
			      const uint8_t *input, size_t input_length,
			      const uint8_t *signature, size_t signature_length)
{
	uint8_t verification_key[EDHOC_EXP_PQC_CS1_MLDSA44_PK_LEN] = { 0 };
	size_t verification_key_len = 0;
	int ret;

	(void)user_context;

	if (NULL == key_id || NULL == input || NULL == signature) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	ret = exp_pqc_cs1_export_raw_key(key_id, verification_key,
					 sizeof(verification_key),
					 &verification_key_len);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Export verification key");
		return ret;
	}

	if (EDHOC_EXP_PQC_CS1_MLDSA44_PK_LEN != verification_key_len) {
		EDHOC_LOG_ERR("Invalid verification key length: %zu",
			      verification_key_len);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	if (OQS_SUCCESS != OQS_SIG_ml_dsa_44_verify(input, input_length,
						    signature, signature_length,
						    verification_key)) {
		EDHOC_LOG_ERR("ML-DSA verify");
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int exp_pqc_cs1_hash(void *user_context, const uint8_t *input,
			    size_t input_length, uint8_t *hash,
			    size_t hash_size, size_t *hash_length)
{
	(void)user_context;

	if (NULL == input || NULL == hash || NULL == hash_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (hash_size < EDHOC_EXP_PQC_CS1_HASH_LEN) {
		EDHOC_LOG_ERR("Hash buffer too small: %zu", hash_size);
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	OQS_SHA3_shake256(hash, EDHOC_EXP_PQC_CS1_HASH_LEN, input,
			  input_length);
	*hash_length = EDHOC_EXP_PQC_CS1_HASH_LEN;
	return EDHOC_SUCCESS;
}

static int exp_pqc_cs1_extract(void *user_context, const void *key_id,
			       const uint8_t *salt, size_t salt_len,
			       uint8_t *pseudo_random_key,
			       size_t pseudo_random_key_size,
			       size_t *pseudo_random_key_length)
{
	uint8_t input_key_material[EDHOC_EXP_PQC_CS1_KMAC_KEY_BUF_LEN] = { 0 };
	size_t input_key_material_len = 0;
	int ret;

	(void)user_context;

	if (NULL == key_id || NULL == salt || 0 == salt_len ||
	    NULL == pseudo_random_key || NULL == pseudo_random_key_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (pseudo_random_key_size < EDHOC_EXP_PQC_CS1_HASH_LEN) {
		EDHOC_LOG_ERR("PRK buffer too small");
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}

	ret = exp_pqc_cs1_export_raw_key(key_id, input_key_material,
					 sizeof(input_key_material),
					 &input_key_material_len);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Export input key material");
		return ret;
	}

	ret = exp_pqc_cs1_kmac256(salt, salt_len, input_key_material,
				  input_key_material_len, NULL, 0,
				  pseudo_random_key,
				  EDHOC_EXP_PQC_CS1_HASH_LEN * 8);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("KMAC extract");
		return ret;
	}

	*pseudo_random_key_length = EDHOC_EXP_PQC_CS1_HASH_LEN;
	return EDHOC_SUCCESS;
}

static int exp_pqc_cs1_expand(void *user_context, const void *key_id,
			      const uint8_t *info, size_t info_length,
			      uint8_t *output_keying_material,
			      size_t output_keying_material_length)
{
	uint8_t prk[EDHOC_EXP_PQC_CS1_HASH_LEN] = { 0 };
	size_t prk_len = 0;
	int ret;

	(void)user_context;

	if (NULL == key_id || NULL == info || 0 == info_length ||
	    NULL == output_keying_material ||
	    0 == output_keying_material_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	ret = exp_pqc_cs1_export_raw_key(key_id, prk, sizeof(prk), &prk_len);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("Export PRK");
		return ret;
	}

	ret = exp_pqc_cs1_kmac256(prk, prk_len, info, info_length, NULL, 0,
				  output_keying_material,
				  output_keying_material_length * 8U);
	if (EDHOC_SUCCESS != ret) {
		EDHOC_LOG_ERR("KMAC expand");
		return ret;
	}

	return EDHOC_SUCCESS;
}

static int exp_pqc_cs1_encrypt(void *user_context, const void *key_id,
			       const uint8_t *nonce, size_t nonce_length,
			       const uint8_t *additional_data,
			       size_t additional_data_length,
			       const uint8_t *plaintext,
			       size_t plaintext_length, uint8_t *ciphertext,
			       size_t ciphertext_size,
			       size_t *ciphertext_length)
{
	(void)user_context;

	if (NULL == key_id || NULL == nonce || NULL == ciphertext ||
	    NULL == ciphertext_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_key_id_t key = *(const psa_key_id_t *)key_id;
	const psa_status_t status = psa_aead_encrypt(
		key, EDHOC_EXP_PQC_CS1_CCM_ALG, nonce, nonce_length,
		additional_data, additional_data_length, plaintext,
		plaintext_length, ciphertext, ciphertext_size,
		ciphertext_length);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("AEAD encryption: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static int exp_pqc_cs1_decrypt(void *user_context, const void *key_id,
			       const uint8_t *nonce, size_t nonce_length,
			       const uint8_t *additional_data,
			       size_t additional_data_length,
			       const uint8_t *ciphertext,
			       size_t ciphertext_length, uint8_t *plaintext,
			       size_t plaintext_size, size_t *plaintext_length)
{
	(void)user_context;

	if (NULL == key_id || NULL == nonce || NULL == ciphertext ||
	    NULL == plaintext || NULL == plaintext_length) {
		EDHOC_LOG_ERR("Invalid arguments");
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	const psa_key_id_t key = *(const psa_key_id_t *)key_id;
	const psa_status_t status = psa_aead_decrypt(
		key, EDHOC_EXP_PQC_CS1_CCM_ALG, nonce, nonce_length,
		additional_data, additional_data_length, ciphertext,
		ciphertext_length, plaintext, plaintext_size, plaintext_length);

	if (PSA_SUCCESS != status) {
		EDHOC_LOG_ERR("AEAD decryption: %d", status);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	return EDHOC_SUCCESS;
}

static const struct edhoc_keys edhoc_exp_pqc_cipher_suite_1_keys = {
	.import_key = exp_pqc_cs1_key_import,
	.destroy_key = exp_pqc_cs1_key_destroy,
};

static const struct edhoc_crypto_pqc edhoc_exp_pqc_cipher_suite_1_crypto = {
	.make_key_pair = exp_pqc_cs1_make_key_pair,
	.encapsulate = exp_pqc_cs1_encapsulate,
	.decapsulate = exp_pqc_cs1_decapsulate,
	.signature = exp_pqc_cs1_signature,
	.verify = exp_pqc_cs1_verify,
	.extract = exp_pqc_cs1_extract,
	.expand = exp_pqc_cs1_expand,
	.encrypt = exp_pqc_cs1_encrypt,
	.decrypt = exp_pqc_cs1_decrypt,
	.hash = exp_pqc_cs1_hash,
};

static const struct edhoc_cipher_suite_pqc edhoc_exp_pqc_cipher_suite_1_suite = {
	.value = EDHOC_EXP_PQC_CS1_VALUE,
	.aead_key_length = EDHOC_EXP_PQC_CS1_AEAD_KEY_LEN,
	.aead_tag_length = EDHOC_EXP_PQC_CS1_AEAD_TAG_LEN,
	.aead_iv_length = EDHOC_EXP_PQC_CS1_AEAD_IV_LEN,
	.hash_length = EDHOC_EXP_PQC_CS1_HASH_LEN,
	.mac_length = EDHOC_EXP_PQC_CS1_MAC_LEN,
	.kem_public_key_length = EDHOC_EXP_PQC_CS1_MLKEM512_EK_LEN,
	.kem_private_key_length = EDHOC_EXP_PQC_CS1_MLKEM512_DK_LEN,
	.kem_ciphertext_length = EDHOC_EXP_PQC_CS1_MLKEM512_CT_LEN,
	.kem_shared_secret_length = EDHOC_EXP_PQC_CS1_MLKEM512_SS_LEN,
	.signature_length = EDHOC_EXP_PQC_CS1_MLDSA44_SIG_LEN,
};

/* Module interface function definitions ----------------------------------- */

const struct edhoc_keys *edhoc_exp_pqc_cipher_suite_1_get_keys(void)
{
	return &edhoc_exp_pqc_cipher_suite_1_keys;
}

const struct edhoc_crypto_pqc *edhoc_exp_pqc_cipher_suite_1_get_crypto(void)
{
	return &edhoc_exp_pqc_cipher_suite_1_crypto;
}

const struct edhoc_cipher_suite_pqc *
edhoc_exp_pqc_cipher_suite_1_get_suite(void)
{
	return &edhoc_exp_pqc_cipher_suite_1_suite;
}
