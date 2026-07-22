/**
 * \file    test_rfc9529_support.h
 * \author  Kamil Kielbasa
 * \brief   Shared helpers for the RFC 9529 known-answer (KAT) tests.
 *
 *          A derived key now lives only as a non-exportable key-store handle,
 *          so the RFC 9529 trace tests can no longer memcpy raw secrets into or
 *          out of the EDHOC context. These helpers bridge the gap:
 *            - import a fixed vector value as a key-store handle with the exact
 *              suite-0 attributes (ephemeral X25519 or HKDF derive key),
 *            - inject such a handle into an EDHOC key slot (isolated-step
 *              pre-condition),
 *            - verify an (ephemeral, peer-public) agreement equals the RFC
 *              shared secret,
 *            - verify a slot handle equals an RFC vector via an HKDF-Expand
 *              probe, without ever exporting the key.
 *
 * \copyright Copyright (c) 2026
 *
 */

#ifndef TEST_RFC9529_SUPPORT_H
#define TEST_RFC9529_SUPPORT_H

/* Expose the TF-PSA-Crypto builtin ECP/bignum prototypes (mbedtls_ecp_*,
 * mbedtls_mpi_*) that tv_p256_uncompress needs. These live behind
 * MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS in the builtin headers, so it must be
 * defined before any PSA or mbedTLS header is parsed in the translation unit.
 * This header is the first to pull them in: no EDHOC public header includes
 * <psa/crypto.h>. */
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

/* Include files ----------------------------------------------------------- */

/* EDHOC library-internal context (white-box: key_slots, slot identifiers): */
#include "edhoc_context_internal.h"

/* EDHOC public headers: */
#include <edhoc/cipher_suite.h>
#include <edhoc/crypto.h>
#include <edhoc/values.h>

/* PSA crypto headers: */
#include <psa/crypto.h>

/* mbedTLS low-level ECP/bignum (P-256 peer-point decompression for the KAT
 * shared-secret cross-check): */
#include <mbedtls/private/ecp.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Unity headers: */
#include <unity.h>

/* Defines ----------------------------------------------------------------- */

/**
 * \brief Number of expand_raw output bytes compared to prove two key-slot
 *        handles hold identical key material, and the maximum shared-secret
 *        length compared by \ref tv_check_shared_secret (suite 0 is 32 bytes).
 */
#define TEST_RFC9529_OKM_LEN (32)

/**
 * \brief Length of an uncompressed SECP_R1 (P-256) point: \c 0x04||X||Y.
 */
#define TEST_P256_UNCOMPRESSED_LEN (65)

/* Module interface function definitions ----------------------------------- */

/**
 * \brief Import an X25519 ephemeral private scalar (\c X / \c Y) as a volatile
 *        ECDH key-store handle.
 *
 * \param[in] scalar                    Raw 32-byte Montgomery private scalar.
 * \param scalar_len                    Length of \p scalar in bytes.
 *
 * \return Volatile key-store handle owning the imported private key.
 */
static inline psa_key_id_t tv_import_x25519(const uint8_t *scalar,
					    size_t scalar_len)
{
	TEST_ASSERT_NOT_NULL(scalar);
	TEST_ASSERT_NOT_EQUAL(0, scalar_len);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	const psa_status_t status =
		psa_import_key(&attr, scalar, scalar_len, &kid);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

	return kid;
}

/**
 * \brief Import a P-256 ephemeral / static-DH private scalar as a volatile
 *        ECDH key-store handle (cipher suite 2).
 *
 * \param[in] scalar                    Raw 32-byte SECP_R1 private scalar.
 * \param scalar_len                    Length of \p scalar in bytes.
 *
 * \return Volatile key-store handle owning the imported private key.
 */
static inline psa_key_id_t tv_import_p256(const uint8_t *scalar,
					  size_t scalar_len)
{
	TEST_ASSERT_NOT_NULL(scalar);
	TEST_ASSERT_NOT_EQUAL(0, scalar_len);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	const psa_status_t status =
		psa_import_key(&attr, scalar, scalar_len, &kid);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

	return kid;
}

/**
 * \brief Import raw bytes (shared secret / pseudorandom key) as a volatile
 *        HKDF derive key-store handle, using the suite-0 derive-key attributes
 *        so the library and \c expand_raw can consume it.
 *
 * \param[in] bytes                     Raw key material.
 * \param bytes_len                     Length of \p bytes in bytes.
 *
 * \return Volatile key-store handle owning the imported derive key.
 */
static inline psa_key_id_t tv_import_derive(const uint8_t *bytes,
					    size_t bytes_len)
{
	TEST_ASSERT_NOT_NULL(bytes);
	TEST_ASSERT_NOT_EQUAL(0, bytes_len);

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
	psa_set_key_enrollment_algorithm(&attr,
					 PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));

	psa_key_id_t kid = PSA_KEY_ID_NULL;
	const psa_status_t status =
		psa_import_key(&attr, bytes, bytes_len, &kid);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

	return kid;
}

/**
 * \brief White-box injection: store a live key-store handle into an EDHOC key
 *        slot (a pre-condition for an isolated message-step test).
 *
 * \param[in,out] ctx                   EDHOC context to inject into.
 * \param slot                          Destination key slot.
 * \param kid                           Live key-store handle to store.
 */
static inline void tv_inject_slot(struct edhoc_context *ctx,
				  enum edhoc_key_slot_id slot, psa_key_id_t kid)
{
	TEST_ASSERT_NOT_NULL(ctx);
	TEST_ASSERT_TRUE(slot < EDHOC_KEY_SLOT_COUNT);

	memcpy(ctx->key_slots[slot].key_id, &kid, sizeof(kid));
	ctx->key_slots[slot].present = true;
}

/**
 * \brief Decompress a P-256 (SECP_R1) x-coordinate into a full uncompressed
 *        point \c 0x04||X||Y.
 *
 *        This is a faithful port of the library's own \c mbedtls_ecp_decompress()
 *        (see \c library/cipher_suites/cipher_suite_2/edhoc_cipher_suite_2.c):
 *        the same short-Weierstrass recovery of \c y from
 *        \c y^2 = x^3 + ax + b over the field \c P, using
 *        \c y = (x^3 + ax + b)^{(P+1)/4} mod P (valid because \c P == 3 (mod 4),
 *        which holds for P-256). The only intentional differences are that this
 *        copy loads the SECP_R1 group itself and reports failures with Unity
 *        assertions instead of the \c MBEDTLS_MPI_CHK / \c goto idiom.
 *
 *        \ref tv_check_shared_secret needs a full uncompressed point because
 *        EDHOC transmits a P-256 ephemeral as its 32-byte x-coordinate only.
 *
 * \param[in] raw_key                   Raw SECP_R1 x-coordinate (32 bytes).
 * \param raw_key_len                   Length of \p raw_key in bytes.
 * \param[out] decomp_key               Buffer for the uncompressed point.
 * \param decomp_key_size               Size of \p decomp_key in bytes (>= 65).
 * \param[out] decomp_key_len           On success, the uncompressed length (65).
 */
static inline void tv_p256_uncompress(const uint8_t *raw_key,
				      size_t raw_key_len, uint8_t *decomp_key,
				      size_t decomp_key_size,
				      size_t *decomp_key_len)
{
	TEST_ASSERT_NOT_NULL(raw_key);
	TEST_ASSERT_NOT_EQUAL(0, raw_key_len);
	TEST_ASSERT_NOT_NULL(decomp_key);
	TEST_ASSERT_NOT_NULL(decomp_key_len);

	mbedtls_ecp_group grp;
	mbedtls_ecp_group_init(&grp);
	TEST_ASSERT_EQUAL(0, mbedtls_ecp_group_load(&grp,
						    MBEDTLS_ECP_DP_SECP256R1));

	const size_t p_len = mbedtls_mpi_size(&grp.P);

	*decomp_key_len = (2 * p_len) + 1;
	TEST_ASSERT_TRUE(decomp_key_size >= *decomp_key_len);
	TEST_ASSERT_EQUAL(p_len, raw_key_len);

	/* decomp_key will consist of 0x04 | X | Y. */
	memcpy(&decomp_key[1], raw_key, raw_key_len);
	decomp_key[0] = 0x04;

	mbedtls_mpi r;
	mbedtls_mpi x;
	mbedtls_mpi n;
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&x);
	mbedtls_mpi_init(&n);

	/* x <= raw_key */
	TEST_ASSERT_EQUAL(0, mbedtls_mpi_read_binary(&x, raw_key, p_len));

	/* r = x^2 */
	TEST_ASSERT_EQUAL(0, mbedtls_mpi_mul_mpi(&r, &x, &x));

	/* r = x^2 + a */
	if (NULL == grp.A.MBEDTLS_PRIVATE(p)) {
		/* Special case where a is -3 (e.g. P-256). */
		TEST_ASSERT_EQUAL(0, mbedtls_mpi_sub_int(&r, &r, 3));
	} else {
		TEST_ASSERT_EQUAL(0, mbedtls_mpi_add_mpi(&r, &r, &grp.A));
	}

	/* r = x^3 + ax */
	TEST_ASSERT_EQUAL(0, mbedtls_mpi_mul_mpi(&r, &r, &x));

	/* r = x^3 + ax + b */
	TEST_ASSERT_EQUAL(0, mbedtls_mpi_add_mpi(&r, &r, &grp.B));

	/* Square root of r over the field P:
	 *   r = sqrt(x^3 + ax + b) = (x^3 + ax + b) ^ ((P + 1) / 4) (mod P) */

	/* n = P + 1 */
	TEST_ASSERT_EQUAL(0, mbedtls_mpi_add_int(&n, &grp.P, 1));

	/* n = (P + 1) / 4 */
	TEST_ASSERT_EQUAL(0, mbedtls_mpi_shift_r(&n, 2));

	/* r = r ^ ((P + 1) / 4) (mod P) */
	TEST_ASSERT_EQUAL(0, mbedtls_mpi_exp_mod(&r, &r, &n, &grp.P, NULL));

	/* Select the root with the matching parity, exactly as the library
	 * does. Either root gives the same ECDH shared-secret x-coordinate, so
	 * for this cross-check the specific choice does not matter. */
	if ((raw_key[0] == 0x03) != mbedtls_mpi_get_bit(&r, 0)) {
		/* r = P - r */
		TEST_ASSERT_EQUAL(0, mbedtls_mpi_sub_mpi(&r, &grp.P, &r));
	}

	/* y => decomp_key */
	TEST_ASSERT_EQUAL(
		0, mbedtls_mpi_write_binary(&r, &decomp_key[1 + p_len], p_len));

	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&x);
	mbedtls_mpi_free(&n);
	mbedtls_ecp_group_free(&grp);
}

/**
 * \brief Verify that the ECDH agreement of \p priv with \p peer_pub equals the
 *        RFC's shared secret vector (\c G_XY).
 *
 *        Used inside the deterministic \c encapsulate / \c decapsulate
 *        overrides, where the shared secret is still available before the
 *        library releases it at the end of the message-2 step.
 *
 * \param priv                          Ephemeral private key-store handle.
 * \param[in] peer_pub                  Peer ephemeral public value.
 * \param peer_pub_len                  Length of \p peer_pub in bytes.
 * \param[in] g_xy                      Expected shared secret (RFC vector).
 * \param g_xy_len                      Length of \p g_xy in bytes.
 */
static inline void tv_check_shared_secret(psa_key_id_t priv,
					  const uint8_t *peer_pub,
					  size_t peer_pub_len,
					  const uint8_t *g_xy, size_t g_xy_len)
{
	TEST_ASSERT_NOT_NULL(peer_pub);
	TEST_ASSERT_NOT_EQUAL(0, peer_pub_len);
	TEST_ASSERT_NOT_NULL(g_xy);
	TEST_ASSERT_TRUE(0 != g_xy_len && g_xy_len <= TEST_RFC9529_OKM_LEN);

	uint8_t raw[TEST_RFC9529_OKM_LEN] = { 0 };
	size_t raw_len = 0;

	const psa_status_t status =
		psa_raw_key_agreement(PSA_ALG_ECDH, priv, peer_pub,
				      peer_pub_len, raw, sizeof(raw), &raw_len);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);

	TEST_ASSERT_EQUAL(g_xy_len, raw_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(g_xy, raw, g_xy_len);
}

/**
 * \brief Assert that the key material in \p slot equals an RFC vector.
 *
 *        A derived key is a non-exportable handle, so the value is compared
 *        indirectly: running the same HKDF-Expand over the slot handle and over
 *        an imported reference of \p ref yields identical output iff the key
 *        material matches.
 *
 * \param suite                         Cipher suite whose crypto probes the slot.
 * \param[in] ctx                       EDHOC context holding the slot.
 * \param slot                          Key slot to compare.
 * \param[in] ref                       Expected key material (RFC vector).
 * \param ref_len                       Length of \p ref in bytes.
 */
static inline void tv_assert_slot_equals_vector(
	enum edhoc_cipher_suite_id suite, const struct edhoc_context *ctx,
	enum edhoc_key_slot_id slot, const uint8_t *ref, size_t ref_len)
{
	TEST_ASSERT_NOT_NULL(ctx);
	TEST_ASSERT_TRUE(slot < EDHOC_KEY_SLOT_COUNT);
	TEST_ASSERT_NOT_NULL(ref);
	TEST_ASSERT_NOT_EQUAL(0, ref_len);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite);
	static const uint8_t info[] = { 'k', 'e', 'y', '-', 'c',
					'h', 'e', 'c', 'k' };
	uint8_t okm_ctx[TEST_RFC9529_OKM_LEN] = { 0 };
	uint8_t okm_ref[TEST_RFC9529_OKM_LEN] = { 0 };

	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_TRUE(ctx->key_slots[slot].present);

	const psa_key_id_t ref_kid = tv_import_derive(ref, ref_len);

	int ret = crypto->expand_raw(NULL, ctx->key_slots[slot].key_id, info,
				     sizeof(info), okm_ctx, sizeof(okm_ctx));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = crypto->expand_raw(NULL, &ref_kid, info, sizeof(info), okm_ref,
				 sizeof(okm_ref));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(okm_ref, okm_ctx, sizeof(okm_ctx));

	const psa_status_t status = psa_destroy_key(ref_kid);
	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

/**
 * \brief Assert that two caller-owned key handles hold the same key material.
 *
 *        A derived key handle is not exportable. The OSCORE master secret is
 *        exported as an AEAD key handle, so equality is proven by encrypting a
 *        fixed input with each handle through the suite's crypto vtable
 *        (aead_encrypt) and comparing the ciphertexts: they match iff the
 *        underlying keys match. Used to check that two peers derived the same
 *        OSCORE master-secret handle from \c edhoc_export_oscore_session.
 *
 * \param suite                         Cipher suite of the handles.
 * \param[in] key_id_a                  First caller-owned key handle buffer.
 * \param[in] key_id_b                  Second caller-owned key handle buffer.
 */
static inline void tv_assert_handles_equal(enum edhoc_cipher_suite_id suite,
					   const uint8_t *key_id_a,
					   const uint8_t *key_id_b)
{
	TEST_ASSERT_NOT_NULL(key_id_a);
	TEST_ASSERT_NOT_NULL(key_id_b);

	const struct edhoc_crypto *crypto =
		edhoc_cipher_suite_get_crypto(suite);
	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_NOT_NULL(crypto->aead_encrypt);

	const struct edhoc_cipher_suite *params =
		edhoc_cipher_suite_get_params(suite);
	TEST_ASSERT_NOT_NULL(params);

	uint8_t nonce[16] = { 0 };
	const size_t nonce_len = params->aead_iv_length;
	TEST_ASSERT_NOT_EQUAL(0, nonce_len);
	TEST_ASSERT_TRUE(nonce_len <= sizeof(nonce));

	/* The crypto vtable AEAD requires non-empty associated data. */
	static const uint8_t aad[] = { 'h', 'a', 'n', 'd', 'l',
				       'e', '-', 'e', 'q' };
	static const uint8_t plaintext[16] = { 0 };
	uint8_t ct_a[sizeof(plaintext) + 16] = { 0 };
	uint8_t ct_b[sizeof(plaintext) + 16] = { 0 };
	size_t ct_a_len = 0;
	size_t ct_b_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  crypto->aead_encrypt(NULL, key_id_a, nonce, nonce_len,
					       aad, sizeof(aad), plaintext,
					       sizeof(plaintext), ct_a,
					       sizeof(ct_a), &ct_a_len));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  crypto->aead_encrypt(NULL, key_id_b, nonce, nonce_len,
					       aad, sizeof(aad), plaintext,
					       sizeof(plaintext), ct_b,
					       sizeof(ct_b), &ct_b_len));

	TEST_ASSERT_EQUAL(ct_a_len, ct_b_len);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(ct_a, ct_b, ct_a_len);
}

#endif /* TEST_RFC9529_SUPPORT_H */
