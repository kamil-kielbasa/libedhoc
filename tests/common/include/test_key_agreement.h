/**
 * \file    test_key_agreement.h
 * \author  Kamil Kielbasa
 * \brief   Shared test helper: prove two EDHOC peers share a key-slot handle.
 *
 * \copyright Copyright (c) 2026
 *
 */

#ifndef TEST_KEY_AGREEMENT_H
#define TEST_KEY_AGREEMENT_H

/* Include files ----------------------------------------------------------- */

/* EDHOC library-internal context (white-box: key_slots, slot identifiers): */
#include "edhoc_context_internal.h"

/* EDHOC public headers: */
#include <edhoc/edhoc_cipher_suite.h>
#include <edhoc/edhoc_crypto.h>
#include <edhoc/edhoc_values.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Unity headers: */
#include <unity.h>

/* Defines ----------------------------------------------------------------- */

/**
 * \brief Number of expand_raw output bytes compared to prove two key-slot
 *        handles hold identical key material (any nonzero length reliably
 *        detects a mismatch).
 */
#define TEST_SLOT_KEY_CHECK_LENGTH (32)

/* Module interface function definitions ----------------------------------- */

/**
 * \brief Assert that both EDHOC peers hold the same key material in \p slot.
 *
 *        A derived key lives only as a non-exportable key-store handle, so the
 *        two peers can no longer byte-compare the raw shared secret / PRK.
 *        Running the same KDF (expand_raw) over each peer's slot handle yields
 *        identical output iff the underlying key material matches - the
 *        handle-model equivalent of the old raw-secret comparison.
 *
 *        The slot must hold a live, HKDF-expandable key (the PRK slots) on both
 *        peers; ephemeral / DH-agreement / transient-exporter slots do not
 *        apply (each peer's ephemeral differs, DH-agreement outputs are not
 *        HKDF keys, and PRK_exporter is destroyed inside each export call).
 *
 * \param suite                         Cipher suite whose crypto probes the slot.
 * \param[in] lhs                       First EDHOC context.
 * \param[in] rhs                       Second EDHOC context.
 * \param slot                          Key slot to compare across both peers.
 */
static inline void
test_assert_peers_share_slot_key(enum edhoc_cipher_suite_id suite,
				 const struct edhoc_context *lhs,
				 const struct edhoc_context *rhs,
				 enum edhoc_key_slot_id slot)
{
	const struct edhoc_crypto *crypto = edhoc_cipher_suite_get_crypto(suite);
	static const uint8_t info[] = { 'k', 'e', 'y', '-', 'c',
					'h', 'e', 'c', 'k' };
	uint8_t lhs_okm[TEST_SLOT_KEY_CHECK_LENGTH] = { 0 };
	uint8_t rhs_okm[TEST_SLOT_KEY_CHECK_LENGTH] = { 0 };

	TEST_ASSERT_NOT_NULL(crypto);
	TEST_ASSERT_TRUE(lhs->key_slots[slot].present);
	TEST_ASSERT_TRUE(rhs->key_slots[slot].present);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  crypto->expand_raw(NULL, lhs->key_slots[slot].key_id,
					     info, sizeof(info), lhs_okm,
					     sizeof(lhs_okm)));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  crypto->expand_raw(NULL, rhs->key_slots[slot].key_id,
					     info, sizeof(info), rhs_okm,
					     sizeof(rhs_okm)));
	TEST_ASSERT_EQUAL_UINT8_ARRAY(lhs_okm, rhs_okm, sizeof(lhs_okm));
}

#endif /* TEST_KEY_AGREEMENT_H */
