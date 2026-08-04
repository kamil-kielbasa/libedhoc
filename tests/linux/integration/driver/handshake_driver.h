/**
 * \file    handshake_driver.h
 * \author  Kamil Kielbasa
 * \brief   Parametrized full-EDHOC-handshake test driver.
 *
 *          \ref run_handshake drives the full EDHOC message spine between two
 *          fresh contexts and asserts the protocol invariants and key
 *          agreement end to end. Everything that varies between scenarios
 *          (methods, cipher suites, platform, connection ids, credentials, EAD)
 *          is a field of \ref handshake_scenario, so a scenario file is just a
 *          descriptor plus a thin TEST() that calls \ref run_handshake.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef HANDSHAKE_DRIVER_H
#define HANDSHAKE_DRIVER_H

/* Include files ----------------------------------------------------------- */

/* EDHOC internal header: */
#include "edhoc_context_internal.h"

/* Handshake driver building blocks: */
#include "handshake_credentials.h"
#include "handshake_ead.h"

/* EDHOC header: */
#include <edhoc/edhoc.h>
#include <edhoc/cipher_suite.h>

/* Standard library headers: */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Defines ----------------------------------------------------------------- */

/** \brief OSCORE Master Salt length (RFC 9528 Appendix A.1 default). */
#define HS_OSCORE_MASTER_SALT_LENGTH ((size_t)8)

/** \brief OSCORE Master Secret length (RFC 9528 Appendix A.1 default). */
#define HS_OSCORE_MASTER_SECRET_LENGTH ((size_t)16)

/** \brief Upper bound on an exported OSCORE Sender / Recipient ID. */
#define HS_OSCORE_ID_MAX ((size_t)8)

/** \brief Length of the application key-update context byte string. */
#define HS_KEY_UPDATE_CONTEXT_LENGTH ((size_t)16)

/**
 * \brief Message buffer size.
 *
 *        16 KiB: large enough for a full X.509 certificate chain together with
 *        the post-quantum suite's message 3 (the ML-DSA-44 signature is ~2420
 *        bytes) and EAD.
 */
#define HS_MESSAGE_BUFFER_SIZE ((size_t)16384)

/* Types and type definitions ---------------------------------------------- */

/**
 * \brief One EDHOC endpoint of a scenario.
 *
 *        A pointer to this structure is bound to the context as its
 *        \c user_context, so it is the single object every credential and EAD
 *        callback receives: \ref hs_cred_select_local presents \c own, \ref
 *        hs_cred_authenticate_peer authenticates \c peer, and the EAD callbacks read
 *        \c ead.
 */
struct handshake_endpoint {
	/** Role this endpoint plays. */
	enum edhoc_role role;
	/** Connection identifier this endpoint advertises. */
	struct edhoc_buffer connection_id;
	/** Identity this endpoint presents (select_local). */
	const struct hs_identity *own;
	/** Identity this endpoint must verify from the peer
	 *  (authenticate_peer). */
	const struct hs_identity *peer;
	/** EAD tokens for the whole handshake, or NULL to bind no EAD. */
	const struct hs_ead *ead;
	/** Cipher suite the credential callbacks must observe in their call
	 *  context. Filled by \ref run_handshake from the scenario, so a test
	 *  never restates it. */
	int32_t expected_cipher_suite;
};

/**
 * \brief A full-handshake scenario.
 *
 *        The driver owns the fixed spine and the invariant assertions; these
 *        fields carry only what genuinely differs between scenarios.
 */
struct handshake_scenario {
	/** Human-readable scenario name (diagnostics only). */
	const char *name;

	/** Supported EDHOC methods (both peers share the set). */
	const enum edhoc_method *methods;
	/** Number of entries in \p methods. */
	size_t methods_count;

	/** Supported cipher suites (both peers share the set), ready to pass to
	 *  \c edhoc_set_cipher_suites. The driver derives the reference crypto
	 *  from the first entry's IANA value. */
	const struct edhoc_cipher_suite *cipher_suites;
	/** Number of entries in \p cipher_suites. */
	size_t cipher_suites_count;

	/** Platform interface bound to both contexts. */
	const struct edhoc_platform *platform;

	/** Initiator and Responder endpoints. */
	struct handshake_endpoint init;
	struct handshake_endpoint resp;
};

/* Module interface function definitions ----------------------------------- */

/**
 * \brief Memory wipe used by the shared test platform.
 *
 *        The tests run under sanitizers / Valgrind rather than an optimizer
 *        that might elide a plain wipe, so \c memset is enough here.
 */
static inline void hs_platform_zeroize(void *buffer, size_t length)
{
	memset(buffer, 0, length);
}

/**
 * \brief Shared test platform interface, bound via \c .platform in a scenario.
 *
 * \return Pointer to the immutable platform interface.
 */
static inline const struct edhoc_platform *hs_platform(void)
{
	static const struct edhoc_platform platform = {
		.zeroize = hs_platform_zeroize,
	};

	return &platform;
}

/* Module interface function declarations ---------------------------------- */

/**
 * \brief Run one full EDHOC handshake and assert correctness end to end.
 *
 *        Drives the full EDHOC message exchange between two fresh contexts and
 *        asserts correctness end to end (see the file summary). The caller must
 *        have initialised the crypto backend(s) the bound cipher suite relies
 *        on (typically in TEST_SETUP).
 *
 * \param[in] scenario          Scenario descriptor.
 */
void run_handshake(const struct handshake_scenario *scenario);

#endif /* HANDSHAKE_DRIVER_H */
