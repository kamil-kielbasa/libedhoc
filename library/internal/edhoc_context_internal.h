/**
 * \file    edhoc_context_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC context definition (library-internal).
 *
 *          The \ref edhoc_context structure is opaque to library consumers:
 *          the public header \c <edhoc/edhoc_context.h> only forward-declares
 *          it and exposes \ref edhoc_context_size. The full layout lives here
 *          and is visible to the library core and to white-box tests that add
 *          \c library/internal to their private include path.
 * 
 * \copyright Copyright (c) 2026
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CONTEXT_INTERNAL_H
#define EDHOC_CONTEXT_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include "edhoc_config.h"
#endif

/* EDHOC public headers (types referenced by the context): */
#include <edhoc/edhoc_types.h>
#include <edhoc/edhoc_platform.h>
#include <edhoc/edhoc_credentials.h>
#include <edhoc/edhoc_cipher_suite.h>
#include <edhoc/edhoc_crypto.h>
#include <edhoc/edhoc_ead.h>
#include <edhoc/edhoc_values.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Types and type definitions ---------------------------------------------- */

/**
 * \brief RFC 9528: 2. EDHOC Outline.
 */
enum edhoc_role {
	/** EDHOC role - initiator. */
	EDHOC_INITIATOR,
	/** EDHOC role - responder. */
	EDHOC_RESPONDER,
};

/**
 * \brief RFC 9528: Appendix I. Example Protocol State Machine.
 */
enum edhoc_state_machine {
	/** State machine - start. */
	EDHOC_SM_START,
	/** State machine - aborted. */
	EDHOC_SM_ABORTED,

	/* Responder: */

	/** State machine - received message 1. */
	EDHOC_SM_RECEIVED_M1,
	/** State machine - verified message 1. */
	EDHOC_SM_VERIFIED_M1,

	/* Initiator: */

	/** State machine - waiting for message 2. */
	EDHOC_SM_WAIT_M2,
	/** State machine - received message 2. */
	EDHOC_SM_RECEIVED_M2,
	/** State machine - verified message 2. */
	EDHOC_SM_VERIFIED_M2,

	/* Responder: */

	/** State machine - waiting for message 3. */
	EDHOC_SM_WAIT_M3,
	/** State machine - received message 3. */
	EDHOC_SM_RECEIVED_M3,

	/* Initiator: */

	/** State machine - received message 4. */
	EDHOC_SM_RECEIVED_M4,

	/** State machine - completed. */
	EDHOC_SM_COMPLETED,
	/** State machine - persisted. */
	EDHOC_SM_PERSISTED,
};

/**
 * \brief EDHOC transcript hashes states.
 */
enum edhoc_th_state {
	/** Transcript hash invalid. */
	EDHOC_TH_STATE_INVALID,
	/** Transcript hash 1. */
	EDHOC_TH_STATE_1,
	/** Transcript hash 2. */
	EDHOC_TH_STATE_2,
	/** Transcript hash 3. */
	EDHOC_TH_STATE_3,
	/** Transcript hash 4. */
	EDHOC_TH_STATE_4,
};

/**
 * \brief EDHOC pseudorandom keys states.
 */
enum edhoc_prk_state {
	/** Pseudorandom key invalid. */
	EDHOC_PRK_STATE_INVALID,
	/** Pseudorandom key RFC 9528: 4.1.1.1. PRK_2e. */
	EDHOC_PRK_STATE_2E,
	/** Pseudorandom key RFC 9528: 4.1.1.2. PRK_3e2m. */
	EDHOC_PRK_STATE_3E2M,
	/** Pseudorandom key RFC 9528: 4.1.1.3. PRK_4e3m. */
	EDHOC_PRK_STATE_4E3M,
	/** Pseudorandom key RFC 9528: 4.1.3. PRK_out. */
	EDHOC_PRK_STATE_OUT,
	/** Pseudorandom key RFC 9528: 4.2.1. EDHOC_Exporter. */
	EDHOC_PRK_STATE_EXPORTER,
};

/**
 * \brief EDHOC context.
 */
struct edhoc_context {
	/** EDHOC chosen method. */
	enum edhoc_method chosen_method;

	/** EDHOC supported methods. */
	enum edhoc_method method[EDHOC_METHOD_MAX];
	/** Length of the \p method buffer. */
	size_t method_len;

	/** EDHOC cipher suite chosen index. */
	size_t chosen_csuite_idx;
	/** EDHOC cipher suite buffer. */
	struct edhoc_cipher_suite
		csuite[CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES];
	/** Length of the \p csuite buffer. */
	size_t csuite_len;
	/** EDHOC peer cipher suite buffer. */
	struct edhoc_cipher_suite
		peer_csuite[CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES];
	/** Length of the \p peer_csuite buffer. */
	size_t peer_csuite_len;

	/** EDHOC connection identifier. */
	struct edhoc_connection_id cid;
	/** EDHOC peer connection identifier. */
	struct edhoc_connection_id peer_cid;

	/** EDHOC ephemeral Diffie-Hellman public key. */
	uint8_t dh_pub_key[CONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY];
	/** Size of the \p dh_pub_key buffer in bytes. */
	size_t dh_pub_key_len;
	/** EDHOC ephemeral Diffie-Hellman private key. */
	uint8_t dh_priv_key[CONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY];
	/** Size of the \p dh_priv_key buffer in bytes. */
	size_t dh_priv_key_len;

	/** EDHOC ephemeral Diffie-Hellman peer public key. */
	uint8_t dh_peer_pub_key[CONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY];
	/** Size of the \p dh_peer_pub_key buffer in bytes. */
	size_t dh_peer_pub_key_len;
	/** EDHOC ephemeral Diffie-Hellman key agreement. */
	uint8_t dh_secret[CONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY];
	/** Size of the \p dh_secret buffer in bytes. */
	size_t dh_secret_len;

	/** Is context initialized? */
	bool is_init;
	/** Is OSCORE security session export allowed? */
	bool is_oscore_export_allowed;
	/** EDHOC context state machine. */
	enum edhoc_state_machine status;
	/** Current processing EDHOC message. */
	enum edhoc_message message;
	/** EDHOC role. */
	enum edhoc_role role;

	/** EDHOC context transcript hash state. */
	enum edhoc_th_state th_state;
	/** EDHOC context transcript hash buffer. */
	uint8_t th[CONFIG_LIBEDHOC_MAX_LEN_OF_MAC];
	/** Size of the \p th buffer in bytes. */
	size_t th_len;

	/** EDHOC context pseudorandom key state. */
	enum edhoc_prk_state prk_state;
	/** EDHOC context pseudorandom key buffer. */
	uint8_t prk[CONFIG_LIBEDHOC_MAX_LEN_OF_MAC];
	/** Size of the \p prk buffer in bytes. */
	size_t prk_len;

	/** EDHOC interface for external authorization data. */
	struct edhoc_ead ead;
	/** EDHOC interface for cryptographic key operations. */
	struct edhoc_keys keys;
	/** EDHOC interface for cryptographic function operations. */
	struct edhoc_crypto crypto;
	/** EDHOC interface for authentication credentials. */
	struct edhoc_credentials cred;
	/** EDHOC interface for platform services (mandatory \c zeroize). */
	struct edhoc_platform platform;

	/** Set once \ref edhoc_set_methods succeeds. */
	bool methods_present : 1;
	/** Set once \ref edhoc_set_cipher_suites succeeds. */
	bool cipher_suites_present : 1;
	/** Set once \ref edhoc_set_connection_id succeeds. */
	bool connection_id_present : 1;
	/** Set once \ref edhoc_bind_keys succeeds. */
	bool keys_present : 1;
	/** Set once \ref edhoc_bind_crypto succeeds. */
	bool crypto_present : 1;
	/** Set once \ref edhoc_bind_credentials succeeds. */
	bool credentials_present : 1;
	/** Set once \ref edhoc_bind_platform succeeds. */
	bool platform_present : 1;
	/** Set once \ref edhoc_bind_ead succeeds (optional interface). */
	bool ead_present : 1;

	/** EDHOC EAD tokens buffer. */
	struct edhoc_ead_token
		ead_token[CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS + 1];
	/** Length of the \p ead_token buffer. */
	size_t nr_of_ead_tokens;

	/** User context. */
	void *user_ctx;

	/** EDHOC error code. */
	enum edhoc_error_code error_code;
};

/**
 * \brief Is every mandatory input present in \p ctx?
 *
 * The mandatory inputs are the local method(s), cipher suite(s) and connection
 * identifier, plus the keys, crypto, credentials and platform interfaces. The
 * external authorization data interface is optional and is not checked here.
 *
 * \param[in] ctx                       EDHOC context.
 *
 * \return \c true when every mandatory input has been provided.
 */
static inline bool edhoc_context_configured(const struct edhoc_context *ctx)
{
	return ctx->methods_present && ctx->cipher_suites_present &&
	       ctx->connection_id_present && ctx->keys_present &&
	       ctx->crypto_present && ctx->credentials_present &&
	       ctx->platform_present;
}

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_CONTEXT_INTERNAL_H */
