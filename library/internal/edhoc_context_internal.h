/**
 * \file    edhoc_context_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC context definition (library-internal).
 *
 *          \ref edhoc_context is opaque to consumers: \c <edhoc/edhoc.h> only
 *          forward-declares it and exposes \ref edhoc_context_size. The full
 *          layout lives here, visible to the library core and to white-box
 *          tests that add \c library/internal to their private include path.
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
#include <edhoc_config.h>
#endif

/* EDHOC public headers (types referenced by the context): */
#include <edhoc/types.h>
#include <edhoc/platform.h>
#include <edhoc/credentials.h>
#include <edhoc/cipher_suite.h>
#include <edhoc/crypto.h>
#include <edhoc/ead.h>
#include <edhoc/values.h>

/* EDHOC internal headers: */
#include "edhoc_macros_internal.h"
#include "edhoc_key_slot_internal.h"
#include "edhoc_ead_internal.h"
#include "edhoc_connection_id_internal.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Defines ----------------------------------------------------------------- */

/**
 * \brief Storage size for an own/peer ephemeral public value.
 *
 *        The Initiator's \c G_X carries the encapsulation key and the
 *        Responder's \c G_Y carries the KEM ciphertext; a single buffer must
 *        hold whichever the local role produces, so it is sized to the larger
 *        of the two (they are equal for the classical NIKE-as-KEM suites).
 */
#define EDHOC_MAX_LEN_OF_EPHEMERAL_KEY                               \
	(CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_ENCAPSULATION_KEY >          \
			 CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_CIPHERTEXT ? \
		 CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_ENCAPSULATION_KEY :  \
		 CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_CIPHERTEXT)

/* Kconfig enforces these ranges; the standalone CMake build does not, and
 * exceeding a CBOR backend capacity would truncate silently. */
_Static_assert(CONFIG_LIBEDHOC_MAX_NR_OF_METHODS >= 1 &&
		       CONFIG_LIBEDHOC_MAX_NR_OF_METHODS <= 4,
	       "EDHOC defines four authentication methods");
_Static_assert(CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES >= 1 &&
		       CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES <= 3,
	       "the bundled CBOR backend holds at most three cipher suites");
_Static_assert(CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN >= 1 &&
		       CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN <= 3,
	       "the bundled CBOR backend holds at most three certificates");
_Static_assert(CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS <= 3,
	       "the bundled CBOR backend holds at most three EAD tokens");
_Static_assert(CONFIG_LIBEDHOC_KEY_ID_LEN >= 1 &&
		       CONFIG_LIBEDHOC_KEY_ID_LEN <= 32,
	       "key handle length out of range");
_Static_assert(CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID >= 1 &&
		       CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID <= 32,
	       "connection identifier length out of range");

/* Types and type definitions ---------------------------------------------- */

/**
 * \brief RFC 9528: Appendix I. Example Protocol State Machine.
 */
enum edhoc_state_machine {
	/** Start. */
	EDHOC_SM_START,
	/** Aborted. */
	EDHOC_SM_ABORTED,

	/* Responder: */

	/** Received message 1. */
	EDHOC_SM_RECEIVED_M1,
	/** Verified message 1. */
	EDHOC_SM_VERIFIED_M1,

	/* Initiator: */

	/** Waiting for message 2. */
	EDHOC_SM_WAIT_M2,
	/** Received message 2. */
	EDHOC_SM_RECEIVED_M2,
	/** Verified message 2. */
	EDHOC_SM_VERIFIED_M2,

	/* Responder: */

	/** Waiting for message 3. */
	EDHOC_SM_WAIT_M3,
	/** Received message 3. */
	EDHOC_SM_RECEIVED_M3,

	/* Initiator: */

	/** Received message 4. */
	EDHOC_SM_RECEIVED_M4,

	/** Completed. */
	EDHOC_SM_COMPLETED,
	/** Persisted. */
	EDHOC_SM_PERSISTED,
};

/**
 * \brief EDHOC transcript hashes states.
 */
enum edhoc_th_state {
	/** Invalid. */
	EDHOC_TH_STATE_INVALID,
	/** TH_1. */
	EDHOC_TH_STATE_1,
	/** TH_2. */
	EDHOC_TH_STATE_2,
	/** TH_3. */
	EDHOC_TH_STATE_3,
	/** TH_4. */
	EDHOC_TH_STATE_4,
};

/**
 * \brief EDHOC pseudorandom keys states.
 */
enum edhoc_prk_state {
	/** Invalid. */
	EDHOC_PRK_STATE_INVALID,
	/** PRK_2e (RFC 9528: 4.1.1.1). */
	EDHOC_PRK_STATE_2E,
	/** PRK_3e2m (RFC 9528: 4.1.1.2). */
	EDHOC_PRK_STATE_3E2M,
	/** PRK_4e3m (RFC 9528: 4.1.1.3). */
	EDHOC_PRK_STATE_4E3M,
	/** PRK_out (RFC 9528: 4.1.3). */
	EDHOC_PRK_STATE_OUT,
	/** PRK_exporter (RFC 9528: 4.2.1). */
	EDHOC_PRK_STATE_EXPORTER,
};

/**
 * \brief The bound EDHOC interfaces together with their "present" flags.
 */
struct edhoc_interfaces {
	/** EDHOC interface for cryptographic function operations. */
	struct edhoc_crypto crypto;
	/** EDHOC interface for authentication credentials. */
	struct edhoc_credentials cred;
	/** EDHOC interface for platform services (mandatory \c zeroize). */
	struct edhoc_platform platform;
	/** EDHOC interface for external authorization data. */
	struct edhoc_ead ead;

	/** Set once \ref edhoc_bind_crypto succeeds. */
	bool crypto_present : 1;
	/** Set once \ref edhoc_bind_credentials succeeds. */
	bool credentials_present : 1;
	/** Set once \ref edhoc_bind_platform succeeds. */
	bool platform_present : 1;
	/** Set once \ref edhoc_bind_ead succeeds (optional interface). */
	bool ead_present : 1;
};

/**
 * \brief A list of authentication methods.
 */
struct edhoc_method_list {
	/** Method entries. */
	enum edhoc_method entry[CONFIG_LIBEDHOC_MAX_NR_OF_METHODS];
	/** Number of live entries in \p entry. */
	size_t count;
};

/**
 * \brief A list of cipher suites.
 */
struct edhoc_cipher_suite_list {
	/** Cipher suite entries. */
	struct edhoc_cipher_suite entry[CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES];
	/** Number of live entries in \p entry. */
	size_t count;
};

/**
 * \brief Negotiated session parameters: method, cipher suite and connection
 *        identifier (local + peer), each paired with the "present" flag its
 *        \c edhoc_set_* setter raises.
 */
struct edhoc_negotiation {
	/** Selected authentication method. */
	enum edhoc_method selected_method;
	/** Locally supported methods. */
	struct edhoc_method_list method;

	/** Index of the selected suite in \p cipher_suite. */
	size_t selected_cipher_suite_index;
	/** Locally supported cipher suites. */
	struct edhoc_cipher_suite_list cipher_suite;
	/** Peer's advertised cipher suites. */
	struct edhoc_cipher_suite_list peer_cipher_suite;

	/** Own connection identifier. */
	struct connection_id connection_id;
	/** Peer connection identifier. */
	struct connection_id peer_connection_id;

	/** Set once \ref edhoc_set_methods succeeds. */
	bool methods_present : 1;
	/** Set once \ref edhoc_set_cipher_suites succeeds. */
	bool cipher_suites_present : 1;
	/** Set once \ref edhoc_set_connection_id succeeds. */
	bool connection_id_present : 1;
};

/**
 * \brief EDHOC transcript hash: the running value paired with the schedule
 *        stage it currently represents (parallels \ref edhoc_key_slot).
 */
struct edhoc_transcript_hash {
	/** Which transcript hash the buffer currently holds. */
	enum edhoc_th_state stage;
	/** Transcript-hash bytes. */
	uint8_t value[CONFIG_LIBEDHOC_MAX_LEN_OF_MAC];
	/** Size of \p value in bytes. */
	size_t length;
};

/**
 * \brief Runtime protocol state: where the handshake currently is.
 */
struct edhoc_protocol_state {
	/** State machine position (RFC 9528 Appendix I). */
	enum edhoc_state_machine machine;
	/** Message currently being processed. */
	enum edhoc_message message;
	/** Local role (fixed for the session). */
	enum edhoc_role role;
	/** Transcript hash (value + stage). */
	struct edhoc_transcript_hash th;
	/** Pseudorandom-key schedule stage. */
	enum edhoc_prk_state prk_state;
};

/**
 * \brief A public ephemeral value (G_X or G_Y).
 */
struct edhoc_ephemeral_public {
	/** Ephemeral public value bytes. */
	uint8_t value[EDHOC_MAX_LEN_OF_EPHEMERAL_KEY];
	/** Size of \p value in bytes. */
	size_t length;
};

/**
 * \brief The two public ephemeral values exchanged in messages 1 and 2.
 */
struct edhoc_ephemeral_keys {
	/** Own public ephemeral value. */
	struct edhoc_ephemeral_public own;
	/** Peer public ephemeral value. */
	struct edhoc_ephemeral_public peer;
};

/**
 * \brief EDHOC context.
 */
struct edhoc_context {
	/** Negotiated parameters: method / cipher suite / connection id. */
	struct edhoc_negotiation negotiation;
	/** Runtime protocol state (state machine, role, message, TH, PRK). */
	struct edhoc_protocol_state state;
	/** Public ephemeral values (own + peer). */
	struct edhoc_ephemeral_keys ephemeral;

	/** Key-store handle slots, indexed by \ref edhoc_key_slot_id. */
	struct edhoc_key_slot key_slots[EDHOC_KEY_SLOT_COUNT];

	/** Bound EDHOC interfaces and their "present" flags. */
	struct edhoc_interfaces interfaces;

	/** External authorization data tokens. */
	struct edhoc_ead_tokens ead;

	/** Is context initialized? */
	bool is_init : 1;
	/** Is OSCORE security session export allowed? */
	bool is_oscore_export_allowed : 1;

	/** User context passed to backend callbacks. */
	void *user_context;

	/** EDHOC error code. */
	enum edhoc_error_code error_code;
};

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/* Static inline function definitions -------------------------------------- */

/**
 * \brief Is every mandatory input present in \p ctx?
 *
 * The mandatory inputs are the local method(s), cipher suite(s) and connection
 * identifier, plus the crypto, credentials and platform interfaces. The
 * external authorization data interface is optional and is not checked here.
 *
 * \param[in] ctx                       EDHOC context.
 *
 * \return \c true when every mandatory input has been provided.
 */
static inline bool edhoc_context_configured(const struct edhoc_context *ctx)
{
	return ctx->negotiation.methods_present &&
	       ctx->negotiation.cipher_suites_present &&
	       ctx->negotiation.connection_id_present &&
	       ctx->interfaces.crypto_present &&
	       ctx->interfaces.credentials_present &&
	       ctx->interfaces.platform_present;
}

/**
 * \brief The bound cryptographic backend interface.
 *
 * \param[in] ctx                       EDHOC context.
 *
 * \return Pointer to the crypto vtable.
 */
static inline const struct edhoc_crypto *
edhoc_crypto(const struct edhoc_context *ctx)
{
	return &ctx->interfaces.crypto;
}

/**
 * \brief Wipe a buffer through the bound platform \c zeroize hook.
 *
 * \param[in] ctx                       EDHOC context.
 * \param[out] buffer                   Buffer to wipe.
 * \param length                        Number of bytes to wipe.
 */
static inline void edhoc_zeroize(const struct edhoc_context *ctx, void *buffer,
				 size_t length)
{
	ctx->interfaces.platform.zeroize(buffer, length);
}

/**
 * \brief The cipher suite selected for this session.
 *
 * \param[in] ctx                       EDHOC context.
 *
 * \return Pointer to the selected \ref edhoc_cipher_suite.
 */
static inline const struct edhoc_cipher_suite *
edhoc_selected_cipher_suite(const struct edhoc_context *ctx)
{
	const struct edhoc_cipher_suite_list *suites =
		&ctx->negotiation.cipher_suite;

	return &suites->entry[ctx->negotiation.selected_cipher_suite_index];
}

/**
 * \brief Context of a call into an application callback.
 *
 * \param[in] ctx                       EDHOC context.
 *
 * \return Call context describing the current session and message.
 */
static inline struct edhoc_call_context
edhoc_call_context(const struct edhoc_context *ctx)
{
	return (struct edhoc_call_context){
		.role = ctx->state.role,
		.method = ctx->negotiation.selected_method,
		.selected_cipher_suite =
			edhoc_selected_cipher_suite(ctx)->value,
		.message = ctx->state.message,
	};
}

/**
 * \brief Is the local role the Initiator?
 *
 * \param[in] ctx                       EDHOC context.
 *
 * \return \c true when the local role is \ref EDHOC_ROLE_INITIATOR.
 */
static inline bool edhoc_is_initiator(const struct edhoc_context *ctx)
{
	return EDHOC_ROLE_INITIATOR == ctx->state.role;
}

/**
 * \brief Is the local role the Responder?
 *
 * \param[in] ctx                       EDHOC context.
 *
 * \return \c true when the local role is \ref EDHOC_ROLE_RESPONDER.
 */
static inline bool edhoc_is_responder(const struct edhoc_context *ctx)
{
	return EDHOC_ROLE_RESPONDER == ctx->state.role;
}

#endif /* EDHOC_CONTEXT_INTERNAL_H */
