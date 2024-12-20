/**
 * \file    edhoc_context.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC context.
 * \version 0.6
 * \date    2024-08-05
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CONTEXT_H
#define EDHOC_CONTEXT_H

/* Include files ----------------------------------------------------------- */

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* EDHOC headers: */
#include "edhoc_credentials.h"
#include "edhoc_crypto.h"
#include "edhoc_ead.h"
#include "edhoc_macros.h"
#include "edhoc_values.h"

/* Defines ----------------------------------------------------------------- */

#ifndef CONFIG_LIBEDHOC_ENABLE
#error "Library has not been enabled."
#endif

#ifndef CONFIG_LIBEDHOC_KEY_ID_LEN
#error "Lack of defined key identifier length in bytes."
#endif

#ifndef CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES
#error "Lack of defined maximum number of cipher suites in chain for negotiation."
#endif

#ifndef CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID
#error "Lack of defined maximum length of connection identifier in bytes."
#endif

#ifndef CONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY
#error "Lack of defined maximum length of ECC (Elliptic Curve Cryptography) key in bytes."
#endif

#ifndef CONFIG_LIBEDHOC_MAX_LEN_OF_MAC
#error "Lack of defined maximum length of hash in bytes."
#endif

#ifndef CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS
#error "Lack of defined maximum number of EAD (External Authorization Data) tokens."
#endif

#ifndef CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN
#error "Lack of defined maximum number of certificates in X.509 chain."
#endif

/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-context EDHOC context
 * @{
 */

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
	EDHOC_SM_RECEVIED_M4,

	/** State machine - completed. */
	EDHOC_SM_COMPLETED,
	/** State machine - persisted. */
	EDHOC_SM_PERSISTED,
};

/**
 * \brief RFC 9528: 3.2. Method.
 */
enum edhoc_method {
	/** Initiator signature Key to responder signature Key. */
	EDHOC_METHOD_0 = 0,
	/** Initiator signature Key to responder static DH Key. */
	EDHOC_METHOD_1 = 1,
	/** Initiator static DH Key to responder signature Key. */
	EDHOC_METHOD_2 = 2,
	/** Initiator static DH Key to responder static DH Key. */
	EDHOC_METHOD_3 = 3,
	/** Sanity check maximum. */
	EDHOC_METHOD_MAX,
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
 * \brief EDHOC psuedorandom keys states.
 */
enum edhoc_prk_state {
	/** Psuedorandom key invalid. */
	EDHOC_PRK_STATE_INVALID,
	/** Psuedorandom key RFC 9528: 4.1.1.1. PRK_2e. */
	EDHOC_PRK_STATE_2E,
	/** Psuedorandom key RFC 9528: 4.1.1.2. PRK_3e2m. */
	EDHOC_PRK_STATE_3E2M,
	/** Psuedorandom key RFC 9528: 4.1.1.3. PRK_4e3m. */
	EDHOC_PRK_STATE_4E3M,
	/** Psuedorandom key RFC 9528: 4.1.3. PRK_out. */
	EDHOC_PRK_STATE_OUT,
	/** Psuedorandom key RFC 9528: 4.2.1. EDHOC_Exporter. */
	EDHOC_PRK_STATE_EXPORTER,
};

/**
 * \brief EDHOC logger callback.
 */
typedef void (*edhoc_logger_t)(void *user_context, const char *name,
			       const uint8_t *buffer, size_t buffer_length);

/**
 * \brief EDHOC connection identifier encoding type.
 */
enum edhoc_connection_id_type {
	/** Encode connection identifier as CBOR integer. */
	EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
	/** Encode connection identifier as CBOR byte string. */
	EDHOC_CID_TYPE_BYTE_STRING,
};

/**
 * \brief RFC 9528: 3.3.2. Representation of Byte String Identifiers.
 */
struct edhoc_connection_id {
	/** Encoding type of connection identifier. 
         *
         * It must follow representation of byte string identifiers described in RFC 9528: 3.3.2. */
	enum edhoc_connection_id_type encode_type;

	/** Connection identifier as cbor integer. */
	int8_t int_value;

	/** Connection identifier as cbor byte string buffer. */
	uint8_t bstr_value[CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID + 1];
	/** Size of the \p bstr_value buffer in bytes. */
	size_t bstr_length;
};

/**
 * \brief EDHOC error code. RFC 9528: 6. Error Handling.
 */
enum edhoc_error_code {
	/** RFC 9528: 6.1. Success. */
	EDHOC_ERROR_CODE_SUCCESS = 0,
	/** RFC 9528: 6.2. Unspecified Error. */
	EDHOC_ERROR_CODE_UNSPECIFIED_ERROR = 1,
	/** RFC 9528: 6.3. Wrong Selected Cipher Suite. */
	EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE = 2,
	/** RFC 9528: 6.4. Unknown Credential Referenced. */
	EDHOC_ERROR_CODE_UNKNOWN_CREDENTIAL_REFERENCED = 3,
};

/**
 * \brief EDHOC error information. RFC 9528: 6. Error Handling.
 */
struct edhoc_error_info {
	union {
		/** Pointer used only for error code: \ref EDHOC_ERROR_CODE_UNSPECIFIED_ERROR. */
		char *text_string;
		/** Pointer used only for error code: \ref EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE. */
		int32_t *cipher_suites;
	};

	/** Total number of entries from: \p text_string or \p cipher_suites. */
	size_t total_entries;
	/** Number of written entries to: \p text_string or \p cipher_suites. */
	size_t written_entries;
};

/**
 * \brief EDHOC context.
 */
struct edhoc_context {
	/** EDHOC chosen method. */
	enum edhoc_method EDHOC_PRIVATE(chosen_method);

	/** EDHOC supported methods. */
	enum edhoc_method EDHOC_PRIVATE(method[EDHOC_METHOD_MAX]);
	/** Length of the \p method buffer. */
	size_t EDHOC_PRIVATE(method_len);

	/** EDHOC cipher suite chosen index. */
	size_t EDHOC_PRIVATE(chosen_csuite_idx);
	/** EDHOC cipher suite buffer. */
	struct edhoc_cipher_suite
		EDHOC_PRIVATE(csuite)[CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES];
	/** Length of the \p csuite buffer. */
	size_t EDHOC_PRIVATE(csuite_len);
	/** EDHOC peer cipher suite buffer. */
	struct edhoc_cipher_suite EDHOC_PRIVATE(
		peer_csuite)[CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES];
	/** Length of the \p peer_csuite buffer. */
	size_t EDHOC_PRIVATE(peer_csuite_len);

	/** EDHOC connection identifier. */
	struct edhoc_connection_id EDHOC_PRIVATE(cid);
	/** EDHOC peer connection identifier. */
	struct edhoc_connection_id EDHOC_PRIVATE(peer_cid);

	/** EDHOC ephemeral Diffie-Hellman public key. */
	uint8_t EDHOC_PRIVATE(dh_pub_key)[CONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY];
	/** Size of the \p dh_pub_key buffer in bytes. */
	size_t EDHOC_PRIVATE(dh_pub_key_len);
	/** EDHOC ephemeral Diffie-Hellman private key. */
	uint8_t EDHOC_PRIVATE(dh_priv_key)[CONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY];
	/** Size of the \p dh_priv_key buffer in bytes. */
	size_t EDHOC_PRIVATE(dh_priv_key_len);

	/** EDHOC ephemeral Diffie-Hellman peer public key. */
	uint8_t EDHOC_PRIVATE(
		dh_peer_pub_key)[CONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY];
	/** Size of the \p dh_peer_pub_key buffer in bytes. */
	size_t EDHOC_PRIVATE(dh_peer_pub_key_len);
	/** EDHOC ephemeral Diffie-Hellman key agreement. */
	uint8_t EDHOC_PRIVATE(dh_secret)[CONFIG_LIBEDHOC_MAX_LEN_OF_ECC_KEY];
	/** Size of the \p dh_secret buffer in bytes. */
	size_t EDHOC_PRIVATE(dh_secret_len);

	/** Is context initialized? */
	bool EDHOC_PRIVATE(is_init);
	/** Is OSCORE security session export allowed? */
	bool EDHOC_PRIVATE(is_oscore_export_allowed);
	/** EDHOC context state machine. */
	enum edhoc_state_machine EDHOC_PRIVATE(status);
	/** Current processing EDHOC message. */
	enum edhoc_message EDHOC_PRIVATE(message);
	/** EDHOC role. */
	enum edhoc_role EDHOC_PRIVATE(role);

	/** EDHOC context transcript hash state. */
	enum edhoc_th_state EDHOC_PRIVATE(th_state);
	/** EDHOC context transcript hash buffer. */
	uint8_t EDHOC_PRIVATE(th)[CONFIG_LIBEDHOC_MAX_LEN_OF_MAC];
	/** Size of the \p th buffer in bytes. */
	size_t EDHOC_PRIVATE(th_len);

	/** EDHOC context pseudorandom key state. */
	enum edhoc_prk_state EDHOC_PRIVATE(prk_state);
	/** EDHOC context pseudorandom key buffer. */
	uint8_t EDHOC_PRIVATE(prk)[CONFIG_LIBEDHOC_MAX_LEN_OF_MAC];
	/** Size of the \p prk buffer in bytes. */
	size_t EDHOC_PRIVATE(prk_len);

	/** EDHOC interface for external authorization data. */
	struct edhoc_ead EDHOC_PRIVATE(ead);
	/** EDHOC interface for crypographics key operations. */
	struct edhoc_keys EDHOC_PRIVATE(keys);
	/** EDHOC interface for crypographics function operations. */
	struct edhoc_crypto EDHOC_PRIVATE(crypto);
	/** EDHOC interface for authentication credentials. */
	struct edhoc_credentials EDHOC_PRIVATE(cred);

	/** EDHOC EAD tokens buffer. */
	struct edhoc_ead_token EDHOC_PRIVATE(
		ead_token)[CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS + 1];
	/** Length of the \p ead_token buffer. */
	size_t EDHOC_PRIVATE(nr_of_ead_tokens);

	/** User context. */
	void *EDHOC_PRIVATE(user_ctx);

	/** EDHOC error code. */
	enum edhoc_error_code EDHOC_PRIVATE(error_code);

	/** User logger callback. */
	edhoc_logger_t logger;
};

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**@}*/

#endif /* EDHOC_CONTEXT_H */
