/**
 * \file    edhoc_context.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC context.
 * \version 0.2
 * \date    2024-01-01
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

#ifndef EDHOC_KID_LEN
#error "Lack of defined key ID length"
#endif

#ifndef EDHOC_MAX_CSUITES_LEN
#error "Lack of defined cipher suites length"
#endif

#ifndef EDHOC_MAX_CID_LEN
#error "Lack of defined connection ID length"
#endif

#ifndef EDHOC_MAX_ECC_KEY_LEN
#error "Lack of defined length for ellipic curve point X coordinate"
#endif

#ifndef EDHOC_MAX_MAC_LEN
#error "Lack of defined hash length"
#endif

#ifndef EDHOC_MAX_NR_OF_EAD_TOKENS
#error "Lack of defined external authorization data"
#endif

/* Types and type definitions ---------------------------------------------- */

/**
 * \brief RFC 9528: Appendix I. Example Protocol State Machine.
 */
enum edhoc_state_machine {
	EDHOC_SM_START,
	EDHOC_SM_ABORTED,

	/* Responder: */
	EDHOC_SM_RECEIVED_M1,
	EDHOC_SM_VERIFIED_M1,

	/* Initiator: */
	EDHOC_SM_WAIT_M2,
	EDHOC_SM_RECEIVED_M2,
	EDHOC_SM_VERIFIED_M2,

	/* Responder: */
	EDHOC_SM_WAIT_M3,
	EDHOC_SM_RECEIVED_M3,

	/* Initiator: */
	EDHOC_SM_RECEVIED_M4,

	EDHOC_SM_COMPLETED,
	EDHOC_SM_PERSISTED,
};

/**
 * \brief RFC 9528: 3.2. Method.
 */
enum edhoc_method {
	EDHOC_METHOD_0 = 0, /* Signature Key to Signature Key. */
	EDHOC_METHOD_1 = 1, /* Signature Key to Static DH Key. */
	EDHOC_METHOD_2 = 2, /* Static DH Key to Signature Key. */
	EDHOC_METHOD_3 = 3, /* Static DH Key to Static DH Key. */
};

/**
 * \brief EDHOC transcript hashes states.
 */
enum edhoc_th_state {
	EDHOC_TH_STATE_INVALID,
	EDHOC_TH_STATE_1,
	EDHOC_TH_STATE_2,
	EDHOC_TH_STATE_3,
	EDHOC_TH_STATE_4,
};

/**
 * \brief EDHOC psuedorandom keys states.
 */
enum edhoc_prk_state {
	EDHOC_PRK_STATE_INVALID,
	EDHOC_PRK_STATE_2E,
	EDHOC_PRK_STATE_3E2M,
	EDHOC_PRK_STATE_4E3M,
	EDHOC_PRK_STATE_OUT,
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
	EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
	EDHOC_CID_TYPE_BYTE_STRING,
};

/**
 * \brief RFC 9528: 3.3.2. Representation of Byte String Identifiers.
 */
struct edhoc_connection_id {
	enum edhoc_connection_id_type encode_type;

	int8_t int_value;

	uint8_t bstr_value[EDHOC_MAX_CID_LEN];
	size_t bstr_length;
};

/**
 * \brief EDHOC context.
 */
struct edhoc_context {
	/**
         * \brief Private members:
         */

	/* EDHOC method */
	enum edhoc_method EDHOC_PRIVATE(method);

	/* EDHOC cipher suite: */
	size_t EDHOC_PRIVATE(chosen_csuite_idx);
	struct edhoc_cipher_suite EDHOC_PRIVATE(csuite)[EDHOC_MAX_CSUITES_LEN];
	size_t EDHOC_PRIVATE(csuite_len);

	/* EDHOC connection identifier pair: */
	struct edhoc_connection_id EDHOC_PRIVATE(cid);
	struct edhoc_connection_id EDHOC_PRIVATE(peer_cid);

	/* EDHOC ephemeral Diffie-Hellman key pair: */
	uint8_t EDHOC_PRIVATE(dh_pub_key)[EDHOC_MAX_ECC_KEY_LEN];
	size_t EDHOC_PRIVATE(dh_pub_key_len);
	uint8_t EDHOC_PRIVATE(dh_priv_key)[EDHOC_MAX_ECC_KEY_LEN];
	size_t EDHOC_PRIVATE(dh_priv_key_len);

	/* EDHOC ephemeral Diffie-Hellman peer public key and shared secret: */
	uint8_t EDHOC_PRIVATE(dh_peer_pub_key)[EDHOC_MAX_ECC_KEY_LEN];
	size_t EDHOC_PRIVATE(dh_peer_pub_key_len);
	uint8_t EDHOC_PRIVATE(dh_secret)[EDHOC_MAX_ECC_KEY_LEN];
	size_t EDHOC_PRIVATE(dh_secret_len);

	/* Context internal state: */
	bool EDHOC_PRIVATE(is_init);
	bool EDHOC_PRIVATE(is_oscore_export_allowed);
	enum edhoc_state_machine EDHOC_PRIVATE(status);

	/* Context transcript hash: */
	enum edhoc_th_state EDHOC_PRIVATE(th_state);
	uint8_t EDHOC_PRIVATE(th)[EDHOC_MAX_MAC_LEN];
	size_t EDHOC_PRIVATE(th_len);

	/* Context pseudorandom key: */
	enum edhoc_prk_state EDHOC_PRIVATE(prk_state);
	uint8_t EDHOC_PRIVATE(prk)[EDHOC_MAX_MAC_LEN];
	size_t EDHOC_PRIVATE(prk_len);

	/* Context structures with callbacks: */
	struct edhoc_ead EDHOC_PRIVATE(ead);
	struct edhoc_keys EDHOC_PRIVATE(keys);
	struct edhoc_crypto EDHOC_PRIVATE(crypto);
	struct edhoc_credentials EDHOC_PRIVATE(cred);

	/* Context EAD tokens: */
	struct edhoc_ead_token
		EDHOC_PRIVATE(ead_token)[EDHOC_MAX_NR_OF_EAD_TOKENS + 1];
	size_t EDHOC_PRIVATE(nr_of_ead_tokens);

	/* Context user context */
	void *EDHOC_PRIVATE(user_ctx);

	/**
     	 * \brief Public members:
     	 */

	/* Context logger callback */
	edhoc_logger_t logger;
};

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_CONTEXT_H */
