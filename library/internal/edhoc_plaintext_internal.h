/**
 * \file    edhoc_plaintext_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC plaintext of message 2 and 3 (RFC 9528: 5.3.2, 5.4.2).
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_PLAINTEXT_INTERNAL_H
#define EDHOC_PLAINTEXT_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* EDHOC public headers: */
#include <edhoc/types.h>
#include <edhoc/credentials.h>

/* EDHOC internal headers: */
#include "edhoc_credentials_internal.h"

/* Standard library headers: */
#include <stdint.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-plaintext-types EDHOC plaintext types
 * @{
 */

/**
 * \brief Items carried by PLAINTEXT_2 and PLAINTEXT_3, as decoded.
 */
struct plaintext {
	/** ID_CRED_x, as received from the peer. */
	struct edhoc_credential_received peer_credential_id;

	/** Backing store for a 'kid' that arrived in the CBOR integer form
	 *  (RFC 9528: 3.3.2). */
	uint8_t kid_byte;

	/** Cborised Signature_or_MAC (2/3). */
	struct edhoc_buffer sign_or_mac;

	/** Cborised EAD (2/3). */
	struct edhoc_buffer ead;
};

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_PLAINTEXT_INTERNAL_H */
