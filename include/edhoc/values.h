/**
 * \file    values.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC values and error codes.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_VALUES_H
#define EDHOC_VALUES_H

/* Include files ----------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-error-codes EDHOC error codes
 * @{
 */

/** The action was completed successfully. */
#define EDHOC_SUCCESS ((int)0)

/** An unspecified failure that maps to no more specific error code. */
#define EDHOC_ERROR_GENERIC_ERROR ((int)-100)

/** The requested operation, method, or cipher suite is not supported by this
 *  build. */
#define EDHOC_ERROR_NOT_SUPPORTED ((int)-101)

/** The requested action is not permitted in the current configuration or
 *  protocol state. */
#define EDHOC_ERROR_NOT_PERMITTED ((int)-102)

/** An output buffer is too small; retry with a larger buffer. */
#define EDHOC_ERROR_BUFFER_TOO_SMALL ((int)-103)

/** The action is not valid in the current context state: a mandatory input is
 *  missing, or messages were composed/processed out of order. */
#define EDHOC_ERROR_BAD_STATE ((int)-104)

/** A function argument is invalid, e.g. a NULL pointer or a zero length. */
#define EDHOC_ERROR_INVALID_ARGUMENT ((int)-105)

/** A memory allocation failed (heap or custom memory backend). */
#define EDHOC_ERROR_NOT_ENOUGH_MEMORY ((int)-106)

/** CBOR encoding or decoding of an EDHOC message or field failed. */
#define EDHOC_ERROR_CBOR_FAILURE ((int)-110)

/** A cryptographic operation reported by the bound crypto backend failed. */
#define EDHOC_ERROR_CRYPTO_FAILURE ((int)-111)

/** The application's credentials fetch or verify callback returned an error. */
#define EDHOC_ERROR_CREDENTIALS_FAILURE ((int)-112)

/** The application's EAD compose callback returned an error. */
#define EDHOC_ERROR_EAD_COMPOSE_FAILURE ((int)-120)

/** The application's EAD process callback returned an error. */
#define EDHOC_ERROR_EAD_PROCESS_FAILURE ((int)-121)

/** Processing of a received EDHOC message 1 failed. */
#define EDHOC_ERROR_MSG_1_PROCESS_FAILURE ((int)-130)

/** Processing of a received EDHOC message 2 failed. */
#define EDHOC_ERROR_MSG_2_PROCESS_FAILURE ((int)-131)

/** Processing of a received EDHOC message 3 failed. */
#define EDHOC_ERROR_MSG_3_PROCESS_FAILURE ((int)-132)

/** Processing of a received EDHOC message 4 failed. */
#define EDHOC_ERROR_MSG_4_PROCESS_FAILURE ((int)-133)

/** The ephemeral key exchange failed: key generation, agreement, or KEM
 *  encapsulation/decapsulation. */
#define EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE ((int)-134)

/** Computation of an EDHOC transcript hash (TH_2, TH_3, or TH_4) failed. */
#define EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE ((int)-135)

/** Derivation of an EDHOC pseudorandom key (PRK) in the key schedule failed. */
#define EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE ((int)-136)

/** MAC_2 verification failed: the Responder could not be authenticated in
 *  message 2 (static Diffie-Hellman authentication). */
#define EDHOC_ERROR_INVALID_MAC_2 ((int)-137)

/** Signature_or_MAC_2 verification failed: the Responder's authentication in
 *  message 2 is invalid. */
#define EDHOC_ERROR_INVALID_SIGN_OR_MAC_2 ((int)-138)

/** MAC_3 verification failed: the Initiator could not be authenticated in
 *  message 3 (static Diffie-Hellman authentication). */
#define EDHOC_ERROR_INVALID_MAC_3 ((int)-139)

/** Signature_or_MAC_3 verification failed: the Initiator's authentication in
 *  message 3 is invalid. */
#define EDHOC_ERROR_INVALID_SIGN_OR_MAC_3 ((int)-140)

/**@}*/

/** \defgroup edhoc-exporter-labels EDHOC exporter labels
 *
 * RFC 9528: 10.1. EDHOC Exporter Label Registry.
 *
 * @{
 */

/** Minimum value for EDHOC exporter label for private usage. */
#define EDHOC_PRK_EXPORTER_PRIVATE_LABEL_MINIMUM ((size_t)32768)

/** Maximum value for EDHOC exporter label for private usage. */
#define EDHOC_PRK_EXPORTER_PRIVATE_LABEL_MAXIMUM ((size_t)65535)

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**@}*/

#endif /* EDHOC_VALUES_H */
