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

/* Standard library headers: */
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-error-codes EDHOC error codes
 * @{
 */

/** The action was completed successfully. */
#define EDHOC_SUCCESS ((int)0)

/** No specific error code was assigned. Every internal result starts from this
 *  value, so it surfaces only if a failing path forgot to set its own. */
#define EDHOC_ERROR_GENERIC_ERROR ((int)-100)

/** The build or the selected cipher suite cannot perform the requested
 *  operation. */
#define EDHOC_ERROR_NOT_SUPPORTED ((int)-101)

/** The protocol or the current configuration forbids the requested action. */
#define EDHOC_ERROR_NOT_PERMITTED ((int)-102)

/** An output buffer is too small; retry with a larger buffer. */
#define EDHOC_ERROR_BUFFER_TOO_SMALL ((int)-103)

/** The context is not in a state where the call is valid: a mandatory input is
 *  missing, or messages were composed/processed out of order. */
#define EDHOC_ERROR_BAD_STATE ((int)-104)

/** A function argument is invalid, e.g. a NULL pointer or a zero length. */
#define EDHOC_ERROR_INVALID_ARGUMENT ((int)-105)

/** A working-buffer allocation failed in the configured memory backend. */
#define EDHOC_ERROR_NOT_ENOUGH_MEMORY ((int)-106)

/** The bytes are not the CBOR that EDHOC requires, in either direction. */
#define EDHOC_ERROR_CBOR_FAILURE ((int)-110)

/** The bound crypto backend reported a failure. */
#define EDHOC_ERROR_CRYPTO_FAILURE ((int)-111)

/** An authentication credentials callback returned an error, or what it
 *  produced failed the library's validation. */
#define EDHOC_ERROR_CREDENTIALS_FAILURE ((int)-112)

/** The EAD compose callback returned an error, or produced items the library
 *  rejects. */
#define EDHOC_ERROR_EAD_COMPOSE_FAILURE ((int)-120)

/** The EAD process callback returned an error. */
#define EDHOC_ERROR_EAD_PROCESS_FAILURE ((int)-121)

/** A received EDHOC message 1 decoded, but its content was rejected. */
#define EDHOC_ERROR_MSG_1_PROCESS_FAILURE ((int)-130)

/** A received EDHOC message 2 decoded, but its content was rejected. */
#define EDHOC_ERROR_MSG_2_PROCESS_FAILURE ((int)-131)

/** A received EDHOC message 3 decoded, but its content was rejected. */
#define EDHOC_ERROR_MSG_3_PROCESS_FAILURE ((int)-132)

/** A received EDHOC message 4 decoded, but its content was rejected. */
#define EDHOC_ERROR_MSG_4_PROCESS_FAILURE ((int)-133)

/** The ephemeral key exchange failed: key generation, or KEM encapsulation or
 *  decapsulation. */
#define EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE ((int)-134)

/** Computation of an EDHOC transcript hash (TH_2, TH_3, or TH_4) failed. */
#define EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE ((int)-135)

/** Derivation of an EDHOC pseudorandom key (PRK) in the key schedule failed. */
#define EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE ((int)-136)

/** Signature_or_MAC_2 did not verify: the Responder is not authenticated. */
#define EDHOC_ERROR_INVALID_SIGN_OR_MAC_2 ((int)-138)

/** Signature_or_MAC_3 did not verify: the Initiator is not authenticated. */
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

/** OSCORE Master Secret, for \ref edhoc_export and \ref edhoc_export_raw. */
#define EDHOC_EXPORTER_LABEL_OSCORE_MASTER_SECRET ((size_t)0)

/** OSCORE Master Salt, for \ref edhoc_export and \ref edhoc_export_raw. */
#define EDHOC_EXPORTER_LABEL_OSCORE_MASTER_SALT ((size_t)1)

/** Resumption PSK, for \ref edhoc_export_resumption_psk and
 *  \ref edhoc_export_resumption_psk_raw.
 *
 *  draft-ietf-lake-edhoc-psk: 10.2 suggests 2, pending IANA assignment. */
#define EDHOC_EXPORTER_LABEL_RESUMPTION_PSK ((size_t)2)

/** Resumption 'kid', for \ref edhoc_export_resumption_kid_raw.
 *
 *  draft-ietf-lake-edhoc-psk: 10.2 suggests 3, pending IANA assignment. */
#define EDHOC_EXPORTER_LABEL_RESUMPTION_KID ((size_t)3)

/** Default length of the resumption 'kid'
 *  (draft-ietf-lake-edhoc-psk: 6). */
#define EDHOC_EXPORTER_RESUMPTION_KID_DEFAULT_LEN ((size_t)2)

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**@}*/

#endif /* EDHOC_VALUES_H */
