/**
 * \file    edhoc_values.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC values and error codes.
 * \version 1.0
 * \date    2025-04-14
 * 
 * \copyright Copyright (c) 2025
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

/** An error occurred that does not correspond to any defined failure cause. */
#define EDHOC_ERROR_GENERIC_ERROR ((int)-100)

/** The requested operation or a parameter is not supported by this implementation. */
#define EDHOC_ERROR_NOT_SUPPORTED ((int)-101)

/** The requested action is denied by a EDHOC specification. */
#define EDHOC_ERROR_NOT_PERMITTED ((int)-102)

/** An output buffer is too small. */
#define EDHOC_ERROR_BUFFER_TOO_SMALL ((int)-103)

/** The requested action cannot be performed in the current state. */
#define EDHOC_ERROR_BAD_STATE ((int)-104)

/** The parameters passed to the function are invalid. */
#define EDHOC_ERROR_INVALID_ARGUMENT ((int)-105)

/** There was a CBOR failure inside implementation. */
#define EDHOC_ERROR_CBOR_FAILURE ((int)-110)

/** There was a cryptographic operation failure inside implementation. */
#define EDHOC_ERROR_CRYPTO_FAILURE ((int)-111)

/** There was a credentials failure inside implementation. */
#define EDHOC_ERROR_CREDENTIALS_FAILURE ((int)-112)

/** External authorization data compose failed. */
#define EDHOC_ERROR_EAD_COMPOSE_FAILURE ((int)-120)

/** External authorization data process failed. */
#define EDHOC_ERROR_EAD_PROCESS_FAILURE ((int)-121)

/** EDHOC processing of message 1 failure was detected. */
#define EDHOC_ERROR_MSG_1_PROCESS_FAILURE ((int)-130)

/** EDHOC processing of message 2 failure was detected. */
#define EDHOC_ERROR_MSG_2_PROCESS_FAILURE ((int)-131)

/** EDHOC processing of message 3 failure was detected. */
#define EDHOC_ERROR_MSG_3_PROCESS_FAILURE ((int)-132)

/** EDHOC processing of message 4 failure was detected. */
#define EDHOC_ERROR_MSG_4_PROCESS_FAILURE ((int)-133)

/** EDHOC ephemeral Diffie-Hellman key agreement failure was detected. */
#define EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE ((int)-134)

/** EDHOC computing of transcript hash failure was detected. */
#define EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE ((int)-135)

/** EDHOC computing of pseudorandom key failure was detected. */
#define EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE ((int)-136)

/** EDHOC MAC_2 is incorrect. */
#define EDHOC_ERROR_INVALID_MAC_2 ((int)-137)

/** EDHOC Signature_2 or MAC_2 is incorrect. */
#define EDHOC_ERROR_INVALID_SIGN_OR_MAC_2 ((int)-138)

/** EDHOC MAC_3 is incorrect. */
#define EDHOC_ERROR_INVALID_MAC_3 ((int)-139)

/** EDHOC Signature_3 or MAC_3 is incorrect. */
#define EDHOC_ERROR_INVALID_SIGN_OR_MAC_3 ((int)-140)

/**@}*/

/** \defgroup edhoc-values-cbor-one-byte EDHOC CBOR one byte
 *
 * \note It must follow the RFC 9528: 3.3.2. Representation of Byte String Identifiers.
 *
 * @{
 */

/** Minimum value for CBOR one byte integer. */
#define ONE_BYTE_CBOR_INT_MIN_VALUE ((int32_t)-24)

/** Maximum value for CBOR one byte integer. */
#define ONE_BYTE_CBOR_INT_MAX_VALUE ((int32_t)23)

/**@}*/

/** \defgroup edhoc-values-cbor-primitive EDHOC CBOR primitive values
 *
 * Standard CBOR primitive values that may be used in EDHOC implementations.
 *
 * @{
 */

/** CBOR encoding for boolean true (RFC 8949: 3.3.1. Major Type 7). */
#define EDHOC_CBOR_TRUE ((uint8_t)0xf5)

/**@}*/

/** \defgroup edhoc-values-extract EDHOC extract labels
 * @{
 */

/** KEYSTREAM_2 from RFC 9528: 4.1.2. EDHOC_Expand and EDHOC_KDF. */
#define EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTERAM_2 ((size_t)0)

/** SALT_3e2m from RFC 9528: 4.1.2. EDHOC_Expand and EDHOC_KDF. */
#define EDHOC_EXTRACT_PRK_INFO_LABEL_SALT_3E2M ((size_t)1)

/** MAC_2 from RFC 9528: 4.1.2. EDHOC_Expand and EDHOC_KDF. */
#define EDHOC_EXTRACT_PRK_INFO_LABEL_MAC_2 ((size_t)2)

/** K_3 from RFC 9528: 4.1.2. EDHOC_Expand and EDHOC_KDF. */
#define EDHOC_EXTRACT_PRK_INFO_LABEL_K_3 ((size_t)3)

/** IV_3 from RFC 9528: 4.1.2. EDHOC_Expand and EDHOC_KDF. */
#define EDHOC_EXTRACT_PRK_INFO_LABEL_IV_3 ((size_t)4)

/** SALT_4e3m from RFC 9528: 4.1.2. EDHOC_Expand and EDHOC_KDF. */
#define EDHOC_EXTRACT_PRK_INFO_LABEL_SALT_4E3M ((size_t)5)

/** MAC_3 from RFC 9528: 4.1.2. EDHOC_Expand and EDHOC_KDF. */
#define EDHOC_EXTRACT_PRK_INFO_LABEL_MAC_3 ((size_t)6)

/** PRK_out from RFC 9528: 4.1.2. EDHOC_Expand and EDHOC_KDF. */
#define EDHOC_EXTRACT_PRK_INFO_LABEL_PRK_OUT ((size_t)7)

/** K_4 from RFC 9528: 4.1.2. EDHOC_Expand and EDHOC_KDF. */
#define EDHOC_EXTRACT_PRK_INFO_LABEL_K_4 ((size_t)8)

/** IV_4 from RFC 9528: 4.1.2. EDHOC_Expand and EDHOC_KDF. */
#define EDHOC_EXTRACT_PRK_INFO_LABEL_IV_4 ((size_t)9)

/** PRK_Exporter from RFC 9528: 4.2.1. EDHOC_Exporter. */
#define EDHOC_EXTRACT_PRK_INFO_LABEL_PRK_EXPORTER ((size_t)10)

/** PRK_out from RFC 9528: 4.1.3. PRK_out. */
#define EDHOC_EXTRACT_PRK_INFO_LABEL_NEW_PRK_OUT ((size_t)11)

/**
 * \brief RFC 9528: A.1. Deriving the OSCORE Security Context
 */

/** EDHOC exporter label for OSCORE Master Secret from
 * RFC 9528: A.1. Deriving the OSCORE Security Context. */
#define OSCORE_EXTRACT_LABEL_MASTER_SECRET ((size_t)0)

/** EDHOC exporter label for OSCORE Master Salt from
 * RFC 9528: A.1. Deriving the OSCORE Security Context. */
#define OSCORE_EXTRACT_LABEL_MASTER_SALT ((size_t)1)

/**
 * \brief RFC 9528: 10.1. EDHOC Exporter Label Registry
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
