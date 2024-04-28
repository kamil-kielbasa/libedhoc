/**
 * \file    edhoc_values.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC values and error codes.
 * \version 0.2
 * \date    2024-01-01
 * 
 * \copyright Copyright (c) 2024
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

/**
 * \brief The action was completed successfully.
 */
#define EDHOC_SUCCESS ((int)0)

/**
 * \brief An error occurred that does not correspond to any defined failure cause.
 */
#define EDHOC_ERROR_GENERIC_ERROR ((int)-100)

/**
 * \brief The requested operation or a parameter is not supported by this implementation.
 */
#define EDHOC_ERROR_NOT_SUPPORTED ((int)-101)

/**
 * \brief The requested action is denied by a EDHOC specification.
 */
#define EDHOC_ERROR_NOT_PERMITTED ((int)-102)

/**
 * \brief An output buffer is too small.
 */
#define EDHOC_ERROR_BUFFER_TOO_SMALL ((int)-103)

/**
 * \brief The requested action cannot be performed in the current state.
 */
#define EDHOC_ERROR_BAD_STATE ((int)-104)

/**
 * \brief The parameters passed to the function are invalid.
 */
#define EDHOC_ERROR_INVALID_ARGUMENT ((int)-105)

/**
 * \brief There was a CBOR failure inside implementation.
 */
#define EDHOC_ERROR_CBOR_FAILURE ((int)-110)

/**
 * \brief There was a cryptographic operation failure inside implementation.
 */
#define EDHOC_ERROR_CRYPTO_FAILURE ((int)-111)

/**
 * \brief There was a credentials failure inside implementation.
 */
#define EDHOC_ERROR_CREDENTIALS_FAILURE ((int)-112)

/**
 * \brief External authorization data compose failed.
 */
#define EDHOC_ERROR_EAD_COMPOSE_FAILURE ((int)-120)

/**
 * \brief External authorization data process failed.
 */
#define EDHOC_ERROR_EAD_PROCESS_FAILURE ((int)-121)

/**
 * \brief EDHOC processing of message 1 failure was detected.
 */
#define EDHOC_ERROR_MSG_1_PROCESS_FAILURE ((int)-130)

/**
 * \brief EDHOC processing of message 2 failure was detected.
 */
#define EDHOC_ERROR_MSG_2_PROCESS_FAILURE ((int)-131)

/**
 * \brief EDHOC processing of message 3 failure was detected.
 */
#define EDHOC_ERROR_MSG_3_PROCESS_FAILURE ((int)-132)

/**
 * \brief EDHOC processing of message 4 failure was detected.
 */
#define EDHOC_ERROR_MSG_4_PROCESS_FAILURE ((int)-133)

/**
 * \brief EDHOC ephemeral Diffie-Hellman key agreement failure was detected.
 */
#define EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE ((int)-134)

/**
 * \brief EDHOC computing of transcript hash failure was detected.
 */
#define EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE ((int)-135)

/**
 * \brief EDHOC computing of pseudorandom key failure was detected.
 */
#define EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE ((int)-136)

/**
 * \brief EDHOC MAC_2 is incorrect.
 */
#define EDHOC_ERROR_INVALID_MAC_2 ((int)-137)

/**
 * \brief EDHOC Signature_2 or MAC_2 is incorrect.
 */
#define EDHOC_ERROR_INVALID_SIGN_OR_MAC_2 ((int)-138)

/**
 * \brief EDHOC MAC_3 is incorrect.
 */
#define EDHOC_ERROR_INVALID_MAC_3 ((int)-139)

/**
 * \brief EDHOC Signature_3 or MAC_3 is incorrect.
 */
#define EDHOC_ERROR_INVALID_SIGN_OR_MAC_3 ((int)-140)

/**
 * \brief RFC 9528: 3.3.2. Representation of Byte String Identifiers.
 */
#define ONE_BYTE_CBOR_INT_MIN_VALUE ((int32_t)-24)
#define ONE_BYTE_CBOR_INT_MAX_VALUE ((int32_t)23)

/**
 * \brief RFC 9528: 4.1.2. EDHOC_Expand and EDHOC_KDF.
 */
#define EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTERAM_2 ((size_t)0)
#define EDHOC_EXTRACT_PRK_INFO_LABEL_SALT_3E2M ((size_t)1)
#define EDHOC_EXTRACT_PRK_INFO_LABEL_MAC_2 ((size_t)2)
#define EDHOC_EXTRACT_PRK_INFO_LABEL_K_3 ((size_t)3)
#define EDHOC_EXTRACT_PRK_INFO_LABEL_IV_3 ((size_t)4)
#define EDHOC_EXTRACT_PRK_INFO_LABEL_SALT_4E3M ((size_t)5)
#define EDHOC_EXTRACT_PRK_INFO_LABEL_MAC_3 ((size_t)6)
#define EDHOC_EXTRACT_PRK_INFO_LABEL_PRK_OUT ((size_t)7)
#define EDHOC_EXTRACT_PRK_INFO_LABEL_K_4 ((size_t)8)
#define EDHOC_EXTRACT_PRK_INFO_LABEL_IV_4 ((size_t)9)
#define EDHOC_EXTRACT_PRK_INFO_LABEL_PRK_EXPORTER ((size_t)10)
#define EDHOC_EXTRACT_PRK_INFO_LABEL_NEW_PRK_OUT ((size_t)11)

/**
 * \brief RFC 9528: A.1. Deriving the OSCORE Security Context
 */
#define OSCORE_EXTRACT_LABEL_MASTER_SECRET ((size_t)0)
#define OSCORE_EXTRACT_LABEL_MASTER_SALT ((size_t)1)

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_VALUES_H */
