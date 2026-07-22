/**
 * \file    edhoc_values_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC internal constants (CBOR primitives and EDHOC_KDF labels).
 *
 *          These values are implementation details of the EDHOC state machine
 *          and are intentionally kept out of the public \c <edhoc/values.h>
 *          header, which exposes only the error codes and the exporter
 *          private-label range that applications legitimately depend on.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_VALUES_INTERNAL_H
#define EDHOC_VALUES_INTERNAL_H

/* Include files ----------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-values-internal EDHOC internal values
 * @{
 */

/** Minimum value for CBOR one byte integer.
 *  It must follow RFC 9528: 3.3.2. Representation of Byte String Identifiers. */
#define ONE_BYTE_CBOR_INT_MIN_VALUE ((int32_t)-24)

/** Maximum value for CBOR one byte integer.
 *  It must follow RFC 9528: 3.3.2. Representation of Byte String Identifiers. */
#define ONE_BYTE_CBOR_INT_MAX_VALUE ((int32_t)23)

/** CBOR encoding for boolean true (RFC 8949: 3.3.1. Major Type 7). */
#define EDHOC_CBOR_TRUE ((uint8_t)0xf5)

/** KEYSTREAM_2 from RFC 9528: 4.1.2. EDHOC_Expand and EDHOC_KDF. */
#define EDHOC_EXTRACT_PRK_INFO_LABEL_KEYSTREAM_2 ((size_t)0)

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

/** EDHOC exporter label for OSCORE Master Secret from
 * RFC 9528: A.1. Deriving the OSCORE Security Context. */
#define OSCORE_EXTRACT_LABEL_MASTER_SECRET ((size_t)0)

/** EDHOC exporter label for OSCORE Master Salt from
 * RFC 9528: A.1. Deriving the OSCORE Security Context. */
#define OSCORE_EXTRACT_LABEL_MASTER_SALT ((size_t)1)

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_VALUES_INTERNAL_H */
