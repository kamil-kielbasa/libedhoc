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

/** CBOR encoding for boolean true (RFC 8949: 3.3.1. Major Type 7). */
#define EDHOC_CBOR_TRUE ((uint8_t)0xf5)

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
