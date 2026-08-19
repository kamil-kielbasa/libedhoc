/**
 * \file    edhoc_error_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC error message (RFC 9528: 6).
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_ERROR_INTERNAL_H
#define EDHOC_ERROR_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* EDHOC public header: */
#include <edhoc/types.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-error EDHOC error message
 *
 *  Backs the public \c edhoc_message_error_* functions; see
 *  \c <edhoc/edhoc.h> for the argument contract.
 * @{
 */

/** \brief Encode an error message (RFC 9528: 6). */
int edhoc_error_encode(uint8_t *msg_err, size_t msg_err_size,
		       size_t *msg_err_len, enum edhoc_error_code code,
		       const struct edhoc_error_info *info);

/** \brief Decode an error message (RFC 9528: 6). */
int edhoc_error_decode(const uint8_t *msg_err, size_t msg_err_len,
		       enum edhoc_error_code *code,
		       struct edhoc_error_info *info);

/**@}*/

#endif /* EDHOC_ERROR_INTERNAL_H */
