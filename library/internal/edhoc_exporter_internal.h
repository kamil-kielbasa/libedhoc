/**
 * \file    edhoc_exporter_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC_Exporter (RFC 9528: 4.2.1) and EDHOC-KeyUpdate (RFC 9528: 4.4).
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_EXPORTER_INTERNAL_H
#define EDHOC_EXPORTER_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* EDHOC public header: */
#include <edhoc/crypto.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** EDHOC context, defined by \c edhoc_context_internal.h. */
struct edhoc_context;

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-exporter EDHOC exporter
 *
 *  Each entry point backs the public function of the same purpose; see
 *  \c <edhoc/edhoc.h> for the argument contract.
 * @{
 */

/** \brief Export application keying material as a key-store handle. */
int edhoc_exporter_export(struct edhoc_context *ctx, size_t label,
			  const uint8_t *context, size_t context_len,
			  enum edhoc_key_usage usage, void *key_id);

/** \brief Export application keying material as raw bytes. */
int edhoc_exporter_export_raw(struct edhoc_context *ctx, size_t label,
			      const uint8_t *context, size_t context_len,
			      uint8_t *secret, size_t secret_len);

/** \brief Rotate PRK_out (RFC 9528: 4.4). */
int edhoc_exporter_key_update(struct edhoc_context *ctx, const uint8_t *context,
			      size_t context_len);

/** \brief Export an OSCORE security context, master secret as a handle. */
int edhoc_exporter_oscore_context(struct edhoc_context *ctx,
				  void *master_secret_key_id, uint8_t *salt,
				  size_t salt_len, uint8_t *sid,
				  size_t sid_size, size_t *sid_len,
				  uint8_t *rid, size_t rid_size,
				  size_t *rid_len);

/** \brief Export an OSCORE security context, master secret as raw bytes. */
int edhoc_exporter_oscore_context_raw(struct edhoc_context *ctx,
				      uint8_t *secret, size_t secret_len,
				      uint8_t *salt, size_t salt_len,
				      uint8_t *sid, size_t sid_size,
				      size_t *sid_len, uint8_t *rid,
				      size_t rid_size, size_t *rid_len);

/**@}*/

#endif /* EDHOC_EXPORTER_INTERNAL_H */
