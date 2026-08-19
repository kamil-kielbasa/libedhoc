/**
 * \file    edhoc_classic_internal.h
 * \author  Kamil Kielbasa
 * \brief   Classic EDHOC message flow (RFC 9528: 5).
 *
 *          The four messages of the flow that authenticates with signatures or
 *          static Diffie-Hellman. A future flow declares the same four entry
 *          points in its own header and \c edhoc.c picks between them.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CLASSIC_INTERNAL_H
#define EDHOC_CLASSIC_INTERNAL_H

/* Include files ----------------------------------------------------------- */

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

/** \defgroup edhoc-classic Classic EDHOC message flow
 *
 *  Each entry point mirrors the public function of the same number; see
 *  \c <edhoc/edhoc.h> for the argument contract.
 * @{
 */

/** \brief Compose message 1 (RFC 9528: 5.2.2). */
int edhoc_classic_message_1_compose(struct edhoc_context *ctx, uint8_t *msg_1,
				    size_t msg_1_size, size_t *msg_1_len);

/** \brief Process message 1 (RFC 9528: 5.2.3). */
int edhoc_classic_message_1_process(struct edhoc_context *ctx,
				    const uint8_t *msg_1, size_t msg_1_len);

/** \brief Compose message 2 (RFC 9528: 5.3.2). */
int edhoc_classic_message_2_compose(struct edhoc_context *ctx, uint8_t *msg_2,
				    size_t msg_2_size, size_t *msg_2_len);

/** \brief Process message 2 (RFC 9528: 5.3.3). */
int edhoc_classic_message_2_process(struct edhoc_context *ctx,
				    const uint8_t *msg_2, size_t msg_2_len);

/** \brief Compose message 3 (RFC 9528: 5.4.2). */
int edhoc_classic_message_3_compose(struct edhoc_context *ctx, uint8_t *msg_3,
				    size_t msg_3_size, size_t *msg_3_len);

/** \brief Process message 3 (RFC 9528: 5.4.3). */
int edhoc_classic_message_3_process(struct edhoc_context *ctx,
				    const uint8_t *msg_3, size_t msg_3_len);

/** \brief Compose message 4 (RFC 9528: 5.5.2). */
int edhoc_classic_message_4_compose(struct edhoc_context *ctx, uint8_t *msg_4,
				    size_t msg_4_size, size_t *msg_4_len);

/** \brief Process message 4 (RFC 9528: 5.5.3). */
int edhoc_classic_message_4_process(struct edhoc_context *ctx,
				    const uint8_t *msg_4, size_t msg_4_len);

/**@}*/

#endif /* EDHOC_CLASSIC_INTERNAL_H */
