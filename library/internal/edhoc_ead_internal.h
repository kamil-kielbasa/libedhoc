/**
 * \file    edhoc_ead_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC external authorization data (RFC 9528: 3.8).
 *
 *          Every message may carry EAD, and all four handle it the same way:
 *          ask the application for items, hand received items back, and move
 *          them between the context and the CBOR backend structures. The two
 *          generated item types differ only in field names, so both get a
 *          conversion pair here rather than a copied loop per message.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_EAD_INTERNAL_H
#define EDHOC_EAD_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include <edhoc_config.h>
#endif

/* EDHOC public headers: */
#include <edhoc/ead.h>

/* Standard library headers: */
#include <stddef.h>
#include <stdbool.h>

/* Defines ----------------------------------------------------------------- */

/** Number of EAD tokens the application may fill in, zero in a "no EAD" build. */
#define EDHOC_EAD_CAPACITY (CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS)

/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-ead-types EDHOC external authorization data types
 * @{
 */

/** EDHOC context, defined by \c edhoc_context_internal.h. */
struct edhoc_context;

/** Sequence of EAD items, defined by the CBOR backend. */
struct ead;

/**
 * \brief External authorization data tokens carried across a message.
 */
struct edhoc_ead_tokens {
	/** Token storage. The \c +1 keeps the array non-empty when the Kconfig
	 *  count is 0 (a valid "no EAD" build); usable capacity is
	 *  \ref EDHOC_EAD_CAPACITY. */
	struct edhoc_ead_token token[EDHOC_EAD_CAPACITY + 1];
	/** Number of live tokens in \p token. */
	size_t count;
};

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-ead EDHOC external authorization data
 * @{
 */

/**
 * \brief Does the context carry EAD?
 *
 * \param[in] ctx                      EDHOC context.
 *
 * \return \c true when at least one token is live.
 */
bool edhoc_ead_is_present(const struct edhoc_context *ctx);

/**
 * \brief May the library ask the application to compose EAD?
 *
 * \param[in] ctx                      EDHOC context.
 *
 * \return \c true when a callback is bound and there is room for a token.
 */
bool edhoc_ead_may_compose(const struct edhoc_context *ctx);

/**
 * \brief May the library hand received EAD to the application?
 *
 * \param[in] ctx                      EDHOC context.
 *
 * \return \c true when a callback is bound and a token was received.
 */
bool edhoc_ead_may_process(const struct edhoc_context *ctx);

/**
 * \brief Wipe all external authorization data tokens.
 *
 * \param[in,out] ctx                  EDHOC context.
 */
void edhoc_ead_reset(struct edhoc_context *ctx);

/**
 * \brief Ask the application to compose EAD for the current message, then
 *        validate what it returned.
 *
 *        A context without a bound compose callback, or without room for an
 *        item, is a successful no-op that leaves the token list empty.
 *
 * \param[in,out] ctx                   EDHOC context.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_ead_compose(struct edhoc_context *ctx);

/**
 * \brief Hand the received EAD items to the application.
 *
 *        A context without a bound process callback, or without received
 *        items, is a successful no-op.
 *
 *        The items point into the buffer the message was decoded from, so this
 *        must run before that buffer is released.
 *
 * \param[in,out] ctx                   EDHOC context.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_ead_process(struct edhoc_context *ctx);

/**
 * \brief Number of bytes the current EAD items occupy once CBOR-encoded.
 *
 * \param[in] ctx                       EDHOC context.
 * \param[out] length                   On success, the encoded size.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_ead_encoded_length(const struct edhoc_context *ctx, size_t *length);

/**
 * \brief Copy the context EAD items into the CBOR backend structure.
 *
 * \param[in] ctx                       EDHOC context.
 * \param[out] tokens                   Items to fill.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_ead_tokens_encode(const struct edhoc_context *ctx,
			    struct ead *tokens);

/**
 * \brief Take decoded EAD items into the context.
 *
 *        The items are views into the buffer they were decoded from, so the
 *        context tokens stay valid only as long as that buffer does.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param[in] tokens                    Decoded items.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_ead_tokens_decode(struct edhoc_context *ctx,
			    const struct ead *tokens);

/**@}*/

#endif /* EDHOC_EAD_INTERNAL_H */
