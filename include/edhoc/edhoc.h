/**
 * \file    edhoc.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC API.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_H
#define EDHOC_H

/* Include files ----------------------------------------------------------- */

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* EDHOC headers: */
#include "types.h"
#include "credentials.h"
#include "cipher_suite.h"
#include "crypto.h"
#include "ead.h"
#include "platform.h"
#include "values.h"

/* Defines ----------------------------------------------------------------- */

/** \defgroup edhoc-api-version EDHOC API version
 * @{
 */

/** Major version of the EDHOC API. */
#define EDHOC_API_VERSION_MAJOR 2

/** Minor version of the EDHOC API. */
#define EDHOC_API_VERSION_MINOR 0

/** Patch version of the EDHOC API. */
#define EDHOC_API_VERSION_PATCH 0

/**@}*/

/* Types and type definitions ---------------------------------------------- */

/**
 * \brief EDHOC context (opaque).
 *
 * Allocate storage of \ref edhoc_context_size bytes and drive it through the
 * public API; the layout is library-internal.
 *
 * \ingroup edhoc-types
 */
struct edhoc_context;

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-api-setters EDHOC API setters
 *
 * After \ref edhoc_context_init, a context must be fully configured before the
 * message-processing API will run. A message compose or process call made
 * before every **mandatory** input is present returns \ref EDHOC_ERROR_BAD_STATE.
 *
 * **Mandatory** inputs:
 *   - \ref edhoc_set_methods "method(s)"
 *   - \ref edhoc_set_cipher_suites "cipher suite(s)"
 *   - \ref edhoc_set_connection_id "connection identifier"
 *   - \ref edhoc_bind_crypto "crypto interface"
 *   - \ref edhoc_bind_credentials "credentials interface"
 *   - \ref edhoc_bind_platform "platform interface"
 *
 * **Optional** inputs:
 *   - \ref edhoc_set_user_context "user context"
 *   - \ref edhoc_bind_ead "external authorization data (EAD) interface"
 * @{
 */

/**
 * \brief Initialize EDHOC context.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_context_init(struct edhoc_context *edhoc_context);

/**
 * \brief Size in bytes of an EDHOC context for this build.
 *
 * The size depends on the build-time configuration, so it is a run-time value.
 * Allocate at least this many bytes (on the stack or heap) for the
 * \ref edhoc_context passed to \ref edhoc_context_init.
 *
 * \return Size in bytes of \ref edhoc_context.
 */
size_t edhoc_context_size(void);

/**
 * \brief Deinitialize EDHOC context.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_context_deinit(struct edhoc_context *edhoc_context);

/**
 * \brief Set EDHOC method(s) (mandatory).
 *
 * Configures the authentication method(s) the context may use (RFC 9528: 3.2).
 * At least one and at most \c CONFIG_LIBEDHOC_MAX_NR_OF_METHODS methods must be
 * provided. The role selects how the list is used:
 * - the Initiator uses the first method when composing message 1;
 * - the Responder accepts message 1 if its method matches any provided entry.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] method                    EDHOC method.
 * \param method_count                  Number of entries in the \p method array.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_set_methods(struct edhoc_context *edhoc_context,
		      const enum edhoc_method *method, size_t method_count);

/**
 * \brief Set EDHOC cipher suite(s) (mandatory).
 *
 * Configures the cipher suite(s) the context supports (RFC 9528: 3.6). The
 * Initiator offers them in SUITES_I and the Responder checks the selected suite
 * against those it supports (RFC 9528: 5.2.1).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] cipher_suite              EDHOC cipher suites.
 * \param cipher_suite_count            Number of entries in the \p cipher_suite array.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_set_cipher_suites(struct edhoc_context *edhoc_context,
			    const struct edhoc_cipher_suite *cipher_suite,
			    size_t cipher_suite_count);

/**
 * \brief Set EDHOC connection identifier (mandatory).
 *
 * Sets the connection identifier the peer uses to reference this endpoint in
 * the session: C_I for the Initiator (sent in message 1) or C_R for the
 * Responder (sent in message 2) (RFC 9528: 3.3).
 *
 * \note  C_I and C_R are chosen independently; the library does not require
 *        them to differ.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] connection_id             EDHOC connection identifier.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_set_connection_id(struct edhoc_context *edhoc_context,
			    const struct edhoc_connection_id *connection_id);

/**
 * \brief Set user context (optional).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] user_context              User context.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_set_user_context(struct edhoc_context *edhoc_context,
			   void *user_context);

/**
 * \brief Bind the cryptographic operations interface (mandatory).
 *
 * Provides the crypto primitives the library uses: key exchange, AEAD, hash,
 * signature/MAC and key derivation.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] crypto                    EDHOC cryptographic operations structure with callbacks.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_bind_crypto(struct edhoc_context *edhoc_context,
		      const struct edhoc_crypto *crypto);

/**
 * \brief Bind the authentication credentials interface (mandatory).
 *
 * Provides the fetch/verify callbacks the library uses to obtain the local
 * authentication credentials and to verify the peer's (RFC 9528: 3.5).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] credentials               EDHOC authentication credentials structure with callbacks.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_bind_credentials(struct edhoc_context *edhoc_context,
			   const struct edhoc_credentials *credentials);

/**
 * \brief Bind the platform services interface (mandatory).
 *
 * Provides the platform services the library uses.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] platform                  EDHOC platform structure with callbacks.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_bind_platform(struct edhoc_context *edhoc_context,
			const struct edhoc_platform *platform);

/**
 * \brief Bind the external authorization data (EAD) interface (optional).
 *
 * Provides the compose/process callbacks for the EAD items carried in the
 * EDHOC messages (RFC 9528: 3.8). Optional; bind it only if the application
 * sends or receives EAD.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] ead                       EDHOC EAD structure with callbacks.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_bind_ead(struct edhoc_context *edhoc_context,
		   const struct edhoc_ead *ead);

/**@}*/

/** \defgroup edhoc-api-messages EDHOC messages API
 * @{
 */

/**
 * \brief Compose EDHOC message 1.
 *
 *        The Initiator composes message 1: it proposes the method (METHOD) and
 *        cipher suites (SUITES_I) and carries the ephemeral public key G_X, the
 *        connection identifier C_I and optional EAD_1 (RFC 9528: 5.2.1).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] message_1                Buffer where the generated message 1 is to be written.
 * \param message_1_size                Size of the \p message_1 buffer in bytes.
 * \param[out] message_1_length         On success, the number of bytes that make up the message 1.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_message_1_compose(struct edhoc_context *edhoc_context,
			    uint8_t *message_1, size_t message_1_size,
			    size_t *message_1_length);

/**
 * \brief Process EDHOC message 1.
 *
 *        The Responder processes message 1: it reads and verifies that it
 *        supports the proposed method (METHOD) and cipher suites (SUITES_I),
 *        then reads the Initiator's ephemeral public key G_X, the connection
 *        identifier C_I and optional EAD_1 (RFC 9528: 5.2.3).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] message_1                 Buffer containing the message 1.
 * \param message_1_length              Length of the \p message_1 in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_message_1_process(struct edhoc_context *edhoc_context,
			    const uint8_t *message_1, size_t message_1_length);

/**
 * \brief Compose EDHOC message 2.
 *
 *        The Responder composes message 2: it carries G_Y (completing the
 *        ephemeral key exchange) and, encrypted, authenticates the Responder to
 *        the Initiator with ID_CRED_R and Signature_or_MAC_2 (plus C_R and
 *        optional EAD_2) (RFC 9528: 5.3.1).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] message_2                Buffer where the generated message 2 is to be written.
 * \param message_2_size                Size of the \p message_2 buffer in bytes.
 * \param[out] message_2_length         On success, the number of bytes that make up the message 2.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_message_2_compose(struct edhoc_context *edhoc_context,
			    uint8_t *message_2, size_t message_2_size,
			    size_t *message_2_length);

/**
 * \brief Process EDHOC message 2.
 *
 *        The Initiator processes message 2: it completes the ephemeral key
 *        exchange from G_Y and verifies the Responder's authentication
 *        (ID_CRED_R, Signature_or_MAC_2, optional EAD_2) (RFC 9528: 5.3.3).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] message_2                 Buffer containing the message 2.
 * \param message_2_length              Length of the \p message_2 in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_message_2_process(struct edhoc_context *edhoc_context,
			    const uint8_t *message_2, size_t message_2_length);

/**
 * \brief Compose EDHOC message 3.
 *
 *        The Initiator composes message 3: it authenticates the Initiator to
 *        the Responder with the AEAD-encrypted ID_CRED_I and Signature_or_MAC_3
 *        (plus optional EAD_3), completing mutual authentication
 *        (RFC 9528: 5.4.1).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] message_3                Buffer where the generated message 3 is to be written.
 * \param message_3_size                Size of the \p message_3 buffer in bytes.
 * \param[out] message_3_length         On success, the number of bytes that make up the message 3.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_message_3_compose(struct edhoc_context *edhoc_context,
			    uint8_t *message_3, size_t message_3_size,
			    size_t *message_3_length);

/**
 * \brief Process EDHOC message 3.
 *
 *        The Responder processes message 3: it verifies the Initiator's
 *        authentication (ID_CRED_I, Signature_or_MAC_3, optional EAD_3),
 *        completing mutual authentication (RFC 9528: 5.4.3).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] message_3                 Buffer containing the message 3.
 * \param message_3_length              Length of the \p message_3 in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_message_3_process(struct edhoc_context *edhoc_context,
			    const uint8_t *message_3, size_t message_3_length);

/**
 * \brief Compose EDHOC message 4.
 *
 *        The Responder composes the optional message 4, giving the Initiator
 *        explicit key confirmation; it may carry optional EAD_4
 *        (RFC 9528: 5.5.1).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] message_4                Buffer where the generated message 4 is to be written.
 * \param message_4_size                Size of the \p message_4 buffer in bytes.
 * \param[out] message_4_length         On success, the number of bytes that make up the message 4.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_message_4_compose(struct edhoc_context *edhoc_context,
			    uint8_t *message_4, size_t message_4_size,
			    size_t *message_4_length);

/**
 * \brief Process EDHOC message 4.
 *
 *        The Initiator processes the optional message 4, obtaining explicit key
 *        confirmation from the Responder; it may carry optional EAD_4
 *        (RFC 9528: 5.5.3).
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] message_4                 Buffer containing the message 4.
 * \param message_4_length              Length of the \p message_4 in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_message_4_process(struct edhoc_context *edhoc_context,
			    const uint8_t *message_4, size_t message_4_length);

/**
 * \brief Compose an EDHOC error message.
 *
 *        Either party may reply to any EDHOC message with an error message; it
 *        is fatal and aborts the session (RFC 9528: 6). It carries an error
 *        code and matching error information.
 *
 * \param[out] message_error            Buffer where the generated message error is to be written.
 * \param message_error_size            Size of the \p message_error buffer in bytes.
 * \param[out] message_error_length     On success, the number of bytes that make up the message error.
 * \param error_code                    EDHOC error code.
 * \param[in] error_info                EDHOC error information.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_message_error_compose(uint8_t *message_error,
				size_t message_error_size,
				size_t *message_error_length,
				enum edhoc_error_code error_code,
				const struct edhoc_error_info *error_info);

/**
 * \brief Process a received EDHOC error message.
 *
 *        Decodes a received error message into its error code and error
 *        information; receiving one indicates the peer aborted the session
 *        (RFC 9528: 6).
 *
 * \param[in] message_error             Buffer containing the message error.
 * \param message_error_length          Length of the \p message_error in bytes.
 * \param[out] error_code               EDHOC error code.
 * \param[out] error_info               EDHOC error information.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_message_error_process(const uint8_t *message_error,
				size_t message_error_length,
				enum edhoc_error_code *error_code,
				struct edhoc_error_info *error_info);

/**@}*/

/** \defgroup edhoc-api-exporters EDHOC exporters API
 *
 * Derive application keying material from a completed EDHOC session with the
 * EDHOC_Exporter (RFC 9528: 4.2.1). Each exporter comes in two forms: a
 * raw-bytes form (\c _raw) that writes the secret into a caller buffer, and a
 * key-handle form that returns it as an opaque key reference kept inside the
 * bound crypto backend, so the bytes never leave it (e.g. a TrustZone or
 * secure element).
 *
 * Permitted exporter labels (RFC 9528: 10.1) are 0 (OSCORE Master Secret),
 * 1 (OSCORE Master Salt) and the private-use range
 * #EDHOC_PRK_EXPORTER_PRIVATE_LABEL_MINIMUM ..
 * #EDHOC_PRK_EXPORTER_PRIVATE_LABEL_MAXIMUM; any other label is rejected with
 * #EDHOC_ERROR_NOT_PERMITTED.
 * @{
 */

/**
 * \brief Export application keying material as a key handle.
 *
 *        Returns the derived key as an opaque key handle. The derived length is
 *        set by \p usage: #EDHOC_KEY_USAGE_KDF yields the cipher suite hash
 *        length and #EDHOC_KEY_USAGE_AEAD the cipher suite AEAD key length.
 *
 * \note  The returned handle is owned by the caller: the library neither tracks
 *        it nor releases it in \ref edhoc_context_deinit(). Destroy it through
 *        the \c destroy_key entry of the bound \ref edhoc_crypto vtable.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param label                         EDHOC exporter label (RFC 9528: 10.1).
 * \param[in] context                   Exporter context byte string (may be NULL when \p context_length is 0).
 * \param context_length                Size of the \p context buffer in bytes.
 * \param usage                         Intended usage of the derived key; governs its type and length.
 * \param[out] key_id                   Buffer holding a key handle (\c CONFIG_LIBEDHOC_KEY_ID_LEN bytes) that receives the derived key.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_export(struct edhoc_context *edhoc_context, size_t label,
		 const uint8_t *context, size_t context_length,
		 enum edhoc_key_usage usage, void *key_id);

/**
 * \brief Export application keying material as raw bytes.
 *
 *        Derives \p secret_length bytes (RFC 9528: 4.2.1) and writes them to
 *        \p secret.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param label                         EDHOC exporter label (RFC 9528: 10.1).
 * \param[in] context                   Exporter context byte string (may be NULL when \p context_length is 0).
 * \param context_length                Size of the \p context buffer in bytes.
 * \param[out] secret                   Buffer where the generated secret is to be written.
 * \param secret_length                 Size of the \p secret buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_export_raw(struct edhoc_context *edhoc_context, size_t label,
		     const uint8_t *context, size_t context_length,
		     uint8_t *secret, size_t secret_length);

/**
 * \brief Perform key update for subsequent OSCORE Security Context exports.
 *
 *        Implements RFC 9528: 4.4. EDHOC-KeyUpdate(context): rotates PRK_out so
 *        that later OSCORE exports derive fresh keying material bound to the
 *        application-supplied \p context byte string.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] context                   Buffer containing the key-update context.
 * \param context_length                Size of the \p context buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_export_key_update(struct edhoc_context *edhoc_context,
			    const uint8_t *context, size_t context_length);

/**
 * \brief Export the OSCORE security context with the master secret as a handle.
 *
 *        Derives the OSCORE Master Secret (RFC 9528: A.1, exporter label 0) and
 *        returns it as an opaque AEAD key handle of the cipher suite AEAD key
 *        length; the Master Salt (exporter label 1) is returned as raw bytes
 *        and the OSCORE Sender and Recipient IDs are copied out.
 *
 * \note  The returned handle is owned by the caller: the library neither tracks
 *        it nor releases it in \ref edhoc_context_deinit(). Destroy it through
 *        the \c destroy_key entry of the bound \ref edhoc_crypto vtable.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] master_secret_key_id     Buffer holding a key handle (\c CONFIG_LIBEDHOC_KEY_ID_LEN bytes) that receives the master secret.
 * \param[out] master_salt              Buffer where the exported master salt is to be written.
 * \param master_salt_length            Size of the \p master_salt buffer in bytes.
 * \param[out] sender_id                Buffer where the exported sender id is to be written.
 * \param sender_id_size                Size of the \p sender_id buffer in bytes.
 * \param[out] sender_id_length         On success, the number of bytes that make up the sender id.
 * \param[out] recipient_id             Buffer where the exported recipient id is to be written.
 * \param recipient_id_size             Size of the \p recipient_id buffer in bytes.
 * \param[out] recipient_id_length      On success, the number of bytes that make up the recipient id.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_export_oscore_context(struct edhoc_context *edhoc_context,
				void *master_secret_key_id,
				uint8_t *master_salt, size_t master_salt_length,
				uint8_t *sender_id, size_t sender_id_size,
				size_t *sender_id_length, uint8_t *recipient_id,
				size_t recipient_id_size,
				size_t *recipient_id_length);

/**
 * \brief Export the OSCORE security context as raw bytes.
 *
 *        Derives the OSCORE Master Secret and Master Salt (exporter labels 0
 *        and 1) as raw bytes and copies out the OSCORE Sender and Recipient
 *        IDs.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] master_secret            Buffer where the exported master secret is to be written.
 * \param master_secret_length          Size of the \p master_secret buffer in bytes.
 * \param[out] master_salt              Buffer where the exported master salt is to be written.
 * \param master_salt_length            Size of the \p master_salt buffer in bytes.
 * \param[out] sender_id                Buffer where the exported sender id is to be written.
 * \param sender_id_size                Size of the \p sender_id buffer in bytes.
 * \param[out] sender_id_length         On success, the number of bytes that make up the sender id.
 * \param[out] recipient_id             Buffer where the exported recipient id is to be written.
 * \param recipient_id_size             Size of the \p recipient_id buffer in bytes.
 * \param[out] recipient_id_length      On success, the number of bytes that make up the recipient id.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_export_oscore_context_raw(
	struct edhoc_context *edhoc_context, uint8_t *master_secret,
	size_t master_secret_length, uint8_t *master_salt,
	size_t master_salt_length, uint8_t *sender_id, size_t sender_id_size,
	size_t *sender_id_length, uint8_t *recipient_id,
	size_t recipient_id_size, size_t *recipient_id_length);

/**@}*/

/** \defgroup edhoc-api-error EDHOC errors API
 * @{
 */

/**
 * \brief Get the EDHOC error code recorded for the session.
 *
 * Returns the EDHOC error code (RFC 9528: 6) recorded in the context.
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[out] error_code               EDHOC error code.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_error_get_code(const struct edhoc_context *edhoc_context,
			 enum edhoc_error_code *error_code);

/**
 * \brief Retrieve the own and peer cipher suites after a cipher suite
 *        negotiation error.
 *
 * After the peer replies to message 1 with error code
 * #EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE (RFC 9528: 6.3), this returns
 * the local supported suites (SUITES_I) and the peer's supported suites
 * (SUITES_R) so the Initiator can reselect a mutually supported suite for the
 * next message 1 (RFC 9528: 6.3.1).
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[out] cipher_suites            Buffer where the own cipher suite values are written.
 * \param cipher_suites_size            Size of the \p cipher_suites buffer in entries.
 * \param[out] cipher_suites_count      On success, the number of entries written to \p cipher_suites.
 * \param[out] peer_cipher_suites       Buffer where the peer cipher suite values are written.
 * \param peer_cipher_suites_size       Size of the \p peer_cipher_suites buffer in entries.
 * \param[out] peer_cipher_suites_count On success, the number of entries written to \p peer_cipher_suites.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure (\ref edhoc-error-codes).
 */
int edhoc_error_get_cipher_suites(const struct edhoc_context *edhoc_context,
				  int32_t *cipher_suites,
				  size_t cipher_suites_size,
				  size_t *cipher_suites_count,
				  int32_t *peer_cipher_suites,
				  size_t peer_cipher_suites_size,
				  size_t *peer_cipher_suites_count);

/**@}*/

#endif /* EDHOC_H */
