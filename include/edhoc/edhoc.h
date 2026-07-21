/**
 * \file    edhoc.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC API.
 *
 * \copyright Copyright (c) 2025
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

/** The major version of this implementation of the EDHOC API. */
#define EDHOC_API_VERSION_MAJOR 2

/** The minor version of this implementation of the EDHOC API. */
#define EDHOC_API_VERSION_MINOR 0

/** The patch version of this implementation of the EDHOC API. */
#define EDHOC_API_VERSION_PATCH 0

/**@}*/

/* Types and type definitions ---------------------------------------------- */

/**
 * \brief EDHOC context (opaque).
 *
 * The layout is library-internal and intentionally hidden from consumers.
 * Allocate storage sized by \ref edhoc_context_size (stack VLA or heap), then
 * drive the context through the public API. The full definition lives in
 * \c library/internal/edhoc_context_internal.h and is available to the library
 * core and to white-box tests only.
 *
 * \ingroup edhoc-context
 */
struct edhoc_context;

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-api-setters EDHOC API setters
 *
 * After \ref edhoc_context_init, a context must be fully configured before the
 * message-processing API will run. A message compose or process call made
 * before every **mandatory** input is present returns
 * \ref EDHOC_ERROR_BAD_STATE.
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
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Input parameter is invalid.
 */
int edhoc_context_init(struct edhoc_context *edhoc_context);

/**
 * \brief Size in bytes of an EDHOC context for this build.
 *
 * The context is opaque; its size depends on the Kconfig configuration and is
 * not a compile-time constant. Allocate storage of at least this many bytes
 * (stack VLA or heap, suitably aligned for \ref edhoc_context) and pass it to
 * \ref edhoc_context_init.
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
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         Input parameter is invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_context_deinit(struct edhoc_context *edhoc_context);

/**
 * \brief Set EDHOC methods.
 *
 * According to RFC 9528: 3.2. Method. At least one method must be set,
 * but no more than \c CONFIG_LIBEDHOC_MAX_NR_OF_METHODS.
 *
 * Behavior depends on the role:
 * - Initiator always uses the first value (method[0]) when composing message 1.
 * - Responder iterates over all methods to find a match when processing message 1.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] method                    EDHOC method.
 * \param method_length			Number of entries in the \p method array.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_set_methods(struct edhoc_context *edhoc_context,
		      const enum edhoc_method *method, size_t method_length);

/**
 * \brief Set EDHOC cipher suites.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] cipher_suite              EDHOC cipher suites.
 * \param cipher_suite_length           Number of entries in the \p cipher_suite array.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_set_cipher_suites(struct edhoc_context *edhoc_context,
			    const struct edhoc_cipher_suite *cipher_suite,
			    size_t cipher_suite_length);

/**
 * \brief Set EDHOC connection identifier.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] connection_id             EDHOC connection identifier.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_set_connection_id(struct edhoc_context *edhoc_context,
			    const struct edhoc_connection_id *connection_id);

/**
 * \brief Set user context.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] user_context              User context.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_set_user_context(struct edhoc_context *edhoc_context,
			   void *user_context);

/**
 * \brief Bind EDHOC external authorization data (EAD) callbacks.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] ead                       EDHOC EAD structure with callbacks.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_bind_ead(struct edhoc_context *edhoc_context,
		   const struct edhoc_ead *ead);

/**
 * \brief Bind EDHOC cryptographic operations callbacks.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] crypto                    EDHOC cryptographic operations structure with callbacks.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_bind_crypto(struct edhoc_context *edhoc_context,
		      const struct edhoc_crypto *crypto);

/**
 * \brief Bind EDHOC authentication credentials callbacks.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] credentials               EDHOC authentication credentials structure with callbacks.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_bind_credentials(struct edhoc_context *edhoc_context,
			   const struct edhoc_credentials *credentials);

/**
 * \brief Bind EDHOC platform services callbacks.
 *
 * Mandatory. The message-processing API refuses to run until a platform with a
 * valid \p zeroize callback is bound to the context.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] platform                  EDHOC platform structure with callbacks.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_bind_platform(struct edhoc_context *edhoc_context,
			const struct edhoc_platform *platform);

/**@}*/

/** \defgroup edhoc-api-messages EDHOC messages API
 * @{
 */

/**
 * \brief Compose EDHOC message 1.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] message_1                Buffer where the generated message 1 is to be written.
 * \param message_1_size                Size of the \p message_1 buffer in bytes.
 * \param[out] message_1_length         On success, the number of bytes that make up the message 1.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Operation not permitted in the current configuration.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographic operation failure.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE
 *         Ephemeral Diffie-Hellman operation failed.
 * \retval #EDHOC_ERROR_EAD_COMPOSE_FAILURE
 *         EAD compose callback failed.
 */
int edhoc_message_1_compose(struct edhoc_context *edhoc_context,
			    uint8_t *message_1, size_t message_1_size,
			    size_t *message_1_length);

/**
 * \brief Process EDHOC message 1.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] message_1                 Buffer containing the message 1.
 * \param message_1_length              Length of the \p message_1 in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Operation not permitted in the current configuration.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_MSG_1_PROCESS_FAILURE
 *         EDHOC message processing failed.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR decoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographic operation failure.
 * \retval #EDHOC_ERROR_EAD_PROCESS_FAILURE
 *         EAD process callback failed.
 */
int edhoc_message_1_process(struct edhoc_context *edhoc_context,
			    const uint8_t *message_1, size_t message_1_length);

/**
 * \brief Compose EDHOC message 2.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] message_2                Buffer where the generated message 2 is to be written.
 * \param message_2_size                Size of the \p message_2 buffer in bytes.
 * \param[out] message_2_length         On success, the number of bytes that make up the message 2.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Operation not permitted in the current configuration.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographic operation failure.
 * \retval #EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE
 *         Transcript hash computation failed.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Pseudorandom key derivation failed.
 * \retval #EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE
 *         Ephemeral Diffie-Hellman operation failed.
 * \retval #EDHOC_ERROR_CREDENTIALS_FAILURE
 *         Authentication credentials operation failed.
 * \retval #EDHOC_ERROR_EAD_COMPOSE_FAILURE
 *         EAD compose callback failed.
 */
int edhoc_message_2_compose(struct edhoc_context *edhoc_context,
			    uint8_t *message_2, size_t message_2_size,
			    size_t *message_2_length);

/**
 * \brief Process EDHOC message 2.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] message_2                 Buffer containing the message 2.
 * \param message_2_length              Length of the \p message_2 in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Operation not permitted in the current configuration.
 * \retval #EDHOC_ERROR_MSG_2_PROCESS_FAILURE
 *         EDHOC message processing failed.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR decoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographic operation failure.
 * \retval #EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE
 *         Transcript hash computation failed.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Pseudorandom key derivation failed.
 * \retval #EDHOC_ERROR_EPHEMERAL_DIFFIE_HELLMAN_FAILURE
 *         Ephemeral Diffie-Hellman operation failed.
 * \retval #EDHOC_ERROR_INVALID_MAC_2
 *         MAC_2 verification failed.
 * \retval #EDHOC_ERROR_INVALID_SIGN_OR_MAC_2
 *         Signature_or_MAC_2 verification failed.
 * \retval #EDHOC_ERROR_CREDENTIALS_FAILURE
 *         Authentication credentials operation failed.
 * \retval #EDHOC_ERROR_EAD_PROCESS_FAILURE
 *         EAD process callback failed.
 */
int edhoc_message_2_process(struct edhoc_context *edhoc_context,
			    const uint8_t *message_2, size_t message_2_length);

/**
 * \brief Compose EDHOC message 3.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] message_3                Buffer where the generated message 3 is to be written.
 * \param message_3_size                Size of the \p message_3 buffer in bytes.
 * \param[out] message_3_length         On success, the number of bytes that make up the message 3.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Operation not permitted in the current configuration.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographic operation failure.
 * \retval #EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE
 *         Transcript hash computation failed.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Pseudorandom key derivation failed.
 * \retval #EDHOC_ERROR_CREDENTIALS_FAILURE
 *         Authentication credentials operation failed.
 * \retval #EDHOC_ERROR_EAD_COMPOSE_FAILURE
 *         EAD compose callback failed.
 */
int edhoc_message_3_compose(struct edhoc_context *edhoc_context,
			    uint8_t *message_3, size_t message_3_size,
			    size_t *message_3_length);

/**
 * \brief Process EDHOC message 3.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] message_3                 Buffer containing the message 3.
 * \param message_3_length              Length of the \p message_3 in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Operation not permitted in the current configuration.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_MSG_3_PROCESS_FAILURE
 *         EDHOC message processing failed.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR decoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographic operation failure.
 * \retval #EDHOC_ERROR_TRANSCRIPT_HASH_FAILURE
 *         Transcript hash computation failed.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Pseudorandom key derivation failed.
 * \retval #EDHOC_ERROR_INVALID_MAC_3
 *         MAC_3 verification failed.
 * \retval #EDHOC_ERROR_INVALID_SIGN_OR_MAC_3
 *         Signature_or_MAC_3 verification failed.
 * \retval #EDHOC_ERROR_CREDENTIALS_FAILURE
 *         Authentication credentials operation failed.
 * \retval #EDHOC_ERROR_EAD_PROCESS_FAILURE
 *         EAD process callback failed.
 */
int edhoc_message_3_process(struct edhoc_context *edhoc_context,
			    const uint8_t *message_3, size_t message_3_length);

/**
 * \brief Compose EDHOC message 4.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[out] message_4                Buffer where the generated message 4 is to be written.
 * \param message_4_size                Size of the \p message_4 buffer in bytes.
 * \param[out] message_4_length         On success, the number of bytes that make up the message 4.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographic operation failure.
 * \retval #EDHOC_ERROR_EAD_COMPOSE_FAILURE
 *         EAD compose callback failed.
 */
int edhoc_message_4_compose(struct edhoc_context *edhoc_context,
			    uint8_t *message_4, size_t message_4_size,
			    size_t *message_4_length);

/**
 * \brief Process EDHOC message 4.
 *
 * \param[in,out] edhoc_context         EDHOC context.
 * \param[in] message_4                 Buffer containing the message 4.
 * \param message_4_length              Length of the \p message_4 in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_MSG_4_PROCESS_FAILURE
 *         EDHOC message 4 processing failed.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR decoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographic operation failure.
 * \retval #EDHOC_ERROR_EAD_PROCESS_FAILURE
 *         EAD process callback failed.
 */
int edhoc_message_4_process(struct edhoc_context *edhoc_context,
			    const uint8_t *message_4, size_t message_4_length);

/**
 * \brief Compose EDHOC message error.
 *
 * \param[out] message_error            Buffer where the generated message error is to be written.
 * \param message_error_size            Size of the \p message_error buffer in bytes.
 * \param[out] message_error_length     On success, the number of bytes that make up the message error.
 * \param error_code                    EDHOC error code.
 * \param[in] error_info                EDHOC error information.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Operation not permitted in the current configuration.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 */
int edhoc_message_error_compose(uint8_t *message_error,
				size_t message_error_size,
				size_t *message_error_length,
				enum edhoc_error_code error_code,
				const struct edhoc_error_info *error_info);

/**
 * \brief Process EDHOC message error.
 *
 * \param[in] message_error             Buffer containing the message error.
 * \param message_error_length          Length of the \p message_error in bytes.
 * \param[out] error_code               EDHOC error code.
 * \param[out] error_info               EDHOC error information.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Operation not permitted in the current configuration.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR decoding failure.
 */
int edhoc_message_error_process(const uint8_t *message_error,
				size_t message_error_length,
				enum edhoc_error_code *error_code,
				struct edhoc_error_info *error_info);

/**@}*/

/** \defgroup edhoc-api-exporters EDHOC exporters API
 * @{
 */

/**
 * \brief Export application keying material as a key-store handle.
 *
 *        Implements RFC 9528: 4.2.1. EDHOC_Exporter(label, context, length),
 *        deriving a key from PRK_exporter and returning it as an opaque
 *        key-store handle (a key reference) rather than raw bytes. Prefer this
 *        form when the derived key must never be exposed as bytes (for example
 *        a TrustZone or secure element); use \ref edhoc_export_raw() when the
 *        caller needs the raw bytes.
 *
 *        The derived length is governed by \p usage, not chosen by the caller:
 *        #EDHOC_KEY_USAGE_KDF yields a derivation key of the cipher suite hash
 *        length; #EDHOC_KEY_USAGE_AEAD yields an AEAD key of the cipher suite
 *        AEAD key length. Because the length is bound into the KDF info, the
 *        material differs from \ref edhoc_export_raw() unless the raw
 *        \p secret_length equals the length implied by \p usage.
 *
 *        Permitted labels (RFC 9528: 10.1) are 0 (OSCORE Master Secret), 1
 *        (OSCORE Master Salt) and the private-use range 32768-65535; any other
 *        label is rejected with #EDHOC_ERROR_NOT_PERMITTED.
 *
 * \note  The returned handle is owned by the caller: this library neither
 *        tracks it in the EDHOC context nor releases it in
 *        \ref edhoc_context_deinit(). The caller must destroy it, for example
 *        through the \c destroy_key entry of the bound \ref edhoc_crypto vtable.
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
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         The exporter label is not permitted.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographic operation failure.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Pseudorandom key derivation failed.
 */
int edhoc_export(struct edhoc_context *edhoc_context, size_t label,
		 const uint8_t *context, size_t context_length,
		 enum edhoc_key_usage usage, void *key_id);

/**
 * \brief Export application keying material as raw bytes.
 *
 *        Implements RFC 9528: 4.2.1. EDHOC_Exporter(label, context, length),
 *        deriving \p secret_length bytes from PRK_exporter and writing them to
 *        \p secret. Use \ref edhoc_export() when the derived key should remain
 *        an opaque handle instead of raw bytes. Permitted labels are the same
 *        as for \ref edhoc_export().
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
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         The exporter label is not permitted.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographic operation failure.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Pseudorandom key derivation failed.
 */
int edhoc_export_raw(struct edhoc_context *edhoc_context, size_t label,
		     const uint8_t *context, size_t context_length,
		     uint8_t *secret, size_t secret_length);

/**
 * \brief Perform key update for subsequent OSCORE session exports.
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
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Operation not permitted in the current configuration.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographic operation failure.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Pseudorandom key derivation failed.
 */
int edhoc_export_key_update(struct edhoc_context *edhoc_context,
			    const uint8_t *context, size_t context_length);

/**
 * \brief Export the OSCORE security session with the master secret as a handle.
 *
 *        Derives the OSCORE Master Secret (RFC 9528: A.1, exporter label 0) and
 *        returns it as an opaque key-store handle, while the Master Salt
 *        (label 1) and the sender / recipient identifiers are returned as raw
 *        bytes. Use \ref edhoc_export_oscore_session_raw() to obtain the master
 *        secret as raw bytes instead.
 *
 *        The master secret handle is derived with #EDHOC_KEY_USAGE_KDF (a
 *        derivation key of the cipher suite hash length), suitable as input
 *        keying material to the OSCORE HKDF.
 *
 * \note  The returned handle is owned by the caller (see \ref edhoc_export()).
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
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Operation not permitted in the current configuration.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographic operation failure.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Pseudorandom key derivation failed.
 */
int edhoc_export_oscore_session(struct edhoc_context *edhoc_context,
				void *master_secret_key_id,
				uint8_t *master_salt, size_t master_salt_length,
				uint8_t *sender_id, size_t sender_id_size,
				size_t *sender_id_length, uint8_t *recipient_id,
				size_t recipient_id_size,
				size_t *recipient_id_length);

/**
 * \brief Export the OSCORE security session as raw bytes.
 *
 *        Derives the OSCORE Master Secret and Master Salt (exporter labels 0
 *        and 1) and copies the sender / recipient identifiers, all as raw
 *        bytes. Use \ref edhoc_export_oscore_session() to obtain the master
 *        secret as an opaque handle instead.
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
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_NOT_PERMITTED
 *         Operation not permitted in the current configuration.
 * \retval #EDHOC_ERROR_CBOR_FAILURE
 *         CBOR encoding failure.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 * \retval #EDHOC_ERROR_CRYPTO_FAILURE
 *         Cryptographic operation failure.
 * \retval #EDHOC_ERROR_PSEUDORANDOM_KEY_FAILURE
 *         Pseudorandom key derivation failed.
 */
int edhoc_export_oscore_session_raw(
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
 * \brief EDHOC error getter.
 *
 * \param[in] edhoc_context             EDHOC context.
 * \param[out] error_code               EDHOC error code.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 */
int edhoc_error_get_code(const struct edhoc_context *edhoc_context,
			 enum edhoc_error_code *error_code);

/**
 * \brief Retrieve own and peer cipher suites after \p EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE.
 *
 * \param[in] edhoc_context             	EDHOC context.
 * \param[out] cipher_suites			Buffer where the own cipher suite values are written.
 * \param cipher_suites_size            	Size of the \p cipher_suites buffer in entries.
 * \param[out] cipher_suites_length     	On success, the number of entries written to \p cipher_suites.
 * \param[out] peer_cipher_suites		Buffer where the peer cipher suite values are written.
 * \param peer_cipher_suites_size		Size of the \p peer_cipher_suites buffer in entries.
 * \param[out] peer_cipher_suites_length	On success, the number of entries written to \p peer_cipher_suites.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \retval #EDHOC_ERROR_INVALID_ARGUMENT
 *         One or more input parameters are invalid.
 * \retval #EDHOC_ERROR_BAD_STATE
 *         Internal context state is incorrect.
 * \retval #EDHOC_ERROR_BUFFER_TOO_SMALL
 *         Output buffer is too small.
 */
int edhoc_error_get_cipher_suites(const struct edhoc_context *edhoc_context,
				  int32_t *cipher_suites,
				  size_t cipher_suites_size,
				  size_t *cipher_suites_length,
				  int32_t *peer_cipher_suites,
				  size_t peer_cipher_suites_size,
				  size_t *peer_cipher_suites_length);

/**@}*/

#endif /* EDHOC_H */
