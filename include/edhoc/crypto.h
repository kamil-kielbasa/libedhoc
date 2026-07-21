/**
 * \file    crypto.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC cryptographic interface.
 * 
 * \copyright Copyright (c) 2025
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CRYPTO_H
#define EDHOC_CRYPTO_H

/* Include files ----------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>

/* EDHOC headers: */
#include "cipher_suite.h"

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** \defgroup edhoc-interface-crypto-usage EDHOC interface for cryptographic key usage
 * @{
 */

/**
 * \brief Usage of a key handle produced by \ref edhoc_crypto.expand.
 *
 *        A PSA / secure-element key must receive its policy at creation time,
 *        so a key handle is created with the usage it will serve. Unlike the
 *        removed \c enum \c edhoc_key_type, no raw secret ever crosses the
 *        interface boundary: the usage only selects the policy of a key that
 *        is derived and kept inside the backend key store.
 */
enum edhoc_key_usage {
	/** KDF input: chain salts, rolling pseudorandom keys, exported keys. */
	EDHOC_KEY_USAGE_KDF,
	/** AEAD key: K_3, K_4. */
	EDHOC_KEY_USAGE_AEAD,
};

/**@}*/

/** \defgroup edhoc-interface-crypto-operations EDHOC interface for cryptographic operations
 * @{
 */

/**
 * \brief Bind structure for cryptographic operations (handle-only, KEM-style).
 *
 *        Every long-lived secret is an opaque handle into the backend key
 *        store (a software PSA slot, the TrustZone secure world or a secure
 *        element); it is never serialized into \ref edhoc_context or onto the
 *        stack. Peer public keys enter as raw bytes and one-shot public
 *        outputs (keystreams, IVs, MACs) leave as raw bytes. The ephemeral key
 *        exchange is expressed as a KEM: classical Diffie-Hellman suites
 *        implement it as a thin NIKE-as-KEM shim, so ML-KEM drops in behind the
 *        same interface with the wire unchanged (\c G_X carries the
 *        encapsulation key, \c G_Y carries the ciphertext).
 */
struct edhoc_crypto {
	/**
	 * \brief Destroy a key handle and free its key-store slot.
	 *
	 *        Destroying a zeroed / no-key handle is a successful no-op, so
	 *        \ref edhoc_context_deinit may re-destroy already-freed slots.
	 *
	 * \param[in] user_context		User context.
	 * \param[in,out] key_id                Key identifier to destroy.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*destroy_key)(void *user_context, void *key_id);

	/**
	 * \brief Generate an ephemeral key pair (Initiator, message_1).
	 *
	 *        The decapsulation (private) key stays in the key store as a
	 *        handle; only the encapsulation (public) key leaves, to be sent
	 *        in \c G_X.
	 *
	 * \param[in] user_context		User context.
	 * \param[out] decapsulation_key_id     Handle of the generated private key.
	 * \param[out] encapsulation_key        Public key, sent in \c G_X.
	 * \param encapsulation_key_size        Size of the \p encapsulation_key buffer in bytes.
	 * \param[out] encapsulation_key_length On success, the number of bytes that make up the encapsulation key.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*generate_key_pair)(void *user_context, void *decapsulation_key_id,
				 uint8_t *encapsulation_key,
				 size_t encapsulation_key_size,
				 size_t *encapsulation_key_length);
	/**
	 * \brief Encapsulate to a peer encapsulation key (Responder, message_2).
	 *
	 *        For a NIKE-as-KEM shim the backend generates its own ephemeral
	 *        key pair, runs the key agreement and returns its ephemeral
	 *        public key as \p ciphertext (sent in \c G_Y). The ephemeral
	 *        private key is retained as \p decapsulation_key_id so the
	 *        Responder can reuse it for the static-DH \c G_IY agreement in
	 *        message_3 (methods 2 and 3).
	 *
	 * \param[in] user_context		User context.
	 * \param[in] encapsulation_key         Peer public key from \c G_X.
	 * \param encapsulation_key_length      Size of the \p encapsulation_key buffer in bytes.
	 * \param[out] decapsulation_key_id     Handle of the retained ephemeral private key. A KEM
	 *                                      without static-DH support leaves it a null handle.
	 * \param[out] shared_secret_key_id     Handle of the shared secret (\c G_XY).
	 * \param[out] ciphertext               KEM ciphertext, sent in \c G_Y.
	 * \param ciphertext_size               Size of the \p ciphertext buffer in bytes.
	 * \param[out] ciphertext_length        On success, the number of bytes that make up the ciphertext.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*encapsulate)(void *user_context, const uint8_t *encapsulation_key,
			   size_t encapsulation_key_length,
			   void *decapsulation_key_id,
			   void *shared_secret_key_id, uint8_t *ciphertext,
			   size_t ciphertext_size, size_t *ciphertext_length);
	/**
	 * \brief Decapsulate a ciphertext (Initiator, after message_2).
	 *
	 * \param[in] user_context		User context.
	 * \param[in] decapsulation_key_id      Handle of the private key from \ref generate_key_pair.
	 * \param[in] ciphertext                KEM ciphertext from \c G_Y.
	 * \param ciphertext_length             Size of the \p ciphertext buffer in bytes.
	 * \param[out] shared_secret_key_id     Handle of the shared secret (\c G_XY).
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*decapsulate)(void *user_context, const void *decapsulation_key_id,
			   const uint8_t *ciphertext, size_t ciphertext_length,
			   void *shared_secret_key_id);

	/**
	 * \brief Static Diffie-Hellman key agreement (methods 1/2/3, NIKE suites).
	 *
	 *        Used only for static-DH authentication; the shared secret is
	 *        produced as a handle, never as raw bytes.
	 *
	 * \param[in] user_context		User context.
	 * \param[in] private_key_id            Handle of the local static private key.
	 * \param[in] peer_public_key           Peer static public key (raw bytes).
	 * \param peer_public_key_length        Size of the \p peer_public_key buffer in bytes.
	 * \param[out] shared_secret_key_id     Handle of the shared secret.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*key_agreement)(void *user_context, const void *private_key_id,
			     const uint8_t *peer_public_key,
			     size_t peer_public_key_length,
			     void *shared_secret_key_id);

	/**
	 * \brief Generate a digital signature.
	 *
	 * \param[in] user_context		User context.
	 * \param[in] private_key_id            Handle of the signing key.
	 * \param[in] input                     Full message to sign (not a digest).
	 * \param input_length                  Size of the \p input buffer in bytes.
	 * \param[out] signature                Buffer where the signature is to be written.
	 * \param signature_size                Size of the \p signature buffer in bytes.
	 * \param[out] signature_length         On success, the number of bytes that make up the signature.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*sign)(void *user_context, const void *private_key_id,
		    const uint8_t *input, size_t input_length,
		    uint8_t *signature, size_t signature_size,
		    size_t *signature_length);
	/**
	 * \brief Verify a digital signature against a raw peer public key.
	 *
	 * \param[in] user_context		User context.
	 * \param[in] public_key                Peer public key (raw bytes).
	 * \param public_key_length             Size of the \p public_key buffer in bytes.
	 * \param[in] input                     Full signed message (not a digest).
	 * \param input_length                  Size of the \p input buffer in bytes.
	 * \param[in] signature                 Buffer containing the signature to verify.
	 * \param signature_length              Size of the \p signature buffer in bytes.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*verify)(void *user_context, const uint8_t *public_key,
		      size_t public_key_length, const uint8_t *input,
		      size_t input_length, const uint8_t *signature,
		      size_t signature_length);

	/**
	 * \brief EDHOC_Extract: derive a pseudorandom key handle from a salt.
	 *
	 *        The input keying material and the output pseudorandom key are
	 *        handles; the salt is raw bytes. For \c PRK_2e the salt is the
	 *        public \c TH_2; for the rolling pseudorandom keys it is a chain
	 *        salt that the caller derives with \ref expand_raw and zeroizes
	 *        after use.
	 *
	 * \param[in] user_context		User context.
	 * \param[in] ikm_key_id                Input keying material handle.
	 * \param[in] salt                      Raw salt.
	 * \param salt_length                   Size of the \p salt buffer in bytes.
	 * \param[out] prk_key_id               Output pseudorandom key handle.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*extract)(void *user_context, const void *ikm_key_id,
		       const uint8_t *salt, size_t salt_length,
		       void *prk_key_id);
	/**
	 * \brief EDHOC_Expand producing a key handle (handle space).
	 *
	 *        The \p usage selects the policy of the created key, since a
	 *        PSA / secure-element key must receive its policy at creation.
	 *
	 * \param[in] user_context		User context.
	 * \param[in] prk_key_id                Pseudorandom key handle.
	 * \param[in] info                      CBOR-encoded info.
	 * \param info_length                   Size of the \p info buffer in bytes.
	 * \param usage                         Policy of the produced key.
	 * \param[out] output_key_id            Output key handle.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*expand)(void *user_context, const void *prk_key_id,
		      const uint8_t *info, size_t info_length,
		      enum edhoc_key_usage usage, void *output_key_id);
	/**
	 * \brief EDHOC_Expand producing raw output (keystream, IV, MAC, exporter).
	 *
	 * \param[in] user_context		User context.
	 * \param[in] prk_key_id                Pseudorandom key handle.
	 * \param[in] info                      CBOR-encoded info.
	 * \param info_length                   Size of the \p info buffer in bytes.
	 * \param[out] output                   Raw output keying material.
	 * \param output_length                 Requested output length in bytes.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*expand_raw)(void *user_context, const void *prk_key_id,
			  const uint8_t *info, size_t info_length,
			  uint8_t *output, size_t output_length);

	/**
	 * \brief Perform AEAD encryption.
	 *
	 * \param[in] user_context		User context.
	 * \param[in] key_id                    AEAD key handle.
	 * \param[in] nonce                     Nonce or IV to use.
	 * \param nonce_length                  Size of the \p nonce buffer in bytes.
	 * \param[in] additional_data           Additional data that will be authenticated but not encrypted.
	 * \param additional_data_length        Size of the \p additional_data buffer in bytes.
	 * \param[in] plaintext                 Data that will be authenticated and encrypted.
	 * \param plaintext_length              Size of the \p plaintext buffer in bytes.
	 * \param[out] ciphertext               Buffer where the authenticated and encrypted data is to be written.
	 * \param ciphertext_size               Size of the \p ciphertext buffer in bytes.
	 * \param[out] ciphertext_length        On success, the number of bytes that make up the ciphertext.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*aead_encrypt)(void *user_context, const void *key_id,
			    const uint8_t *nonce, size_t nonce_length,
			    const uint8_t *additional_data,
			    size_t additional_data_length,
			    const uint8_t *plaintext, size_t plaintext_length,
			    uint8_t *ciphertext, size_t ciphertext_size,
			    size_t *ciphertext_length);
	/**
	 * \brief Perform AEAD decryption.
	 *
	 * \param[in] user_context		User context.
	 * \param[in] key_id                    AEAD key handle.
	 * \param[in] nonce                     Nonce or IV to use.
	 * \param nonce_length                  Size of the \p nonce buffer in bytes.
	 * \param[in] additional_data           Additional data that will be authenticated but not encrypted.
	 * \param additional_data_length        Size of the \p additional_data buffer in bytes.
	 * \param[in] ciphertext                Buffer containing the authenticated and encrypted data.
	 * \param ciphertext_length             Size of the \p ciphertext buffer in bytes.
	 * \param[out] plaintext                Buffer where the decrypted data is to be written.
	 * \param plaintext_size                Size of the \p plaintext buffer in bytes.
	 * \param[out] plaintext_length         On success, the number of bytes that make up the plaintext.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*aead_decrypt)(void *user_context, const void *key_id,
			    const uint8_t *nonce, size_t nonce_length,
			    const uint8_t *additional_data,
			    size_t additional_data_length,
			    const uint8_t *ciphertext, size_t ciphertext_length,
			    uint8_t *plaintext, size_t plaintext_size,
			    size_t *plaintext_length);

	/**
	 * \brief Begin a multipart hash operation.
	 *
	 *        Multipart-only: large PQC transcripts must be hashed
	 *        incrementally. The operation object is owned by the backend
	 *        (no heap allocation in the library) and released by
	 *        \ref hash_finish or \ref hash_abort.
	 *
	 * \param[in] user_context		User context.
	 * \param[out] operation                On success, backend hash operation.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*hash_init)(void *user_context, void **operation);
	/**
	 * \brief Add input to a multipart hash operation.
	 *
	 * \param[in] user_context		User context.
	 * \param[in] operation                 Backend hash operation.
	 * \param[in] input                     Input message chunk to hash.
	 * \param input_length                  Size of the \p input buffer in bytes.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*hash_update)(void *user_context, void *operation,
			   const uint8_t *input, size_t input_length);
	/**
	 * \brief Finish a multipart hash operation and release it.
	 *
	 * \param[in] user_context		User context.
	 * \param[in] operation                 Backend hash operation.
	 * \param[out] hash                     Buffer where the hash is to be written.
	 * \param hash_size                     Size of the \p hash buffer in bytes.
	 * \param[out] hash_length              On success, the number of bytes that make up the hash.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*hash_finish)(void *user_context, void *operation, uint8_t *hash,
			   size_t hash_size, size_t *hash_length);
	/**
	 * \brief Abort a multipart hash operation and release it.
	 *
	 * \param[in] user_context		User context.
	 * \param[in] operation                 Backend hash operation.
	 *
	 * \retval #EDHOC_SUCCESS
	 *         Success.
	 * \return Negative error code on failure.
	 */
	int (*hash_abort)(void *user_context, void *operation);
};

/**@}*/

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

#endif /* EDHOC_CRYPTO_H */
