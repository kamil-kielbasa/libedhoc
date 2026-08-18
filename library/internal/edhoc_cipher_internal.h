/**
 * \file    edhoc_cipher_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC message encryption (RFC 9528: 5.3, 5.4, 5.5).
 *
 *          Message 2 is protected with a keystream and XOR, messages 3 and 4
 *          with AEAD. The two AEAD messages differ only in which key and label
 *          they use, so that mapping lives in one place and both read it.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CIPHER_INTERNAL_H
#define EDHOC_CIPHER_INTERNAL_H

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

/** \defgroup edhoc-cipher-aead EDHOC AEAD (messages 3 and 4)
 * @{
 */

/**
 * \brief Number of bytes the associated data occupies once CBOR-encoded.
 *
 * \param[in] ctx                       EDHOC context.
 * \param[out] length                   On success, the encoded size.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_cipher_aad_length(const struct edhoc_context *ctx, size_t *length);

/**
 * \brief Derive the content-encryption key, the nonce and the associated data
 *        for the current message.
 *
 *        The key lands in its context slot; the nonce and the associated data
 *        are written to the caller's buffers.
 *
 * \param[in,out] ctx                   EDHOC context.
 * \param[out] iv                       Buffer for the nonce.
 * \param iv_length                     Size of the \p iv buffer in bytes.
 * \param[out] aad                      Buffer for the associated data.
 * \param aad_length                    Size of the \p aad buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_cipher_derive(struct edhoc_context *ctx, uint8_t *iv,
			size_t iv_length, uint8_t *aad, size_t aad_length);

/**
 * \brief AEAD-encrypt the plaintext of the current message.
 *
 * \param[in] ctx                       EDHOC context.
 * \param[in] iv                        Nonce.
 * \param iv_length                     Size of the \p iv buffer in bytes.
 * \param[in] aad                       Associated data.
 * \param aad_length                    Size of the \p aad buffer in bytes.
 * \param[in] plaintext                 Plaintext to encrypt.
 * \param plaintext_length              Size of the \p plaintext buffer in bytes.
 * \param[out] ciphertext               Buffer for the ciphertext.
 * \param ciphertext_size               Size of the \p ciphertext buffer in bytes.
 * \param[out] ciphertext_length        On success, number of bytes written.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_cipher_encrypt(const struct edhoc_context *ctx, const uint8_t *iv,
			 size_t iv_length, const uint8_t *aad,
			 size_t aad_length, const uint8_t *plaintext,
			 size_t plaintext_length, uint8_t *ciphertext,
			 size_t ciphertext_size, size_t *ciphertext_length);

/**
 * \brief AEAD-decrypt the ciphertext of the current message.
 *
 *        The plaintext length is exact: a shorter result fails the call.
 *
 * \param[in] ctx                       EDHOC context.
 * \param[in] iv                        Nonce.
 * \param iv_length                     Size of the \p iv buffer in bytes.
 * \param[in] aad                       Associated data.
 * \param aad_length                    Size of the \p aad buffer in bytes.
 * \param[in] ciphertext                Ciphertext to decrypt.
 * \param ciphertext_length             Size of the \p ciphertext buffer in bytes.
 * \param[out] plaintext                Buffer for the plaintext.
 * \param plaintext_length              Expected plaintext size in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_cipher_decrypt(const struct edhoc_context *ctx, const uint8_t *iv,
			 size_t iv_length, const uint8_t *aad,
			 size_t aad_length, const uint8_t *ciphertext,
			 size_t ciphertext_length, uint8_t *plaintext,
			 size_t plaintext_length);

/**@}*/

/** \defgroup edhoc-cipher-keystream EDHOC keystream (message 2)
 * @{
 */

/**
 * \brief Derive KEYSTREAM_2 (RFC 9528: 5.3.2).
 *
 * \param[in] ctx                       EDHOC context.
 * \param[out] keystream                Buffer for the keystream.
 * \param keystream_length              Size of the \p keystream buffer in bytes.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_cipher_keystream(const struct edhoc_context *ctx, uint8_t *keystream,
			   size_t keystream_length);

/**
 * \brief XOR \p length bytes of \p keystream into \p data, in place.
 *
 * \param[in,out] data                  Memory location to XOR into.
 * \param[in] keystream                 Memory location to XOR from.
 * \param length                        Number of bytes to XOR.
 */
void edhoc_cipher_xor(uint8_t *restrict data, const uint8_t *restrict keystream,
		      size_t length);

/**@}*/

#endif /* EDHOC_CIPHER_INTERNAL_H */
