/**
 * \file    handshake_credentials.h
 * \author  Kamil Kielbasa
 * \brief   Generic authentication-credential callbacks for the handshake
 *          driver.
 *
 *          One \ref hs_identity describes a single EDHOC peer. A scenario
 *          declares the Initiator's and Responder's identity once; each
 *          endpoint then points \c own at the identity it presents and \c peer
 *          at the identity it must verify (see \ref handshake_endpoint in
 *          handshake_driver.h):
 *
 *          - on \b fetch the callback presents \c own (the certificate to send
 *            and the private key to sign / key-agree with);
 *          - on \b verify the callback authenticates the received credential
 *            against \c peer and returns \c peer's public key.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef HANDSHAKE_CREDENTIALS_H
#define HANDSHAKE_CREDENTIALS_H

/* Include files ----------------------------------------------------------- */

/* EDHOC header: */
#include <edhoc/credentials.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Types and type definitions ---------------------------------------------- */

/**
 * \brief How an \ref hs_identity private authentication key is imported.
 */
enum hs_key_import {
	/** Ed25519 seed as a RAW_DATA export-only key (software EdDSA). */
	HS_KEY_RAW_ED25519,
	/** ECC SECP_R1 sign-hash key, ECDSA over SHA-256. */
	HS_KEY_ECDSA_SHA256,
	/** ECC SECP_R1 sign-hash key, ECDSA over SHA-384. */
	HS_KEY_ECDSA_SHA384,
	/** ECC SECP_R1 key-agreement key (static Diffie-Hellman). */
	HS_KEY_ECDH_P256,
	/** ML-DSA-44 signing key imported into the post-quantum keystore. */
	HS_KEY_ML_DSA_44,
};

/**
 * \brief A single certificate reference.
 */
struct hs_cert {
	/** Pointer to the DER-encoded certificate. */
	const uint8_t *pointer;
	/** Certificate size in bytes. */
	size_t length;
};

/**
 * \brief One authenticated EDHOC identity.
 *
 *        Everything an endpoint needs to present this identity (fetch) and
 *        everything a peer needs to accept it (verify).
 */
struct hs_identity {
	/** Credential identification method (COSE header selecting the union
	 *  member of \ref edhoc_auth_credentials): x5chain or x5t here. */
	enum edhoc_cose_header cose_header;

	/** Private authentication key to present in the fetch callback. */
	const uint8_t *private_key;
	/** Size of \p private_key in bytes. */
	size_t private_key_length;
	/** How \p private_key is imported into the backend keystore. */
	enum hs_key_import key_import;

	/** Public authentication key a verifier returns for this identity. */
	const uint8_t *public_key;
	/** Size of \p public_key in bytes. */
	size_t public_key_length;

	/** Certificate chain (\c x5chain) or single certificate. */
	struct hs_cert cert[CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN];
	/** Number of valid entries in \p cert. */
	size_t cert_count;

	/** \c x5t only: certificate thumbprint bytes. */
	const uint8_t *thumbprint;
	/** \c x5t only: size of \p thumbprint in bytes. */
	size_t thumbprint_length;
	/** \c x5t only: COSE algorithm identifier of the thumbprint hash. */
	int32_t thumbprint_algorithm;
};

/* Module interface function declarations ---------------------------------- */

/**
 * \brief Fetch callback: present the local identity (\c user_context->own).
 *
 * \param[in] user_context      The \ref handshake_endpoint being configured.
 * \param[out] auth_credentials Credential structure to populate.
 *
 * \return #EDHOC_SUCCESS on success, negative error code otherwise.
 */
int hs_cred_fetch(void *user_context,
		  struct edhoc_auth_credentials *auth_credentials);

/**
 * \brief Authenticate callback: authenticate the peer identity
 *        (\c user_context->peer) and return its public key.
 *
 * \param[in] user_context      The \ref handshake_endpoint being configured.
 * \param[in] call_context      Session and message the call belongs to.
 * \param[in] received          Peer identification, as received.
 * \param[out] trusted          On success, the peer credential to trust.
 *
 * \return #EDHOC_SUCCESS on success, negative error code otherwise.
 */
int hs_cred_authenticate_peer(void *user_context,
			      const struct edhoc_call_context *call_context,
			      const struct edhoc_credential_received *received,
			      struct edhoc_credential_trusted *trusted);

#endif /* HANDSHAKE_CREDENTIALS_H */
