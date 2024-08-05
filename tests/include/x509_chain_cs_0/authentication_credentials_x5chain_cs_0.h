/**
 * \file    authentication_credentials_x5chain_cs_0.h
 * \author  Kamil Kielbasa
 * \brief   Example implementation of authentication credentials callbacks
 *          for X.509 chain authentication method for cipher suite 0.
 * \version 0.5
 * \date    2024-08-05
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef AUTHENTICATION_CREDENTIALS_X5CHAIN_CS_0_H
#define AUTHENTICATION_CREDENTIALS_X5CHAIN_CS_0_H

/* Include files ----------------------------------------------------------- */

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* EDHOC header: */
#include "edhoc_credentials.h"

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/**
 * \brief Authentication credentials fetch callback for initiator
 *        for single certificate in chain.
 */
int auth_cred_fetch_init_x5chain_cs_0_single_cert(
	void *user_context, struct edhoc_auth_creds *credentials);

/**
 * \brief Authentication credentials fetch callback for responder
 *        for single certificate in chain.
 */
int auth_cred_fetch_resp_x5chain_cs_0_single_cert(
	void *user_context, struct edhoc_auth_creds *credentials);

/**
 * \brief Authentication credentials verify callback for initiator
 *        for single ceritifcate in chain.
 */
int auth_cred_verify_init_x5chain_cs_0_single_cert(
	void *user_context, struct edhoc_auth_creds *credentials,
	const uint8_t **public_key_reference, size_t *public_key_length);

/**
 * \brief Authentication credentials verify callback for responder
 *        for single ceritifcate in chain.
 */
int auth_cred_verify_resp_x5chain_cs_0_single_cert(
	void *user_context, struct edhoc_auth_creds *credentials,
	const uint8_t **public_key_reference, size_t *public_key_length);

/**
 * \brief Authentication credentials fetch callback for initiator.
 *        for many certificates in chain.
 */
int auth_cred_fetch_init_x5chain_cs_0_many_certs(
	void *user_context, struct edhoc_auth_creds *credentials);

/**
 * \brief Authentication credentials fetch callback for responder.
 *        for many certificates in chain.
 */
int auth_cred_fetch_resp_x5chain_cs_0_many_certs(
	void *user_context, struct edhoc_auth_creds *credentials);

/**
 * \brief Authentication credentials verify callback for initiator.
 *        for many certificates in chain.
 */
int auth_cred_verify_init_x5chain_cs_0_many_certs(
	void *user_context, struct edhoc_auth_creds *credentials,
	const uint8_t **public_key_reference, size_t *public_key_length);

/**
 * \brief Authentication credentials verify callback for responder.
 *        for many certificates in chain.
 */
int auth_cred_verify_resp_x5chain_cs_0_many_certs(
	void *user_context, struct edhoc_auth_creds *credentials,
	const uint8_t **public_key_reference, size_t *public_key_length);

#endif /* AUTHENTICATION_CREDENTIALS_X5CHAIN_CS_0_H */
