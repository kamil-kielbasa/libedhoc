/**
 * \file    authentication_credentials_x5t_cs_2.h
 * \author  Kamil Kielbasa
 * \brief   Example implementation of authentication credentials callbacks
 *          for X.509 hash authentication method for cipher suite 2.
 * \version 0.5
 * \date    2024-08-05
 * 
 * \copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef AUTHENTICATION_CREDENTIALS_X5T_CS_2_H
#define AUTHENTICATION_CREDENTIALS_X5T_CS_2_H

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
 * \brief Authentication credentials fetch callback for initiator.
 */
int auth_cred_fetch_init_x5t_cs_2(void *user_context,
				  struct edhoc_auth_creds *credentials);

/**
 * \brief Authentication credentials fetch callback for responder.
 */
int auth_cred_fetch_resp_x5t_cs_2(void *user_context,
				  struct edhoc_auth_creds *credentials);

/**
 * \brief Authentication credentials verify callback for initiator.
 */
int auth_cred_verify_init_x5t_cs_2(void *user_context,
				   struct edhoc_auth_creds *credentials,
				   const uint8_t **public_key_reference,
				   size_t *public_key_length);

/**
 * \brief Authentication credentials verify callback for responder.
 */
int auth_cred_verify_resp_x5t_cs_2(void *user_context,
				   struct edhoc_auth_creds *credentials,
				   const uint8_t **public_key_reference,
				   size_t *public_key_length);

#endif /* AUTHENTICATION_CREDENTIALS_X5T_CS_2_H */
