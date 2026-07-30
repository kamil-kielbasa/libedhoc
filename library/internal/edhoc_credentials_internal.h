/**
 * \file    edhoc_credentials_internal.h
 * \author  Kamil Kielbasa
 * \brief   EDHOC authentication credentials:
 *          - ID_CRED_x decoding.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_CREDENTIALS_INTERNAL_H
#define EDHOC_CREDENTIALS_INTERNAL_H

/* Include files ----------------------------------------------------------- */

/* Build-time configuration (Kconfig provides these on Zephyr): */
#ifndef __ZEPHYR__
#include "edhoc_config.h"
#endif

/* EDHOC headers: */
#include <edhoc/credentials.h>

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Defines ----------------------------------------------------------------- */
/* Types and type definitions ---------------------------------------------- */

/** ID_CRED_x COSE header map, defined by the CBOR backend. */
struct map;

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** \defgroup edhoc-credentials-decode EDHOC ID_CRED_x decoding
 *
 * Shared by message_2 (ID_CRED_R) and message_3 (ID_CRED_I). On failure
 * \p credentials is left untouched, so a rejected ID_CRED_x never reaches the
 * application with a partially populated union.
 * @{
 */

/**
 * \brief Decode ID_CRED_x carried as a bare CBOR integer, i.e. a 'kid' in the
 *        compact encoding (RFC 9528: 3.5.3.2).
 *
 * \param key_id                        Key identifier.
 * \param[out] credentials              On success, authentication credentials.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_parse_id_cred_kid_int(int32_t key_id,
				struct edhoc_auth_credentials *credentials);

/**
 * \brief Decode ID_CRED_x carried as a bare CBOR byte string, i.e. a 'kid' in
 *        the compact encoding (RFC 9528: 3.5.3.2).
 *
 * \param[in] key_id                    Key identifier.
 * \param key_id_length                 Length of \p key_id in bytes.
 * \param[out] credentials              On success, authentication credentials.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_parse_id_cred_kid_bstr(const uint8_t *key_id, size_t key_id_length,
				 struct edhoc_auth_credentials *credentials);

/**
 * \brief Decode ID_CRED_x carried as a COSE header map.
 *
 *        Exactly one supported header parameter must be present: 'x5chain' or
 *        'x5t'. A 'kid' in map form is rejected, see RFC 9528: 3.5.3.2.
 *
 * \param[in] id_cred_map               Decoded ID_CRED_x map.
 * \param[out] credentials              On success, authentication credentials.
 *
 * \retval #EDHOC_SUCCESS
 *         Success.
 * \return Negative error code on failure.
 */
int edhoc_parse_id_cred_map(const struct map *id_cred_map,
			    struct edhoc_auth_credentials *credentials);

/**@}*/

#endif /* EDHOC_CREDENTIALS_INTERNAL_H */
