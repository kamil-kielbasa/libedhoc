/**
 * @file    edhoc.h
 * @author  Kamil Kielbasa
 * @brief   EDHOC API.
 * @version 0.1
 * @date    2024-01-01
 * 
 * @copyright Copyright (c) 2024
 * 
 */

/* Header guard ------------------------------------------------------------ */
#ifndef EDHOC_H
#define EDHOC_H

/* Include files ----------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "edhoc_crypto.h"
#include "edhoc_credentials.h"
#include "edhoc_values.h"
#include "edhoc_macros.h"

/* Defines ----------------------------------------------------------------- */

#ifndef EDHOC_KID_LEN
#error "Lack of defined key ID length"
#endif

#ifndef EDHOC_MAX_CSUITES_LEN
#error "Lack of defined cipher suites length"
#endif

#ifndef EDHOC_MAX_CID_LEN
#error "Lack of defined connection ID length"
#endif

#ifndef EDHOC_MAX_ECC_KEY_LEN
#error "Lack of defined length for ellipic curve point X coordinate"
#endif

#ifndef EDHOC_MAX_MAC_LEN
#error "Lack of defined hash length"
#endif

#ifndef EDHOC_MAX_NR_OF_EAD_TOKENS
#error "Lack of defined external authorization data"
#endif

/* Types and type definitions ---------------------------------------------- */

/**
 * @brief RFC-9528: Appendix I. Example Protocol State Machine.
 */
enum edhoc_state_machine {
	START,
	ABORTED,

	/* Responder: */
	RECEIVED_M1,
	VERIFIED_M1,

	/* Initiator: */
	WAIT_M2,
	RECEIVED_M2,
	VERIFIED_M2,

	/* Responder: */
	WAIT_M3,
	RECEIVED_M3,

	/* Initiator: */
	RECEVIED_M4,

	PERSISTED,
	COMPLETED,
};

/**
 * @brief RFC-9528: 3.2. Method.
 */
enum edhoc_method {
	EDHOC_INIT_SIGN_RESP_SIGN = 0,
	EDHOC_INIT_SIGN_RESP_STAT = 1,
	EDHOC_INIT_STAT_RESP_SIGN = 2,
	EDHOC_INIT_STAT_RESP_STAT = 3,
};

/**
 * @brief RFC-9528: 3.1. General.
 */
enum edhoc_message {
	EDHOC_MSG_1,
	EDHOC_MSG_2,
	EDHOC_MSG_3,
	EDHOC_MSG_4,
};

/**
 * @brief EDHOC transcript hashes states.
 */
enum edhoc_th_state {
	EDHOC_TH_STATE_INVALID,
	EDHOC_TH_STATE_1,
	EDHOC_TH_STATE_2,
	EDHOC_TH_STATE_3,
	EDHOC_TH_STATE_4,
};

/**
 * @brief EDHOC psuedorandom key states.
 */
enum edhoc_prk_state {
	EDHOC_PRK_STATE_INVALID,
	EDHOC_PRK_STATE_2E,
	EDHOC_PRK_STATE_3E2M,
	EDHOC_PRK_STATE_4E3M,
	EDHOC_PRK_STATE_OUT,
	EDHOC_PRK_STATE_EXPORTER,
};

/**
 * @brief RFC-9528: 3.8. External Authorization Data (EAD).
 */
struct edhoc_ead_token {
	int32_t label;

	const uint8_t *value;
	size_t value_len;
};

/** 
 * \brief Callback for external authorization data (EAD) composing.
 *
 * \param[in] user_ctx          User context.
 * \param msg                   Message number for context information. (EAD_1, EAD_2, EAD_3 or EAD_4 ?)
 * \param[in] ead               Buffer where the generated EAD is to be written.
 * \param ead_size              Size of the \p ead buffer in bytes.
 * \param[out] ead_len          On success, the number of bytes that make up the EAD.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_ead_compose)(void *user_ctx, enum edhoc_message msg,
				 struct edhoc_ead_token *ead_token,
				 size_t nr_of_ead_tokens,
				 size_t *nr_of_written_ead_tokens);

/** 
 * \brief Callback for external authorization data (EAD) processing.
 *
 * \param[in] user_ctx          User context.
 * \param msg                   Message number for context information. (EAD_1, EAD_2, EAD_3 or EAD_4 ?)
 * \param[in] ead               Buffer containing the EAD.
 * \param ead_len               Size of the \p ead buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
typedef int (*edhoc_ead_process)(void *user_ctx, enum edhoc_message msg,
				 const struct edhoc_ead_token *ead_token,
				 size_t nr_of_ead_tokens);

/**
 * @brief EDHOC context.
 */
struct edhoc_context {
	bool is_init;

	enum edhoc_method method;

	size_t chosen_csuite_idx;
	struct edhoc_cipher_suite csuite[EDHOC_MAX_CSUITES_LEN];
	size_t csuite_len;

	uint8_t cid[EDHOC_MAX_CID_LEN];
	size_t cid_len;

	uint8_t peer_cid[EDHOC_MAX_CID_LEN];
	size_t peer_cid_len;

	uint8_t dh_pub_key[EDHOC_MAX_ECC_KEY_LEN];
	size_t dh_pub_key_len;
	uint8_t dh_priv_key[EDHOC_MAX_ECC_KEY_LEN];
	size_t dh_priv_key_len;
	uint8_t dh_secret[EDHOC_MAX_ECC_KEY_LEN];
	size_t dh_secret_len;

	uint8_t dh_peer_pub_key[EDHOC_MAX_ECC_KEY_LEN];
	size_t dh_peer_pub_key_len;

	enum edhoc_th_state th_state;
	uint8_t th[EDHOC_MAX_MAC_LEN];
	size_t th_len;

	enum edhoc_prk_state prk_state;
	uint8_t prk[EDHOC_MAX_MAC_LEN];
	size_t prk_len;

	struct edhoc_keys keys_cb;
	struct edhoc_crypto crypto_cb;
	struct edhoc_credentials creds_cb;

	enum edhoc_state_machine status;

	void *user_ctx;

	struct edhoc_ead_token ead_token[EDHOC_MAX_NR_OF_EAD_TOKENS + 1];
	size_t nr_of_ead_tokens;

	edhoc_ead_compose ead_compose;
	edhoc_ead_process ead_process;
};

/* Module interface variables and constants -------------------------------- */
/* Extern variables and constant declarations ------------------------------ */
/* Module interface function declarations ---------------------------------- */

/** 
 * \brief Initialize EDHOC context.
 *
 * \param[in,out] edhoc_context         EDHOC context structure.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_context_init(struct edhoc_context *edhoc_context);

/** 
 * \brief Deinitialize EDHOC context.
 *
 * \param[in,out] edhoc_context         EDHOC context structure.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_context_deinit(struct edhoc_context *edhoc_context);

/** 
 * \brief Set EDHOC method.
 *
 * \param[in,out] edhoc_context         EDHOC context structure.
 * \param method                        EDHOC method.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_set_method(struct edhoc_context *edhoc_context,
		     enum edhoc_method method);

/** 
 * \brief Set EDHOC supproted cipher suites.
 *
 * \param[in,out] edhoc_context         EDHOC context structure.
 * \param[in] csuite                    EDHOC cipher suites.
 * \param csuite_len                    Length of the \p csuite buffer.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_set_cipher_suites(struct edhoc_context *edhoc_context,
			    const struct edhoc_cipher_suite *csuite,
			    size_t csuite_len);

/** 
 * \brief Set EDHOC connection identifier.
 *
 * \param[in,out] edhoc_context         EDHOC context structure.
 * \param[in] conn_id                   EDHOC connection identifier.
 * \param conn_id_len                   Length of the \p conn_id buffer.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_set_conn_id(struct edhoc_context *edhoc_context,
		      const int32_t *conn_id, size_t conn_id_len);

/** 
 * \brief Set user context.
 *
 * \param[in,out] edhoc_context         EDHOC context structure.
 * \param[in] user_context              User context.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_set_user_context(struct edhoc_context *edhoc_context,
			   void *user_context);

/** 
 * \brief Bind EDHOC external authorization data callbacks.
 *
 * \param[in,out] edhoc_context         EDHOC context structure.
 * \param[in] ead_compose               EDHOC EAD compose callback.
 * \param[in] ead_process               EDHOC EAD process callback.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_bind_ead(struct edhoc_context *edhoc_context,
		   const edhoc_ead_compose ead_compose,
		   const edhoc_ead_process ead_process);

/** 
 * \brief Bind EDHOC crypto keys callback.
 *
 * \param[in,out] edhoc_context         EDHOC context structure.
 * \param[in] keys                      EDHOC crypto keys callback.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_bind_keys(struct edhoc_context *edhoc_context,
		    const struct edhoc_keys keys);

/** 
 * \brief Bind EDHOC cryptographics operations callback.
 *
 * \param[in,out] edhoc_context         EDHOC context structure.
 * \param[in] crypto                    EDHOC cryptographic operations callback.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_bind_crypto(struct edhoc_context *edhoc_context,
		      const struct edhoc_crypto crypto);

/** 
 * \brief Bind EDHOC authentication callback.
 *
 * \param[in,out] edhoc_context         EDHOC context structure.
 * \param[in] crypto                    EDHOC cryptographic operations callback.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_bind_credentials(struct edhoc_context *edhoc_context,
			   const struct edhoc_credentials creds_cb);

/** 
 * \brief Compose EDHOC message 1.
 *
 * \param edhoc_context             EDHOC context structure.
 * \param[out] message_1            Buffer where the generated message 1 is to be written.
 * \param message_1_size            Size of the \p message_1 buffer in bytes.
 * \param[out] message_1_length     On success, the number of bytes that make up the message 1.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_message_1_compose(struct edhoc_context *edhoc_context,
			    uint8_t *message_1, size_t message_1_size,
			    size_t *message_1_length);

/**
 * @brief Process EDHOC message 1.
 *
 * \param edhoc_context             EDHOC context structure.
 * \param[in] message_1             Buffer containing the message 1.
 * \param message_1_length          Size of the \p message_1 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_message_1_process(struct edhoc_context *edhoc_context,
			    const uint8_t *message_1, size_t message_1_length);

/**
 * @brief Compose EDHOC message 2.
 *
 * \param edhoc_context             EDHOC context structure.
 * \param[out] message_2            Buffer where the generated message 2 is to be written.
 * \param message_2_size            Size of the \p message_2 buffer in bytes.
 * \param[out] message_2_length     On success, the number of bytes that make up the message 2.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_message_2_compose(struct edhoc_context *edhoc_context,
			    uint8_t *message_2, size_t message_2_size,
			    size_t *message_2_length);

/**
 * @brief Process EDHOC message 2.
 *
 * \param edhoc_context             EDHOC context structure.
 * \param[in] message_2             Buffer containing the message 2.
 * \param message_2_length          Size of the \p message_2 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_message_2_process(struct edhoc_context *edhoc_context,
			    const uint8_t *message_2, size_t message_2_length);

/**
 * @brief Compose EDHOC message 3.
 *
 * \param edhoc_context             EDHOC context structure.
 * \param[out] message_3            Buffer where the generated message 3 is to be written.
 * \param message_3_size            Size of the \p message_3 buffer in bytes.
 * \param[out] message_3_length     On success, the number of bytes that make up the message 3.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_message_3_compose(struct edhoc_context *edhoc_context,
			    uint8_t *message_3, size_t message_3_size,
			    size_t *message_3_length);

/**
 * @brief Process EDHOC message 3.
 *
 * \param edhoc_context             EDHOC context structure.
 * \param[in] message_3             Buffer containing the message 3.
 * \param message_3_length          Size of the \p message_3 buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_message_3_process(struct edhoc_context *edhoc_context,
			    const uint8_t *message_3, size_t message_3_length);

/**
 * @brief Deriving the OSCORE Security Context.
 *
 * \param edhoc_context             EDHOC context structure.
 * \param[out] oscore_secret        Buffer where the derived OSCORE key is to be written.
 * \param oscore_secret_len         Size of the \p oscore_secret buffer in bytes.
 * \param[out] oscore_salt          Buffer where the derived OSCORE salt is to be written.
 * \param oscore_salt_len           Size of the \p oscore_salt buffer in bytes.
 *
 * \return EDHOC_SUCCESS on success, otherwise failure.
 */
int edhoc_export_secret_and_salt(struct edhoc_context *edhoc_context,
				 uint8_t *oscore_secret,
				 size_t oscore_secret_len, uint8_t *oscore_salt,
				 size_t oscore_salt_len);

#endif /* EDHOC_H */