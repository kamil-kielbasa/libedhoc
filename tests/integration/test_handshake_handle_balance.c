/**
 * \file    test_handshake_handle_balance.c
 * \author  Kamil Kielbasa
 * \brief   PSA key-handle balance tests for the EDHOC handshake.
 *
 *          Every long-lived secret in the key schedule is an opaque key-store
 *          handle rather than raw bytes, so a leaked handle is invisible to a
 *          functional test (the handshake still completes) yet exhausts the
 *          backend key store over time. The library creates and destroys those
 *          handles only through the bound \ref edhoc_crypto vtable, so these
 *          tests wrap a real cipher suite 2 backend with a counting layer. The
 *          wrapper records the live key handles and multipart hash operations
 *          in a per-test state that is threaded to every callback through
 *          \ref edhoc_set_user_context, then asserts that
 *          \c edhoc_context_deinit() releases every one of them: on the success
 *          path (including an EDHOC-KeyUpdate), on repeated runs, on a partial
 *          abort, on a malformed message, and on a crypto failure injected
 *          mid-handshake.
 *
 * \copyright Copyright (c) 2026
 */

/* Include files ----------------------------------------------------------- */

/* Cipher suite 2 and library-internal headers: */
#include "test_platform.h"
#include "edhoc_context_internal.h"
#include "edhoc_cipher_suite_2.h"

/* Standard library headers: */
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* EDHOC headers: */
#include <edhoc/edhoc.h>
#include "test_ead.h"

/* PSA crypto header: */
#include <psa/crypto.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */

#define TEST_HANDSHAKE_MSG_BUF_SIZE                                  \
	((size_t)(64U + (CONFIG_LIBEDHOC_MAX_LEN_OF_NIKE_KEY * 8U) + \
		  (CONFIG_LIBEDHOC_MAX_LEN_OF_MAC * 4U) +            \
		  (CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN * 320U)))

/** Upper bound on simultaneously-live key handles the tracker holds; the real
 *  peak across two peers stays well below this. */
#define MAX_TRACKED_KEYS ((size_t)64)

/** Upper bound on simultaneously-live multipart hash operations. */
#define MAX_TRACKED_HASH_OPS ((size_t)8)

/*
 * P-256 keys shared by both sign and static-DH authentication. The
 * certificates (CRED_I, CRED_R) carry the matching public keys, so the same
 * vectors drive every authentication method by selecting the signature or the
 * X-coordinate public key.
 */

/* Initiator private key (same for both sign and DH). */
static const uint8_t TEST_VEC_SK_I[] = {
	0xfb, 0x13, 0xad, 0xeb, 0x65, 0x18, 0xce, 0xe5, 0xf8, 0x84, 0x17,
	0x66, 0x08, 0x41, 0x14, 0x2e, 0x83, 0x0a, 0x81, 0xfe, 0x33, 0x43,
	0x80, 0xa9, 0x53, 0x40, 0x6a, 0x13, 0x05, 0xe8, 0x70, 0x6b,
};

/* Initiator uncompressed public key (signature verification). */
static const uint8_t TEST_VEC_PK_I_SIG[] = {
	0x04, 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e, 0xd6,
	0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf, 0x16, 0xdf,
	0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30, 0x7f, 0x7e, 0xb6,
	0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b, 0x8a, 0x82, 0x11, 0x33,
	0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52, 0xa3, 0x87, 0xd2, 0x57, 0xe6,
	0xdb, 0x3c, 0x2a, 0x93, 0xdf, 0x21, 0xff, 0x3a, 0xff, 0xc8,
};

/* Initiator X-coordinate public key (DH key agreement). */
static const uint8_t TEST_VEC_PK_I_DH[] = {
	0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e, 0xd6, 0x03,
	0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf, 0x16, 0xdf, 0x96,
	0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30, 0x7f, 0x7e, 0xb6,
};

/* Responder private key (same for both sign and DH). */
static const uint8_t TEST_VEC_SK_R[] = {
	0x72, 0xcc, 0x47, 0x61, 0xdb, 0xd4, 0xc7, 0x8f, 0x75, 0x89, 0x31,
	0xaa, 0x58, 0x9d, 0x34, 0x8d, 0x1e, 0xf8, 0x74, 0xa7, 0xe3, 0x03,
	0xed, 0xe2, 0xf1, 0x40, 0xdc, 0xf3, 0xe6, 0xaa, 0x4a, 0xac,
};

/* Responder uncompressed public key (signature verification). */
static const uint8_t TEST_VEC_PK_R_SIG[] = {
	0x04, 0xbb, 0xc3, 0x49, 0x60, 0x52, 0x6e, 0xa4, 0xd3, 0x2e, 0x94,
	0x0c, 0xad, 0x2a, 0x23, 0x41, 0x48, 0xdd, 0xc2, 0x17, 0x91, 0xa1,
	0x2a, 0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20, 0x46, 0xdd, 0x44, 0xf0,
	0x45, 0x19, 0xe2, 0x57, 0x23, 0x6b, 0x2a, 0x0c, 0xe2, 0x02, 0x3f,
	0x09, 0x31, 0xf1, 0xf3, 0x86, 0xca, 0x7a, 0xfd, 0xa6, 0x4f, 0xcd,
	0xe0, 0x10, 0x8c, 0x22, 0x4c, 0x51, 0xea, 0xbf, 0x60, 0x72,
};

/* Responder X-coordinate public key (DH key agreement). */
static const uint8_t TEST_VEC_PK_R_DH[] = {
	0xbb, 0xc3, 0x49, 0x60, 0x52, 0x6e, 0xa4, 0xd3, 0x2e, 0x94, 0x0c,
	0xad, 0x2a, 0x23, 0x41, 0x48, 0xdd, 0xc2, 0x17, 0x91, 0xa1, 0x2a,
	0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20, 0x46, 0xdd, 0x44, 0xf0,
};

/* Initiator certificate (same for sign and DH usage). */
static const uint8_t TEST_VEC_CRED_I[] = {
	0x30, 0x82, 0x01, 0x1e, 0x30, 0x81, 0xc5, 0xa0, 0x03, 0x02, 0x01, 0x02,
	0x02, 0x04, 0x62, 0x32, 0xef, 0x6f, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
	0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11,
	0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x45, 0x44, 0x48, 0x4f, 0x43,
	0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x32, 0x30,
	0x33, 0x31, 0x37, 0x30, 0x38, 0x32, 0x31, 0x30, 0x33, 0x5a, 0x17, 0x0d,
	0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30,
	0x5a, 0x30, 0x1a, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03,
	0x0c, 0x0f, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x49, 0x6e, 0x69, 0x74,
	0x69, 0x61, 0x74, 0x6f, 0x72, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
	0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
	0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xac, 0x75, 0xe9, 0xec,
	0xe3, 0xe5, 0x0b, 0xfc, 0x8e, 0xd6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40,
	0x5c, 0x47, 0xbf, 0x16, 0xdf, 0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4,
	0x30, 0x7f, 0x7e, 0xb6, 0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b, 0x8a,
	0x82, 0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52, 0xa3, 0x87, 0xd2,
	0x57, 0xe6, 0xdb, 0x3c, 0x2a, 0x93, 0xdf, 0x21, 0xff, 0x3a, 0xff, 0xc8,
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
	0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0x8c, 0x32, 0x3a, 0x1f,
	0x33, 0x21, 0x38, 0xaa, 0xb9, 0xd0, 0xbe, 0xaf, 0xb8, 0x5f, 0x8d, 0x5a,
	0x44, 0x07, 0x3c, 0x58, 0x0f, 0x59, 0x5b, 0xc5, 0x21, 0xef, 0x91, 0x3f,
	0x6e, 0xf4, 0x8d, 0x11, 0x02, 0x20, 0x6c, 0x0a, 0xf1, 0xa1, 0x85, 0xa4,
	0xe4, 0xde, 0x06, 0x35, 0x36, 0x99, 0x23, 0x1c, 0x73, 0x3a, 0x6e, 0x8d,
	0xd2, 0xdf, 0x65, 0x13, 0x96, 0x6c, 0x91, 0x30, 0x15, 0x2a, 0x07, 0xa2,
	0xbe, 0xde,
};

/* Responder certificate (same for sign and DH usage). */
static const uint8_t TEST_VEC_CRED_R[] = {
	0x30, 0x82, 0x01, 0x1e, 0x30, 0x81, 0xc5, 0xa0, 0x03, 0x02, 0x01, 0x02,
	0x02, 0x04, 0x61, 0xe9, 0x98, 0x1e, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
	0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11,
	0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x45, 0x44, 0x48, 0x4f, 0x43,
	0x20, 0x52, 0x6f, 0x6f, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x32, 0x30,
	0x31, 0x32, 0x30, 0x31, 0x37, 0x31, 0x33, 0x30, 0x32, 0x5a, 0x17, 0x0d,
	0x32, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30,
	0x5a, 0x30, 0x1a, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03,
	0x0c, 0x0f, 0x45, 0x44, 0x48, 0x4f, 0x43, 0x20, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x64, 0x65, 0x72, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
	0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
	0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xbb, 0xc3, 0x49, 0x60,
	0x52, 0x6e, 0xa4, 0xd3, 0x2e, 0x94, 0x0c, 0xad, 0x2a, 0x23, 0x41, 0x48,
	0xdd, 0xc2, 0x17, 0x91, 0xa1, 0x2a, 0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20,
	0x46, 0xdd, 0x44, 0xf0, 0x45, 0x19, 0xe2, 0x57, 0x23, 0x6b, 0x2a, 0x0c,
	0xe2, 0x02, 0x3f, 0x09, 0x31, 0xf1, 0xf3, 0x86, 0xca, 0x7a, 0xfd, 0xa6,
	0x4f, 0xcd, 0xe0, 0x10, 0x8c, 0x22, 0x4c, 0x51, 0xea, 0xbf, 0x60, 0x72,
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
	0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x30, 0x19, 0x4e, 0xf5, 0xfc,
	0x65, 0xc8, 0xb7, 0x95, 0xcd, 0xcd, 0x0b, 0xb4, 0x31, 0xbf, 0x83, 0xee,
	0x67, 0x41, 0xc1, 0x37, 0x0c, 0x22, 0xc8, 0xeb, 0x8e, 0xe9, 0xed, 0xd2,
	0xa7, 0x05, 0x19, 0x02, 0x21, 0x00, 0xb5, 0x83, 0x0e, 0x9c, 0x89, 0xa6,
	0x2a, 0xc7, 0x3c, 0xe1, 0xeb, 0xce, 0x00, 0x61, 0x70, 0x7d, 0xb8, 0xa8,
	0x8e, 0x23, 0x70, 0x9b, 0x4a, 0xcc, 0x58, 0xa1, 0x31, 0x3b, 0x13, 0x3d,
	0x05, 0x58,
};

/* Module types and type definitions --------------------------------------- */

/** \brief Whether a peer authenticates with a signature or a static-DH key. */
enum auth_key_kind {
	AUTH_KEY_SIGN,
	AUTH_KEY_DH,
};

/** \brief The crypto operation whose next call the wrapper forces to fail. */
enum crypto_fault_op {
	CRYPTO_FAULT_NONE = 0,
	CRYPTO_FAULT_EXTRACT,
	CRYPTO_FAULT_EXPAND,
};

/** \brief Live key handles and hash operations created through the vtable. */
struct handle_tracker {
	psa_key_id_t keys[MAX_TRACKED_KEYS];
	size_t key_count;
	const void *hash_ops[MAX_TRACKED_HASH_OPS];
	size_t hash_op_count;
};

/** \brief Selects a crypto call to fail, driving error-cleanup scenarios. */
struct crypto_fault {
	enum crypto_fault_op op;
	size_t at;
	size_t extract_calls;
	size_t expand_calls;
};

/** \brief Per-method authentication material for both peers. */
struct auth_vectors {
	const uint8_t *init_pub_key;
	size_t init_pub_key_length;
	const uint8_t *resp_pub_key;
	size_t resp_pub_key_length;
	enum auth_key_kind init_kind;
	enum auth_key_kind resp_kind;
};

/**
 * \brief Whole per-test state, threaded to every crypto and credential
 *        callback through \ref edhoc_set_user_context so the callbacks need no
 *        globals. Both peers share one instance, so the tracker sees the union
 *        of the handles either side creates.
 */
struct test_context {
	const struct edhoc_crypto *backend;
	struct handle_tracker tracker;
	struct crypto_fault fault;
	struct auth_vectors auth;
};

/* Static function declarations -------------------------------------------- */

/** \brief Read a PSA key handle from a (possibly unaligned) key-store slot. */
static psa_key_id_t handle_of(const void *key_id);

/** \brief Record the handle written to \p key_id as live (idempotent). */
static void tracker_key_add(struct handle_tracker *tracker, const void *key_id);

/** \brief Drop the handle passed to \p key_id from the live set (idempotent). */
static void tracker_key_remove(struct handle_tracker *tracker,
			       const void *key_id);

/** \brief Record a multipart hash operation as live (idempotent). */
static void tracker_hash_add(struct handle_tracker *tracker, const void *op);

/** \brief Drop a multipart hash operation from the live set (idempotent). */
static void tracker_hash_remove(struct handle_tracker *tracker, const void *op);

/** \brief Counting wrapper for \ref edhoc_crypto.destroy_key. */
static int counting_destroy_key(void *user_context, void *key_id);

/** \brief Counting wrapper for \ref edhoc_crypto.generate_key_pair. */
static int counting_generate_key_pair(void *user_context,
				      void *decapsulation_key_id,
				      uint8_t *encapsulation_key,
				      size_t encapsulation_key_size,
				      size_t *encapsulation_key_length);

/** \brief Counting wrapper for \ref edhoc_crypto.encapsulate. */
static int counting_encapsulate(void *user_context,
				const uint8_t *encapsulation_key,
				size_t encapsulation_key_length,
				void *decapsulation_key_id,
				void *shared_secret_key_id, uint8_t *ciphertext,
				size_t ciphertext_size,
				size_t *ciphertext_length);

/** \brief Counting wrapper for \ref edhoc_crypto.decapsulate. */
static int counting_decapsulate(void *user_context,
				const void *decapsulation_key_id,
				const uint8_t *ciphertext,
				size_t ciphertext_length,
				void *shared_secret_key_id);

/** \brief Counting wrapper for \ref edhoc_crypto.key_agreement. */
static int counting_key_agreement(void *user_context,
				  const void *private_key_id,
				  const uint8_t *peer_public_key,
				  size_t peer_public_key_length,
				  void *shared_secret_key_id);

/** \brief Counting wrapper for \ref edhoc_crypto.sign. */
static int counting_sign(void *user_context, const void *private_key_id,
			 const uint8_t *input, size_t input_length,
			 uint8_t *signature, size_t signature_size,
			 size_t *signature_length);

/** \brief Counting wrapper for \ref edhoc_crypto.verify. */
static int counting_verify(void *user_context, const uint8_t *public_key,
			   size_t public_key_length, const uint8_t *input,
			   size_t input_length, const uint8_t *signature,
			   size_t signature_length);

/** \brief Counting wrapper for \ref edhoc_crypto.extract. */
static int counting_extract(void *user_context, const void *ikm_key_id,
			    const uint8_t *salt, size_t salt_length,
			    void *prk_key_id);

/** \brief Counting wrapper for \ref edhoc_crypto.expand. */
static int counting_expand(void *user_context, const void *prk_key_id,
			   const uint8_t *info, size_t info_length,
			   enum edhoc_key_usage usage, void *output_key_id);

/** \brief Counting wrapper for \ref edhoc_crypto.expand_raw. */
static int counting_expand_raw(void *user_context, const void *prk_key_id,
			       const uint8_t *info, size_t info_length,
			       uint8_t *output, size_t output_length);

/** \brief Counting wrapper for \ref edhoc_crypto.aead_encrypt. */
static int counting_aead_encrypt(void *user_context, const void *key_id,
				 const uint8_t *nonce, size_t nonce_length,
				 const uint8_t *additional_data,
				 size_t additional_data_length,
				 const uint8_t *plaintext,
				 size_t plaintext_length, uint8_t *ciphertext,
				 size_t ciphertext_size,
				 size_t *ciphertext_length);

/** \brief Counting wrapper for \ref edhoc_crypto.aead_decrypt. */
static int counting_aead_decrypt(void *user_context, const void *key_id,
				 const uint8_t *nonce, size_t nonce_length,
				 const uint8_t *additional_data,
				 size_t additional_data_length,
				 const uint8_t *ciphertext,
				 size_t ciphertext_length, uint8_t *plaintext,
				 size_t plaintext_size,
				 size_t *plaintext_length);

/** \brief Counting wrapper for \ref edhoc_crypto.hash_init. */
static int counting_hash_init(void *user_context, void **operation);

/** \brief Counting wrapper for \ref edhoc_crypto.hash_update. */
static int counting_hash_update(void *user_context, void *operation,
				const uint8_t *input, size_t input_length);

/** \brief Counting wrapper for \ref edhoc_crypto.hash_finish. */
static int counting_hash_finish(void *user_context, void *operation,
				uint8_t *hash, size_t hash_size,
				size_t *hash_length);

/** \brief Counting wrapper for \ref edhoc_crypto.hash_abort. */
static int counting_hash_abort(void *user_context, void *operation);

/** \brief Import a raw P-256 scalar as a sign or key-agreement private key. */
static int import_auth_priv_key(enum auth_key_kind kind, const uint8_t *priv,
				size_t priv_length, uint8_t *key_id);

/** \brief Authentication credentials fetch callback for the Initiator. */
static int auth_cred_fetch_init(void *user_context,
				struct edhoc_auth_creds *credentials);

/** \brief Authentication credentials fetch callback for the Responder. */
static int auth_cred_fetch_resp(void *user_context,
				struct edhoc_auth_creds *credentials);

/** \brief Authentication credentials verify callback for the Initiator. */
static int auth_cred_verify_init(void *user_context,
				 struct edhoc_auth_creds *credentials,
				 const uint8_t **public_key,
				 size_t *public_key_length);

/** \brief Authentication credentials verify callback for the Responder. */
static int auth_cred_verify_resp(void *user_context,
				 struct edhoc_auth_creds *credentials,
				 const uint8_t **public_key,
				 size_t *public_key_length);

/** \brief Return the per-method authentication vectors for \p method. */
static struct auth_vectors auth_vectors_for_method(enum edhoc_method method);

/** \brief Build a fresh per-test state for \p method (empty tracker/fault). */
static struct test_context make_test_context(enum edhoc_method method);

/** \brief Configure one peer bound to the counting wrapper and \p state. */
static void setup_peer(struct edhoc_context *ctx, enum edhoc_method method,
		       const struct edhoc_credentials *credentials,
		       const struct edhoc_connection_id *connection_id,
		       struct test_context *state);

/** \brief Configure the Initiator and Responder peers for \p method. */
static void setup_peers(struct test_context *state,
			struct edhoc_context *init_ctx,
			struct edhoc_context *resp_ctx,
			enum edhoc_method method);

/** \brief Run a complete handshake (with KeyUpdate) and assert 0 leaks. */
static void run_full_handshake(enum edhoc_method method);

/* Static variables and constants ------------------------------------------ */

/** \brief Counting wrapper presented to the library in place of the backend. */
static const struct edhoc_crypto counting_crypto = {
	.destroy_key = counting_destroy_key,
	.generate_key_pair = counting_generate_key_pair,
	.encapsulate = counting_encapsulate,
	.decapsulate = counting_decapsulate,
	.key_agreement = counting_key_agreement,
	.sign = counting_sign,
	.verify = counting_verify,
	.extract = counting_extract,
	.expand = counting_expand,
	.expand_raw = counting_expand_raw,
	.aead_encrypt = counting_aead_encrypt,
	.aead_decrypt = counting_aead_decrypt,
	.hash_init = counting_hash_init,
	.hash_update = counting_hash_update,
	.hash_finish = counting_hash_finish,
	.hash_abort = counting_hash_abort,
};

static const struct edhoc_connection_id cid_init = {
	.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
	.int_value = -24,
};

static const struct edhoc_connection_id cid_resp = {
	.encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
	.int_value = -8,
};

static const struct edhoc_credentials cred_init = {
	.fetch = auth_cred_fetch_init,
	.verify = auth_cred_verify_resp,
};

static const struct edhoc_credentials cred_resp = {
	.fetch = auth_cred_fetch_resp,
	.verify = auth_cred_verify_init,
};

/* Static function definitions --------------------------------------------- */

static psa_key_id_t handle_of(const void *key_id)
{
	psa_key_id_t kid = PSA_KEY_ID_NULL;

	memcpy(&kid, key_id, sizeof(kid));

	return kid;
}

static void tracker_key_add(struct handle_tracker *tracker, const void *key_id)
{
	const psa_key_id_t kid = handle_of(key_id);

	if (PSA_KEY_ID_NULL == kid) {
		return;
	}

	for (size_t i = 0; i < tracker->key_count; ++i) {
		if (tracker->keys[i] == kid) {
			return;
		}
	}

	TEST_ASSERT_TRUE_MESSAGE(tracker->key_count < MAX_TRACKED_KEYS,
				 "key handle tracker overflow");

	tracker->keys[tracker->key_count++] = kid;
}

static void tracker_key_remove(struct handle_tracker *tracker,
			       const void *key_id)
{
	const psa_key_id_t kid = handle_of(key_id);

	if (PSA_KEY_ID_NULL == kid) {
		return;
	}

	for (size_t i = 0; i < tracker->key_count; ++i) {
		if (tracker->keys[i] == kid) {
			tracker->keys[i] = tracker->keys[--tracker->key_count];
			return;
		}
	}
}

static void tracker_hash_add(struct handle_tracker *tracker, const void *op)
{
	TEST_ASSERT_NOT_NULL(op);

	for (size_t i = 0; i < tracker->hash_op_count; ++i) {
		if (tracker->hash_ops[i] == op) {
			return;
		}
	}

	TEST_ASSERT_TRUE_MESSAGE(tracker->hash_op_count < MAX_TRACKED_HASH_OPS,
				 "hash operation tracker overflow");

	tracker->hash_ops[tracker->hash_op_count++] = op;
}

static void tracker_hash_remove(struct handle_tracker *tracker, const void *op)
{
	TEST_ASSERT_NOT_NULL(op);

	for (size_t i = 0; i < tracker->hash_op_count; ++i) {
		if (tracker->hash_ops[i] == op) {
			tracker->hash_ops[i] =
				tracker->hash_ops[--tracker->hash_op_count];
			return;
		}
	}
}

static int counting_destroy_key(void *user_context, void *key_id)
{
	struct test_context *state = user_context;

	const int ret = state->backend->destroy_key(user_context, key_id);

	if (EDHOC_SUCCESS == ret) {
		tracker_key_remove(&state->tracker, key_id);
	}

	return ret;
}

static int counting_generate_key_pair(void *user_context,
				      void *decapsulation_key_id,
				      uint8_t *encapsulation_key,
				      size_t encapsulation_key_size,
				      size_t *encapsulation_key_length)
{
	struct test_context *state = user_context;

	const int ret = state->backend->generate_key_pair(
		user_context, decapsulation_key_id, encapsulation_key,
		encapsulation_key_size, encapsulation_key_length);

	if (EDHOC_SUCCESS == ret) {
		tracker_key_add(&state->tracker, decapsulation_key_id);
	}

	return ret;
}

static int counting_encapsulate(void *user_context,
				const uint8_t *encapsulation_key,
				size_t encapsulation_key_length,
				void *decapsulation_key_id,
				void *shared_secret_key_id, uint8_t *ciphertext,
				size_t ciphertext_size,
				size_t *ciphertext_length)
{
	struct test_context *state = user_context;

	const int ret = state->backend->encapsulate(
		user_context, encapsulation_key, encapsulation_key_length,
		decapsulation_key_id, shared_secret_key_id, ciphertext,
		ciphertext_size, ciphertext_length);

	if (EDHOC_SUCCESS == ret) {
		tracker_key_add(&state->tracker, decapsulation_key_id);
		tracker_key_add(&state->tracker, shared_secret_key_id);
	}

	return ret;
}

static int counting_decapsulate(void *user_context,
				const void *decapsulation_key_id,
				const uint8_t *ciphertext,
				size_t ciphertext_length,
				void *shared_secret_key_id)
{
	struct test_context *state = user_context;

	const int ret = state->backend->decapsulate(
		user_context, decapsulation_key_id, ciphertext,
		ciphertext_length, shared_secret_key_id);

	if (EDHOC_SUCCESS == ret) {
		tracker_key_add(&state->tracker, shared_secret_key_id);
	}

	return ret;
}

static int counting_key_agreement(void *user_context,
				  const void *private_key_id,
				  const uint8_t *peer_public_key,
				  size_t peer_public_key_length,
				  void *shared_secret_key_id)
{
	struct test_context *state = user_context;

	const int ret = state->backend->key_agreement(
		user_context, private_key_id, peer_public_key,
		peer_public_key_length, shared_secret_key_id);

	if (EDHOC_SUCCESS == ret) {
		tracker_key_add(&state->tracker, shared_secret_key_id);
	}

	return ret;
}

static int counting_sign(void *user_context, const void *private_key_id,
			 const uint8_t *input, size_t input_length,
			 uint8_t *signature, size_t signature_size,
			 size_t *signature_length)
{
	struct test_context *state = user_context;

	return state->backend->sign(user_context, private_key_id, input,
				    input_length, signature, signature_size,
				    signature_length);
}

static int counting_verify(void *user_context, const uint8_t *public_key,
			   size_t public_key_length, const uint8_t *input,
			   size_t input_length, const uint8_t *signature,
			   size_t signature_length)
{
	struct test_context *state = user_context;

	return state->backend->verify(user_context, public_key,
				      public_key_length, input, input_length,
				      signature, signature_length);
}

static int counting_extract(void *user_context, const void *ikm_key_id,
			    const uint8_t *salt, size_t salt_length,
			    void *prk_key_id)
{
	struct test_context *state = user_context;

	if (CRYPTO_FAULT_EXTRACT == state->fault.op &&
	    ++state->fault.extract_calls >= state->fault.at) {
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	const int ret = state->backend->extract(user_context, ikm_key_id, salt,
						salt_length, prk_key_id);

	if (EDHOC_SUCCESS == ret) {
		tracker_key_add(&state->tracker, prk_key_id);
	}

	return ret;
}

static int counting_expand(void *user_context, const void *prk_key_id,
			   const uint8_t *info, size_t info_length,
			   enum edhoc_key_usage usage, void *output_key_id)
{
	struct test_context *state = user_context;

	if (CRYPTO_FAULT_EXPAND == state->fault.op &&
	    ++state->fault.expand_calls >= state->fault.at) {
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}

	const int ret = state->backend->expand(user_context, prk_key_id, info,
					       info_length, usage,
					       output_key_id);

	if (EDHOC_SUCCESS == ret) {
		tracker_key_add(&state->tracker, output_key_id);
	}

	return ret;
}

static int counting_expand_raw(void *user_context, const void *prk_key_id,
			       const uint8_t *info, size_t info_length,
			       uint8_t *output, size_t output_length)
{
	struct test_context *state = user_context;

	return state->backend->expand_raw(user_context, prk_key_id, info,
					  info_length, output, output_length);
}

static int counting_aead_encrypt(void *user_context, const void *key_id,
				 const uint8_t *nonce, size_t nonce_length,
				 const uint8_t *additional_data,
				 size_t additional_data_length,
				 const uint8_t *plaintext,
				 size_t plaintext_length, uint8_t *ciphertext,
				 size_t ciphertext_size,
				 size_t *ciphertext_length)
{
	struct test_context *state = user_context;

	return state->backend->aead_encrypt(user_context, key_id, nonce,
					    nonce_length, additional_data,
					    additional_data_length, plaintext,
					    plaintext_length, ciphertext,
					    ciphertext_size, ciphertext_length);
}

static int counting_aead_decrypt(void *user_context, const void *key_id,
				 const uint8_t *nonce, size_t nonce_length,
				 const uint8_t *additional_data,
				 size_t additional_data_length,
				 const uint8_t *ciphertext,
				 size_t ciphertext_length, uint8_t *plaintext,
				 size_t plaintext_size,
				 size_t *plaintext_length)
{
	struct test_context *state = user_context;

	return state->backend->aead_decrypt(user_context, key_id, nonce,
					    nonce_length, additional_data,
					    additional_data_length, ciphertext,
					    ciphertext_length, plaintext,
					    plaintext_size, plaintext_length);
}

static int counting_hash_init(void *user_context, void **operation)
{
	struct test_context *state = user_context;

	const int ret = state->backend->hash_init(user_context, operation);

	if (EDHOC_SUCCESS == ret) {
		tracker_hash_add(&state->tracker, *operation);
	}

	return ret;
}

static int counting_hash_update(void *user_context, void *operation,
				const uint8_t *input, size_t input_length)
{
	struct test_context *state = user_context;

	return state->backend->hash_update(user_context, operation, input,
					   input_length);
}

static int counting_hash_finish(void *user_context, void *operation,
				uint8_t *hash, size_t hash_size,
				size_t *hash_length)
{
	struct test_context *state = user_context;

	const int ret = state->backend->hash_finish(
		user_context, operation, hash, hash_size, hash_length);

	/* hash_finish releases the operation; the library aborts it on a later
	 * failure, so drop it here unconditionally (removal is idempotent). */
	tracker_hash_remove(&state->tracker, operation);

	return ret;
}

static int counting_hash_abort(void *user_context, void *operation)
{
	struct test_context *state = user_context;

	const int ret = state->backend->hash_abort(user_context, operation);

	tracker_hash_remove(&state->tracker, operation);

	return ret;
}

static int import_auth_priv_key(enum auth_key_kind kind, const uint8_t *priv,
				size_t priv_length, uint8_t *key_id)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);

	if (AUTH_KEY_SIGN == kind) {
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
		psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	} else {
		psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
		psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	}

	psa_set_key_type(&attr,
			 PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));

	psa_key_id_t kid = PSA_KEY_ID_NULL;

	if (PSA_SUCCESS != psa_import_key(&attr, priv, priv_length, &kid)) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	memcpy(key_id, &kid, sizeof(kid));

	return EDHOC_SUCCESS;
}

static int auth_cred_fetch_init(void *user_context,
				struct edhoc_auth_creds *credentials)
{
	const struct test_context *state = user_context;

	credentials->label = EDHOC_COSE_HEADER_X509_CHAIN;
	credentials->x509_chain.nr_of_certs = 1;
	credentials->x509_chain.cert[0] = TEST_VEC_CRED_I;
	credentials->x509_chain.cert_len[0] = ARRAY_SIZE(TEST_VEC_CRED_I);

	return import_auth_priv_key(state->auth.init_kind, TEST_VEC_SK_I,
				    ARRAY_SIZE(TEST_VEC_SK_I),
				    credentials->priv_key_id);
}

static int auth_cred_fetch_resp(void *user_context,
				struct edhoc_auth_creds *credentials)
{
	const struct test_context *state = user_context;

	credentials->label = EDHOC_COSE_HEADER_X509_CHAIN;
	credentials->x509_chain.nr_of_certs = 1;
	credentials->x509_chain.cert[0] = TEST_VEC_CRED_R;
	credentials->x509_chain.cert_len[0] = ARRAY_SIZE(TEST_VEC_CRED_R);

	return import_auth_priv_key(state->auth.resp_kind, TEST_VEC_SK_R,
				    ARRAY_SIZE(TEST_VEC_SK_R),
				    credentials->priv_key_id);
}

static int auth_cred_verify_init(void *user_context,
				 struct edhoc_auth_creds *credentials,
				 const uint8_t **public_key,
				 size_t *public_key_length)
{
	const struct test_context *state = user_context;

	if (NULL == credentials || NULL == public_key ||
	    NULL == public_key_length) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_COSE_HEADER_X509_CHAIN != credentials->label) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (1 != credentials->x509_chain.nr_of_certs) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (credentials->x509_chain.cert_len[0] !=
	    ARRAY_SIZE(TEST_VEC_CRED_I)) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (0 != memcmp(TEST_VEC_CRED_I, credentials->x509_chain.cert[0],
			credentials->x509_chain.cert_len[0])) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	*public_key = state->auth.init_pub_key;
	*public_key_length = state->auth.init_pub_key_length;

	return EDHOC_SUCCESS;
}

static int auth_cred_verify_resp(void *user_context,
				 struct edhoc_auth_creds *credentials,
				 const uint8_t **public_key,
				 size_t *public_key_length)
{
	const struct test_context *state = user_context;

	if (NULL == credentials || NULL == public_key ||
	    NULL == public_key_length) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}

	if (EDHOC_COSE_HEADER_X509_CHAIN != credentials->label) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (1 != credentials->x509_chain.nr_of_certs) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (credentials->x509_chain.cert_len[0] !=
	    ARRAY_SIZE(TEST_VEC_CRED_R)) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	if (0 != memcmp(TEST_VEC_CRED_R, credentials->x509_chain.cert[0],
			credentials->x509_chain.cert_len[0])) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}

	*public_key = state->auth.resp_pub_key;
	*public_key_length = state->auth.resp_pub_key_length;

	return EDHOC_SUCCESS;
}

static struct auth_vectors auth_vectors_for_method(enum edhoc_method method)
{
	const enum auth_key_kind init_kind =
		(EDHOC_METHOD_0 == method || EDHOC_METHOD_1 == method) ?
			AUTH_KEY_SIGN :
			AUTH_KEY_DH;
	const enum auth_key_kind resp_kind =
		(EDHOC_METHOD_0 == method || EDHOC_METHOD_2 == method) ?
			AUTH_KEY_SIGN :
			AUTH_KEY_DH;

	struct auth_vectors vectors = { .init_kind = init_kind,
					.resp_kind = resp_kind };

	if (AUTH_KEY_SIGN == init_kind) {
		vectors.init_pub_key = TEST_VEC_PK_I_SIG;
		vectors.init_pub_key_length = ARRAY_SIZE(TEST_VEC_PK_I_SIG);
	} else {
		vectors.init_pub_key = TEST_VEC_PK_I_DH;
		vectors.init_pub_key_length = ARRAY_SIZE(TEST_VEC_PK_I_DH);
	}

	if (AUTH_KEY_SIGN == resp_kind) {
		vectors.resp_pub_key = TEST_VEC_PK_R_SIG;
		vectors.resp_pub_key_length = ARRAY_SIZE(TEST_VEC_PK_R_SIG);
	} else {
		vectors.resp_pub_key = TEST_VEC_PK_R_DH;
		vectors.resp_pub_key_length = ARRAY_SIZE(TEST_VEC_PK_R_DH);
	}

	return vectors;
}

static struct test_context make_test_context(enum edhoc_method method)
{
	struct test_context state = {
		.backend = edhoc_cipher_suite_2_get_crypto(),
		.auth = auth_vectors_for_method(method),
	};

	TEST_ASSERT_NOT_NULL(state.backend);

	return state;
}

static void setup_peer(struct edhoc_context *ctx, enum edhoc_method method,
		       const struct edhoc_credentials *credentials,
		       const struct edhoc_connection_id *connection_id,
		       struct test_context *state)
{
	const enum edhoc_method methods[] = { method };
	int ret;

	ret = edhoc_context_init(ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_methods(ctx, methods, ARRAY_SIZE(methods));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_cipher_suites(ctx, edhoc_cipher_suite_2_get_suite(), 1);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_connection_id(ctx, connection_id);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_set_user_context(ctx, state);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_ead(ctx, &test_ead_stubs);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_crypto(ctx, &counting_crypto);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_platform(ctx, test_get_platform());
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_bind_credentials(ctx, credentials);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

static void setup_peers(struct test_context *state,
			struct edhoc_context *init_ctx,
			struct edhoc_context *resp_ctx,
			enum edhoc_method method)
{
	setup_peer(init_ctx, method, &cred_init, &cid_init, state);
	setup_peer(resp_ctx, method, &cred_resp, &cid_resp, state);
}

static void run_full_handshake(enum edhoc_method method)
{
	struct test_context state = make_test_context(method);

	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	setup_peers(&state, &init_ctx, &resp_ctx, method);

	uint8_t buffer[TEST_HANDSHAKE_MSG_BUF_SIZE] = { 0 };
	size_t msg_len = 0;
	int ret;

	/* Message 1: Initiator -> Responder. */
	ret = edhoc_message_1_compose(&init_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_1_process(&resp_ctx, buffer, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Message 2: Responder -> Initiator. */
	memset(buffer, 0, sizeof(buffer));

	ret = edhoc_message_2_compose(&resp_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_2_process(&init_ctx, buffer, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Message 3: Initiator -> Responder. */
	memset(buffer, 0, sizeof(buffer));

	ret = edhoc_message_3_compose(&init_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_3_process(&resp_ctx, buffer, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Message 4: Responder -> Initiator. */
	memset(buffer, 0, sizeof(buffer));

	ret = edhoc_message_4_compose(&resp_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_4_process(&init_ctx, buffer, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* After completion both peers still hold the exporter handles, so the
	 * tracker is intentionally non-empty here; the OSCORE export exercises
	 * those retained handles before they are released at deinit. */
	TEST_ASSERT_GREATER_THAN_UINT(0, state.tracker.key_count);

	/* Export the OSCORE session on both sides and require agreement. */
	uint8_t init_secret[OSCORE_MASTER_SECRET_LENGTH] = { 0 };
	uint8_t init_salt[OSCORE_MASTER_SALT_LENGTH] = { 0 };
	uint8_t init_sender_id[8] = { 0 };
	size_t init_sender_id_len = 0;
	uint8_t init_recipient_id[8] = { 0 };
	size_t init_recipient_id_len = 0;

	ret = edhoc_export_oscore_session(
		&init_ctx, init_secret, sizeof(init_secret), init_salt,
		sizeof(init_salt), init_sender_id, sizeof(init_sender_id),
		&init_sender_id_len, init_recipient_id,
		sizeof(init_recipient_id), &init_recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t resp_secret[OSCORE_MASTER_SECRET_LENGTH] = { 0 };
	uint8_t resp_salt[OSCORE_MASTER_SALT_LENGTH] = { 0 };
	uint8_t resp_sender_id[8] = { 0 };
	size_t resp_sender_id_len = 0;
	uint8_t resp_recipient_id[8] = { 0 };
	size_t resp_recipient_id_len = 0;

	ret = edhoc_export_oscore_session(
		&resp_ctx, resp_secret, sizeof(resp_secret), resp_salt,
		sizeof(resp_salt), resp_sender_id, sizeof(resp_sender_id),
		&resp_sender_id_len, resp_recipient_id,
		sizeof(resp_recipient_id), &resp_recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_secret, resp_secret,
				      OSCORE_MASTER_SECRET_LENGTH);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_salt, resp_salt,
				      OSCORE_MASTER_SALT_LENGTH);

	/* EDHOC-KeyUpdate (RFC 9528, section 4.4): both peers feed the same
	 * context and must still agree, on a fresh master secret. */
	static const uint8_t key_update_context[] = {
		0xd6, 0x64, 0x7c, 0x93, 0x0e, 0xdb, 0xa1, 0x2d,
		0x1e, 0x3c, 0x6b, 0x2f, 0x9c, 0x51, 0x8a, 0x47,
	};

	ret = edhoc_export_key_update(&init_ctx, key_update_context,
				      sizeof(key_update_context));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_export_key_update(&resp_ctx, key_update_context,
				      sizeof(key_update_context));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t init_secret_upd[OSCORE_MASTER_SECRET_LENGTH] = { 0 };
	uint8_t init_salt_upd[OSCORE_MASTER_SALT_LENGTH] = { 0 };

	ret = edhoc_export_oscore_session(
		&init_ctx, init_secret_upd, sizeof(init_secret_upd),
		init_salt_upd, sizeof(init_salt_upd), init_sender_id,
		sizeof(init_sender_id), &init_sender_id_len, init_recipient_id,
		sizeof(init_recipient_id), &init_recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	uint8_t resp_secret_upd[OSCORE_MASTER_SECRET_LENGTH] = { 0 };
	uint8_t resp_salt_upd[OSCORE_MASTER_SALT_LENGTH] = { 0 };

	ret = edhoc_export_oscore_session(
		&resp_ctx, resp_secret_upd, sizeof(resp_secret_upd),
		resp_salt_upd, sizeof(resp_salt_upd), resp_sender_id,
		sizeof(resp_sender_id), &resp_sender_id_len, resp_recipient_id,
		sizeof(resp_recipient_id), &resp_recipient_id_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT8_ARRAY(init_secret_upd, resp_secret_upd,
				      OSCORE_MASTER_SECRET_LENGTH);
	TEST_ASSERT_TRUE(0 != memcmp(init_secret, init_secret_upd,
				     OSCORE_MASTER_SECRET_LENGTH));

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* The whole point: deinit released every key handle and hash operation
	 * the library created. */
	TEST_ASSERT_EQUAL_UINT_MESSAGE(0, state.tracker.key_count,
				       "handshake leaked PSA key handles");
	TEST_ASSERT_EQUAL_UINT_MESSAGE(0, state.tracker.hash_op_count,
				       "handshake leaked hash operations");
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(handshake_handle_balance);

TEST_SETUP(handshake_handle_balance)
{
	const psa_status_t status = psa_crypto_init();
	TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

TEST_TEAR_DOWN(handshake_handle_balance)
{
	mbedtls_psa_crypto_free();
}

TEST(handshake_handle_balance, method_0_sig_sig_balanced)
{
	run_full_handshake(EDHOC_METHOD_0);
}

TEST(handshake_handle_balance, method_1_sig_dh_balanced)
{
	run_full_handshake(EDHOC_METHOD_1);
}

TEST(handshake_handle_balance, method_2_dh_sig_balanced)
{
	run_full_handshake(EDHOC_METHOD_2);
}

TEST(handshake_handle_balance, method_3_dh_dh_balanced)
{
	run_full_handshake(EDHOC_METHOD_3);
}

TEST(handshake_handle_balance, repeated_handshakes_no_accumulation)
{
	for (size_t i = 0; i < 8; ++i) {
		run_full_handshake(EDHOC_METHOD_3);
	}
}

TEST(handshake_handle_balance, partial_abort_after_message_1_balanced)
{
	struct test_context state = make_test_context(EDHOC_METHOD_0);

	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	setup_peers(&state, &init_ctx, &resp_ctx, EDHOC_METHOD_0);

	uint8_t buffer[TEST_HANDSHAKE_MSG_BUF_SIZE] = { 0 };
	size_t msg_len = 0;
	int ret;

	ret = edhoc_message_1_compose(&init_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_1_process(&resp_ctx, buffer, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* The Initiator created an ephemeral key pair during message 1. */
	TEST_ASSERT_GREATER_THAN_UINT(0, state.tracker.key_count);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT_MESSAGE(0, state.tracker.key_count,
				       "partial abort leaked PSA key handles");
	TEST_ASSERT_EQUAL_UINT_MESSAGE(0, state.tracker.hash_op_count,
				       "partial abort leaked hash operations");
}

TEST(handshake_handle_balance, corrupted_message_2_balanced)
{
	struct test_context state = make_test_context(EDHOC_METHOD_0);

	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	setup_peers(&state, &init_ctx, &resp_ctx, EDHOC_METHOD_0);

	uint8_t buffer[TEST_HANDSHAKE_MSG_BUF_SIZE] = { 0 };
	size_t msg_len = 0;
	int ret;

	ret = edhoc_message_1_compose(&init_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_1_process(&resp_ctx, buffer, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	memset(buffer, 0, sizeof(buffer));

	ret = edhoc_message_2_compose(&resp_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Corrupt the ciphertext tail so decryption / MAC verification fails. */
	TEST_ASSERT_GREATER_THAN_UINT(0, msg_len);
	buffer[msg_len - 1] ^= 0xff;

	ret = edhoc_message_2_process(&init_ctx, buffer, msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT_MESSAGE(
		0, state.tracker.key_count,
		"malformed-message error leaked PSA key handles");
	TEST_ASSERT_EQUAL_UINT_MESSAGE(
		0, state.tracker.hash_op_count,
		"malformed-message error leaked hash operations");
}

TEST(handshake_handle_balance, corrupted_message_3_balanced)
{
	struct test_context state = make_test_context(EDHOC_METHOD_0);

	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	setup_peers(&state, &init_ctx, &resp_ctx, EDHOC_METHOD_0);

	uint8_t buffer[TEST_HANDSHAKE_MSG_BUF_SIZE] = { 0 };
	size_t msg_len = 0;
	int ret;

	ret = edhoc_message_1_compose(&init_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_1_process(&resp_ctx, buffer, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	memset(buffer, 0, sizeof(buffer));

	ret = edhoc_message_2_compose(&resp_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_2_process(&init_ctx, buffer, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	memset(buffer, 0, sizeof(buffer));

	ret = edhoc_message_3_compose(&init_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Corrupt the ciphertext tail so decryption / MAC verification fails. */
	TEST_ASSERT_GREATER_THAN_UINT(0, msg_len);
	buffer[msg_len - 1] ^= 0xff;

	ret = edhoc_message_3_process(&resp_ctx, buffer, msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT_MESSAGE(
		0, state.tracker.key_count,
		"malformed-message error leaked PSA key handles");
	TEST_ASSERT_EQUAL_UINT_MESSAGE(
		0, state.tracker.hash_op_count,
		"malformed-message error leaked hash operations");
}

TEST(handshake_handle_balance, corrupted_message_4_balanced)
{
	struct test_context state = make_test_context(EDHOC_METHOD_0);

	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	setup_peers(&state, &init_ctx, &resp_ctx, EDHOC_METHOD_0);

	uint8_t buffer[TEST_HANDSHAKE_MSG_BUF_SIZE] = { 0 };
	size_t msg_len = 0;
	int ret;

	ret = edhoc_message_1_compose(&init_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_1_process(&resp_ctx, buffer, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	memset(buffer, 0, sizeof(buffer));

	ret = edhoc_message_2_compose(&resp_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_2_process(&init_ctx, buffer, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	memset(buffer, 0, sizeof(buffer));

	ret = edhoc_message_3_compose(&init_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_3_process(&resp_ctx, buffer, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	memset(buffer, 0, sizeof(buffer));

	ret = edhoc_message_4_compose(&resp_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Corrupt the ciphertext tail so decryption / MAC verification fails. */
	TEST_ASSERT_GREATER_THAN_UINT(0, msg_len);
	buffer[msg_len - 1] ^= 0xff;

	ret = edhoc_message_4_process(&init_ctx, buffer, msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT_MESSAGE(
		0, state.tracker.key_count,
		"malformed-message error leaked PSA key handles");
	TEST_ASSERT_EQUAL_UINT_MESSAGE(
		0, state.tracker.hash_op_count,
		"malformed-message error leaked hash operations");
}

TEST(handshake_handle_balance, crypto_extract_failure_balanced)
{
	struct test_context state = make_test_context(EDHOC_METHOD_0);

	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	setup_peers(&state, &init_ctx, &resp_ctx, EDHOC_METHOD_0);

	uint8_t buffer[TEST_HANDSHAKE_MSG_BUF_SIZE] = { 0 };
	size_t msg_len = 0;
	int ret;

	ret = edhoc_message_1_compose(&init_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_1_process(&resp_ctx, buffer, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Fail the first EDHOC_Extract, which derives PRK_2e in message 2. */
	state.fault.op = CRYPTO_FAULT_EXTRACT;
	state.fault.at = 1;

	memset(buffer, 0, sizeof(buffer));

	ret = edhoc_message_2_compose(&resp_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	/* The Responder already created ephemeral + shared-secret handles. */
	TEST_ASSERT_GREATER_THAN_UINT(0, state.tracker.key_count);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT_MESSAGE(
		0, state.tracker.key_count,
		"crypto-failure cleanup leaked PSA key handles");
	TEST_ASSERT_EQUAL_UINT_MESSAGE(
		0, state.tracker.hash_op_count,
		"crypto-failure cleanup leaked hash operations");
}

TEST(handshake_handle_balance, crypto_expand_failure_balanced)
{
	struct test_context state = make_test_context(EDHOC_METHOD_0);

	struct edhoc_context init_ctx = { 0 };
	struct edhoc_context resp_ctx = { 0 };

	setup_peers(&state, &init_ctx, &resp_ctx, EDHOC_METHOD_0);

	uint8_t buffer[TEST_HANDSHAKE_MSG_BUF_SIZE] = { 0 };
	size_t msg_len = 0;
	int ret;

	ret = edhoc_message_1_compose(&init_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_1_process(&resp_ctx, buffer, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	memset(buffer, 0, sizeof(buffer));

	ret = edhoc_message_2_compose(&resp_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_message_2_process(&init_ctx, buffer, msg_len);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	/* Fail an EDHOC_Expand raised while the Initiator composes message 3. */
	state.fault.op = CRYPTO_FAULT_EXPAND;
	state.fault.at = 1;

	memset(buffer, 0, sizeof(buffer));

	ret = edhoc_message_3_compose(&init_ctx, buffer,
				      TEST_HANDSHAKE_MSG_BUF_SIZE, &msg_len);
	TEST_ASSERT_NOT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&init_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	ret = edhoc_context_deinit(&resp_ctx);
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);

	TEST_ASSERT_EQUAL_UINT_MESSAGE(
		0, state.tracker.key_count,
		"crypto-failure cleanup leaked PSA key handles");
	TEST_ASSERT_EQUAL_UINT_MESSAGE(
		0, state.tracker.hash_op_count,
		"crypto-failure cleanup leaked hash operations");
}

TEST_GROUP_RUNNER(handshake_handle_balance)
{
	RUN_TEST_CASE(handshake_handle_balance, method_0_sig_sig_balanced);
	RUN_TEST_CASE(handshake_handle_balance, method_1_sig_dh_balanced);
	RUN_TEST_CASE(handshake_handle_balance, method_2_dh_sig_balanced);
	RUN_TEST_CASE(handshake_handle_balance, method_3_dh_dh_balanced);
	RUN_TEST_CASE(handshake_handle_balance,
		      repeated_handshakes_no_accumulation);
	RUN_TEST_CASE(handshake_handle_balance,
		      partial_abort_after_message_1_balanced);
	RUN_TEST_CASE(handshake_handle_balance, corrupted_message_2_balanced);
	RUN_TEST_CASE(handshake_handle_balance, corrupted_message_3_balanced);
	RUN_TEST_CASE(handshake_handle_balance, corrupted_message_4_balanced);
	RUN_TEST_CASE(handshake_handle_balance,
		      crypto_extract_failure_balanced);
	RUN_TEST_CASE(handshake_handle_balance, crypto_expand_failure_balanced);
}
