/**
 * \file    test_internals_credentials.c
 * \author  Kamil Kielbasa
 * \brief   Unit tests for ID_CRED_x decoding, driven through the PLAINTEXT
 *          parsers of message_2 and message_3.
 *
 * \copyright Copyright (c) 2026
 *
 */

/* Include files ----------------------------------------------------------- */

/* Internal headers: */
#include "internals_common.h"
#include "edhoc_macros_internal.h"
#include "edhoc_credentials_internal.h"

/* Standard library headers: */
#include <stdint.h>
#include <stddef.h>

/* Unity headers: */
#include <unity.h>
#include <unity_fixture.h>

/* Module defines ---------------------------------------------------------- */
/* Module types and type definitiones -------------------------------------- */
/* Module interface variables and constants -------------------------------- */
/* Static function declarations -------------------------------------------- */

/** \brief Run PLAINTEXT_2 through the parser on a throwaway context. */
static int parse_ptxt_2(const uint8_t *ptxt, size_t ptxt_len,
			struct plaintext *parsed);

/** \brief Run PLAINTEXT_3 through the parser on a throwaway context. */
static int parse_ptxt_3(const uint8_t *ptxt, size_t ptxt_len,
			struct plaintext *parsed);

/**
 * \brief Assert that Signature_or_MAC is a view on \p expected. It follows
 *        ID_CRED_x, so a wrong offset here means ID_CRED_x was mis-sized.
 */
static void assert_sign_or_mac(const struct plaintext *parsed,
			       const uint8_t *expected);

/** \brief Assert that a rejected ID_CRED_x left nothing behind. */
static void assert_untouched(const struct plaintext *parsed);

/** \brief Build credentials referenced by a key identifier that pass validation. */
static struct edhoc_auth_credentials make_valid_kid(void);

/** \brief Build a single certificate chain that passes validation. */
static struct edhoc_auth_credentials make_valid_x5chain(void);

/** \brief Build a certificate fingerprint credential that passes validation. */
static struct edhoc_auth_credentials make_valid_x5t(void);

/* Static variables and constants ------------------------------------------ */

/*
 * PLAINTEXT_2 = ( C_R, ID_CRED_R, Signature_or_MAC_2, ? EAD_2 )
 * PLAINTEXT_3 = (      ID_CRED_I, Signature_or_MAC_3, ? EAD_3 )
 *
 * C_R is the CBOR integer -8 (0x27) throughout. Signature_or_MAC is always the
 * eight byte string 0xc0..0xc7, so where it lands doubles as a check that
 * ID_CRED_x was consumed to exactly the right length.
 */

/** ID_CRED_I = -12: a 'kid' in the compact integer encoding. */
static const uint8_t ptxt_3_kid_int[] = {
	0x2b, 0x48, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

/** ID_CRED_I = h'AA': a 'kid' in the compact byte string encoding. */
static const uint8_t ptxt_3_kid_bstr[] = {
	0x41, 0xaa, 0x48, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

/** ID_CRED_I as a 32 byte 'kid': exactly the capacity. Byte 0 opens a byte
 *  string whose one byte length follows, the payload stays zeroed, then
 *  Signature_or_MAC_3. */
static const uint8_t ptxt_3_kid_bstr_32[2 + 32 + 1 + 8] = {
	[0] = 0x58,
	[1] = 32,
	[34] = 0x48,
};

/** ID_CRED_I as a 33 byte 'kid': one byte over the capacity. */
static const uint8_t ptxt_3_kid_bstr_33[2 + 33 + 1 + 8] = {
	[0] = 0x58,
	[1] = 33,
	[35] = 0x48,
};

/** ID_CRED_I as a 64 byte 'kid'. Byte 0 opens a byte string whose one byte
 *  length follows, the payload stays zeroed, then Signature_or_MAC_3. */
static const uint8_t ptxt_3_kid_bstr_64[2 + 64 + 1 + 8] = {
	[0] = 0x58,
	[1] = 64,
	[66] = 0x48,
};

/** ID_CRED_I as a 255 byte 'kid'. Before the bound check this overflowed the
 *  two byte destination buffer of the decoder. */
static const uint8_t ptxt_3_kid_bstr_255[2 + 255 + 1 + 8] = {
	[0] = 0x58,
	[1] = 255,
	[257] = 0x48,
};

/** ID_CRED_I = { 4 : h'AA' }: a 'kid' that skipped the compact encoding. */
static const uint8_t ptxt_3_map_kid[] = {
	0xa1, 0x04, 0x41, 0xaa, 0x48, 0xc0, 0xc1,
	0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

/** ID_CRED_I = {}: no header parameter at all. */
static const uint8_t ptxt_3_map_empty[] = {
	0xa0, 0x48, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

/** ID_CRED_I = { 33 : x5chain, 34 : x5t }: two competing header parameters. */
static const uint8_t ptxt_3_map_two_labels[] = {
	0xa2, 0x18, 0x21, 0x43, 0x30, 0x00, 0x01, 0x18, 0x22, 0x82,
	0x2e, 0x48, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0x48, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

/** ID_CRED_I = { 33 : h'300001' }: a single certificate is a byte string, not
 *  a one element array (RFC 9360: 2). */
static const uint8_t ptxt_3_x5chain_one[] = {
	0xa1, 0x18, 0x21, 0x43, 0x30, 0x00, 0x01, 0x48,
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

/** ID_CRED_I = { 33 : [ h'300001', h'300002' ] }: two certificates. */
static const uint8_t ptxt_3_x5chain_two[] = {
	0xa1, 0x18, 0x21, 0x82, 0x43, 0x30, 0x00, 0x01, 0x43, 0x30, 0x00,
	0x02, 0x48, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

/** ID_CRED_I with three certificates: the largest chain the CBOR model admits. */
static const uint8_t ptxt_3_x5chain_three[] = {
	0xa1, 0x18, 0x21, 0x83, 0x43, 0x30, 0x00, 0x01, 0x43,
	0x30, 0x00, 0x02, 0x43, 0x30, 0x00, 0x03, 0x48, 0xc0,
	0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

/** ID_CRED_I = { 34 : [ -15, h'F0..F7' ] }: x5t with an integer hashAlg. */
static const uint8_t ptxt_3_x5t_alg_int[] = {
	0xa1, 0x18, 0x22, 0x82, 0x2e, 0x48, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
	0xf6, 0xf7, 0x48, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

/** ID_CRED_I x5t with the text hashAlg "sha". */
static const uint8_t ptxt_3_x5t_alg_tstr[] = {
	0xa1, 0x18, 0x22, 0x82, 0x63, 0x73, 0x68, 0x61, 0x48,
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0x48,
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

/** ID_CRED_I x5t with a 33 byte text hashAlg: one byte over its capacity.
 *  Header is { 34 : [ tstr(33), bstr(8) ] }, the name stays zeroed. */
static const uint8_t ptxt_3_x5t_alg_tstr_33[6 + 33 + 1 + 8 + 1 + 8] = {
	[0] = 0xa1, [1] = 0x18, [2] = 0x22,  [3] = 0x82,
	[4] = 0x78, [5] = 33,	[39] = 0x48, [48] = 0x48,
};

/** ID_CRED_I x5t with a 65 byte fingerprint: one byte over the SHA-512 bound.
 *  Header is { 34 : [ -15, bstr(65) ] }, the fingerprint stays zeroed. */
static const uint8_t ptxt_3_x5t_fingerprint_65[7 + 65 + 1 + 8] = {
	[0] = 0xa1, [1] = 0x18, [2] = 0x22, [3] = 0x82,
	[4] = 0x2e, [5] = 0x58, [6] = 65,   [72] = 0x48,
};

/** PLAINTEXT_2 with ID_CRED_R = -12. */
static const uint8_t ptxt_2_kid_int[] = {
	0x27, 0x2b, 0x48, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

/** PLAINTEXT_2 with ID_CRED_R as a 255 byte 'kid'. */
static const uint8_t ptxt_2_kid_bstr_255[1 + 2 + 255 + 1 + 8] = {
	[0] = 0x27,
	[1] = 0x58,
	[2] = 255,
	[258] = 0x48,
};

/** PLAINTEXT_2 with ID_CRED_R = { 4 : h'AA' }. */
static const uint8_t ptxt_2_map_kid[] = {
	0x27, 0xa1, 0x04, 0x41, 0xaa, 0x48, 0xc0,
	0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

/** PLAINTEXT_2 with ID_CRED_R = { 33 : h'300001' }. */
static const uint8_t ptxt_2_x5chain_one[] = {
	0x27, 0xa1, 0x18, 0x21, 0x43, 0x30, 0x00, 0x01, 0x48,
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

/** Signature_or_MAC value shared by every vector above. */
static const uint8_t sign_or_mac[] = {
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

/** The first certificate of every x5chain vector above. */
static const uint8_t first_certificate[] = { 0x30, 0x00, 0x01 };

/** The x5t fingerprint of every COSE_CertHash vector above. */
static const uint8_t fingerprint[] = { 0xf0, 0xf1, 0xf2, 0xf3,
				       0xf4, 0xf5, 0xf6, 0xf7 };

/* Static function definitions --------------------------------------------- */

static int parse_ptxt_2(const uint8_t *ptxt, size_t ptxt_len,
			struct plaintext *parsed)
{
	struct edhoc_context ctx = { 0 };

	return parse_plaintext_2(&ctx, ptxt, ptxt_len, parsed);
}

static int parse_ptxt_3(const uint8_t *ptxt, size_t ptxt_len,
			struct plaintext *parsed)
{
	struct edhoc_context ctx = { 0 };

	return parse_plaintext_3(&ctx, ptxt, ptxt_len, parsed);
}

static void assert_sign_or_mac(const struct plaintext *parsed,
			       const uint8_t *expected)
{
	TEST_ASSERT_EQUAL_size_t(ARRAY_SIZE(sign_or_mac),
				 parsed->sign_or_mac_len);
	TEST_ASSERT_EQUAL_PTR(expected, parsed->sign_or_mac);
	TEST_ASSERT_EQUAL_MEMORY(sign_or_mac, parsed->sign_or_mac,
				 ARRAY_SIZE(sign_or_mac));
}

static void assert_untouched(const struct plaintext *parsed)
{
	const struct plaintext zeroed = { 0 };

	TEST_ASSERT_EQUAL_MEMORY(&zeroed, parsed, sizeof(zeroed));
}

static struct edhoc_auth_credentials make_valid_kid(void)
{
	return (struct edhoc_auth_credentials){
		.label = EDHOC_COSE_HEADER_KID,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.key_id = {
			.encode_type = EDHOC_ENCODE_TYPE_INTEGER,
			.key_id_int = -12,
			.credential = first_certificate,
			.credential_length = ARRAY_SIZE(first_certificate),
		},
	};
}

static struct edhoc_auth_credentials make_valid_x5chain(void)
{
	return (struct edhoc_auth_credentials){
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_chain = {
			.certificate_count = 1,
			.certificate = { first_certificate },
			.certificate_length = { ARRAY_SIZE(first_certificate) },
		},
	};
}

static struct edhoc_auth_credentials make_valid_x5t(void)
{
	return (struct edhoc_auth_credentials){
		.label = EDHOC_COSE_HEADER_X509_HASH,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_hash = {
			.certificate = first_certificate,
			.certificate_length = ARRAY_SIZE(first_certificate),
			.certificate_fingerprint = fingerprint,
			.certificate_fingerprint_length =
				ARRAY_SIZE(fingerprint),
			.encode_type = EDHOC_ENCODE_TYPE_INTEGER,
			.algorithm_int = -15,
		},
	};
}

/* Module interface function definitions ----------------------------------- */

TEST_GROUP(internals_credentials);

TEST_SETUP(internals_credentials)
{
}

TEST_TEAR_DOWN(internals_credentials)
{
}

TEST(internals_credentials, kid_int)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_kid_int, ARRAY_SIZE(ptxt_3_kid_int),
				     &parsed);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_KID, parsed.auth_cred.label);
	TEST_ASSERT_EQUAL(EDHOC_ENCODE_TYPE_INTEGER,
			  parsed.auth_cred.key_id.encode_type);
	TEST_ASSERT_EQUAL_INT32(-12, parsed.auth_cred.key_id.key_id_int);
	assert_sign_or_mac(&parsed, &ptxt_3_kid_int[2]);
}

TEST(internals_credentials, kid_bstr_within_capacity)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_kid_bstr,
				     ARRAY_SIZE(ptxt_3_kid_bstr), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_KID, parsed.auth_cred.label);
	TEST_ASSERT_EQUAL(EDHOC_ENCODE_TYPE_STRING,
			  parsed.auth_cred.key_id.encode_type);
	TEST_ASSERT_EQUAL_size_t(1, parsed.auth_cred.key_id.key_id_bstr.length);
	TEST_ASSERT_EQUAL_MEMORY(&ptxt_3_kid_bstr[1],
				 parsed.auth_cred.key_id.key_id_bstr.value, 1);
	assert_sign_or_mac(&parsed, &ptxt_3_kid_bstr[3]);
}

TEST(internals_credentials, kid_bstr_at_capacity)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_kid_bstr_32,
				     ARRAY_SIZE(ptxt_3_kid_bstr_32), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_KID, parsed.auth_cred.label);
	TEST_ASSERT_EQUAL_size_t(EDHOC_CREDENTIAL_KID_MAX_LEN,
				 parsed.auth_cred.key_id.key_id_bstr.length);
}

TEST(internals_credentials, kid_bstr_over_capacity)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_kid_bstr_33,
				     ARRAY_SIZE(ptxt_3_kid_bstr_33), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
	assert_untouched(&parsed);
}

TEST(internals_credentials, kid_bstr_64_rejected)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_kid_bstr_64,
				     ARRAY_SIZE(ptxt_3_kid_bstr_64), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
	assert_untouched(&parsed);
}

TEST(internals_credentials, kid_bstr_255_rejected)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_kid_bstr_255,
				     ARRAY_SIZE(ptxt_3_kid_bstr_255), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
	assert_untouched(&parsed);
}

TEST(internals_credentials, map_kid_rejected)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_map_kid, ARRAY_SIZE(ptxt_3_map_kid),
				     &parsed);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
	assert_untouched(&parsed);
}

TEST(internals_credentials, map_empty_rejected)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_map_empty,
				     ARRAY_SIZE(ptxt_3_map_empty), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
	assert_untouched(&parsed);
}

TEST(internals_credentials, map_two_labels_rejected)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_map_two_labels,
				     ARRAY_SIZE(ptxt_3_map_two_labels),
				     &parsed);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
	assert_untouched(&parsed);
}

TEST(internals_credentials, x5chain_single_certificate)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_x5chain_one,
				     ARRAY_SIZE(ptxt_3_x5chain_one), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_X509_CHAIN, parsed.auth_cred.label);
	TEST_ASSERT_EQUAL_size_t(1,
				 parsed.auth_cred.x509_chain.certificate_count);
	TEST_ASSERT_EQUAL_size_t(
		ARRAY_SIZE(first_certificate),
		parsed.auth_cred.x509_chain.certificate_length[0]);
	TEST_ASSERT_EQUAL_PTR(&ptxt_3_x5chain_one[4],
			      parsed.auth_cred.x509_chain.certificate[0]);
	TEST_ASSERT_EQUAL_MEMORY(first_certificate,
				 parsed.auth_cred.x509_chain.certificate[0],
				 ARRAY_SIZE(first_certificate));
	assert_sign_or_mac(&parsed, &ptxt_3_x5chain_one[8]);
}

TEST(internals_credentials, x5chain_two_certificates)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_x5chain_two,
				     ARRAY_SIZE(ptxt_3_x5chain_two), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_X509_CHAIN, parsed.auth_cred.label);
	TEST_ASSERT_EQUAL_size_t(2,
				 parsed.auth_cred.x509_chain.certificate_count);
	TEST_ASSERT_EQUAL_size_t(
		3, parsed.auth_cred.x509_chain.certificate_length[0]);
	TEST_ASSERT_EQUAL_size_t(
		3, parsed.auth_cred.x509_chain.certificate_length[1]);
	TEST_ASSERT_EQUAL_PTR(&ptxt_3_x5chain_two[5],
			      parsed.auth_cred.x509_chain.certificate[0]);
	TEST_ASSERT_EQUAL_PTR(&ptxt_3_x5chain_two[9],
			      parsed.auth_cred.x509_chain.certificate[1]);
	assert_sign_or_mac(&parsed, &ptxt_3_x5chain_two[13]);
}

TEST(internals_credentials, x5chain_three_certificates)
{
	/* Three is the largest chain the CBOR model admits, so this vector only
	 * fits a build configured for the maximum. The rejection path is
	 * covered by validate_fetched_x5chain_over_capacity. */
	if (EDHOC_CREDENTIAL_X5CHAIN_CAPACITY < 3) {
		TEST_IGNORE_MESSAGE("chain capacity below three certificates");
	}

	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_x5chain_three,
				     ARRAY_SIZE(ptxt_3_x5chain_three), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_X509_CHAIN, parsed.auth_cred.label);
	TEST_ASSERT_EQUAL_size_t(3,
				 parsed.auth_cred.x509_chain.certificate_count);
	TEST_ASSERT_EQUAL_PTR(&ptxt_3_x5chain_three[13],
			      parsed.auth_cred.x509_chain.certificate[2]);
	assert_sign_or_mac(&parsed, &ptxt_3_x5chain_three[17]);
}

TEST(internals_credentials, x5t_algorithm_int)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_x5t_alg_int,
				     ARRAY_SIZE(ptxt_3_x5t_alg_int), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_X509_HASH, parsed.auth_cred.label);
	TEST_ASSERT_EQUAL(EDHOC_ENCODE_TYPE_INTEGER,
			  parsed.auth_cred.x509_hash.encode_type);
	TEST_ASSERT_EQUAL_INT32(-15, parsed.auth_cred.x509_hash.algorithm_int);
	TEST_ASSERT_EQUAL_size_t(
		ARRAY_SIZE(fingerprint),
		parsed.auth_cred.x509_hash.certificate_fingerprint_length);
	TEST_ASSERT_EQUAL_PTR(
		&ptxt_3_x5t_alg_int[6],
		parsed.auth_cred.x509_hash.certificate_fingerprint);
	TEST_ASSERT_EQUAL_MEMORY(
		fingerprint, parsed.auth_cred.x509_hash.certificate_fingerprint,
		ARRAY_SIZE(fingerprint));
	assert_sign_or_mac(&parsed, &ptxt_3_x5t_alg_int[15]);
}

TEST(internals_credentials, x5t_algorithm_tstr)
{
	static const uint8_t sha[] = { 's', 'h', 'a' };
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_x5t_alg_tstr,
				     ARRAY_SIZE(ptxt_3_x5t_alg_tstr), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_X509_HASH, parsed.auth_cred.label);
	TEST_ASSERT_EQUAL(EDHOC_ENCODE_TYPE_STRING,
			  parsed.auth_cred.x509_hash.encode_type);
	TEST_ASSERT_EQUAL_size_t(
		ARRAY_SIZE(sha),
		parsed.auth_cred.x509_hash.algorithm_bstr.length);
	TEST_ASSERT_EQUAL_MEMORY(
		sha, parsed.auth_cred.x509_hash.algorithm_bstr.value,
		ARRAY_SIZE(sha));
	assert_sign_or_mac(&parsed, &ptxt_3_x5t_alg_tstr[18]);
}

TEST(internals_credentials, x5t_algorithm_tstr_over_capacity_rejected)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_x5t_alg_tstr_33,
				     ARRAY_SIZE(ptxt_3_x5t_alg_tstr_33),
				     &parsed);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
	assert_untouched(&parsed);
}

TEST(internals_credentials, x5t_fingerprint_over_limit_rejected)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_x5t_fingerprint_65,
				     ARRAY_SIZE(ptxt_3_x5t_fingerprint_65),
				     &parsed);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
	assert_untouched(&parsed);
}

TEST(internals_credentials, msg2_kid_int)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_2(ptxt_2_kid_int, ARRAY_SIZE(ptxt_2_kid_int),
				     &parsed);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_KID, parsed.auth_cred.label);
	TEST_ASSERT_EQUAL(EDHOC_ENCODE_TYPE_INTEGER,
			  parsed.auth_cred.key_id.encode_type);
	TEST_ASSERT_EQUAL_INT32(-12, parsed.auth_cred.key_id.key_id_int);
	assert_sign_or_mac(&parsed, &ptxt_2_kid_int[3]);
}

TEST(internals_credentials, msg2_kid_bstr_255_rejected)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_2(ptxt_2_kid_bstr_255,
				     ARRAY_SIZE(ptxt_2_kid_bstr_255), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
	assert_untouched(&parsed);
}

TEST(internals_credentials, msg2_map_kid_rejected)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_2(ptxt_2_map_kid, ARRAY_SIZE(ptxt_2_map_kid),
				     &parsed);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
	assert_untouched(&parsed);
}

TEST(internals_credentials, msg2_x5chain_single_certificate)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_2(ptxt_2_x5chain_one,
				     ARRAY_SIZE(ptxt_2_x5chain_one), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_X509_CHAIN, parsed.auth_cred.label);
	TEST_ASSERT_EQUAL_size_t(1,
				 parsed.auth_cred.x509_chain.certificate_count);
	TEST_ASSERT_EQUAL_PTR(&ptxt_2_x5chain_one[5],
			      parsed.auth_cred.x509_chain.certificate[0]);
	TEST_ASSERT_EQUAL_MEMORY(first_certificate,
				 parsed.auth_cred.x509_chain.certificate[0],
				 ARRAY_SIZE(first_certificate));
	assert_sign_or_mac(&parsed, &ptxt_2_x5chain_one[9]);
}

TEST(internals_credentials, validate_fetched_null)
{
	const int ret = edhoc_validate_credential_fetched(NULL);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_credentials, validate_fetched_unknown_label)
{
	const struct edhoc_auth_credentials credentials = {
		.label = (enum edhoc_cose_header)99,
	};

	const int ret = edhoc_validate_credential_fetched(&credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);
}

TEST(internals_credentials, validate_fetched_accepts_each_variant)
{
	const struct edhoc_auth_credentials kid = make_valid_kid();
	const struct edhoc_auth_credentials x5chain = make_valid_x5chain();
	const struct edhoc_auth_credentials x5t = make_valid_x5t();

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_validate_credential_fetched(&kid));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_validate_credential_fetched(&x5chain));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_validate_credential_fetched(&x5t));
}

TEST(internals_credentials, validate_fetched_kid_without_credential)
{
	struct edhoc_auth_credentials credentials = make_valid_kid();

	credentials.key_id.credential = NULL;

	const int ret = edhoc_validate_credential_fetched(&credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE, ret);
}

TEST(internals_credentials, validate_fetched_kid_bad_encode_type)
{
	struct edhoc_auth_credentials credentials = make_valid_kid();

	credentials.key_id.encode_type = (enum edhoc_encode_type)7;

	const int ret = edhoc_validate_credential_fetched(&credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_fetched_kid_format_unset)
{
	struct edhoc_auth_credentials credentials = make_valid_kid();

	credentials.format = EDHOC_CREDENTIAL_FORMAT_NONE;

	const int ret = edhoc_validate_credential_fetched(&credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_fetched_kid_bad_format)
{
	struct edhoc_auth_credentials credentials = make_valid_kid();

	credentials.format = (enum edhoc_credential_format)7;

	const int ret = edhoc_validate_credential_fetched(&credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_verified_kid_format_unset)
{
	struct edhoc_auth_credentials credentials = make_valid_kid();

	credentials.format = EDHOC_CREDENTIAL_FORMAT_NONE;

	const int ret = edhoc_validate_credential_verified(
		&credentials, fingerprint, ARRAY_SIZE(fingerprint));

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_fetched_kid_cbor_encoded)
{
	struct edhoc_auth_credentials credentials = make_valid_kid();

	/* The format describes CRED, which for 'kid' may be a CCS or a CWT. */
	credentials.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;

	const int ret = edhoc_validate_credential_fetched(&credentials);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_credentials, validate_fetched_x5chain_cbor_encoded_rejected)
{
	struct edhoc_auth_credentials credentials = make_valid_x5chain();

	credentials.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;

	const int ret = edhoc_validate_credential_fetched(&credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_fetched_x5t_cbor_encoded_rejected)
{
	struct edhoc_auth_credentials credentials = make_valid_x5t();

	credentials.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;

	const int ret = edhoc_validate_credential_fetched(&credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_fetched_x5chain_format_unset)
{
	struct edhoc_auth_credentials credentials = make_valid_x5chain();

	credentials.format = EDHOC_CREDENTIAL_FORMAT_NONE;

	const int ret = edhoc_validate_credential_fetched(&credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_verified_x5t_cbor_encoded_rejected)
{
	struct edhoc_auth_credentials credentials = make_valid_x5t();

	credentials.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;

	const int ret = edhoc_validate_credential_verified(
		&credentials, fingerprint, ARRAY_SIZE(fingerprint));

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_fetched_kid_over_capacity)
{
	struct edhoc_auth_credentials credentials = make_valid_kid();

	credentials.key_id.encode_type = EDHOC_ENCODE_TYPE_STRING;
	credentials.key_id.key_id_bstr.length =
		EDHOC_CREDENTIAL_KID_MAX_LEN + 1;

	const int ret = edhoc_validate_credential_fetched(&credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(internals_credentials, validate_fetched_x5chain_empty)
{
	struct edhoc_auth_credentials credentials = make_valid_x5chain();

	credentials.x509_chain.certificate_count = 0;

	const int ret = edhoc_validate_credential_fetched(&credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(internals_credentials, validate_fetched_x5chain_over_capacity)
{
	struct edhoc_auth_credentials credentials = make_valid_x5chain();

	credentials.x509_chain.certificate_count =
		EDHOC_CREDENTIAL_X5CHAIN_CAPACITY + 1;

	const int ret = edhoc_validate_credential_fetched(&credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(internals_credentials, validate_fetched_x5chain_null_certificate)
{
	struct edhoc_auth_credentials credentials = make_valid_x5chain();

	credentials.x509_chain.certificate[0] = NULL;

	const int ret = edhoc_validate_credential_fetched(&credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE, ret);
}

TEST(internals_credentials, validate_fetched_x5t_without_fingerprint)
{
	struct edhoc_auth_credentials credentials = make_valid_x5t();

	credentials.x509_hash.certificate_fingerprint_length = 0;

	const int ret = edhoc_validate_credential_fetched(&credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE, ret);
}

TEST(internals_credentials, validate_fetched_x5t_fingerprint_over_limit)
{
	struct edhoc_auth_credentials credentials = make_valid_x5t();

	credentials.x509_hash.certificate_fingerprint_length =
		EDHOC_CREDENTIAL_X5T_FINGERPRINT_MAX_LEN + 1;

	const int ret = edhoc_validate_credential_fetched(&credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_fetched_x5t_bad_encode_type)
{
	struct edhoc_auth_credentials credentials = make_valid_x5t();

	credentials.x509_hash.encode_type = (enum edhoc_encode_type)7;

	const int ret = edhoc_validate_credential_fetched(&credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_verified_null)
{
	const int ret = edhoc_validate_credential_verified(
		NULL, first_certificate, ARRAY_SIZE(first_certificate));

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_credentials, validate_verified_without_public_key)
{
	const struct edhoc_auth_credentials credentials = make_valid_kid();

	const int ret =
		edhoc_validate_credential_verified(&credentials, NULL, 0);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE, ret);
}

TEST(internals_credentials, validate_verified_kid_without_credential)
{
	struct edhoc_auth_credentials credentials = make_valid_kid();

	credentials.key_id.credential_length = 0;

	const int ret = edhoc_validate_credential_verified(
		&credentials, fingerprint, ARRAY_SIZE(fingerprint));

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE, ret);
}

TEST(internals_credentials, validate_verified_x5t_without_certificate)
{
	struct edhoc_auth_credentials credentials = make_valid_x5t();

	credentials.x509_hash.certificate = NULL;

	const int ret = edhoc_validate_credential_verified(
		&credentials, fingerprint, ARRAY_SIZE(fingerprint));

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE, ret);
}

TEST(internals_credentials, validate_verified_accepts_each_variant)
{
	const struct edhoc_auth_credentials kid = make_valid_kid();
	const struct edhoc_auth_credentials x5chain = make_valid_x5chain();
	const struct edhoc_auth_credentials x5t = make_valid_x5t();

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_validate_credential_verified(
				  &kid, fingerprint, ARRAY_SIZE(fingerprint)));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_validate_credential_verified(
						 &x5chain, fingerprint,
						 ARRAY_SIZE(fingerprint)));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_validate_credential_verified(
				  &x5t, fingerprint, ARRAY_SIZE(fingerprint)));
}

TEST(internals_credentials, material_kid)
{
	const uint8_t credential[10] = { 0 };
	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_KID,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER,
		.key_id.key_id_int = 5,
		.key_id.credential = credential,
		.key_id.credential_length = sizeof(credential),
	};

	struct edhoc_credential_material material = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_credential_material_from_auth(
						 &cred, &material));

	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_KID, material.label);
	TEST_ASSERT_EQUAL(EDHOC_CREDENTIAL_FORMAT_RAW, material.format);
	TEST_ASSERT_EQUAL(EDHOC_ENCODE_TYPE_INTEGER, material.kid.encode_type);
	TEST_ASSERT_EQUAL_INT32(5, material.kid.integer);
	TEST_ASSERT_EQUAL_PTR(credential, material.credential.value);
	TEST_ASSERT_EQUAL_size_t(sizeof(credential),
				 material.credential.length);
}

TEST(internals_credentials, material_x5chain_cred_is_end_entity)
{
	const uint8_t leaf[10] = { 0 };
	const uint8_t issuer[20] = { 0 };
	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_chain.certificate_count = 2,
		.x509_chain.certificate[0] = leaf,
		.x509_chain.certificate_length[0] = sizeof(leaf),
		.x509_chain.certificate[1] = issuer,
		.x509_chain.certificate_length[1] = sizeof(issuer),
	};

	struct edhoc_credential_material material = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_credential_material_from_auth(
						 &cred, &material));

	TEST_ASSERT_EQUAL_size_t(2, material.x509_chain.count);
	TEST_ASSERT_EQUAL_PTR(issuer, material.x509_chain.certificate[1].value);
	TEST_ASSERT_EQUAL_PTR(leaf, material.credential.value);
	TEST_ASSERT_EQUAL_size_t(sizeof(leaf), material.credential.length);
}

TEST(internals_credentials, material_x5t)
{
	const uint8_t certificate[30] = { 0 };
	const uint8_t x5t_fingerprint[32] = { 0 };
	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_X509_HASH,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_hash.encode_type = EDHOC_ENCODE_TYPE_INTEGER,
		.x509_hash.algorithm_int = -16,
		.x509_hash.certificate = certificate,
		.x509_hash.certificate_length = sizeof(certificate),
		.x509_hash.certificate_fingerprint = x5t_fingerprint,
		.x509_hash.certificate_fingerprint_length =
			sizeof(x5t_fingerprint),
	};

	struct edhoc_credential_material material = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_credential_material_from_auth(
						 &cred, &material));

	TEST_ASSERT_EQUAL_INT32(-16, material.x509_hash.algorithm.integer);
	TEST_ASSERT_EQUAL_PTR(x5t_fingerprint,
			      material.x509_hash.fingerprint.value);
	TEST_ASSERT_EQUAL_PTR(certificate, material.credential.value);
}

TEST(internals_credentials, material_null_args)
{
	const struct edhoc_auth_credentials cred = { 0 };
	struct edhoc_credential_material material = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_material_from_auth(NULL, &material));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_material_from_auth(&cred, NULL));
}

TEST(internals_credentials, material_unsupported_label)
{
	const struct edhoc_auth_credentials cred = {
		.label = 99,
	};

	struct edhoc_credential_material material = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED,
			  edhoc_credential_material_from_auth(&cred,
							      &material));
}

TEST(internals_credentials, material_x5t_bad_encode_type)
{
	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_X509_HASH,
		.x509_hash.encode_type = 99,
	};

	struct edhoc_credential_material material = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED,
			  edhoc_credential_material_from_auth(&cred,
							      &material));
}

TEST(internals_credentials, material_x5chain_over_capacity)
{
	const struct edhoc_auth_credentials cred = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.x509_chain.certificate_count =
			EDHOC_CREDENTIAL_X5CHAIN_CAPACITY + 1,
	};

	struct edhoc_credential_material material = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED,
			  edhoc_credential_material_from_auth(&cred,
							      &material));
}

TEST(internals_credentials, id_cred_len_kid_int)
{
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .encode_type = EDHOC_ENCODE_TYPE_INTEGER,
			 .integer = 5 },
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_id_cred_length(&material, &len));
	TEST_ASSERT_EQUAL_size_t(4, len);
}

TEST(internals_credentials, id_cred_len_kid_bstr)
{
	const uint8_t kid[1] = { 0 };
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .encode_type = EDHOC_ENCODE_TYPE_STRING,
			 .string = { .value = kid, .length = sizeof(kid) } },
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_id_cred_length(&material, &len));
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_credentials, id_cred_len_x5chain_single)
{
	const uint8_t cert[100] = { 0 };
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.x509_chain.count = 1,
		.x509_chain.certificate[0] = { .value = cert,
					       .length = sizeof(cert) },
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_id_cred_length(&material, &len));
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_credentials, id_cred_len_x5chain_multi)
{
	const uint8_t cert0[50] = { 0 };
	const uint8_t cert1[60] = { 0 };
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.x509_chain.count = 2,
		.x509_chain.certificate[0] = { .value = cert0,
					       .length = sizeof(cert0) },
		.x509_chain.certificate[1] = { .value = cert1,
					       .length = sizeof(cert1) },
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_id_cred_length(&material, &len));
	TEST_ASSERT_GREATER_THAN(sizeof(cert0) + sizeof(cert1), len);
}

TEST(internals_credentials, id_cred_len_x5t_int)
{
	const uint8_t x5t_fingerprint[32] = { 0 };
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_X509_HASH,
		.x509_hash.algorithm = { .encode_type =
						 EDHOC_ENCODE_TYPE_INTEGER,
					 .integer = -8 },
		.x509_hash.fingerprint = { .value = x5t_fingerprint,
					   .length = sizeof(x5t_fingerprint) },
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_id_cred_length(&material, &len));
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_credentials, id_cred_len_x5t_tstr)
{
	const uint8_t algorithm[2] = { 'S', 'H' };
	const uint8_t x5t_fingerprint[32] = { 0 };
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_X509_HASH,
		.x509_hash.algorithm = { .encode_type =
						 EDHOC_ENCODE_TYPE_STRING,
					 .string = { .value = algorithm,
						     .length = sizeof(
							     algorithm) } },
		.x509_hash.fingerprint = { .value = x5t_fingerprint,
					   .length = sizeof(x5t_fingerprint) },
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_id_cred_length(&material, &len));
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_credentials, id_cred_len_unsupported)
{
	const struct edhoc_credential_material material = {
		.label = 99,
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED,
			  edhoc_credential_id_cred_length(&material, &len));
}

TEST(internals_credentials, id_cred_len_null_args)
{
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_KID,
	};
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_id_cred_length(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_id_cred_length(&material, NULL));
}

TEST(internals_credentials, cred_len_follows_credential)
{
	const uint8_t credential[100] = { 0 };
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_KID,
		.credential = { .value = credential,
				.length = sizeof(credential) },
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_cred_length(&material, &len));
	TEST_ASSERT_GREATER_THAN(sizeof(credential), len);
}

TEST(internals_credentials, cred_len_unsupported)
{
	const struct edhoc_credential_material material = {
		.label = 99,
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED,
			  edhoc_credential_cred_length(&material, &len));
}

TEST(internals_credentials, cred_len_null_args)
{
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_KID,
	};
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_cred_length(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_cred_length(&material, NULL));
}

TEST(internals_credentials, compact_kid_int)
{
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .encode_type = EDHOC_ENCODE_TYPE_INTEGER,
			 .integer = 7 },
	};

	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_encode_id_cred_compact(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(1, len);
	TEST_ASSERT_EQUAL_HEX8(0x07, buffer[0]);
}

TEST(internals_credentials, compact_kid_int_multi_byte)
{
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .encode_type = EDHOC_ENCODE_TYPE_INTEGER,
			 .integer = 100 },
	};

	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_encode_id_cred_compact(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(2, len);
	TEST_ASSERT_EQUAL_HEX8(0x18, buffer[0]);
	TEST_ASSERT_EQUAL_HEX8(0x64, buffer[1]);
}

TEST(internals_credentials, compact_kid_bstr_takes_the_short_form)
{
	/* RFC 9529: 3 uses ID_CRED_I = { 4 : h'2b' }, whose compact form is the
	 * CBOR integer -12, i.e. the same byte. */
	const uint8_t kid[1] = { 0x2b };
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .encode_type = EDHOC_ENCODE_TYPE_STRING,
			 .string = { .value = kid, .length = sizeof(kid) } },
	};

	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_encode_id_cred_compact(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(1, len);
	TEST_ASSERT_EQUAL_HEX8(0x2b, buffer[0]);
}

TEST(internals_credentials, compact_kid_bstr_outside_the_short_form)
{
	/* One byte, but 0x40 is not a CBOR integer on its own, so the short
	 * form does not apply and the identifier stays a byte string. */
	const uint8_t kid[1] = { 0x40 };
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .encode_type = EDHOC_ENCODE_TYPE_STRING,
			 .string = { .value = kid, .length = sizeof(kid) } },
	};

	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_encode_id_cred_compact(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(2, len);
	TEST_ASSERT_EQUAL_HEX8(0x41, buffer[0]);
	TEST_ASSERT_EQUAL_HEX8(0x40, buffer[1]);
}

TEST(internals_credentials, compact_kid_bstr_multi_byte)
{
	const uint8_t kid[2] = { 0xaa, 0xbb };
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .encode_type = EDHOC_ENCODE_TYPE_STRING,
			 .string = { .value = kid, .length = sizeof(kid) } },
	};

	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_encode_id_cred_compact(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(3, len);
	TEST_ASSERT_EQUAL_HEX8(0x42, buffer[0]);
	TEST_ASSERT_EQUAL_HEX8_ARRAY(kid, &buffer[1], sizeof(kid));
}

TEST(internals_credentials, compact_kid_bstr_empty)
{
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .encode_type = EDHOC_ENCODE_TYPE_STRING },
	};

	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_encode_id_cred_compact(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	/* An empty byte string is one CBOR byte: 0x40. */
	TEST_ASSERT_EQUAL_size_t(1, len);
	TEST_ASSERT_EQUAL_HEX8(0x40, buffer[0]);
}

TEST(internals_credentials, compact_kid_bstr_buffer_too_small)
{
	const uint8_t kid[4] = { 0 };
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .encode_type = EDHOC_ENCODE_TYPE_STRING,
			 .string = { .value = kid, .length = sizeof(kid) } },
	};

	uint8_t buffer[2] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE,
			  edhoc_credential_encode_id_cred_compact(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
}

TEST(internals_credentials, compact_kid_invalid_encode_type)
{
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .encode_type = 99 },
	};

	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED,
			  edhoc_credential_encode_id_cred_compact(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
}

TEST(internals_credentials, compact_absent_for_x509)
{
	const uint8_t cert[10] = { 0 };
	const struct edhoc_credential_material material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_chain.count = 1,
		.x509_chain.certificate[0] = { .value = cert,
					       .length = sizeof(cert) },
	};

	uint8_t buffer[8] = { 0 };
	size_t len = SIZE_MAX;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_encode_id_cred_compact(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(0, len);
}

TEST_GROUP_RUNNER(internals_credentials)
{
	RUN_TEST_CASE(internals_credentials, kid_int);
	RUN_TEST_CASE(internals_credentials, kid_bstr_within_capacity);
	RUN_TEST_CASE(internals_credentials, kid_bstr_at_capacity);
	RUN_TEST_CASE(internals_credentials, kid_bstr_over_capacity);
	RUN_TEST_CASE(internals_credentials, kid_bstr_64_rejected);
	RUN_TEST_CASE(internals_credentials, kid_bstr_255_rejected);

	/* COSE header map without a usable header parameter. */
	RUN_TEST_CASE(internals_credentials, map_kid_rejected);
	RUN_TEST_CASE(internals_credentials, map_empty_rejected);
	RUN_TEST_CASE(internals_credentials, map_two_labels_rejected);

	/* x5chain: byte string and array forms, and the chain capacity. */
	RUN_TEST_CASE(internals_credentials, x5chain_single_certificate);
	RUN_TEST_CASE(internals_credentials, x5chain_two_certificates);
	RUN_TEST_CASE(internals_credentials, x5chain_three_certificates);

	/* x5t: hash algorithm forms and the fingerprint bound. */
	RUN_TEST_CASE(internals_credentials, x5t_algorithm_int);
	RUN_TEST_CASE(internals_credentials, x5t_algorithm_tstr);
	RUN_TEST_CASE(internals_credentials,
		      x5t_algorithm_tstr_over_capacity_rejected);
	RUN_TEST_CASE(internals_credentials,
		      x5t_fingerprint_over_limit_rejected);

	/* message_2 reaches the same decoder as message_3. */
	RUN_TEST_CASE(internals_credentials, msg2_kid_int);
	RUN_TEST_CASE(internals_credentials, msg2_kid_bstr_255_rejected);
	RUN_TEST_CASE(internals_credentials, msg2_map_kid_rejected);
	RUN_TEST_CASE(internals_credentials, msg2_x5chain_single_certificate);

	/* Validation of the credentials returned from fetch. */
	RUN_TEST_CASE(internals_credentials, validate_fetched_null);
	RUN_TEST_CASE(internals_credentials, validate_fetched_unknown_label);
	RUN_TEST_CASE(internals_credentials,
		      validate_fetched_accepts_each_variant);
	RUN_TEST_CASE(internals_credentials,
		      validate_fetched_kid_without_credential);
	RUN_TEST_CASE(internals_credentials,
		      validate_fetched_kid_bad_encode_type);
	RUN_TEST_CASE(internals_credentials, validate_fetched_kid_format_unset);
	RUN_TEST_CASE(internals_credentials, validate_fetched_kid_bad_format);
	RUN_TEST_CASE(internals_credentials, validate_fetched_kid_cbor_encoded);
	RUN_TEST_CASE(internals_credentials,
		      validate_fetched_x5chain_cbor_encoded_rejected);
	RUN_TEST_CASE(internals_credentials,
		      validate_fetched_x5t_cbor_encoded_rejected);
	RUN_TEST_CASE(internals_credentials,
		      validate_fetched_x5chain_format_unset);
	RUN_TEST_CASE(internals_credentials,
		      validate_verified_kid_format_unset);
	RUN_TEST_CASE(internals_credentials,
		      validate_verified_x5t_cbor_encoded_rejected);
	RUN_TEST_CASE(internals_credentials,
		      validate_fetched_kid_over_capacity);
	RUN_TEST_CASE(internals_credentials, validate_fetched_x5chain_empty);
	RUN_TEST_CASE(internals_credentials,
		      validate_fetched_x5chain_over_capacity);
	RUN_TEST_CASE(internals_credentials,
		      validate_fetched_x5chain_null_certificate);
	RUN_TEST_CASE(internals_credentials,
		      validate_fetched_x5t_without_fingerprint);
	RUN_TEST_CASE(internals_credentials,
		      validate_fetched_x5t_fingerprint_over_limit);
	RUN_TEST_CASE(internals_credentials,
		      validate_fetched_x5t_bad_encode_type);

	/* Validation of the credentials returned from verify. */
	RUN_TEST_CASE(internals_credentials, validate_verified_null);
	RUN_TEST_CASE(internals_credentials,
		      validate_verified_without_public_key);
	RUN_TEST_CASE(internals_credentials,
		      validate_verified_kid_without_credential);
	RUN_TEST_CASE(internals_credentials,
		      validate_verified_x5t_without_certificate);
	RUN_TEST_CASE(internals_credentials,
		      validate_verified_accepts_each_variant);

	/* Encoder input. */
	RUN_TEST_CASE(internals_credentials, material_kid);
	RUN_TEST_CASE(internals_credentials,
		      material_x5chain_cred_is_end_entity);
	RUN_TEST_CASE(internals_credentials, material_x5t);
	RUN_TEST_CASE(internals_credentials, material_null_args);
	RUN_TEST_CASE(internals_credentials, material_unsupported_label);
	RUN_TEST_CASE(internals_credentials, material_x5t_bad_encode_type);
	RUN_TEST_CASE(internals_credentials, material_x5chain_over_capacity);

	/* ID_CRED_x and CRED_x lengths. */
	RUN_TEST_CASE(internals_credentials, id_cred_len_kid_int);
	RUN_TEST_CASE(internals_credentials, id_cred_len_kid_bstr);
	RUN_TEST_CASE(internals_credentials, id_cred_len_x5chain_single);
	RUN_TEST_CASE(internals_credentials, id_cred_len_x5chain_multi);
	RUN_TEST_CASE(internals_credentials, id_cred_len_x5t_int);
	RUN_TEST_CASE(internals_credentials, id_cred_len_x5t_tstr);
	RUN_TEST_CASE(internals_credentials, id_cred_len_unsupported);
	RUN_TEST_CASE(internals_credentials, id_cred_len_null_args);
	RUN_TEST_CASE(internals_credentials, cred_len_follows_credential);
	RUN_TEST_CASE(internals_credentials, cred_len_unsupported);
	RUN_TEST_CASE(internals_credentials, cred_len_null_args);

	/* Compact ID_CRED_x. */
	RUN_TEST_CASE(internals_credentials, compact_kid_int);
	RUN_TEST_CASE(internals_credentials, compact_kid_int_multi_byte);
	RUN_TEST_CASE(internals_credentials,
		      compact_kid_bstr_takes_the_short_form);
	RUN_TEST_CASE(internals_credentials,
		      compact_kid_bstr_outside_the_short_form);
	RUN_TEST_CASE(internals_credentials, compact_kid_bstr_multi_byte);
	RUN_TEST_CASE(internals_credentials, compact_kid_bstr_empty);
	RUN_TEST_CASE(internals_credentials, compact_kid_bstr_buffer_too_small);
	RUN_TEST_CASE(internals_credentials, compact_kid_invalid_encode_type);
	RUN_TEST_CASE(internals_credentials, compact_absent_for_x509);
}
