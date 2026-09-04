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

/** \brief One key identifier and the ID_CRED_x it compacts to. */
struct compact_kid_case {
	/** Key identifier, as the application supplies it. */
	struct edhoc_buffer kid;
	/** Expected compact encoding. */
	uint8_t expected[3];
	/** Number of valid bytes in \p expected. */
	size_t expected_length;
};

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
static struct edhoc_credential_selected make_valid_kid(void);

/** \brief Build a single certificate chain that passes validation. */
static struct edhoc_credential_selected make_valid_x5chain(void);

/** \brief Build a certificate fingerprint credential that passes validation. */
static struct edhoc_credential_selected make_valid_x5t(void);

/**
 * \brief Build peer identification for \p label. The payload stays empty:
 *        \ref edhoc_credential_validate_trusted only reads the label.
 */
static struct edhoc_credential_received
make_received(enum edhoc_cose_header label);

/** \brief Build a credential by reference that passes validation. */
static struct edhoc_credential_trusted make_valid_trusted(void);

/** \brief Build a method 4 credential every field of which passes validation. */
static struct edhoc_credential_selected psk_selected_ok(void);

/** \brief Build the peer counterpart of \ref psk_selected_ok. */
static struct edhoc_credential_trusted psk_trusted_ok(void);

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

/* Key identifiers from the examples in RFC 9528: 3.3.2, plus both ends of the
 * one byte CBOR integer range. */
static const uint8_t compact_kid_21[] = { 0x21 };
static const uint8_t compact_kid_0d[] = { 0x0d };
static const uint8_t compact_kid_18[] = { 0x18 };
static const uint8_t compact_kid_38[] = { 0x38 };
static const uint8_t compact_kid_abcd[] = { 0xab, 0xcd };
static const uint8_t compact_kid_00[] = { 0x00 };
static const uint8_t compact_kid_17[] = { 0x17 };
static const uint8_t compact_kid_37[] = { 0x37 };

static const struct compact_kid_case compact_kid_cases[] = {
	{
		.kid = { .value = compact_kid_21,
			 .length = ARRAY_SIZE(compact_kid_21) },
		.expected = { 0x21 },
		.expected_length = 1,
	},
	{
		.kid = { .value = compact_kid_0d,
			 .length = ARRAY_SIZE(compact_kid_0d) },
		.expected = { 0x0d },
		.expected_length = 1,
	},
	{
		.kid = { .value = compact_kid_18,
			 .length = ARRAY_SIZE(compact_kid_18) },
		.expected = { 0x41, 0x18 },
		.expected_length = 2,
	},
	{
		.kid = { .value = compact_kid_38,
			 .length = ARRAY_SIZE(compact_kid_38) },
		.expected = { 0x41, 0x38 },
		.expected_length = 2,
	},
	{
		.kid = { .value = compact_kid_abcd,
			 .length = ARRAY_SIZE(compact_kid_abcd) },
		.expected = { 0x42, 0xab, 0xcd },
		.expected_length = 3,
	},
	{
		.kid = { .value = compact_kid_00,
			 .length = ARRAY_SIZE(compact_kid_00) },
		.expected = { 0x00 },
		.expected_length = 1,
	},
	{
		.kid = { .value = compact_kid_17,
			 .length = ARRAY_SIZE(compact_kid_17) },
		.expected = { 0x17 },
		.expected_length = 1,
	},
	{
		.kid = { .value = compact_kid_37,
			 .length = ARRAY_SIZE(compact_kid_37) },
		.expected = { 0x37 },
		.expected_length = 1,
	},
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

	return edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_CLASSIC_2, ptxt,
				     ptxt_len, parsed);
}

static int parse_ptxt_3(const uint8_t *ptxt, size_t ptxt_len,
			struct plaintext *parsed)
{
	struct edhoc_context ctx = { 0 };

	return edhoc_plaintext_parse(&ctx, EDHOC_PLAINTEXT_CLASSIC_3, ptxt,
				     ptxt_len, parsed);
}

static void assert_sign_or_mac(const struct plaintext *parsed,
			       const uint8_t *expected)
{
	TEST_ASSERT_EQUAL_size_t(ARRAY_SIZE(sign_or_mac),
				 parsed->sign_or_mac.length);
	TEST_ASSERT_EQUAL_PTR(expected, parsed->sign_or_mac.value);
	TEST_ASSERT_EQUAL_MEMORY(sign_or_mac, parsed->sign_or_mac.value,
				 ARRAY_SIZE(sign_or_mac));
}

static void assert_untouched(const struct plaintext *parsed)
{
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_NONE,
			  parsed->peer_credential_id.label);
	TEST_ASSERT_EQUAL_HEX8(0, parsed->kid_byte);
	TEST_ASSERT_NULL(parsed->sign_or_mac.value);
	TEST_ASSERT_EQUAL_size_t(0, parsed->sign_or_mac.length);
	TEST_ASSERT_NULL(parsed->ead.value);
	TEST_ASSERT_EQUAL_size_t(0, parsed->ead.length);
}

static struct edhoc_credential_selected make_valid_kid(void)
{
	static const uint8_t identifier[] = { 0x2b };

	return (struct edhoc_credential_selected){
		.asymmetric = {
			.label = EDHOC_COSE_HEADER_KID,
			.kid = {
				.identifier = { .value = identifier,
						.length = ARRAY_SIZE(identifier) },
				.credential = { .value = first_certificate,
						.length = ARRAY_SIZE(first_certificate) },
				.format = EDHOC_CREDENTIAL_FORMAT_RAW,
			},
		},
	};
}

static struct edhoc_credential_selected make_valid_x5chain(void)
{
	return (struct edhoc_credential_selected){
		.asymmetric = {
			.label = EDHOC_COSE_HEADER_X509_CHAIN,
			.x509_chain = {
				.count = 1,
				.certificate = { { .value = first_certificate,
						   .length = ARRAY_SIZE(
							   first_certificate) } },
			},
		},
	};
}

static struct edhoc_credential_selected make_valid_x5t(void)
{
	return (struct edhoc_credential_selected){
		.asymmetric = {
			.label = EDHOC_COSE_HEADER_X509_HASH,
			.x509_hash = {
				.algorithm = { .encode_type = EDHOC_ENCODE_TYPE_INTEGER,
					       .integer = -15 },
				.fingerprint = { .value = fingerprint,
						 .length = ARRAY_SIZE(fingerprint) },
				.certificate = { .value = first_certificate,
						 .length = ARRAY_SIZE(
							 first_certificate) },
			},
		},
	};
}

static struct edhoc_credential_received
make_received(enum edhoc_cose_header label)
{
	return (struct edhoc_credential_received){
		.label = label,
	};
}

static struct edhoc_credential_trusted make_valid_trusted(void)
{
	return (struct edhoc_credential_trusted){
		.asymmetric = {
			.credential = { .value = first_certificate,
					.length = ARRAY_SIZE(first_certificate) },
			.format = EDHOC_CREDENTIAL_FORMAT_RAW,
			.public_key = { .value = fingerprint,
					.length = ARRAY_SIZE(fingerprint) },
		},
	};
}

static struct edhoc_credential_selected psk_selected_ok(void)
{
	static const uint8_t kid[] = { 0x00, 0x10 };
	static const uint8_t cred_i[] = { 0xa1, 0x02, 0x41, 0x49 };
	static const uint8_t cred_r[] = { 0xa1, 0x02, 0x41, 0x52 };

	struct edhoc_credential_selected selected = { 0 };

	selected.psk.label = EDHOC_COSE_HEADER_KID;
	selected.psk.kid.identifier.value = kid;
	selected.psk.kid.identifier.length = ARRAY_SIZE(kid);
	selected.psk.cred_i.value = cred_i;
	selected.psk.cred_i.length = ARRAY_SIZE(cred_i);
	selected.psk.cred_r.value = cred_r;
	selected.psk.cred_r.length = ARRAY_SIZE(cred_r);
	selected.psk.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;

	return selected;
}

static struct edhoc_credential_trusted psk_trusted_ok(void)
{
	static const uint8_t cred_i[] = { 0xa1, 0x02, 0x41, 0x49 };
	static const uint8_t cred_r[] = { 0xa1, 0x02, 0x41, 0x52 };

	struct edhoc_credential_trusted trusted = { 0 };

	trusted.psk.cred_i.value = cred_i;
	trusted.psk.cred_i.length = ARRAY_SIZE(cred_i);
	trusted.psk.cred_r.value = cred_r;
	trusted.psk.cred_r.length = ARRAY_SIZE(cred_r);
	trusted.psk.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;

	return trusted;
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
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_KID,
			  parsed.peer_credential_id.label);
	/* RFC 9528: 3.3.2 - the integer -12 stands for the byte string h'2B'. */
	TEST_ASSERT_EQUAL_size_t(
		1, parsed.peer_credential_id.kid.identifier.length);
	TEST_ASSERT_EQUAL_HEX8(
		0x2b, parsed.peer_credential_id.kid.identifier.value[0]);
	assert_sign_or_mac(&parsed, &ptxt_3_kid_int[2]);
}

TEST(internals_credentials, kid_bstr_within_capacity)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_kid_bstr,
				     ARRAY_SIZE(ptxt_3_kid_bstr), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_KID,
			  parsed.peer_credential_id.label);
	TEST_ASSERT_EQUAL_size_t(
		1, parsed.peer_credential_id.kid.identifier.length);
	TEST_ASSERT_EQUAL_PTR(&ptxt_3_kid_bstr[1],
			      parsed.peer_credential_id.kid.identifier.value);
	assert_sign_or_mac(&parsed, &ptxt_3_kid_bstr[3]);
}

TEST(internals_credentials, kid_bstr_at_capacity)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_kid_bstr_32,
				     ARRAY_SIZE(ptxt_3_kid_bstr_32), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_KID,
			  parsed.peer_credential_id.label);
	TEST_ASSERT_EQUAL_size_t(
		EDHOC_CREDENTIAL_KID_MAX_LEN,
		parsed.peer_credential_id.kid.identifier.length);
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
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_X509_CHAIN,
			  parsed.peer_credential_id.label);
	TEST_ASSERT_EQUAL_size_t(1, parsed.peer_credential_id.x509_chain.count);
	TEST_ASSERT_EQUAL_size_t(
		ARRAY_SIZE(first_certificate),
		parsed.peer_credential_id.x509_chain.certificate[0].length);
	TEST_ASSERT_EQUAL_PTR(
		&ptxt_3_x5chain_one[4],
		parsed.peer_credential_id.x509_chain.certificate[0].value);
	TEST_ASSERT_EQUAL_MEMORY(
		first_certificate,
		parsed.peer_credential_id.x509_chain.certificate[0].value,
		ARRAY_SIZE(first_certificate));
	assert_sign_or_mac(&parsed, &ptxt_3_x5chain_one[8]);
}

TEST(internals_credentials, x5chain_two_certificates)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_x5chain_two,
				     ARRAY_SIZE(ptxt_3_x5chain_two), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_X509_CHAIN,
			  parsed.peer_credential_id.label);
	TEST_ASSERT_EQUAL_size_t(2, parsed.peer_credential_id.x509_chain.count);
	TEST_ASSERT_EQUAL_size_t(
		3, parsed.peer_credential_id.x509_chain.certificate[0].length);
	TEST_ASSERT_EQUAL_size_t(
		3, parsed.peer_credential_id.x509_chain.certificate[1].length);
	TEST_ASSERT_EQUAL_PTR(
		&ptxt_3_x5chain_two[5],
		parsed.peer_credential_id.x509_chain.certificate[0].value);
	TEST_ASSERT_EQUAL_PTR(
		&ptxt_3_x5chain_two[9],
		parsed.peer_credential_id.x509_chain.certificate[1].value);
	assert_sign_or_mac(&parsed, &ptxt_3_x5chain_two[13]);
}

TEST(internals_credentials, x5chain_three_certificates)
{
	/* Three is the largest chain the CBOR model admits, so this vector only
	 * fits a build configured for the maximum. The rejection path is
	 * covered by validate_selected_x5chain_over_capacity. */
	if (EDHOC_CREDENTIAL_X5CHAIN_CAPACITY < 3) {
		TEST_IGNORE_MESSAGE("chain capacity below three certificates");
	}

	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_x5chain_three,
				     ARRAY_SIZE(ptxt_3_x5chain_three), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_X509_CHAIN,
			  parsed.peer_credential_id.label);
	TEST_ASSERT_EQUAL_size_t(3, parsed.peer_credential_id.x509_chain.count);
	TEST_ASSERT_EQUAL_PTR(
		&ptxt_3_x5chain_three[13],
		parsed.peer_credential_id.x509_chain.certificate[2].value);
	assert_sign_or_mac(&parsed, &ptxt_3_x5chain_three[17]);
}

TEST(internals_credentials, x5t_algorithm_int)
{
	struct plaintext parsed = { 0 };

	const int ret = parse_ptxt_3(ptxt_3_x5t_alg_int,
				     ARRAY_SIZE(ptxt_3_x5t_alg_int), &parsed);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_X509_HASH,
			  parsed.peer_credential_id.label);
	TEST_ASSERT_EQUAL(
		EDHOC_ENCODE_TYPE_INTEGER,
		parsed.peer_credential_id.x509_hash.algorithm.encode_type);
	TEST_ASSERT_EQUAL_INT32(
		-15, parsed.peer_credential_id.x509_hash.algorithm.integer);
	TEST_ASSERT_EQUAL_size_t(
		ARRAY_SIZE(fingerprint),
		parsed.peer_credential_id.x509_hash.fingerprint.length);
	TEST_ASSERT_EQUAL_PTR(
		&ptxt_3_x5t_alg_int[6],
		parsed.peer_credential_id.x509_hash.fingerprint.value);
	TEST_ASSERT_EQUAL_MEMORY(
		fingerprint,
		parsed.peer_credential_id.x509_hash.fingerprint.value,
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
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_X509_HASH,
			  parsed.peer_credential_id.label);
	TEST_ASSERT_EQUAL(
		EDHOC_ENCODE_TYPE_STRING,
		parsed.peer_credential_id.x509_hash.algorithm.encode_type);
	TEST_ASSERT_EQUAL_size_t(
		ARRAY_SIZE(sha),
		parsed.peer_credential_id.x509_hash.algorithm.string.length);
	TEST_ASSERT_EQUAL_MEMORY(
		sha, parsed.peer_credential_id.x509_hash.algorithm.string.value,
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
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_KID,
			  parsed.peer_credential_id.label);
	TEST_ASSERT_EQUAL_size_t(
		1, parsed.peer_credential_id.kid.identifier.length);
	TEST_ASSERT_EQUAL_HEX8(
		0x2b, parsed.peer_credential_id.kid.identifier.value[0]);
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
	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_X509_CHAIN,
			  parsed.peer_credential_id.label);
	TEST_ASSERT_EQUAL_size_t(1, parsed.peer_credential_id.x509_chain.count);
	TEST_ASSERT_EQUAL_PTR(
		&ptxt_2_x5chain_one[5],
		parsed.peer_credential_id.x509_chain.certificate[0].value);
	TEST_ASSERT_EQUAL_MEMORY(
		first_certificate,
		parsed.peer_credential_id.x509_chain.certificate[0].value,
		ARRAY_SIZE(first_certificate));
	assert_sign_or_mac(&parsed, &ptxt_2_x5chain_one[9]);
}

TEST(internals_credentials, validate_selected_null)
{
	const int ret =
		edhoc_credential_validate_selected(EDHOC_METHOD_0, NULL);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT, ret);
}

TEST(internals_credentials, validate_selected_unknown_label)
{
	const struct edhoc_credential_selected credentials = {
		.asymmetric.label = (enum edhoc_cose_header)99,
	};

	const int ret = edhoc_credential_validate_selected(EDHOC_METHOD_0,
							   &credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);
}

TEST(internals_credentials, validate_selected_accepts_each_variant)
{
	const struct edhoc_credential_selected kid = make_valid_kid();
	const struct edhoc_credential_selected x5chain = make_valid_x5chain();
	const struct edhoc_credential_selected x5t = make_valid_x5t();

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_credential_validate_selected(
						 EDHOC_METHOD_0, &kid));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_credential_validate_selected(
						 EDHOC_METHOD_0, &x5chain));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_credential_validate_selected(
						 EDHOC_METHOD_0, &x5t));
}

TEST(internals_credentials, validate_selected_kid_without_credential)
{
	struct edhoc_credential_selected credentials = make_valid_kid();

	credentials.asymmetric.kid.credential.value = NULL;

	const int ret = edhoc_credential_validate_selected(EDHOC_METHOD_0,
							   &credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE, ret);
}

TEST(internals_credentials, validate_selected_kid_without_buffer)
{
	struct edhoc_credential_selected credentials = make_valid_kid();

	/* An empty identifier is legal, a length without a buffer is not. */
	credentials.asymmetric.kid.identifier.value = NULL;
	credentials.asymmetric.kid.identifier.length = 1;

	const int ret = edhoc_credential_validate_selected(EDHOC_METHOD_0,
							   &credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE, ret);
}

TEST(internals_credentials, validate_selected_kid_format_unset)
{
	struct edhoc_credential_selected credentials = make_valid_kid();

	credentials.asymmetric.kid.format = EDHOC_CREDENTIAL_FORMAT_NONE;

	const int ret = edhoc_credential_validate_selected(EDHOC_METHOD_0,
							   &credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_selected_kid_bad_format)
{
	struct edhoc_credential_selected credentials = make_valid_kid();

	credentials.asymmetric.kid.format = (enum edhoc_credential_format)7;

	const int ret = edhoc_credential_validate_selected(EDHOC_METHOD_0,
							   &credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_trusted_kid_format_unset)
{
	const struct edhoc_credential_received received =
		make_received(EDHOC_COSE_HEADER_KID);
	struct edhoc_credential_trusted trusted = make_valid_trusted();

	trusted.asymmetric.format = EDHOC_CREDENTIAL_FORMAT_NONE;

	const int ret = edhoc_credential_validate_trusted(EDHOC_METHOD_0,
							  &received, &trusted);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_selected_kid_cbor_encoded)
{
	struct edhoc_credential_selected credentials = make_valid_kid();

	/* The format describes CRED, which for 'kid' may be a CCS or a CWT. */
	credentials.asymmetric.kid.format =
		EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;

	const int ret = edhoc_credential_validate_selected(EDHOC_METHOD_0,
							   &credentials);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, ret);
}

TEST(internals_credentials, validate_trusted_x5t_cbor_encoded_rejected)
{
	const struct edhoc_credential_received received =
		make_received(EDHOC_COSE_HEADER_X509_HASH);
	struct edhoc_credential_trusted trusted = make_valid_trusted();

	trusted.asymmetric.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;

	const int ret = edhoc_credential_validate_trusted(EDHOC_METHOD_0,
							  &received, &trusted);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_selected_kid_over_capacity)
{
	struct edhoc_credential_selected credentials = make_valid_kid();

	credentials.asymmetric.kid.identifier.length =
		EDHOC_CREDENTIAL_KID_MAX_LEN + 1;

	const int ret = edhoc_credential_validate_selected(EDHOC_METHOD_0,
							   &credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(internals_credentials, validate_selected_x5chain_empty)
{
	struct edhoc_credential_selected credentials = make_valid_x5chain();

	credentials.asymmetric.x509_chain.count = 0;

	const int ret = edhoc_credential_validate_selected(EDHOC_METHOD_0,
							   &credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(internals_credentials, validate_selected_x5chain_over_capacity)
{
	struct edhoc_credential_selected credentials = make_valid_x5chain();

	credentials.asymmetric.x509_chain.count =
		EDHOC_CREDENTIAL_X5CHAIN_CAPACITY + 1;

	const int ret = edhoc_credential_validate_selected(EDHOC_METHOD_0,
							   &credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL, ret);
}

TEST(internals_credentials, validate_selected_x5chain_null_certificate)
{
	struct edhoc_credential_selected credentials = make_valid_x5chain();

	credentials.asymmetric.x509_chain.certificate[0].value = NULL;

	const int ret = edhoc_credential_validate_selected(EDHOC_METHOD_0,
							   &credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE, ret);
}

TEST(internals_credentials, validate_selected_x5t_without_fingerprint)
{
	struct edhoc_credential_selected credentials = make_valid_x5t();

	credentials.asymmetric.x509_hash.fingerprint.length = 0;

	const int ret = edhoc_credential_validate_selected(EDHOC_METHOD_0,
							   &credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE, ret);
}

TEST(internals_credentials, validate_selected_x5t_fingerprint_over_limit)
{
	struct edhoc_credential_selected credentials = make_valid_x5t();

	credentials.asymmetric.x509_hash.fingerprint.length =
		EDHOC_CREDENTIAL_X5T_FINGERPRINT_MAX_LEN + 1;

	const int ret = edhoc_credential_validate_selected(EDHOC_METHOD_0,
							   &credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_selected_x5t_bad_encode_type)
{
	struct edhoc_credential_selected credentials = make_valid_x5t();

	credentials.asymmetric.x509_hash.algorithm.encode_type =
		(enum edhoc_encode_type)7;

	const int ret = edhoc_credential_validate_selected(EDHOC_METHOD_0,
							   &credentials);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_trusted_null)
{
	const struct edhoc_credential_received received =
		make_received(EDHOC_COSE_HEADER_KID);
	const struct edhoc_credential_trusted trusted = make_valid_trusted();

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_validate_trusted(EDHOC_METHOD_0,
							    NULL, &trusted));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_validate_trusted(EDHOC_METHOD_0,
							    &received, NULL));
}

TEST(internals_credentials, validate_trusted_without_public_key)
{
	const struct edhoc_credential_received received =
		make_received(EDHOC_COSE_HEADER_KID);
	struct edhoc_credential_trusted trusted = make_valid_trusted();

	trusted.asymmetric.public_key = (struct edhoc_buffer){ 0 };

	const int ret = edhoc_credential_validate_trusted(EDHOC_METHOD_0,
							  &received, &trusted);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE, ret);
}

TEST(internals_credentials, validate_trusted_kid_without_credential)
{
	const struct edhoc_credential_received received =
		make_received(EDHOC_COSE_HEADER_KID);
	struct edhoc_credential_trusted trusted = make_valid_trusted();

	trusted.asymmetric.credential.length = 0;

	const int ret = edhoc_credential_validate_trusted(EDHOC_METHOD_0,
							  &received, &trusted);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE, ret);
}

TEST(internals_credentials, validate_trusted_x5t_without_certificate)
{
	const struct edhoc_credential_received received =
		make_received(EDHOC_COSE_HEADER_X509_HASH);
	struct edhoc_credential_trusted trusted = make_valid_trusted();

	trusted.asymmetric.credential.value = NULL;

	const int ret = edhoc_credential_validate_trusted(EDHOC_METHOD_0,
							  &received, &trusted);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE, ret);
}

TEST(internals_credentials, validate_trusted_unsupported_label)
{
	const struct edhoc_credential_received received =
		make_received(EDHOC_COSE_HEADER_NONE);
	const struct edhoc_credential_trusted trusted = make_valid_trusted();

	const int ret = edhoc_credential_validate_trusted(EDHOC_METHOD_0,
							  &received, &trusted);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED, ret);
}

TEST(internals_credentials, validate_trusted_x5chain_without_credential)
{
	const struct edhoc_credential_received received =
		make_received(EDHOC_COSE_HEADER_X509_CHAIN);
	struct edhoc_credential_trusted trusted = make_valid_trusted();

	/* The same requirement as for the other methods: CRED is mandatory,
	 * here the received end-entity certificate handed straight back. */
	trusted.asymmetric.credential = (struct edhoc_buffer){ 0 };

	const int ret = edhoc_credential_validate_trusted(EDHOC_METHOD_0,
							  &received, &trusted);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE, ret);
}

TEST(internals_credentials, validate_trusted_x5chain_cbor_encoded_rejected)
{
	const struct edhoc_credential_received received =
		make_received(EDHOC_COSE_HEADER_X509_CHAIN);
	struct edhoc_credential_trusted trusted = make_valid_trusted();

	trusted.asymmetric.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;

	const int ret = edhoc_credential_validate_trusted(EDHOC_METHOD_0,
							  &received, &trusted);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED, ret);
}

TEST(internals_credentials, validate_trusted_accepts_each_variant)
{
	const struct edhoc_credential_received kid =
		make_received(EDHOC_COSE_HEADER_KID);
	const struct edhoc_credential_received x5chain =
		make_received(EDHOC_COSE_HEADER_X509_CHAIN);
	const struct edhoc_credential_received x5t =
		make_received(EDHOC_COSE_HEADER_X509_HASH);

	const struct edhoc_credential_trusted trusted = make_valid_trusted();

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_validate_trusted(EDHOC_METHOD_0,
							    &kid, &trusted));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_validate_trusted(
				  EDHOC_METHOD_0, &x5chain, &trusted));
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_validate_trusted(EDHOC_METHOD_0,
							    &x5t, &trusted));
}

TEST(internals_credentials, material_kid)
{
	static const uint8_t identifier[] = { 0x05 };
	const uint8_t credential[10] = { 0 };
	const struct edhoc_credential_selected cred = {
		.asymmetric.label = EDHOC_COSE_HEADER_KID,
		.asymmetric.kid.identifier = { .value = identifier,
					       .length =
						       ARRAY_SIZE(identifier) },
		.asymmetric.kid.credential = { .value = credential,
					       .length =
						       ARRAY_SIZE(credential) },
		.asymmetric.kid.format = EDHOC_CREDENTIAL_FORMAT_RAW,
	};

	struct edhoc_credential_material_asymmetric material = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_material_from_selected(
				  &cred, &material));

	TEST_ASSERT_EQUAL(EDHOC_COSE_HEADER_KID, material.label);
	TEST_ASSERT_EQUAL(EDHOC_CREDENTIAL_FORMAT_RAW, material.format);
	TEST_ASSERT_EQUAL_PTR(identifier, material.kid.value);
	TEST_ASSERT_EQUAL_size_t(ARRAY_SIZE(identifier), material.kid.length);
	TEST_ASSERT_EQUAL_PTR(credential, material.credential.value);
	TEST_ASSERT_EQUAL_size_t(sizeof(credential),
				 material.credential.length);
}

TEST(internals_credentials, material_x5chain_cred_is_end_entity)
{
	const uint8_t leaf[10] = { 0 };
	const uint8_t issuer[20] = { 0 };
	const struct edhoc_credential_selected cred = {
		.asymmetric.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.asymmetric.x509_chain.count = 2,
		.asymmetric.x509_chain.certificate[0] = { .value = leaf,
							  .length = ARRAY_SIZE(
								  leaf) },
		.asymmetric.x509_chain.certificate[1] = { .value = issuer,
							  .length = ARRAY_SIZE(
								  issuer) },
	};

	struct edhoc_credential_material_asymmetric material = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_material_from_selected(
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
	const struct edhoc_credential_selected cred = {
		.asymmetric.label = EDHOC_COSE_HEADER_X509_HASH,
		.asymmetric.x509_hash
			.algorithm = { .encode_type = EDHOC_ENCODE_TYPE_INTEGER,
				       .integer = -16 },
		.asymmetric.x509_hash.fingerprint = { .value = x5t_fingerprint,
						      .length = ARRAY_SIZE(
							      x5t_fingerprint) },
		.asymmetric.x509_hash.certificate = { .value = certificate,
						      .length = ARRAY_SIZE(
							      certificate) },
	};

	struct edhoc_credential_material_asymmetric material = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_material_from_selected(
				  &cred, &material));

	TEST_ASSERT_EQUAL_INT32(-16, material.x509_hash.algorithm.integer);
	TEST_ASSERT_EQUAL_PTR(x5t_fingerprint,
			      material.x509_hash.fingerprint.value);
	TEST_ASSERT_EQUAL_PTR(certificate, material.credential.value);
}

TEST(internals_credentials, material_null_args)
{
	const struct edhoc_credential_selected cred = { 0 };
	struct edhoc_credential_material_asymmetric material = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_asymmetric_material_from_selected(
				  NULL, &material));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_asymmetric_material_from_selected(
				  &cred, NULL));
}

TEST(internals_credentials, material_unsupported_label)
{
	const struct edhoc_credential_selected cred = {
		.asymmetric.label = (enum edhoc_cose_header)99,
	};

	struct edhoc_credential_material_asymmetric material = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED,
			  edhoc_credential_asymmetric_material_from_selected(
				  &cred, &material));
}

TEST(internals_credentials, material_x5chain_over_capacity)
{
	const struct edhoc_credential_selected cred = {
		.asymmetric.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.asymmetric.x509_chain.count =
			EDHOC_CREDENTIAL_X5CHAIN_CAPACITY + 1,
	};

	struct edhoc_credential_material_asymmetric material = { 0 };
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED,
			  edhoc_credential_asymmetric_material_from_selected(
				  &cred, &material));
}

TEST(internals_credentials, id_cred_len_kid_one_byte)
{
	const uint8_t kid[1] = { 0x05 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .value = kid, .length = ARRAY_SIZE(kid) },
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_id_cred_length(&material,
								     &len));
	/* An upper bound: the map header is sized for the worst case. */
	TEST_ASSERT_GREATER_OR_EQUAL_size_t(4, len);
}

TEST(internals_credentials, id_cred_len_kid_long)
{
	const uint8_t kid[EDHOC_CREDENTIAL_KID_MAX_LEN] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .value = kid, .length = ARRAY_SIZE(kid) },
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_id_cred_length(&material,
								     &len));
	TEST_ASSERT_GREATER_THAN(ARRAY_SIZE(kid), len);
}

TEST(internals_credentials, id_cred_len_x5chain_single)
{
	const uint8_t cert[100] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.x509_chain.count = 1,
		.x509_chain.certificate[0] = { .value = cert,
					       .length = sizeof(cert) },
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_id_cred_length(&material,
								     &len));
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_credentials, id_cred_len_x5chain_multi)
{
	const uint8_t cert0[50] = { 0 };
	const uint8_t cert1[60] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.x509_chain.count = 2,
		.x509_chain.certificate[0] = { .value = cert0,
					       .length = sizeof(cert0) },
		.x509_chain.certificate[1] = { .value = cert1,
					       .length = sizeof(cert1) },
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_id_cred_length(&material,
								     &len));
	TEST_ASSERT_GREATER_THAN(sizeof(cert0) + sizeof(cert1), len);
}

TEST(internals_credentials, cbor_int_or_string_len_unknown_encoding)
{
	const struct edhoc_cbor_int_or_string value = {
		.encode_type = (enum edhoc_encode_type)7,
	};

	TEST_ASSERT_EQUAL(0, cbor_int_or_string_len(&value));
}

TEST(internals_credentials, id_cred_len_x5t_int)
{
	const uint8_t x5t_fingerprint[32] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_HASH,
		.x509_hash.algorithm = { .encode_type =
						 EDHOC_ENCODE_TYPE_INTEGER,
					 .integer = -8 },
		.x509_hash.fingerprint = { .value = x5t_fingerprint,
					   .length = sizeof(x5t_fingerprint) },
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_id_cred_length(&material,
								     &len));
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_credentials, id_cred_len_x5t_tstr)
{
	const uint8_t algorithm[2] = { 'S', 'H' };
	const uint8_t x5t_fingerprint[32] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
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
			  edhoc_credential_asymmetric_id_cred_length(&material,
								     &len));
	TEST_ASSERT_GREATER_THAN(0, len);
}

TEST(internals_credentials, id_cred_len_unsupported)
{
	const struct edhoc_credential_material_asymmetric material = {
		.label = 99,
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED,
			  edhoc_credential_asymmetric_id_cred_length(&material,
								     &len));
}

TEST(internals_credentials, id_cred_len_null_args)
{
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
	};
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_asymmetric_id_cred_length(NULL,
								     &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_asymmetric_id_cred_length(&material,
								     NULL));
}

TEST(internals_credentials, cred_len_follows_credential)
{
	const uint8_t credential[100] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
		.credential = { .value = credential,
				.length = sizeof(credential) },
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_cred_length(&material,
								  &len));
	TEST_ASSERT_GREATER_THAN(sizeof(credential), len);
}

TEST(internals_credentials, cred_len_unsupported)
{
	const struct edhoc_credential_material_asymmetric material = {
		.label = 99,
	};

	size_t len = 0;
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED,
			  edhoc_credential_asymmetric_cred_length(&material,
								  &len));
}

TEST(internals_credentials, cred_len_null_args)
{
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
	};
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_asymmetric_cred_length(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_asymmetric_cred_length(&material,
								  NULL));
}

TEST(internals_credentials, compact_kid_follows_rfc_examples)
{
	for (size_t i = 0; i < ARRAY_SIZE(compact_kid_cases); ++i) {
		const struct edhoc_credential_material_asymmetric material = {
			.label = EDHOC_COSE_HEADER_KID,
			.kid = compact_kid_cases[i].kid,
		};

		uint8_t buffer[8] = { 0 };
		size_t len = 0;

		TEST_ASSERT_EQUAL(
			EDHOC_SUCCESS,
			edhoc_credential_asymmetric_encode_id_cred_compact(
				&material, buffer, ARRAY_SIZE(buffer), &len));
		TEST_ASSERT_EQUAL_size_t(compact_kid_cases[i].expected_length,
					 len);
		TEST_ASSERT_EQUAL_HEX8_ARRAY(compact_kid_cases[i].expected,
					     buffer, len);
	}
}

TEST(internals_credentials, parse_kid_null_args)
{
	struct edhoc_credential_received received = { 0 };
	uint8_t byte = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_parse_kid_int(0, NULL, &received));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_parse_kid_int(0, &byte, NULL));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_parse_kid_bstr(NULL, 0, &received));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_parse_kid_bstr(&byte, 1, NULL));
}

TEST(internals_credentials, id_cred_kid_is_always_a_map)
{
	/* The full form goes into context_x, where RFC 9528: 3.5.3.2 forbids the
	 * compact encoding, so even a 'kid' in the short range stays a map. */
	const uint8_t kid[] = { 0x2b };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .value = kid, .length = ARRAY_SIZE(kid) },
	};
	const uint8_t expected[] = { 0xa1, 0x04, 0x41, 0x2b };

	uint8_t buffer[16] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_encode_id_cred(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(ARRAY_SIZE(expected), len);
	TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, buffer, len);
}

TEST(internals_credentials, id_cred_null_args)
{
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
	};
	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_asymmetric_encode_id_cred(
				  NULL, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_asymmetric_encode_id_cred(
				  &material, NULL, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_asymmetric_encode_id_cred(
				  &material, buffer, 0, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_asymmetric_encode_id_cred(
				  &material, buffer, ARRAY_SIZE(buffer), NULL));
}

TEST(internals_credentials, cred_raw_is_wrapped_in_a_byte_string)
{
	const uint8_t der[] = { 0x30, 0x00, 0x01 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.credential = { .value = der, .length = ARRAY_SIZE(der) },
	};
	const uint8_t expected[] = { 0x43, 0x30, 0x00, 0x01 };

	uint8_t buffer[16] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_encode_cred(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(ARRAY_SIZE(expected), len);
	TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, buffer, len);
}

TEST(internals_credentials, cred_cbor_encoded_is_embedded_as_it_is)
{
	const uint8_t ccs[] = { 0xa1, 0x02, 0x41, 0x2b };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
		.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED,
		.credential = { .value = ccs, .length = ARRAY_SIZE(ccs) },
	};

	uint8_t buffer[16] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_encode_cred(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(ARRAY_SIZE(ccs), len);
	TEST_ASSERT_EQUAL_HEX8_ARRAY(ccs, buffer, len);
}

TEST(internals_credentials, cred_format_unset_is_rejected)
{
	const uint8_t der[] = { 0x30, 0x00, 0x01 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_NONE,
		.credential = { .value = der, .length = ARRAY_SIZE(der) },
	};

	uint8_t buffer[16] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED,
			  edhoc_credential_asymmetric_encode_cred(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
}

TEST(internals_credentials, cred_null_args)
{
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
	};
	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_asymmetric_encode_cred(
				  NULL, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_asymmetric_encode_cred(
				  &material, NULL, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_asymmetric_encode_cred(
				  &material, buffer, 0, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_asymmetric_encode_cred(
				  &material, buffer, ARRAY_SIZE(buffer), NULL));
}

TEST(internals_credentials, compact_kid_bstr_takes_the_short_form)
{
	/* RFC 9529: 3 uses ID_CRED_I = { 4 : h'2b' }, whose compact form is the
	 * CBOR integer -12, i.e. the same byte. */
	const uint8_t kid[1] = { 0x2b };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .value = kid, .length = ARRAY_SIZE(kid) },
	};

	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_encode_id_cred_compact(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(1, len);
	TEST_ASSERT_EQUAL_HEX8(0x2b, buffer[0]);
}

TEST(internals_credentials, compact_kid_bstr_outside_the_short_form)
{
	/* One byte, but 0x40 is not a CBOR integer on its own, so the short
	 * form does not apply and the identifier stays a byte string. */
	const uint8_t kid[1] = { 0x40 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .value = kid, .length = ARRAY_SIZE(kid) },
	};

	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_encode_id_cred_compact(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(2, len);
	TEST_ASSERT_EQUAL_HEX8(0x41, buffer[0]);
	TEST_ASSERT_EQUAL_HEX8(0x40, buffer[1]);
}

TEST(internals_credentials, compact_kid_bstr_multi_byte)
{
	const uint8_t kid[2] = { 0xaa, 0xbb };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .value = kid, .length = ARRAY_SIZE(kid) },
	};

	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_encode_id_cred_compact(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(3, len);
	TEST_ASSERT_EQUAL_HEX8(0x42, buffer[0]);
	TEST_ASSERT_EQUAL_HEX8_ARRAY(kid, &buffer[1], sizeof(kid));
}

TEST(internals_credentials, compact_kid_bstr_empty)
{
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { 0 },
	};

	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_encode_id_cred_compact(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	/* An empty byte string is one CBOR byte: 0x40. */
	TEST_ASSERT_EQUAL_size_t(1, len);
	TEST_ASSERT_EQUAL_HEX8(0x40, buffer[0]);
}

TEST(internals_credentials, compact_kid_bstr_buffer_too_small)
{
	const uint8_t kid[4] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_KID,
		.kid = { .value = kid, .length = ARRAY_SIZE(kid) },
	};

	uint8_t buffer[2] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE,
			  edhoc_credential_asymmetric_encode_id_cred_compact(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
}

TEST(internals_credentials, compact_absent_for_x509)
{
	const uint8_t cert[10] = { 0 };
	const struct edhoc_credential_material_asymmetric material = {
		.label = EDHOC_COSE_HEADER_X509_CHAIN,
		.format = EDHOC_CREDENTIAL_FORMAT_RAW,
		.x509_chain.count = 1,
		.x509_chain.certificate[0] = { .value = cert,
					       .length = sizeof(cert) },
	};

	uint8_t buffer[8] = { 0 };
	size_t len = SIZE_MAX;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_asymmetric_encode_id_cred_compact(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(0, len);
}

TEST(internals_credentials, psk_validate_selected_accepts)
{
	const struct edhoc_credential_selected selected = psk_selected_ok();

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS, edhoc_credential_validate_selected(
						 EDHOC_METHOD_4, &selected));
}

TEST(internals_credentials, psk_validate_selected_label_unset)
{
	struct edhoc_credential_selected selected = psk_selected_ok();

	selected.psk.label = EDHOC_COSE_HEADER_NONE;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE,
			  edhoc_credential_validate_selected(EDHOC_METHOD_4,
							     &selected));
}

TEST(internals_credentials, psk_validate_selected_label_not_kid)
{
	struct edhoc_credential_selected selected = psk_selected_ok();

	selected.psk.label = EDHOC_COSE_HEADER_X509_CHAIN;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED,
			  edhoc_credential_validate_selected(EDHOC_METHOD_4,
							     &selected));
}

TEST(internals_credentials, psk_validate_selected_empty_kid)
{
	struct edhoc_credential_selected selected = psk_selected_ok();

	selected.psk.kid.identifier.length = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE,
			  edhoc_credential_validate_selected(EDHOC_METHOD_4,
							     &selected));
}

TEST(internals_credentials, psk_validate_selected_kid_over_capacity)
{
	static const uint8_t kid[EDHOC_CREDENTIAL_KID_MAX_LEN + 1] = { 0 };

	struct edhoc_credential_selected selected = psk_selected_ok();

	selected.psk.kid.identifier.value = kid;
	selected.psk.kid.identifier.length = ARRAY_SIZE(kid);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL,
			  edhoc_credential_validate_selected(EDHOC_METHOD_4,
							     &selected));
}

TEST(internals_credentials, psk_validate_selected_empty_credential)
{
	struct edhoc_credential_selected selected = psk_selected_ok();

	selected.psk.cred_i.length = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE,
			  edhoc_credential_validate_selected(EDHOC_METHOD_4,
							     &selected));

	selected = psk_selected_ok();
	selected.psk.cred_r.length = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE,
			  edhoc_credential_validate_selected(EDHOC_METHOD_4,
							     &selected));
}

TEST(internals_credentials, psk_validate_selected_equal_credentials)
{
	struct edhoc_credential_selected selected = psk_selected_ok();

	/* draft-ietf-lake-edhoc-psk: 3.1.2 - the two credentials identify the
	 * two peers, so a Selfie run is rejected. */
	selected.psk.cred_r = selected.psk.cred_i;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE,
			  edhoc_credential_validate_selected(EDHOC_METHOD_4,
							     &selected));
}

TEST(internals_credentials, psk_validate_selected_format_unset)
{
	struct edhoc_credential_selected selected = psk_selected_ok();

	selected.psk.format = EDHOC_CREDENTIAL_FORMAT_NONE;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE,
			  edhoc_credential_validate_selected(EDHOC_METHOD_4,
							     &selected));
}

TEST(internals_credentials, psk_validate_selected_bad_format)
{
	struct edhoc_credential_selected selected = psk_selected_ok();

	selected.psk.format = (enum edhoc_credential_format)99;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED,
			  edhoc_credential_validate_selected(EDHOC_METHOD_4,
							     &selected));
}

TEST(internals_credentials, psk_validate_trusted_accepts)
{
	const struct edhoc_credential_received received = {
		.label = EDHOC_COSE_HEADER_KID,
	};
	const struct edhoc_credential_trusted trusted = psk_trusted_ok();

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_validate_trusted(
				  EDHOC_METHOD_4, &received, &trusted));
}

TEST(internals_credentials, psk_validate_trusted_rejects)
{
	const struct edhoc_credential_received received = {
		.label = EDHOC_COSE_HEADER_KID,
	};
	struct edhoc_credential_trusted trusted = psk_trusted_ok();

	trusted.psk.cred_i.length = 0;
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE,
			  edhoc_credential_validate_trusted(
				  EDHOC_METHOD_4, &received, &trusted));

	trusted = psk_trusted_ok();
	trusted.psk.cred_r.length = 0;
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE,
			  edhoc_credential_validate_trusted(
				  EDHOC_METHOD_4, &received, &trusted));

	trusted = psk_trusted_ok();
	trusted.psk.cred_r = trusted.psk.cred_i;
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE,
			  edhoc_credential_validate_trusted(
				  EDHOC_METHOD_4, &received, &trusted));

	trusted = psk_trusted_ok();
	trusted.psk.format = EDHOC_CREDENTIAL_FORMAT_NONE;
	TEST_ASSERT_EQUAL(EDHOC_ERROR_CREDENTIALS_FAILURE,
			  edhoc_credential_validate_trusted(
				  EDHOC_METHOD_4, &received, &trusted));

	trusted = psk_trusted_ok();
	trusted.psk.format = (enum edhoc_credential_format)99;
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_PERMITTED,
			  edhoc_credential_validate_trusted(
				  EDHOC_METHOD_4, &received, &trusted));
}

TEST(internals_credentials, psk_material_from_selected)
{
	const struct edhoc_credential_selected selected = psk_selected_ok();
	struct edhoc_credential_material_psk material = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_psk_material_from_selected(
				  &selected, &material));

	TEST_ASSERT_EQUAL_PTR(selected.psk.kid.identifier.value,
			      material.kid.value);
	TEST_ASSERT_EQUAL_PTR(selected.psk.cred_i.value, material.cred_i.value);
	TEST_ASSERT_EQUAL_PTR(selected.psk.cred_r.value, material.cred_r.value);
	TEST_ASSERT_EQUAL(selected.psk.format, material.format);
}

TEST(internals_credentials, psk_material_from_selected_rejects)
{
	struct edhoc_credential_selected selected = psk_selected_ok();
	struct edhoc_credential_material_psk material = { 0 };

	TEST_ASSERT_EQUAL(
		EDHOC_ERROR_INVALID_ARGUMENT,
		edhoc_credential_psk_material_from_selected(NULL, &material));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_material_from_selected(&selected,
								      NULL));

	selected.psk.label = EDHOC_COSE_HEADER_X509_HASH;
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED,
			  edhoc_credential_psk_material_from_selected(
				  &selected, &material));
}

TEST(internals_credentials, psk_material_from_trusted)
{
	const struct edhoc_credential_received received = {
		.label = EDHOC_COSE_HEADER_KID,
	};
	const struct edhoc_credential_trusted trusted = psk_trusted_ok();
	struct edhoc_credential_material_psk material = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_psk_material_from_trusted(
				  &received, &trusted, &material));

	TEST_ASSERT_EQUAL_PTR(trusted.psk.cred_i.value, material.cred_i.value);
	TEST_ASSERT_EQUAL_PTR(trusted.psk.cred_r.value, material.cred_r.value);
}

TEST(internals_credentials, psk_material_from_trusted_rejects)
{
	struct edhoc_credential_received received = {
		.label = EDHOC_COSE_HEADER_KID,
	};
	const struct edhoc_credential_trusted trusted = psk_trusted_ok();
	struct edhoc_credential_material_psk material = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_material_from_trusted(
				  NULL, &trusted, &material));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_material_from_trusted(
				  &received, NULL, &material));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_material_from_trusted(
				  &received, &trusted, NULL));

	received.label = EDHOC_COSE_HEADER_X509_CHAIN;
	TEST_ASSERT_EQUAL(EDHOC_ERROR_NOT_SUPPORTED,
			  edhoc_credential_psk_material_from_trusted(
				  &received, &trusted, &material));
}

TEST(internals_credentials, psk_lengths)
{
	const struct edhoc_credential_selected selected = psk_selected_ok();
	struct edhoc_credential_material_psk material = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_psk_material_from_selected(
				  &selected, &material));

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_psk_id_cred_length(&material, &len));
	TEST_ASSERT_GREATER_THAN(material.kid.length, len);

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_psk_creds_length(&material, &len));
	TEST_ASSERT_GREATER_THAN(
		material.cred_i.length + material.cred_r.length, len);

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_id_cred_length(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_id_cred_length(&material, NULL));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_creds_length(NULL, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_creds_length(&material, NULL));
}

TEST(internals_credentials, psk_encode_id_cred_bstr)
{
	const struct edhoc_credential_selected selected = psk_selected_ok();
	struct edhoc_credential_material_psk material = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_psk_material_from_selected(
				  &selected, &material));

	/* draft-ietf-lake-edhoc-psk: B.3 - h'0010' compacts to 0x42 0x00 0x10. */
	static const uint8_t expected[] = { 0x42, 0x00, 0x10 };

	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_psk_encode_id_cred(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(ARRAY_SIZE(expected), len);
	TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, buffer, len);
}

TEST(internals_credentials, psk_encode_id_cred_one_byte_int)
{
	/* RFC 9528: 3.3.2 - a one byte 'kid' that is a complete CBOR integer
	 * travels as that integer. */
	static const uint8_t kid[] = { 0x2b };

	struct edhoc_credential_material_psk material = {
		.kid = { .value = kid, .length = ARRAY_SIZE(kid) },
		.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED,
	};

	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_psk_encode_id_cred(
				  &material, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL_size_t(1, len);
	TEST_ASSERT_EQUAL_HEX8(kid[0], buffer[0]);
}

TEST(internals_credentials, psk_encode_id_cred_rejects)
{
	const struct edhoc_credential_selected selected = psk_selected_ok();
	struct edhoc_credential_material_psk material = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_psk_material_from_selected(
				  &selected, &material));

	uint8_t buffer[8] = { 0 };
	size_t len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_encode_id_cred(
				  NULL, buffer, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_encode_id_cred(
				  &material, NULL, ARRAY_SIZE(buffer), &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_encode_id_cred(&material, buffer,
							      0, &len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_encode_id_cred(
				  &material, buffer, ARRAY_SIZE(buffer), NULL));

	uint8_t tiny[1] = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_ERROR_CBOR_FAILURE,
			  edhoc_credential_psk_encode_id_cred(
				  &material, tiny, ARRAY_SIZE(tiny), &len));
}

TEST(internals_credentials, psk_encode_creds)
{
	const struct edhoc_credential_selected selected = psk_selected_ok();
	struct edhoc_credential_material_psk material = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_psk_material_from_selected(
				  &selected, &material));

	uint8_t buffer[32] = { 0 };
	size_t cred_i_len = 0;
	size_t cred_r_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_psk_encode_creds(
				  &material, buffer, ARRAY_SIZE(buffer),
				  &cred_i_len, &cred_r_len));

	/* CBOR-encoded credentials are embedded as they are, in this order. */
	TEST_ASSERT_EQUAL_size_t(material.cred_i.length, cred_i_len);
	TEST_ASSERT_EQUAL_size_t(material.cred_r.length, cred_r_len);
	TEST_ASSERT_EQUAL_HEX8_ARRAY(material.cred_i.value, buffer, cred_i_len);
	TEST_ASSERT_EQUAL_HEX8_ARRAY(material.cred_r.value, &buffer[cred_i_len],
				     cred_r_len);
}

TEST(internals_credentials, psk_encode_creds_rejects)
{
	const struct edhoc_credential_selected selected = psk_selected_ok();
	struct edhoc_credential_material_psk material = { 0 };

	TEST_ASSERT_EQUAL(EDHOC_SUCCESS,
			  edhoc_credential_psk_material_from_selected(
				  &selected, &material));

	uint8_t buffer[32] = { 0 };
	size_t cred_i_len = 0;
	size_t cred_r_len = 0;

	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_encode_creds(
				  NULL, buffer, ARRAY_SIZE(buffer), &cred_i_len,
				  &cred_r_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_encode_creds(
				  &material, NULL, ARRAY_SIZE(buffer),
				  &cred_i_len, &cred_r_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_encode_creds(&material, buffer,
							    0, &cred_i_len,
							    &cred_r_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_encode_creds(&material, buffer,
							    ARRAY_SIZE(buffer),
							    NULL, &cred_r_len));
	TEST_ASSERT_EQUAL(EDHOC_ERROR_INVALID_ARGUMENT,
			  edhoc_credential_psk_encode_creds(&material, buffer,
							    ARRAY_SIZE(buffer),
							    &cred_i_len, NULL));

	/* CRED_I fits exactly, so CRED_R has nowhere to go. */
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL,
			  edhoc_credential_psk_encode_creds(
				  &material, buffer, material.cred_i.length,
				  &cred_i_len, &cred_r_len));

	/* CRED_I does not fit at all. */
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL,
			  edhoc_credential_psk_encode_creds(&material, buffer,
							    1, &cred_i_len,
							    &cred_r_len));

	/* CRED_R starts but does not fit. */
	TEST_ASSERT_EQUAL(EDHOC_ERROR_BUFFER_TOO_SMALL,
			  edhoc_credential_psk_encode_creds(
				  &material, buffer, material.cred_i.length + 1,
				  &cred_i_len, &cred_r_len));
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
	RUN_TEST_CASE(internals_credentials, validate_selected_null);
	RUN_TEST_CASE(internals_credentials, validate_selected_unknown_label);
	RUN_TEST_CASE(internals_credentials,
		      validate_selected_accepts_each_variant);
	RUN_TEST_CASE(internals_credentials,
		      validate_selected_kid_without_credential);
	RUN_TEST_CASE(internals_credentials,
		      validate_selected_kid_without_buffer);
	RUN_TEST_CASE(internals_credentials,
		      validate_selected_kid_format_unset);
	RUN_TEST_CASE(internals_credentials, validate_selected_kid_bad_format);
	RUN_TEST_CASE(internals_credentials,
		      validate_selected_kid_cbor_encoded);
	RUN_TEST_CASE(internals_credentials,
		      validate_selected_kid_over_capacity);
	RUN_TEST_CASE(internals_credentials, validate_selected_x5chain_empty);
	RUN_TEST_CASE(internals_credentials,
		      validate_selected_x5chain_over_capacity);
	RUN_TEST_CASE(internals_credentials,
		      validate_selected_x5chain_null_certificate);
	RUN_TEST_CASE(internals_credentials,
		      validate_selected_x5t_without_fingerprint);
	RUN_TEST_CASE(internals_credentials,
		      validate_selected_x5t_fingerprint_over_limit);
	RUN_TEST_CASE(internals_credentials,
		      validate_selected_x5t_bad_encode_type);

	/* Method 4 credentials. */
	RUN_TEST_CASE(internals_credentials, psk_validate_selected_accepts);
	RUN_TEST_CASE(internals_credentials, psk_validate_selected_label_unset);
	RUN_TEST_CASE(internals_credentials,
		      psk_validate_selected_label_not_kid);
	RUN_TEST_CASE(internals_credentials, psk_validate_selected_empty_kid);
	RUN_TEST_CASE(internals_credentials,
		      psk_validate_selected_kid_over_capacity);
	RUN_TEST_CASE(internals_credentials,
		      psk_validate_selected_empty_credential);
	RUN_TEST_CASE(internals_credentials,
		      psk_validate_selected_equal_credentials);
	RUN_TEST_CASE(internals_credentials,
		      psk_validate_selected_format_unset);
	RUN_TEST_CASE(internals_credentials, psk_validate_selected_bad_format);
	RUN_TEST_CASE(internals_credentials, psk_validate_trusted_accepts);
	RUN_TEST_CASE(internals_credentials, psk_validate_trusted_rejects);
	RUN_TEST_CASE(internals_credentials, psk_material_from_selected);
	RUN_TEST_CASE(internals_credentials,
		      psk_material_from_selected_rejects);
	RUN_TEST_CASE(internals_credentials, psk_material_from_trusted);
	RUN_TEST_CASE(internals_credentials, psk_material_from_trusted_rejects);
	RUN_TEST_CASE(internals_credentials, psk_lengths);
	RUN_TEST_CASE(internals_credentials, psk_encode_id_cred_bstr);
	RUN_TEST_CASE(internals_credentials, psk_encode_id_cred_one_byte_int);
	RUN_TEST_CASE(internals_credentials, psk_encode_id_cred_rejects);
	RUN_TEST_CASE(internals_credentials, psk_encode_creds);
	RUN_TEST_CASE(internals_credentials, psk_encode_creds_rejects);

	/* Validation of the credentials returned from authenticate_peer. */
	RUN_TEST_CASE(internals_credentials, validate_trusted_null);
	RUN_TEST_CASE(internals_credentials,
		      validate_trusted_without_public_key);
	RUN_TEST_CASE(internals_credentials,
		      validate_trusted_kid_without_credential);
	RUN_TEST_CASE(internals_credentials, validate_trusted_kid_format_unset);
	RUN_TEST_CASE(internals_credentials,
		      validate_trusted_x5t_without_certificate);
	RUN_TEST_CASE(internals_credentials,
		      validate_trusted_x5t_cbor_encoded_rejected);
	RUN_TEST_CASE(internals_credentials,
		      validate_trusted_unsupported_label);
	RUN_TEST_CASE(internals_credentials,
		      validate_trusted_x5chain_without_credential);
	RUN_TEST_CASE(internals_credentials,
		      validate_trusted_x5chain_cbor_encoded_rejected);
	RUN_TEST_CASE(internals_credentials,
		      validate_trusted_accepts_each_variant);

	/* Encoder input. */
	RUN_TEST_CASE(internals_credentials, material_kid);
	RUN_TEST_CASE(internals_credentials,
		      material_x5chain_cred_is_end_entity);
	RUN_TEST_CASE(internals_credentials, material_x5t);
	RUN_TEST_CASE(internals_credentials, material_null_args);
	RUN_TEST_CASE(internals_credentials, material_unsupported_label);
	RUN_TEST_CASE(internals_credentials, material_x5chain_over_capacity);

	/* ID_CRED_x and CRED_x lengths. */
	RUN_TEST_CASE(internals_credentials, id_cred_len_kid_one_byte);
	RUN_TEST_CASE(internals_credentials, id_cred_len_kid_long);
	RUN_TEST_CASE(internals_credentials, id_cred_len_x5chain_single);
	RUN_TEST_CASE(internals_credentials, id_cred_len_x5chain_multi);
	RUN_TEST_CASE(internals_credentials, id_cred_len_x5t_int);
	RUN_TEST_CASE(internals_credentials, id_cred_len_x5t_tstr);
	RUN_TEST_CASE(internals_credentials,
		      cbor_int_or_string_len_unknown_encoding);
	RUN_TEST_CASE(internals_credentials, id_cred_len_unsupported);
	RUN_TEST_CASE(internals_credentials, id_cred_len_null_args);
	RUN_TEST_CASE(internals_credentials, cred_len_follows_credential);
	RUN_TEST_CASE(internals_credentials, cred_len_unsupported);
	RUN_TEST_CASE(internals_credentials, cred_len_null_args);

	/* Compact ID_CRED_x. */
	RUN_TEST_CASE(internals_credentials, compact_kid_follows_rfc_examples);
	RUN_TEST_CASE(internals_credentials, parse_kid_null_args);
	RUN_TEST_CASE(internals_credentials, id_cred_kid_is_always_a_map);
	RUN_TEST_CASE(internals_credentials, id_cred_null_args);
	RUN_TEST_CASE(internals_credentials,
		      cred_raw_is_wrapped_in_a_byte_string);
	RUN_TEST_CASE(internals_credentials,
		      cred_cbor_encoded_is_embedded_as_it_is);
	RUN_TEST_CASE(internals_credentials, cred_format_unset_is_rejected);
	RUN_TEST_CASE(internals_credentials, cred_null_args);
	RUN_TEST_CASE(internals_credentials,
		      compact_kid_bstr_takes_the_short_form);
	RUN_TEST_CASE(internals_credentials,
		      compact_kid_bstr_outside_the_short_form);
	RUN_TEST_CASE(internals_credentials, compact_kid_bstr_multi_byte);
	RUN_TEST_CASE(internals_credentials, compact_kid_bstr_empty);
	RUN_TEST_CASE(internals_credentials, compact_kid_bstr_buffer_too_small);
	RUN_TEST_CASE(internals_credentials, compact_absent_for_x509);
}
