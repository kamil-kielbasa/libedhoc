/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_encode.h"
#include "backend_cbor_id_cred_x_encode.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_repeated_id_cred_x_kid(zcbor_state_t *state, const struct id_cred_x_kid_ *input);
static bool encode_COSE_X509(zcbor_state_t *state, const struct COSE_X509_ *input);
static bool encode_repeated_id_cred_x_x5chain(zcbor_state_t *state, const struct id_cred_x_x5chain *input);
static bool encode_COSE_CertHash(zcbor_state_t *state, const struct COSE_CertHash *input);
static bool encode_repeated_id_cred_x_x5t(zcbor_state_t *state, const struct id_cred_x_x5t *input);
static bool encode_id_cred_x(zcbor_state_t *state, const struct id_cred_x *input);


static bool encode_repeated_id_cred_x_kid(
		zcbor_state_t *state, const struct id_cred_x_kid_ *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (4))))
	&& (((*input)._id_cred_x_kid_choice == _id_cred_x_kid_int) ? ((zcbor_int32_encode(state, (&(*input)._id_cred_x_kid_int))))
	: (((*input)._id_cred_x_kid_choice == _id_cred_x_kid_bstr) ? ((zcbor_bstr_encode(state, (&(*input)._id_cred_x_kid_bstr))))
	: false))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_COSE_X509(
		zcbor_state_t *state, const struct COSE_X509_ *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((*input)._COSE_X509_choice == _COSE_X509_bstr) ? ((zcbor_bstr_encode(state, (&(*input)._COSE_X509_bstr))))
	: (((*input)._COSE_X509_choice == _COSE_X509__certs) ? ((zcbor_list_start_encode(state, 3) && ((zcbor_multi_encode_minmax(2, 3, &(*input)._COSE_X509__certs_certs_count, (zcbor_encoder_t *)zcbor_bstr_encode, state, (&(*input)._COSE_X509__certs_certs), sizeof(struct zcbor_string))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 3)))
	: false))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_repeated_id_cred_x_x5chain(
		zcbor_state_t *state, const struct id_cred_x_x5chain *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (33))))
	&& (encode_COSE_X509(state, (&(*input)._id_cred_x_x5chain)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_COSE_CertHash(
		zcbor_state_t *state, const struct COSE_CertHash *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((zcbor_list_start_encode(state, 2) && ((((((*input)._COSE_CertHash_hashAlg_choice == _COSE_CertHash_hashAlg_int) ? ((zcbor_int32_encode(state, (&(*input)._COSE_CertHash_hashAlg_int))))
	: (((*input)._COSE_CertHash_hashAlg_choice == _COSE_CertHash_hashAlg_tstr) ? ((zcbor_tstr_encode(state, (&(*input)._COSE_CertHash_hashAlg_tstr))))
	: false)))
	&& ((zcbor_bstr_encode(state, (&(*input)._COSE_CertHash_hashValue))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_repeated_id_cred_x_x5t(
		zcbor_state_t *state, const struct id_cred_x_x5t *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (34))))
	&& (encode_COSE_CertHash(state, (&(*input)._id_cred_x_x5t)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_id_cred_x(
		zcbor_state_t *state, const struct id_cred_x *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 3) && ((zcbor_present_encode(&((*input)._id_cred_x_kid_present), (zcbor_encoder_t *)encode_repeated_id_cred_x_kid, state, (&(*input)._id_cred_x_kid))
	&& zcbor_present_encode(&((*input)._id_cred_x_x5chain_present), (zcbor_encoder_t *)encode_repeated_id_cred_x_x5chain, state, (&(*input)._id_cred_x_x5chain))
	&& zcbor_present_encode(&((*input)._id_cred_x_x5t_present), (zcbor_encoder_t *)encode_repeated_id_cred_x_x5t, state, (&(*input)._id_cred_x_x5t))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 3))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_encode_id_cred_x(
		uint8_t *payload, size_t payload_len,
		const struct id_cred_x *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 1);

	bool ret = encode_id_cred_x(states, input);

	if (ret && (payload_len_out != NULL)) {
		*payload_len_out = MIN(payload_len,
				(size_t)states[0].payload - (size_t)payload);
	}

	if (!ret) {
		int err = zcbor_pop_error(states);

		zcbor_print("Return error: %d\r\n", err);
		return (err == ZCBOR_SUCCESS) ? ZCBOR_ERR_UNKNOWN : err;
	}
	return ZCBOR_SUCCESS;
}
