/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_decode.h"
#include "backend_cbor_id_cred_x_decode.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_repeated_id_cred_x_kid(zcbor_state_t *state, struct id_cred_x_kid_ *result);
static bool decode_COSE_X509(zcbor_state_t *state, struct COSE_X509_ *result);
static bool decode_repeated_id_cred_x_x5chain(zcbor_state_t *state, struct id_cred_x_x5chain *result);
static bool decode_COSE_CertHash(zcbor_state_t *state, struct COSE_CertHash *result);
static bool decode_repeated_id_cred_x_x5t(zcbor_state_t *state, struct id_cred_x_x5t *result);
static bool decode_id_cred_x(zcbor_state_t *state, struct id_cred_x *result);


static bool decode_repeated_id_cred_x_kid(
		zcbor_state_t *state, struct id_cred_x_kid_ *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = ((((zcbor_uint32_expect(state, (4))))
	&& (zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result)._id_cred_x_kid_int)))) && (((*result)._id_cred_x_kid_choice = _id_cred_x_kid_int), true))
	|| (((zcbor_bstr_decode(state, (&(*result)._id_cred_x_kid_bstr)))) && (((*result)._id_cred_x_kid_choice = _id_cred_x_kid_bstr), true))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_COSE_X509(
		zcbor_state_t *state, struct COSE_X509_ *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_bstr_decode(state, (&(*result)._COSE_X509_bstr)))) && (((*result)._COSE_X509_choice = _COSE_X509_bstr), true))
	|| (zcbor_union_elem_code(state) && (((zcbor_list_start_decode(state) && ((zcbor_multi_decode(2, 3, &(*result)._COSE_X509__certs_certs_count, (zcbor_decoder_t *)zcbor_bstr_decode, state, (&(*result)._COSE_X509__certs_certs), sizeof(struct zcbor_string))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))) && (((*result)._COSE_X509_choice = _COSE_X509__certs), true)))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_id_cred_x_x5chain(
		zcbor_state_t *state, struct id_cred_x_x5chain *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (33))))
	&& (decode_COSE_X509(state, (&(*result)._id_cred_x_x5chain)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_COSE_CertHash(
		zcbor_state_t *state, struct COSE_CertHash *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((zcbor_list_start_decode(state) && ((((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result)._COSE_CertHash_hashAlg_int)))) && (((*result)._COSE_CertHash_hashAlg_choice = _COSE_CertHash_hashAlg_int), true))
	|| (((zcbor_tstr_decode(state, (&(*result)._COSE_CertHash_hashAlg_tstr)))) && (((*result)._COSE_CertHash_hashAlg_choice = _COSE_CertHash_hashAlg_tstr), true))), zcbor_union_end_code(state), int_res)))
	&& ((zcbor_bstr_decode(state, (&(*result)._COSE_CertHash_hashValue))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_id_cred_x_x5t(
		zcbor_state_t *state, struct id_cred_x_x5t *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (34))))
	&& (decode_COSE_CertHash(state, (&(*result)._id_cred_x_x5t)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_id_cred_x(
		zcbor_state_t *state, struct id_cred_x *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && ((zcbor_present_decode(&((*result)._id_cred_x_kid_present), (zcbor_decoder_t *)decode_repeated_id_cred_x_kid, state, (&(*result)._id_cred_x_kid))
	&& zcbor_present_decode(&((*result)._id_cred_x_x5chain_present), (zcbor_decoder_t *)decode_repeated_id_cred_x_x5chain, state, (&(*result)._id_cred_x_x5chain))
	&& zcbor_present_decode(&((*result)._id_cred_x_x5t_present), (zcbor_decoder_t *)decode_repeated_id_cred_x_x5t, state, (&(*result)._id_cred_x_x5t))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_decode_id_cred_x(
		const uint8_t *payload, size_t payload_len,
		struct id_cred_x *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 1);

	bool ret = decode_id_cred_x(states, result);

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
