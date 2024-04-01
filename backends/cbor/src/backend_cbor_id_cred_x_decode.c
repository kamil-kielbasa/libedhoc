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
static bool decode_repeated_id_cred_x_x5bag(zcbor_state_t *state, struct id_cred_x_x5bag *result);
static bool decode_repeated_id_cred_x_x5chain(zcbor_state_t *state, struct id_cred_x_x5chain *result);
static bool decode_repeated_id_cred_x_x5t(zcbor_state_t *state, struct id_cred_x_x5t_ *result);
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

static bool decode_repeated_id_cred_x_x5bag(
		zcbor_state_t *state, struct id_cred_x_x5bag *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (32))))
	&& (zcbor_bstr_decode(state, (&(*result)._id_cred_x_x5bag)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_id_cred_x_x5chain(
		zcbor_state_t *state, struct id_cred_x_x5chain *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (33))))
	&& (zcbor_bstr_decode(state, (&(*result)._id_cred_x_x5chain)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_id_cred_x_x5t(
		zcbor_state_t *state, struct id_cred_x_x5t_ *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = ((((zcbor_uint32_expect(state, (34))))
	&& (zcbor_list_start_decode(state) && ((((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result)._id_cred_x_x5t_alg_int)))) && (((*result)._id_cred_x_x5t_alg_choice = _id_cred_x_x5t_alg_int), true))
	|| (((zcbor_bstr_decode(state, (&(*result)._id_cred_x_x5t_alg_bstr)))) && (((*result)._id_cred_x_x5t_alg_choice = _id_cred_x_x5t_alg_bstr), true))), zcbor_union_end_code(state), int_res)))
	&& ((zcbor_bstr_decode(state, (&(*result)._id_cred_x_x5t_hash))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_id_cred_x(
		zcbor_state_t *state, struct id_cred_x *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && ((zcbor_present_decode(&((*result)._id_cred_x_kid_present), (zcbor_decoder_t *)decode_repeated_id_cred_x_kid, state, (&(*result)._id_cred_x_kid))
	&& zcbor_present_decode(&((*result)._id_cred_x_x5bag_present), (zcbor_decoder_t *)decode_repeated_id_cred_x_x5bag, state, (&(*result)._id_cred_x_x5bag))
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
