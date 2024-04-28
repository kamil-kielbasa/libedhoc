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
#include "backend_cbor_plaintext_3_decode.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_repeated_map_kid(zcbor_state_t *state, struct map_kid_ *result);
static bool decode_repeated_map_x5bag(zcbor_state_t *state, struct map_x5bag *result);
static bool decode_repeated_map_x5chain(zcbor_state_t *state, struct map_x5chain *result);
static bool decode_repeated_map_x5t(zcbor_state_t *state, struct map_x5t_ *result);
static bool decode_map(zcbor_state_t *state, struct map *result);
static bool decode_repeated_ead_x(zcbor_state_t *state, struct ead_x *result);
static bool decode_ead_x(zcbor_state_t *state, struct ead_x_ *result);
static bool decode_plaintext_3(zcbor_state_t *state, struct plaintext_3 *result);


static bool decode_repeated_map_kid(
		zcbor_state_t *state, struct map_kid_ *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = ((((zcbor_uint32_expect(state, (4))))
	&& (zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result)._map_kid_int)))) && (((*result)._map_kid_choice = _map_kid_int), true))
	|| (((zcbor_bstr_decode(state, (&(*result)._map_kid_bstr)))) && (((*result)._map_kid_choice = _map_kid_bstr), true))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_map_x5bag(
		zcbor_state_t *state, struct map_x5bag *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (32))))
	&& (zcbor_bstr_decode(state, (&(*result)._map_x5bag)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_map_x5chain(
		zcbor_state_t *state, struct map_x5chain *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (33))))
	&& (zcbor_bstr_decode(state, (&(*result)._map_x5chain)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_map_x5t(
		zcbor_state_t *state, struct map_x5t_ *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = ((((zcbor_uint32_expect(state, (34))))
	&& (zcbor_list_start_decode(state) && ((((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result)._map_x5t_alg_int)))) && (((*result)._map_x5t_alg_choice = _map_x5t_alg_int), true))
	|| (((zcbor_bstr_decode(state, (&(*result)._map_x5t_alg_bstr)))) && (((*result)._map_x5t_alg_choice = _map_x5t_alg_bstr), true))), zcbor_union_end_code(state), int_res)))
	&& ((zcbor_bstr_decode(state, (&(*result)._map_x5t_hash))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_map(
		zcbor_state_t *state, struct map *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && ((zcbor_present_decode(&((*result)._map_kid_present), (zcbor_decoder_t *)decode_repeated_map_kid, state, (&(*result)._map_kid))
	&& zcbor_present_decode(&((*result)._map_x5bag_present), (zcbor_decoder_t *)decode_repeated_map_x5bag, state, (&(*result)._map_x5bag))
	&& zcbor_present_decode(&((*result)._map_x5chain_present), (zcbor_decoder_t *)decode_repeated_map_x5chain, state, (&(*result)._map_x5chain))
	&& zcbor_present_decode(&((*result)._map_x5t_present), (zcbor_decoder_t *)decode_repeated_map_x5t, state, (&(*result)._map_x5t))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_ead_x(
		zcbor_state_t *state, struct ead_x *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_decode(state, (&(*result)._ead_x_ead_label))))
	&& zcbor_present_decode(&((*result)._ead_x_ead_value_present), (zcbor_decoder_t *)zcbor_bstr_decode, state, (&(*result)._ead_x_ead_value)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_ead_x(
		zcbor_state_t *state, struct ead_x_ *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (zcbor_multi_decode(1, 3, &(*result)._ead_x_count, (zcbor_decoder_t *)decode_repeated_ead_x, state, (&(*result)._ead_x), sizeof(struct ead_x)));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_plaintext_3(
		zcbor_state_t *state, struct plaintext_3 *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result)._plaintext_3_ID_CRED_I_int)))) && (((*result)._plaintext_3_ID_CRED_I_choice = _plaintext_3_ID_CRED_I_int), true))
	|| (((zcbor_bstr_decode(state, (&(*result)._plaintext_3_ID_CRED_I_bstr)))) && (((*result)._plaintext_3_ID_CRED_I_choice = _plaintext_3_ID_CRED_I_bstr), true))
	|| (zcbor_union_elem_code(state) && (((decode_map(state, (&(*result)._plaintext_3_ID_CRED_I__map)))) && (((*result)._plaintext_3_ID_CRED_I_choice = _plaintext_3_ID_CRED_I__map), true)))), zcbor_union_end_code(state), int_res)))
	&& ((zcbor_bstr_decode(state, (&(*result)._plaintext_3_Signature_or_MAC_3))))
	&& zcbor_present_decode(&((*result)._plaintext_3_EAD_3_present), (zcbor_decoder_t *)decode_ead_x, state, (&(*result)._plaintext_3_EAD_3)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_decode_plaintext_3(
		const uint8_t *payload, size_t payload_len,
		struct plaintext_3 *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[6];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 8);

	bool ret = decode_plaintext_3(states, result);

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
