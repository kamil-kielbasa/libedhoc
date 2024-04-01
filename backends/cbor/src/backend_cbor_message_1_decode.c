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
#include "backend_cbor_message_1_decode.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_suites(zcbor_state_t *state, struct suites_ *result);
static bool decode_repeated_ead(zcbor_state_t *state, struct ead *result);
static bool decode_ead(zcbor_state_t *state, struct ead_ *result);
static bool decode_message_1(zcbor_state_t *state, struct message_1 *result);


static bool decode_suites(
		zcbor_state_t *state, struct suites_ *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_list_start_decode(state) && ((zcbor_multi_decode(2, 3, &(*result)._suites__int_int_count, (zcbor_decoder_t *)zcbor_int32_decode, state, (&(*result)._suites__int_int), sizeof(int32_t))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))) && (((*result)._suites_choice = _suites__int), true))
	|| (zcbor_union_elem_code(state) && (((zcbor_int32_decode(state, (&(*result)._suites_int)))) && (((*result)._suites_choice = _suites_int), true)))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_ead(
		zcbor_state_t *state, struct ead *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_decode(state, (&(*result)._ead_label))))
	&& zcbor_present_decode(&((*result)._ead_value_present), (zcbor_decoder_t *)zcbor_bstr_decode, state, (&(*result)._ead_value)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_ead(
		zcbor_state_t *state, struct ead_ *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (zcbor_multi_decode(1, 3, &(*result)._ead_count, (zcbor_decoder_t *)decode_repeated_ead, state, (&(*result)._ead), sizeof(struct ead)));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_message_1(
		zcbor_state_t *state, struct message_1 *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((((zcbor_int32_decode(state, (&(*result)._message_1_METHOD))))
	&& ((decode_suites(state, (&(*result)._message_1_SUITES_I))))
	&& ((zcbor_bstr_decode(state, (&(*result)._message_1_G_X))))
	&& ((zcbor_union_start_code(state) && (int_res = ((((zcbor_bstr_decode(state, (&(*result)._message_1_C_I_bstr)))) && (((*result)._message_1_C_I_choice = _message_1_C_I_bstr), true))
	|| (((zcbor_int32_decode(state, (&(*result)._message_1_C_I_int)))
	&& ((((*result)._message_1_C_I_int >= -24)
	&& ((*result)._message_1_C_I_int <= 23)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) && (((*result)._message_1_C_I_choice = _message_1_C_I_int), true))), zcbor_union_end_code(state), int_res)))
	&& zcbor_present_decode(&((*result)._message_1_EAD_1_present), (zcbor_decoder_t *)decode_ead, state, (&(*result)._message_1_EAD_1)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_decode_message_1(
		const uint8_t *payload, size_t payload_len,
		struct message_1 *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 10);

	bool ret = decode_message_1(states, result);

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
