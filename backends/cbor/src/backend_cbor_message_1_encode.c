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
#include "backend_cbor_message_1_encode.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_suites(zcbor_state_t *state, const struct suites_ *input);
static bool encode_repeated_ead(zcbor_state_t *state, const struct ead *input);
static bool encode_ead(zcbor_state_t *state, const struct ead_ *input);
static bool encode_message_1(zcbor_state_t *state, const struct message_1 *input);


static bool encode_suites(
		zcbor_state_t *state, const struct suites_ *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((*input)._suites_choice == _suites__int) ? ((zcbor_list_start_encode(state, 3) && ((zcbor_multi_encode_minmax(2, 3, &(*input)._suites__int_int_count, (zcbor_encoder_t *)zcbor_int32_encode, state, (&(*input)._suites__int_int), sizeof(int32_t))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 3)))
	: (((*input)._suites_choice == _suites_int) ? ((zcbor_int32_encode(state, (&(*input)._suites_int))))
	: false))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_repeated_ead(
		zcbor_state_t *state, const struct ead *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_encode(state, (&(*input)._ead_label))))
	&& zcbor_present_encode(&((*input)._ead_value_present), (zcbor_encoder_t *)zcbor_bstr_encode, state, (&(*input)._ead_value)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_ead(
		zcbor_state_t *state, const struct ead_ *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (zcbor_multi_encode_minmax(1, 3, &(*input)._ead_count, (zcbor_encoder_t *)encode_repeated_ead, state, (&(*input)._ead), sizeof(struct ead)));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_message_1(
		zcbor_state_t *state, const struct message_1 *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_encode(state, (&(*input)._message_1_METHOD))))
	&& ((encode_suites(state, (&(*input)._message_1_SUITES_I))))
	&& ((zcbor_bstr_encode(state, (&(*input)._message_1_G_X))))
	&& ((((*input)._message_1_C_I_choice == _message_1_C_I_bstr) ? ((zcbor_bstr_encode(state, (&(*input)._message_1_C_I_bstr))))
	: (((*input)._message_1_C_I_choice == _message_1_C_I_int) ? (((((*input)._message_1_C_I_int >= -24)
	&& ((*input)._message_1_C_I_int <= 23)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))
	&& (zcbor_int32_encode(state, (&(*input)._message_1_C_I_int))))
	: false)))
	&& zcbor_present_encode(&((*input)._message_1_EAD_1_present), (zcbor_encoder_t *)encode_ead, state, (&(*input)._message_1_EAD_1)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_encode_message_1(
		uint8_t *payload, size_t payload_len,
		const struct message_1 *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 10);

	bool ret = encode_message_1(states, input);

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
