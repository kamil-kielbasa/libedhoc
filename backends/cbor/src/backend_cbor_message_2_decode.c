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
#include "backend_cbor_message_2_decode.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_message_2(zcbor_state_t *state, struct message_2 *result);


static bool decode_message_2(
		zcbor_state_t *state, struct message_2 *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((((zcbor_bstr_decode(state, (&(*result)._message_2_G_Y_CIPHERTEXT_2))))
	&& ((zcbor_union_start_code(state) && (int_res = ((((zcbor_bstr_decode(state, (&(*result)._message_2_C_R_bstr)))) && (((*result)._message_2_C_R_choice = _message_2_C_R_bstr), true))
	|| (((zcbor_int32_decode(state, (&(*result)._message_2_C_R_int)))
	&& ((((*result)._message_2_C_R_int >= -24)
	&& ((*result)._message_2_C_R_int <= 23)) || (zcbor_error(state, ZCBOR_ERR_WRONG_RANGE), false))) && (((*result)._message_2_C_R_choice = _message_2_C_R_int), true))), zcbor_union_end_code(state), int_res))))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_decode_message_2(
		const uint8_t *payload, size_t payload_len,
		struct message_2 *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 2);

	bool ret = decode_message_2(states, result);

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
